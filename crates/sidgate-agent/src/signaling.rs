//! Serveur HTTPS et canal de signalisation WSS.
//!
//! L'agent sert lui-même la PWA, embarquée dans le binaire : aucun fichier à
//! déployer à côté, et rien qu'un tiers puisse remplacer sur le disque.
//!
//! Une seule session à la fois. La limite n'est pas technique, elle est
//! délibérée : deux clients pilotant simultanément la même souris ne donne
//! jamais rien de bon, et un second visiteur ne doit pas pouvoir observer la
//! session du premier.

use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{ConnectInfo, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use bytes::BytesMut;
use futures_util::{SinkExt, StreamExt};
use parking_lot::Mutex;
use rand::TryRngCore;
use tokio::sync::mpsc;

use sidgate_input::{InputSink, PressedState};
use sidgate_proto::control::{
    Capabilities, ControlCommand, ControlEvent, CursorMode, RejectReason, Stats,
};
use sidgate_proto::input::{InputFrame, SeqTracker};
use sidgate_proto::signaling::{
    self, AuthError, ClientMessage, ServerMessage, NONCE_LEN,
};
use sidgate_proto::{CHANNEL_CONTROL, CHANNEL_INPUT, PROTOCOL_VERSION};
use webrtc::data_channel::{DataChannel, DataChannelEvent};
use webrtc::peer_connection::RTCIceCandidateInit;

use crate::config::Config;
use crate::control::{Dispatcher, Effect};
use crate::identity::Identity;
use crate::pipeline::{Pipeline, StatsSnapshot};
use crate::session::{self, Session, SessionEvent};
use crate::tls::TlsMaterial;

/// Période des remontées de télémétrie.
const STATS_INTERVAL: Duration = Duration::from_secs(2);
/// Intervalle entre deux tentatives d'ouverture de la capture.
const CAPTURE_RETRY_INTERVAL: Duration = Duration::from_secs(2);
/// Délai maximal accordé au handshake d'authentification.
///
/// Une connexion qui reste muette après le défi consomme l'unique emplacement
/// de session ; la refermer d'office évite un déni de service trivial. Le délai
/// est large parce qu'il court aussi pendant qu'un humain recopie un code
/// d'appairage depuis l'écran de l'hôte — ce n'est pas ce délai qui protège du
/// force brute, c'est la limitation de débit par source.
const AUTH_TIMEOUT: Duration = Duration::from_secs(180);

/// État partagé par toutes les connexions HTTP.
pub struct AppState {
    /// Identité et registre des clients.
    pub identity: Mutex<Identity>,
    /// Configuration de l'agent.
    pub config: Config,
    /// Une session est-elle déjà en cours ?
    pub busy: AtomicBool,
}

/// Démarre le serveur et ne rend la main qu'à son arrêt.
pub async fn serve(state: Arc<AppState>, tls: TlsMaterial) -> anyhow::Result<()> {
    let address = SocketAddr::new(state.config.network.bind, state.config.network.port);
    let use_tls = state.config.network.tls;

    let app = Router::new()
        .route("/", get(index))
        .route("/app.js", get(app_js))
        .route("/keymap.js", get(keymap_js))
        .route("/sw.js", get(service_worker))
        .route("/manifest.webmanifest", get(manifest))
        .route("/ws", get(websocket))
        .with_state(state);

    let service = app.into_make_service_with_connect_info::<SocketAddr>();

    if use_tls {
        let config =
            axum_server::tls_rustls::RustlsConfig::from_pem(tls.cert_pem, tls.key_pem).await?;
        tracing::info!(%address, "serveur prêt en HTTPS");
        axum_server::bind_rustls(address, config).serve(service).await?;
    } else {
        tracing::warn!(
            %address,
            "serveur en clair — réservé au développement sur la boucle locale"
        );
        axum_server::bind(address).serve(service).await?;
    }
    Ok(())
}

// --- Ressources statiques ---------------------------------------------------
//
// Embarquées dans le binaire : un agent se déploie en copiant un seul fichier,
// et la page servie ne peut pas être remplacée sur le disque.

async fn index() -> Response {
    html(include_str!("../../../client/index.html"))
}

async fn app_js() -> Response {
    javascript(include_str!("../../../client/app.js"))
}

async fn keymap_js() -> Response {
    javascript(include_str!("../../../client/keymap.js"))
}

async fn service_worker() -> Response {
    javascript(include_str!("../../../client/sw.js"))
}

async fn manifest() -> Response {
    (
        [(header::CONTENT_TYPE, "application/manifest+json")],
        include_str!("../../../client/manifest.webmanifest"),
    )
        .into_response()
}

fn html(body: &'static str) -> Response {
    (
        [
            (header::CONTENT_TYPE, "text/html; charset=utf-8"),
            // La page ne charge rien d'externe : le verrouiller explicitement
            // supprime toute possibilité d'injection par ressource tierce.
            (
                header::CONTENT_SECURITY_POLICY,
                "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; \
                 img-src 'self' data:; media-src 'self' blob:; connect-src 'self' ws: wss:; \
                 base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
            ),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
            (header::REFERRER_POLICY, "no-referrer"),
        ],
        body,
    )
        .into_response()
}

fn javascript(body: &'static str) -> Response {
    (
        [
            (header::CONTENT_TYPE, "text/javascript; charset=utf-8"),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
        ],
        body,
    )
        .into_response()
}

// --- Signalisation ----------------------------------------------------------

async fn websocket(
    upgrade: WebSocketUpgrade,
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
) -> Response {
    if state
        .busy
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        tracing::warn!(%peer, "session déjà en cours, connexion refusée");
        return (StatusCode::CONFLICT, "une session est déjà en cours").into_response();
    }
    upgrade.on_upgrade(move |socket| async move {
        let outcome = run_connection(socket, Arc::clone(&state), peer.ip()).await;
        if let Err(e) = outcome {
            tracing::warn!(%peer, error = %e, "session terminée sur erreur");
        }
        state.busy.store(false, Ordering::Release);
    })
}

/// Déroule une connexion complète : authentification, négociation, session.
async fn run_connection(
    socket: WebSocket,
    state: Arc<AppState>,
    peer: IpAddr,
) -> anyhow::Result<()> {
    let (mut sink, mut stream) = socket.split();

    let server_nonce = random_nonce()?;
    // Un seul verrou pour les deux lectures : `parking_lot::Mutex` n'est pas
    // réentrant, et deux `lock()` dans la même expression s'interbloquent —
    // le garde du premier vit jusqu'à la fin de l'instruction.
    let challenge = {
        let identity = state.identity.lock();
        ServerMessage::Challenge {
            protocol: PROTOCOL_VERSION,
            server_nonce: signaling::to_hex(&server_nonce),
            agent_key: identity.public_key_hex(),
            pairing_open: identity.pairing_open(),
        }
    };
    tracing::debug!(%peer, "défi émis");
    sink.send(Message::Text(serde_json::to_string(&challenge)?.into()))
        .await?;

    let authenticated =
        match tokio::time::timeout(AUTH_TIMEOUT, authenticate(&mut stream, &state, peer, &server_nonce))
            .await
        {
            Ok(Ok(result)) => result,
            Ok(Err(e)) => return Err(e),
            Err(_) => {
                tracing::warn!(%peer, "handshake abandonné, délai dépassé");
                return Ok(());
            }
        };

    let (client_key, client_nonce) = match authenticated {
        Ok(pair) => pair,
        Err(reason) => {
            let message = ServerMessage::AuthFailed { reason };
            sink.send(Message::Text(serde_json::to_string(&message)?.into()))
                .await?;
            tracing::warn!(%peer, ?reason, "authentification refusée");
            return Ok(());
        }
    };

    let key_bytes = signaling::from_hex(&client_key).unwrap_or_default();
    let agent_signature =
        state
            .identity
            .lock()
            .sign_agent_transcript(&server_nonce, &client_nonce, &key_bytes);
    let session_id = signaling::to_hex(&random_nonce()?[..8]);
    let ok = ServerMessage::AuthOk {
        agent_signature,
        session_id: session_id.clone(),
    };
    sink.send(Message::Text(serde_json::to_string(&ok)?.into()))
        .await?;
    tracing::info!(%peer, session = %session_id, "client authentifié");

    run_session(sink, stream, state, session_id).await
}

type AuthOutcome = Result<(String, [u8; NONCE_LEN]), AuthError>;

/// Attend et vérifie le message d'authentification ou d'appairage.
async fn authenticate(
    stream: &mut futures_util::stream::SplitStream<WebSocket>,
    state: &Arc<AppState>,
    peer: IpAddr,
    server_nonce: &[u8; NONCE_LEN],
) -> anyhow::Result<AuthOutcome> {
    while let Some(message) = stream.next().await {
        let text = match message? {
            Message::Text(text) => text,
            Message::Close(_) => return Ok(Err(AuthError::UnexpectedMessage)),
            _ => continue,
        };

        let Ok(message) = serde_json::from_str::<ClientMessage>(&text) else {
            return Ok(Err(AuthError::UnexpectedMessage));
        };

        return Ok(match message {
            ClientMessage::Authenticate {
                protocol,
                client_key,
                client_nonce,
                signature,
            } => {
                if protocol != PROTOCOL_VERSION {
                    return Ok(Err(AuthError::ProtocolMismatch));
                }
                let Some(nonce) = signaling::from_hex_exact::<NONCE_LEN>(&client_nonce) else {
                    return Ok(Err(AuthError::Rejected));
                };
                state
                    .identity
                    .lock()
                    .authenticate(peer, &client_key, server_nonce, &nonce, &signature)
                    .map(|key| (key, nonce))
            }
            ClientMessage::Pair {
                protocol,
                code,
                client_key,
                client_nonce,
                signature,
                label,
            } => {
                if protocol != PROTOCOL_VERSION {
                    return Ok(Err(AuthError::ProtocolMismatch));
                }
                let Some(nonce) = signaling::from_hex_exact::<NONCE_LEN>(&client_nonce) else {
                    return Ok(Err(AuthError::Rejected));
                };
                state
                    .identity
                    .lock()
                    .pair(
                        peer,
                        &code,
                        &client_key,
                        &label,
                        server_nonce,
                        &nonce,
                        &signature,
                    )
                    .map(|key| (key, nonce))
            }
            _ => Err(AuthError::UnexpectedMessage),
        });
    }
    Ok(Err(AuthError::UnexpectedMessage))
}

/// État partagé entre les tâches d'une même session.
struct SessionRuntime {
    dispatcher: Mutex<Dispatcher>,
    sink: Mutex<sidgate_input::Sink>,
    pipeline: Mutex<Option<Pipeline>>,
    seq: Mutex<SeqTracker>,
    control: Mutex<Option<Arc<dyn DataChannel>>>,
    cursor_absolute: AtomicBool,
    rejected_inputs: AtomicU64,
    config: Config,
}

impl SessionRuntime {
    /// Envoie un événement sur le canal fiable, si celui-ci est ouvert.
    async fn emit(&self, event: ControlEvent) {
        let channel = self.control.lock().clone();
        let Some(channel) = channel else { return };
        let Ok(text) = serde_json::to_string(&event) else {
            return;
        };
        if let Err(e) = channel.send_text(&text).await {
            tracing::debug!(error = %e, "émission sur le canal de contrôle");
        }
    }
}

/// Boucle principale d'une session authentifiée.
async fn run_session(
    mut ws_tx: futures_util::stream::SplitSink<WebSocket, Message>,
    mut ws_rx: futures_util::stream::SplitStream<WebSocket>,
    state: Arc<AppState>,
    session_id: String,
) -> anyhow::Result<()> {
    let bind = SocketAddr::new(state.config.network.bind, 0);
    let (session, mut events) = Session::new(
        bind,
        &state.config.network.stun_servers,
        state.config.video.framerate,
    )
    .await?;
    let session = Arc::new(session);

    let runtime = Arc::new(SessionRuntime {
        dispatcher: Mutex::new(Dispatcher::new(state.config.security.clone(), 0, 0)),
        sink: Mutex::new(sidgate_input::Sink::new()),
        pipeline: Mutex::new(None),
        seq: Mutex::new(SeqTracker::new()),
        control: Mutex::new(None),
        cursor_absolute: AtomicBool::new(false),
        rejected_inputs: AtomicU64::new(0),
        config: state.config.clone(),
    });

    let mut tasks: Vec<tokio::task::JoinHandle<()>> = Vec::new();

    loop {
        tokio::select! {
            incoming = ws_rx.next() => {
                let Some(message) = incoming else { break };
                match message? {
                    Message::Text(text) => {
                        if !handle_client_message(&text, &session, &mut ws_tx).await? {
                            break;
                        }
                    }
                    Message::Close(_) => break,
                    _ => {}
                }
            }
            event = events.recv() => {
                let Some(event) = event else { break };
                match event {
                    SessionEvent::IceCandidate(init) => {
                        let message = ServerMessage::Candidate {
                            candidate: init.candidate,
                            sdp_mid: init.sdp_mid,
                            sdp_mline_index: init.sdp_mline_index,
                        };
                        ws_tx
                            .send(Message::Text(serde_json::to_string(&message)?.into()))
                            .await?;
                    }
                    SessionEvent::DataChannel(channel) => {
                        tasks.push(spawn_channel(channel, Arc::clone(&runtime)));
                    }
                    SessionEvent::ConnectionState(connection_state) => {
                        if session::is_connected(connection_state) {
                            tasks.extend(
                                start_streaming(&session, &runtime, &state).await,
                            );
                        } else if session::is_terminal(connection_state) {
                            tracing::warn!(session = %session_id, ?connection_state, "transport perdu");
                            break;
                        }
                    }
                }
            }
        }
    }

    teardown(&session, &runtime, tasks, &session_id).await;
    Ok(())
}

/// Traite un message de signalisation du client. Renvoie `false` pour fermer.
async fn handle_client_message(
    text: &str,
    session: &Arc<Session>,
    ws_tx: &mut futures_util::stream::SplitSink<WebSocket, Message>,
) -> anyhow::Result<bool> {
    let Ok(message) = serde_json::from_str::<ClientMessage>(text) else {
        tracing::warn!("message de signalisation illisible");
        return Ok(true);
    };

    match message {
        ClientMessage::Offer { sdp } => {
            let answer = session.accept_offer(sdp).await?;
            let message = ServerMessage::Answer { sdp: answer };
            ws_tx
                .send(Message::Text(serde_json::to_string(&message)?.into()))
                .await?;
        }
        ClientMessage::Candidate {
            candidate,
            sdp_mid,
            sdp_mline_index,
        } => {
            let init = RTCIceCandidateInit {
                candidate,
                sdp_mid,
                sdp_mline_index,
                ..Default::default()
            };
            if let Err(e) = session.add_candidate(init).await {
                tracing::debug!(error = %e, "candidat distant ignoré");
            }
        }
        ClientMessage::Bye => return Ok(false),
        // L'authentification est déjà faite : la rejouer en séance serait au
        // mieux inutile, au pire une tentative de confusion d'état.
        ClientMessage::Authenticate { .. } | ClientMessage::Pair { .. } => {
            tracing::warn!("authentification rejouée en séance, ignorée");
        }
    }
    Ok(true)
}

/// Démarre le pipeline et les tâches d'émission une fois le transport établi.
///
/// Un bureau momentanément inaccessible — session hôte verrouillée, bureau
/// sécurisé — ne met pas fin à la session : le client reste connecté, en est
/// informé, et la vidéo démarre dès que la capture redevient possible. Couper
/// la session dans ce cas obligerait à tout renégocier au déverrouillage.
async fn start_streaming(
    session: &Arc<Session>,
    runtime: &Arc<SessionRuntime>,
    state: &Arc<AppState>,
) -> Option<tokio::task::JoinHandle<()>> {
    match try_start_pipeline(session, runtime, state).await {
        Ok(()) => None,
        Err(e) if is_desktop_unavailable(&e) => {
            tracing::warn!(error = %e, "capture différée");
            runtime
                .emit(ControlEvent::CaptureUnavailable {
                    message: e.to_string(),
                })
                .await;
            Some(spawn_capture_retry(
                Arc::clone(session),
                Arc::clone(runtime),
                Arc::clone(state),
            ))
        }
        Err(e) => {
            tracing::error!(error = %e, "démarrage du pipeline impossible");
            runtime
                .emit(ControlEvent::CaptureUnavailable {
                    message: e.to_string(),
                })
                .await;
            None
        }
    }
}

/// Le bureau est-il seulement indisponible pour l'instant ?
fn is_desktop_unavailable(error: &anyhow::Error) -> bool {
    matches!(
        error.downcast_ref::<sidgate_capture::CaptureError>(),
        Some(sidgate_capture::CaptureError::DesktopUnavailable),
    )
}

/// Réessaie d'ouvrir la capture jusqu'à ce que le bureau redevienne accessible.
fn spawn_capture_retry(
    session: Arc<Session>,
    runtime: Arc<SessionRuntime>,
    state: Arc<AppState>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(CAPTURE_RETRY_INTERVAL);
        ticker.tick().await;
        loop {
            ticker.tick().await;
            match try_start_pipeline(&session, &runtime, &state).await {
                Ok(()) => {
                    runtime.emit(ControlEvent::CaptureResumed).await;
                    tracing::info!("capture reprise");
                    return;
                }
                Err(e) if is_desktop_unavailable(&e) => continue,
                Err(e) => {
                    tracing::error!(error = %e, "capture définitivement indisponible");
                    return;
                }
            }
        }
    })
}

/// Tentative unique de démarrage du pipeline.
async fn try_start_pipeline(
    session: &Arc<Session>,
    runtime: &Arc<SessionRuntime>,
    state: &Arc<AppState>,
) -> anyhow::Result<()> {
    if runtime.pipeline.lock().is_some() {
        return Ok(());
    }

    let (frames_tx, frames_rx) = mpsc::channel(crate::pipeline::FRAME_QUEUE_DEPTH);
    let bitrate = state.config.video.quality.target_bitrate_1080p();
    let pipeline = Pipeline::start(&state.config.video, bitrate, frames_tx)?;
    let desktop = pipeline.desktop();

    *runtime.dispatcher.lock() =
        Dispatcher::new(state.config.security.clone(), desktop.width, desktop.height);
    let stats_handle = Arc::clone(pipeline.stats());
    *runtime.pipeline.lock() = Some(pipeline);

    session.spawn_video_sender(frames_rx, state.config.video.framerate);
    spawn_stats_reporter(Arc::clone(runtime), stats_handle);

    runtime
        .emit(ControlEvent::Hello {
            version: env!("CARGO_PKG_VERSION").to_string(),
            capabilities: Capabilities {
                power_actions: state.config.security.allow_power_actions,
                input_injection: state.config.security.allow_input,
                video_codec: "H264".to_string(),
                width: desktop.width,
                height: desktop.height,
            },
        })
        .await;

    tracing::info!(
        width = desktop.width,
        height = desktop.height,
        "diffusion démarrée"
    );
    Ok(())
}

/// Libère tout : entrées maintenues, pipeline, transport, et verrouillage.
async fn teardown(
    session: &Arc<Session>,
    runtime: &Arc<SessionRuntime>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
    session_id: &str,
) {
    for task in tasks {
        task.abort();
    }

    // Relâcher avant de verrouiller : une touche restée enfoncée survivrait au
    // verrouillage et gênerait l'utilisateur physique de la machine.
    if let Err(e) = runtime.sink.lock().release_all() {
        tracing::debug!(error = %e, "relâchement des entrées");
    }

    // Le pipeline part ici, ce qui rend la VRAM, arrête le thread de capture et
    // ramène l'agent à sa consommation de repos.
    runtime.pipeline.lock().take();
    session.close().await;

    if runtime.config.security.lock_on_disconnect {
        match sidgate_input::system::lock_session() {
            Ok(()) => tracing::warn!(session = %session_id, "killswitch: session verrouillée"),
            Err(e) => tracing::error!(session = %session_id, error = %e, "killswitch en échec"),
        }
    }
    tracing::info!(session = %session_id, "session close");
}

/// Consomme un canal de données jusqu'à sa fermeture.
fn spawn_channel(
    channel: Arc<dyn DataChannel>,
    runtime: Arc<SessionRuntime>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let label = channel.label().await.unwrap_or_default();
        tracing::info!(%label, "canal de données ouvert");

        if label == CHANNEL_CONTROL {
            *runtime.control.lock() = Some(Arc::clone(&channel));
        } else if label != CHANNEL_INPUT {
            tracing::warn!(%label, "canal inattendu, ignoré");
            return;
        }

        while let Some(event) = channel.poll().await {
            match event {
                DataChannelEvent::OnMessage(message) => {
                    if label == CHANNEL_INPUT {
                        handle_input(&message.data, &runtime);
                    } else {
                        handle_control(&message.data, &runtime).await;
                    }
                }
                DataChannelEvent::OnClose | DataChannelEvent::OnError => break,
                _ => {}
            }
        }
        tracing::info!(%label, "canal de données fermé");
    })
}

/// Décode et applique une trame d'entrées.
fn handle_input(payload: &BytesMut, runtime: &Arc<SessionRuntime>) {
    if !runtime.dispatcher.lock().input_allowed() {
        runtime.rejected_inputs.fetch_add(1, Ordering::Relaxed);
        return;
    }

    let frame = match InputFrame::decode(payload) {
        Ok(frame) => frame,
        Err(e) => {
            tracing::debug!(error = %e, "trame d'entrée rejetée");
            runtime.rejected_inputs.fetch_add(1, Ordering::Relaxed);
            return;
        }
    };

    // Canal non ordonné : une trame plus ancienne que la dernière appliquée
    // rejouerait des appuis dans le désordre.
    if !runtime.seq.lock().accept(frame.seq) {
        return;
    }

    if let Err(e) = runtime.sink.lock().apply(&frame) {
        tracing::debug!(error = %e, "injection refusée");
    }
}

/// Décode, autorise et applique une commande.
async fn handle_control(payload: &BytesMut, runtime: &Arc<SessionRuntime>) {
    let Ok(text) = std::str::from_utf8(payload) else {
        return;
    };
    let command = match serde_json::from_str::<ControlCommand>(text) {
        Ok(command) => command,
        Err(e) => {
            tracing::warn!(error = %e, "commande illisible rejetée");
            runtime
                .emit(ControlEvent::CommandRejected {
                    command: "inconnue".into(),
                    reason: RejectReason::Malformed,
                })
                .await;
            return;
        }
    };

    let name = command.name().to_string();
    let decision = runtime.dispatcher.lock().dispatch(command);
    match decision {
        Ok(effect) => {
            let outcome = apply(effect, runtime).await;
            let event = match outcome {
                Ok(()) => ControlEvent::CommandAccepted { command: name },
                Err(reason) => ControlEvent::CommandRejected {
                    command: name,
                    reason,
                },
            };
            runtime.emit(event).await;
        }
        Err(reason) => {
            runtime
                .emit(ControlEvent::CommandRejected {
                    command: name,
                    reason,
                })
                .await;
        }
    }
}

/// Exécute l'effet décidé par le dispatcher.
async fn apply(effect: Effect, runtime: &Arc<SessionRuntime>) -> Result<(), RejectReason> {
    match effect {
        Effect::Keyframe => {
            with_pipeline(runtime, |p| p.request_keyframe())?;
        }
        Effect::Bitrate(bitrate) => {
            with_pipeline(runtime, |p| p.set_bitrate(bitrate))?;
        }
        Effect::CursorMode(mode) => {
            runtime
                .cursor_absolute
                .store(mode == CursorMode::Absolute, Ordering::Relaxed);
        }
        Effect::SendStats => {
            let snapshot = runtime
                .pipeline
                .lock()
                .as_ref()
                .map(|p| p.stats().snapshot())
                .unwrap_or_default();
            runtime
                .emit(ControlEvent::Stats(stats_from(&snapshot, STATS_INTERVAL)))
                .await;
        }
        Effect::Pong(_) => {}
        Effect::Lock => sidgate_input::system::lock_session().map_err(|_| RejectReason::Failed)?,
        Effect::Sleep => sidgate_input::system::sleep().map_err(|_| RejectReason::Failed)?,
        Effect::Reboot => sidgate_input::system::reboot().map_err(|_| RejectReason::Failed)?,
        Effect::Shutdown => sidgate_input::system::shutdown().map_err(|_| RejectReason::Failed)?,
    }
    Ok(())
}

fn with_pipeline<F>(runtime: &Arc<SessionRuntime>, action: F) -> Result<(), RejectReason>
where
    F: FnOnce(&Pipeline),
{
    match runtime.pipeline.lock().as_ref() {
        Some(pipeline) => {
            action(pipeline);
            Ok(())
        }
        None => Err(RejectReason::WrongState),
    }
}

/// Émet la télémétrie à intervalle régulier.
fn spawn_stats_reporter(
    runtime: Arc<SessionRuntime>,
    stats: Arc<crate::pipeline::PipelineStats>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut previous = stats.snapshot();
        let mut last = Instant::now();
        let mut ticker = tokio::time::interval(STATS_INTERVAL);
        ticker.tick().await;

        loop {
            ticker.tick().await;
            if runtime.pipeline.lock().is_none() {
                break;
            }
            let current = stats.snapshot();
            let delta = current.delta(&previous);
            let elapsed = last.elapsed();
            previous = current;
            last = Instant::now();

            runtime
                .emit(ControlEvent::Stats(stats_from(&delta, elapsed)))
                .await;
        }
    })
}

fn stats_from(delta: &StatsSnapshot, elapsed: Duration) -> Stats {
    Stats {
        frames_captured: delta.captured,
        frames_encoded: delta.encoded,
        frames_dropped: delta.dropped,
        frames_idle: delta.idle,
        bitrate_bps: delta.bitrate_bps(elapsed),
        fps: delta.fps(elapsed),
        encode_ms: delta.encode_ms(),
        cpu_percent: 0.0,
        rss_mb: 0.0,
    }
}

fn random_nonce() -> anyhow::Result<[u8; NONCE_LEN]> {
    let mut nonce = [0u8; NONCE_LEN];
    rand::rngs::OsRng
        .try_fill_bytes(&mut nonce)
        .map_err(|e| anyhow::anyhow!("générateur aléatoire indisponible: {e}"))?;
    Ok(nonce)
}

/// Rend visible le type d'état suivi, pour éviter un import inutilisé.
#[allow(dead_code)]
fn pressed_kind(_: &PressedState) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stats_are_derived_from_the_interval() {
        let delta = StatsSnapshot {
            captured: 120,
            encoded: 118,
            dropped: 2,
            idle: 5,
            bytes: 2_000_000,
            encode_us: 120_000,
        };
        let stats = stats_from(&delta, Duration::from_secs(2));
        assert_eq!(stats.fps, 59.0);
        assert_eq!(stats.bitrate_bps, 8_000_000);
        assert_eq!(stats.frames_dropped, 2);
        assert!((stats.encode_ms - 1.0).abs() < 0.001);
    }

    #[test]
    fn nonces_are_unique_and_full_length() {
        let a = random_nonce().unwrap();
        let b = random_nonce().unwrap();
        assert_eq!(a.len(), NONCE_LEN);
        assert_ne!(a, b);
        assert_ne!(a, [0u8; NONCE_LEN]);
    }
}
