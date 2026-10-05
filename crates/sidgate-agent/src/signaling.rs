//! Serveur HTTPS et canal de signalisation WSS.
//!
//! L'agent sert lui-même la PWA, embarquée dans le binaire : aucun fichier à
//! déployer à côté, et rien qu'un tiers puisse remplacer sur le disque.
//!
//! # Une session à la fois
//!
//! La limite n'est pas technique, elle est délibérée : deux clients pilotant
//! simultanément la même souris ne donne jamais rien de bon, et un second
//! visiteur ne doit pas pouvoir observer la session du premier.
//!
//! Un client **authentifié** qui se présente pendant une session la remplace :
//! c'est le téléphone qu'on sort de sa poche alors que l'ordinateur portable
//! est resté connecté. Tant qu'il ne s'est pas authentifié, un visiteur
//! n'approche pas de la session en cours — il n'occupe qu'une place parmi les
//! poignées de main en attente, qui sont comptées.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{ConnectInfo, State};
use axum::http::header;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use bytes::BytesMut;
use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt, StreamExt};
use parking_lot::Mutex;
use rand::TryRngCore;
use tokio::sync::{mpsc, Notify, Semaphore};

use sidgate_capture::{DesktopInfo, OutputInfo, PointerShape, PointerState};
use sidgate_input::{AbsoluteMapping, InputSink, ScreenRect};
use sidgate_proto::control::{
    Capabilities, ControlCommand, ControlEvent, DisplayInfo, QualityPreset, RejectReason, Stats,
};
use sidgate_proto::input::{InputFrame, SeqTracker};
use sidgate_proto::pointer::{clamp_coordinate, PointerUpdate};
use sidgate_proto::signaling::{
    self, AuthError, ClientMessage, CloseReason, ServerMessage, NONCE_LEN,
};
use sidgate_proto::{CHANNEL_CONTROL, CHANNEL_INPUT, PROTOCOL_VERSION};
use webrtc::data_channel::{DataChannel, DataChannelEvent};
use webrtc::peer_connection::RTCIceCandidateInit;

use crate::adapt::BitrateController;
use crate::config::Config;
use crate::control::{Dispatcher, Effect};
use crate::identity::{Identity, Proof};
use crate::pipeline::{Pipeline, PipelineFeedback, PipelineStats, StatsSnapshot};
use crate::process::{ProcessMeter, ProcessSample};
use crate::session::{self, Session, SessionEvent};
use crate::tls::TlsMaterial;

/// Période des remontées de télémétrie.
const STATS_INTERVAL: Duration = Duration::from_secs(2);
/// Intervalle entre deux tentatives d'ouverture de la capture.
const CAPTURE_RETRY_INTERVAL: Duration = Duration::from_secs(2);
/// Délai maximal accordé au handshake d'authentification.
///
/// Le délai est large parce qu'il court aussi pendant qu'un humain recopie un
/// code d'appairage depuis l'écran de l'hôte — ce n'est pas ce délai qui
/// protège du force brute, c'est la limitation de débit par source.
const AUTH_TIMEOUT: Duration = Duration::from_secs(180);
/// Poignées de main simultanées tolérées avant authentification.
///
/// Chacune peut rester ouverte jusqu'à [`AUTH_TIMEOUT`] ; sans plafond, il
/// suffirait d'ouvrir des connexions muettes pour épuiser l'agent.
const MAX_PENDING_HANDSHAKES: usize = 8;
/// Poignées de main simultanées tolérées depuis une même adresse.
///
/// Un appareil légitime en tient une, deux s'il se reconnecte pendant qu'un
/// formulaire d'appairage est resté ouvert. Sans ce plafond, une seule machine
/// du maillage suffirait à occuper toutes les places et à fermer la porte aux
/// autres.
const MAX_PENDING_PER_SOURCE: u32 = 2;
/// Temps laissé à la session en cours pour se retirer devant un remplaçant.
const TAKEOVER_TIMEOUT: Duration = Duration::from_secs(10);
/// Période de vérification qu'un client en session n'a pas été révoqué.
const REVOCATION_CHECK_INTERVAL: Duration = Duration::from_secs(5);
/// Taille maximale d'un message de signalisation.
///
/// Une offre SDP pèse quelques kilo-octets. Le plafond par défaut de la
/// bibliothèque, lui, se compte en dizaines de mégaoctets.
const MAX_SIGNALING_MESSAGE: usize = 256 * 1024;
/// Intervalle minimal entre deux images clés accordées au client.
///
/// Un client en difficulté en réclame une à chaque image qu'il ne peut pas
/// décoder, et chacune pèse dix à trente fois une image ordinaire : toutes les
/// lui servir saturerait le lien qui vient justement de perdre des paquets.
const KEYFRAME_MIN_INTERVAL: Duration = Duration::from_millis(400);
/// Intervalle minimal entre deux positions de curseur émises.
///
/// Une souris remonte jusqu'à mille positions par seconde ; l'écran du client
/// en affiche soixante ou cent vingt.
const POINTER_MIN_INTERVAL: Duration = Duration::from_millis(8);
/// Plus grand côté d'une forme de curseur transmise au client.
///
/// Un message du canal de données est plafonné à 64 Ko. Une image de 96 pixels
/// de côté en occupe 49 une fois encodée, et couvre les curseurs système
/// jusqu'à une mise à l'échelle de 300 %.
const MAX_SENT_POINTER_SIDE: u32 = 96;
/// Taille maximale d'un message émis sur le canal de contrôle.
const MAX_CONTROL_MESSAGE: usize = 60 * 1024;
/// Taille maximale du texte de presse-papiers lu sur l'hôte.
const MAX_CLIPBOARD_BYTES: usize = 32 * 1024;

/// État partagé par toutes les connexions HTTP.
pub struct AppState {
    /// Identité et registre des clients.
    pub identity: Mutex<Identity>,
    /// Configuration de l'agent.
    pub config: Config,
    /// Places disponibles pour les poignées de main non authentifiées.
    handshakes: Semaphore,
    /// Poignées de main en cours, par adresse d'origine.
    pending: Mutex<HashMap<IpAddr, u32>>,
    /// L'unique emplacement de session.
    slot: tokio::sync::Mutex<()>,
    /// De quoi demander à la session en cours de se retirer.
    current: Mutex<Option<Arc<Notify>>>,
}

impl AppState {
    /// État initial : aucune session, toutes les places libres.
    pub fn new(identity: Identity, config: Config) -> Self {
        Self {
            identity: Mutex::new(identity),
            config,
            handshakes: Semaphore::new(MAX_PENDING_HANDSHAKES),
            pending: Mutex::new(HashMap::new()),
            slot: tokio::sync::Mutex::new(()),
            current: Mutex::new(None),
        }
    }

    /// Réserve une place de poignée de main pour `peer`, s'il en reste une au
    /// total et pour cette adresse. La place se libère avec la valeur rendue.
    fn reserve_handshake(&self, peer: IpAddr) -> Option<HandshakeSlot<'_>> {
        let permit = self.handshakes.try_acquire().ok()?;
        let mut pending = self.pending.lock();
        let count = pending.entry(peer).or_insert(0);
        if *count >= MAX_PENDING_PER_SOURCE {
            return None;
        }
        *count += 1;
        Some(HandshakeSlot {
            state: self,
            peer,
            _permit: permit,
        })
    }
}

/// Place occupée par une poignée de main en cours.
struct HandshakeSlot<'a> {
    state: &'a AppState,
    peer: IpAddr,
    _permit: tokio::sync::SemaphorePermit<'a>,
}

impl Drop for HandshakeSlot<'_> {
    fn drop(&mut self) {
        let mut pending = self.state.pending.lock();
        if let Some(count) = pending.get_mut(&self.peer) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                pending.remove(&self.peer);
            }
        }
    }
}

/// Démarre le serveur et ne rend la main qu'à son arrêt.
pub async fn serve(state: Arc<AppState>, tls: TlsMaterial) -> anyhow::Result<()> {
    let address = SocketAddr::new(state.config.network.bind, state.config.network.port);
    let use_tls = state.config.network.tls;

    let app = Router::new()
        .route("/", get(index))
        .route("/app.js", get(app_js))
        .route("/core.js", get(core_js))
        .route("/keymap.js", get(keymap_js))
        .route("/sw.js", get(service_worker))
        .route("/manifest.webmanifest", get(manifest))
        .route("/icon.svg", get(icon_svg))
        .route("/icon-192.png", get(icon_192))
        .route("/icon-512.png", get(icon_512))
        .route("/ws", get(websocket))
        .with_state(state);

    let service = app.into_make_service_with_connect_info::<SocketAddr>();

    if use_tls {
        let config =
            axum_server::tls_rustls::RustlsConfig::from_pem(tls.cert_pem, tls.key_pem).await?;
        tracing::info!(%address, "serveur prêt en HTTPS");
        axum_server::bind_rustls(address, config)
            .serve(service)
            .await?;
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

async fn core_js() -> Response {
    javascript(include_str!("../../../client/core.js"))
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

async fn icon_svg() -> Response {
    image("image/svg+xml", include_bytes!("../../../client/icon.svg"))
}

async fn icon_192() -> Response {
    image("image/png", include_bytes!("../../../client/icon-192.png"))
}

async fn icon_512() -> Response {
    image("image/png", include_bytes!("../../../client/icon-512.png"))
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
                 img-src 'self' data: blob:; media-src 'self' blob:; connect-src 'self' ws: wss:; \
                 base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
            ),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
            (header::REFERRER_POLICY, "no-referrer"),
            (header::CACHE_CONTROL, "no-cache"),
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
            (header::CACHE_CONTROL, "no-cache"),
        ],
        body,
    )
        .into_response()
}

fn image(content_type: &'static str, body: &'static [u8]) -> Response {
    (
        [
            (header::CONTENT_TYPE, content_type),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
            (header::CACHE_CONTROL, "public, max-age=86400"),
        ],
        body,
    )
        .into_response()
}

// --- Signalisation ----------------------------------------------------------

type WsSink = SplitSink<WebSocket, Message>;
type WsStream = SplitStream<WebSocket>;

async fn websocket(
    upgrade: WebSocketUpgrade,
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
) -> Response {
    upgrade
        .max_message_size(MAX_SIGNALING_MESSAGE)
        .on_upgrade(move |socket| async move {
            if let Err(e) = run_connection(socket, state, peer.ip()).await {
                tracing::warn!(%peer, error = %e, "connexion terminée sur erreur");
            }
        })
}

async fn send(sink: &mut WsSink, message: &ServerMessage) -> anyhow::Result<()> {
    sink.send(Message::Text(serde_json::to_string(message)?.into()))
        .await?;
    Ok(())
}

/// Déroule une connexion complète : authentification, négociation, session.
async fn run_connection(
    socket: WebSocket,
    state: Arc<AppState>,
    peer: IpAddr,
) -> anyhow::Result<()> {
    let (mut sink, mut stream) = socket.split();

    let Some(permit) = state.reserve_handshake(peer) else {
        tracing::warn!(%peer, "trop de poignées de main en attente, connexion refusée");
        return send(
            &mut sink,
            &ServerMessage::Closed {
                reason: CloseReason::Busy,
            },
        )
        .await;
    };

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
    send(&mut sink, &challenge).await?;

    let authenticated = match tokio::time::timeout(
        AUTH_TIMEOUT,
        authenticate(&mut stream, &state, peer, &server_nonce),
    )
    .await
    {
        Ok(Ok(result)) => result,
        Ok(Err(e)) => return Err(e),
        Err(_) => {
            tracing::warn!(%peer, "handshake abandonné, délai dépassé");
            return Ok(());
        }
    };
    drop(permit);

    let (client_key, client_nonce) = match authenticated {
        Ok(pair) => pair,
        Err(reason) => {
            send(&mut sink, &ServerMessage::AuthFailed { reason }).await?;
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
    send(&mut sink, &ok).await?;
    tracing::info!(%peer, session = %session_id, "client authentifié");

    // À partir d'ici le client a prouvé son identité : il a le droit de
    // prendre la place de la session en cours.
    let kick = Arc::new(Notify::new());
    if let Some(previous) = state.current.lock().replace(Arc::clone(&kick)) {
        tracing::warn!(session = %session_id, "session en cours remplacée par ce client");
        previous.notify_one();
    }
    let slot = match tokio::time::timeout(TAKEOVER_TIMEOUT, state.slot.lock()).await {
        Ok(slot) => slot,
        Err(_) => {
            release_current(&state, &kick);
            tracing::error!(session = %session_id, "la session précédente ne s'est pas retirée");
            return send(
                &mut sink,
                &ServerMessage::Error {
                    message: "La session précédente ne s'est pas terminée.".into(),
                },
            )
            .await;
        }
    };

    let outcome = run_session(sink, stream, &state, &session_id, &client_key, &kick).await;
    release_current(&state, &kick);
    drop(slot);
    outcome
}

/// Oublie la poignée de remplacement d'une session, si c'est encore la sienne.
fn release_current(state: &AppState, kick: &Arc<Notify>) {
    let mut current = state.current.lock();
    if current.as_ref().is_some_and(|held| Arc::ptr_eq(held, kick)) {
        *current = None;
    }
}

type AuthOutcome = Result<(String, [u8; NONCE_LEN]), AuthError>;

/// Attend et vérifie le message d'authentification ou d'appairage.
async fn authenticate(
    stream: &mut WsStream,
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
                let proof = Proof {
                    client_key_hex: &client_key,
                    server_nonce,
                    client_nonce: &nonce,
                    signature_hex: &signature,
                };
                state
                    .identity
                    .lock()
                    .authenticate(peer, proof)
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
                let proof = Proof {
                    client_key_hex: &client_key,
                    server_nonce,
                    client_nonce: &nonce,
                    signature_hex: &signature,
                };
                state
                    .identity
                    .lock()
                    .pair(peer, &code, &label, proof)
                    .map(|key| (key, nonce))
            }
            _ => Err(AuthError::UnexpectedMessage),
        });
    }
    Ok(Err(AuthError::UnexpectedMessage))
}

// --- Session ----------------------------------------------------------------

/// Pourquoi une session s'est terminée.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EndReason {
    /// Le client a dit au revoir.
    ClientLeft,
    /// Le canal de signalisation s'est fermé.
    SignalingClosed,
    /// Le transport WebRTC est tombé.
    TransportLost,
    /// Un autre client appairé a pris la place.
    Replaced,
    /// Le client a été révoqué pendant sa session.
    Revoked,
    /// La négociation a échoué.
    Failed,
}

impl EndReason {
    /// La fin de session doit-elle verrouiller le poste ?
    ///
    /// Toujours, sauf quand un client autorisé en remplace un autre : la
    /// session ne s'interrompt pas, elle change de mains, et verrouiller
    /// accueillerait le nouveau venu sur l'écran de verrouillage.
    fn triggers_killswitch(self) -> bool {
        !matches!(self, Self::Replaced)
    }
}

/// Sonde de latence applicative.
///
/// Une sonde part avec chaque remontée de télémétrie ; la réponse du client
/// donne l'aller-retour vu par l'application, files d'attente comprises.
#[derive(Debug, Default)]
struct Probe {
    next_seq: u32,
    pending: Option<(u32, Instant)>,
    rtt_ms: Option<f32>,
}

impl Probe {
    /// Prépare une nouvelle sonde et renvoie son numéro.
    ///
    /// Si la précédente est restée sans réponse, la dernière mesure est
    /// périmée : elle redevient inconnue plutôt que de rester affichée.
    fn begin(&mut self, now: Instant) -> u32 {
        if self.pending.is_some() {
            self.rtt_ms = None;
        }
        let seq = self.next_seq;
        self.next_seq = self.next_seq.wrapping_add(1);
        self.pending = Some((seq, now));
        seq
    }

    /// Enregistre la réponse à la sonde `seq`. Une réponse à une sonde
    /// ancienne ou jamais émise est ignorée.
    fn complete(&mut self, seq: u32, now: Instant) {
        if let Some((expected, sent)) = self.pending {
            if expected == seq {
                self.rtt_ms = Some(now.duration_since(sent).as_secs_f32() * 1000.0);
                self.pending = None;
            }
        }
    }
}

/// État partagé entre les tâches d'une même session.
struct SessionRuntime {
    session: Session,
    config: Config,
    dispatcher: Mutex<Dispatcher>,
    sink: Mutex<sidgate_input::Sink>,
    pipeline: Mutex<Option<Pipeline>>,
    /// Sérialise les démarrages et arrêts du pipeline : la reprise de capture,
    /// le changement d'écran et la fermeture peuvent survenir au même instant.
    starting: tokio::sync::Mutex<()>,
    /// La session se ferme : plus aucun pipeline ne doit démarrer.
    closed: AtomicBool,
    /// Tâche qui retente d'ouvrir la capture, s'il y en a une.
    retry: Mutex<Option<tokio::task::JoinHandle<()>>>,
    seq: Mutex<SeqTracker>,
    control: Mutex<Option<Arc<dyn DataChannel>>>,
    input: Mutex<Option<Arc<dyn DataChannel>>>,
    /// Sortie vidéo capturée, modifiable par le client.
    output: AtomicU32,
    outputs: Mutex<Vec<OutputInfo>>,
    /// Palier choisi par le client, reconduit quand le pipeline redémarre.
    preset: Mutex<QualityPreset>,
    bitrate: Mutex<BitrateController>,
    probe: Mutex<Probe>,
    pointer_seq: AtomicU32,
    last_keyframe: Mutex<Option<Instant>>,
    last_stats: Mutex<Option<Stats>>,
    rejected_inputs: AtomicU64,
}

impl SessionRuntime {
    fn new(session: Session, config: Config) -> Self {
        let preset = config.video.quality;
        Self {
            session,
            dispatcher: Mutex::new(Dispatcher::new(config.security.clone(), 0, 0)),
            sink: Mutex::new(sidgate_input::Sink::new()),
            pipeline: Mutex::new(None),
            starting: tokio::sync::Mutex::new(()),
            closed: AtomicBool::new(false),
            retry: Mutex::new(None),
            seq: Mutex::new(SeqTracker::new()),
            control: Mutex::new(None),
            input: Mutex::new(None),
            output: AtomicU32::new(config.video.output),
            outputs: Mutex::new(Vec::new()),
            preset: Mutex::new(preset),
            bitrate: Mutex::new(BitrateController::new(preset.target_bitrate_1080p())),
            probe: Mutex::new(Probe::default()),
            pointer_seq: AtomicU32::new(0),
            last_keyframe: Mutex::new(None),
            last_stats: Mutex::new(None),
            rejected_inputs: AtomicU64::new(0),
            config,
        }
    }

    /// Envoie un événement sur le canal fiable, si celui-ci est ouvert.
    async fn emit(&self, event: ControlEvent) {
        let channel = self.control.lock().clone();
        let Some(channel) = channel else { return };
        let Ok(text) = serde_json::to_string(&event) else {
            return;
        };
        if text.len() > MAX_CONTROL_MESSAGE {
            tracing::warn!(bytes = text.len(), "événement trop volumineux, non émis");
            return;
        }
        if let Err(e) = channel.send_text(&text).await {
            tracing::debug!(error = %e, "émission sur le canal de contrôle");
        }
    }

    /// Envoie la position du curseur sur le canal non fiable.
    async fn send_pointer(&self, pointer: PointerState) {
        let channel = self.input.lock().clone();
        let Some(channel) = channel else { return };
        let update = PointerUpdate {
            seq: self.pointer_seq.fetch_add(1, Ordering::Relaxed),
            x: clamp_coordinate(pointer.x),
            y: clamp_coordinate(pointer.y),
            visible: pointer.visible,
        };
        let _ = channel.send(BytesMut::from(&update.encode()[..])).await;
    }

    /// Demande une image clé au pipeline, sans dépasser la cadence permise.
    fn request_keyframe(&self) {
        let now = Instant::now();
        {
            let mut last = self.last_keyframe.lock();
            if last.is_some_and(|at| now.duration_since(at) < KEYFRAME_MIN_INTERVAL) {
                return;
            }
            *last = Some(now);
        }
        if let Some(pipeline) = self.pipeline.lock().as_ref() {
            pipeline.request_keyframe();
            tracing::debug!("image clé demandée par le client");
        }
    }

    /// Ajuste le débit d'après la part de paquets perdus rapportée.
    fn on_loss_report(&self, fraction_lost: u8) {
        if !self.config.video.adaptive_bitrate {
            return;
        }
        let Some(bitrate) = self.bitrate.lock().on_report(fraction_lost, Instant::now()) else {
            return;
        };
        if let Some(pipeline) = self.pipeline.lock().as_ref() {
            pipeline.set_bitrate(bitrate);
            tracing::info!(
                bitrate,
                loss_percent = f32::from(fraction_lost) * 100.0 / 256.0,
                "débit adapté aux pertes"
            );
        }
    }

    /// Le pipeline courant est-il celui auquel appartiennent ces compteurs ?
    ///
    /// Les tâches lancées pour un pipeline s'en servent pour s'arrêter quand
    /// il est remplacé, au changement d'écran par exemple.
    fn owns(&self, stats: &Arc<PipelineStats>) -> bool {
        self.pipeline
            .lock()
            .as_ref()
            .is_some_and(|pipeline| Arc::ptr_eq(pipeline.stats(), stats))
    }
}

/// Boucle principale d'une session authentifiée.
async fn run_session(
    mut ws_tx: WsSink,
    mut ws_rx: WsStream,
    state: &Arc<AppState>,
    session_id: &str,
    client_key: &str,
    kick: &Notify,
) -> anyhow::Result<()> {
    let bind = SocketAddr::new(state.config.network.bind, 0);
    let created = Session::new(
        bind,
        &state.config.network.stun_servers,
        state.config.video.framerate,
    )
    .await;
    let (session, mut events) = match created {
        Ok(created) => created,
        Err(e) => {
            // Ce client vient peut-être de remplacer une session, laquelle
            // s'est retirée sans verrouiller le poste. S'il ne peut pas
            // prendre la suite, plus personne ne tient la session : le
            // killswitch s'applique.
            if state.config.security.lock_on_disconnect {
                let _ = sidgate_input::system::lock_session();
            }
            return Err(e);
        }
    };
    let runtime = Arc::new(SessionRuntime::new(session, state.config.clone()));

    let mut tasks: Vec<tokio::task::JoinHandle<()>> = Vec::new();
    let mut streaming = false;
    let mut revocation = tokio::time::interval(REVOCATION_CHECK_INTERVAL);
    revocation.tick().await;

    // Toutes les sorties de boucle passent par un motif : la fermeture qui
    // suit — relâchement des touches, arrêt de la capture, verrouillage — ne
    // doit être sautée sur aucun chemin, erreur comprise.
    let reason = loop {
        tokio::select! {
            incoming = ws_rx.next() => {
                let text = match incoming {
                    Some(Ok(Message::Text(text))) => text,
                    Some(Ok(Message::Close(_))) | None => break EndReason::SignalingClosed,
                    Some(Ok(_)) => continue,
                    Some(Err(e)) => {
                        tracing::warn!(session = %session_id, error = %e, "signalisation interrompue");
                        break EndReason::SignalingClosed;
                    }
                };
                match handle_client_message(&text, &runtime.session, &mut ws_tx).await {
                    Ok(true) => {}
                    Ok(false) => break EndReason::ClientLeft,
                    Err(e) => {
                        tracing::warn!(session = %session_id, error = %e, "négociation en échec");
                        let _ = send(&mut ws_tx, &ServerMessage::Error {
                            message: "La négociation du flux a échoué.".into(),
                        }).await;
                        break EndReason::Failed;
                    }
                }
            }
            event = events.recv() => {
                let Some(event) = event else { break EndReason::TransportLost };
                match event {
                    SessionEvent::IceCandidate(init) => {
                        let message = ServerMessage::Candidate {
                            candidate: init.candidate,
                            sdp_mid: init.sdp_mid,
                            sdp_mline_index: init.sdp_mline_index,
                        };
                        if send(&mut ws_tx, &message).await.is_err() {
                            break EndReason::SignalingClosed;
                        }
                    }
                    SessionEvent::DataChannel(channel) => {
                        tasks.push(spawn_channel(channel, Arc::clone(&runtime)));
                    }
                    SessionEvent::ConnectionState(connection_state) => {
                        if session::is_connected(connection_state) {
                            if !streaming {
                                streaming = true;
                                tasks.push(runtime.session.spawn_feedback_reader());
                                start_streaming(&runtime).await;
                            }
                        } else if session::is_terminal(connection_state) {
                            tracing::warn!(session = %session_id, ?connection_state, "transport perdu");
                            break EndReason::TransportLost;
                        }
                    }
                    SessionEvent::KeyframeRequested => runtime.request_keyframe(),
                    SessionEvent::LossReport(fraction_lost) => runtime.on_loss_report(fraction_lost),
                }
            }
            () = kick.notified() => break EndReason::Replaced,
            _ = revocation.tick() => {
                if !state.identity.lock().is_authorized(client_key) {
                    tracing::warn!(session = %session_id, "client révoqué en cours de session");
                    break EndReason::Revoked;
                }
            }
        }
    };

    if reason == EndReason::Replaced {
        let _ = send(
            &mut ws_tx,
            &ServerMessage::Closed {
                reason: CloseReason::Replaced,
            },
        )
        .await;
    }
    teardown(&runtime, tasks, session_id, reason).await;
    Ok(())
}

/// Traite un message de signalisation du client. Renvoie `false` pour fermer.
async fn handle_client_message(
    text: &str,
    session: &Session,
    ws_tx: &mut WsSink,
) -> anyhow::Result<bool> {
    let Ok(message) = serde_json::from_str::<ClientMessage>(text) else {
        tracing::warn!("message de signalisation illisible");
        return Ok(true);
    };

    match message {
        ClientMessage::Offer { sdp } => {
            let answer = session.accept_offer(sdp).await?;
            send(ws_tx, &ServerMessage::Answer { sdp: answer }).await?;
        }
        ClientMessage::Candidate {
            candidate,
            sdp_mid,
            sdp_mline_index,
        } => {
            if is_mdns_candidate(&candidate) {
                // Un navigateur masque ses adresses locales derrière un nom
                // `.local` à résoudre par diffusion sur le réseau physique.
                // L'agent n'émet rien hors de son interface d'écoute : le
                // candidat est ignoré, et la connexion s'établit depuis les
                // nôtres, que le client reçoit de toute façon.
                tracing::debug!("candidat mDNS ignoré");
                return Ok(true);
            }
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

/// Le candidat ICE désigne-t-il un nom mDNS plutôt qu'une adresse ?
///
/// Une ligne de candidat se lit `candidate:<fondation> <composant> <transport>
/// <priorité> <adresse> <port> typ …` : l'adresse est le cinquième champ.
fn is_mdns_candidate(candidate: &str) -> bool {
    candidate
        .split_ascii_whitespace()
        .nth(4)
        .is_some_and(|address| address.to_ascii_lowercase().ends_with(".local"))
}

/// Démarre le pipeline et les tâches d'émission une fois le transport établi.
///
/// Un bureau momentanément inaccessible — session hôte verrouillée, bureau
/// sécurisé — ne met pas fin à la session : le client reste connecté, en est
/// informé, et la vidéo démarre dès que la capture redevient possible. Couper
/// la session dans ce cas obligerait à tout renégocier au déverrouillage.
async fn start_streaming(runtime: &Arc<SessionRuntime>) {
    let _starting = runtime.starting.lock().await;
    if let Err(e) = start_pipeline_locked(runtime).await {
        capture_failed(runtime, &e).await;
    }
}

/// Le bureau est-il seulement indisponible pour l'instant ?
fn is_desktop_unavailable(error: &anyhow::Error) -> bool {
    matches!(
        error.downcast_ref::<sidgate_capture::CaptureError>(),
        Some(sidgate_capture::CaptureError::DesktopUnavailable),
    )
}

/// La sortie vidéo demandée n'existe-t-elle pas, ou plus ?
fn is_output_missing(error: &anyhow::Error) -> bool {
    matches!(
        error.downcast_ref::<sidgate_capture::CaptureError>(),
        Some(sidgate_capture::CaptureError::OutputNotFound(_)),
    )
}

/// La capture ne tourne pas : le dit au client, et programme une reprise si la
/// cause est de celles qui passent.
async fn capture_failed(runtime: &Arc<SessionRuntime>, error: &anyhow::Error) {
    let transient = is_desktop_unavailable(error);
    if transient {
        tracing::warn!(error = %error, "capture différée");
        ensure_capture_retry(runtime);
    } else {
        tracing::error!(error = %error, "démarrage du pipeline impossible");
    }
    runtime
        .emit(ControlEvent::CaptureUnavailable {
            message: error.to_string(),
            transient,
        })
        .await;
}

/// Lance la tâche de reprise de capture, si elle ne tourne pas déjà.
fn ensure_capture_retry(runtime: &Arc<SessionRuntime>) {
    if runtime.closed.load(Ordering::Acquire) {
        return;
    }
    let mut retry = runtime.retry.lock();
    if retry.as_ref().is_some_and(|task| !task.is_finished()) {
        return;
    }
    *retry = Some(spawn_capture_retry(Arc::clone(runtime)));
}

/// Réessaie d'ouvrir la capture jusqu'à ce que le bureau redevienne accessible.
fn spawn_capture_retry(runtime: Arc<SessionRuntime>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(CAPTURE_RETRY_INTERVAL);
        ticker.tick().await;
        loop {
            ticker.tick().await;
            match try_start_pipeline(&runtime).await {
                Ok(()) => {
                    runtime.emit(ControlEvent::CaptureResumed).await;
                    tracing::info!("capture reprise");
                    return;
                }
                Err(e) if is_desktop_unavailable(&e) => continue,
                Err(e) => {
                    tracing::error!(error = %e, "capture définitivement indisponible");
                    runtime
                        .emit(ControlEvent::CaptureUnavailable {
                            message: e.to_string(),
                            transient: false,
                        })
                        .await;
                    return;
                }
            }
        }
    })
}

/// Tentative unique de démarrage du pipeline. Sans effet s'il tourne déjà.
async fn try_start_pipeline(runtime: &Arc<SessionRuntime>) -> anyhow::Result<()> {
    let _starting = runtime.starting.lock().await;
    start_pipeline_locked(runtime).await
}

/// Démarre le pipeline. À n'appeler qu'en tenant `starting`.
async fn start_pipeline_locked(runtime: &Arc<SessionRuntime>) -> anyhow::Result<()> {
    // Vérifié sous le verrou : la fermeture le prend avant d'arrêter le
    // pipeline, donc rien de ce qui démarre ici ne peut lui échapper.
    anyhow::ensure!(
        !runtime.closed.load(Ordering::Acquire),
        "la session se ferme"
    );
    if runtime.pipeline.lock().is_some() {
        return Ok(());
    }

    let preset = *runtime.preset.lock();
    let open = |output: u32| {
        let (frames_tx, frames_rx) = mpsc::channel(crate::pipeline::FRAME_QUEUE_DEPTH);
        // L'ouverture de la duplication et de l'encodeur prend quelques
        // centaines de millisecondes d'appels système bloquants.
        tokio::task::block_in_place(|| {
            Pipeline::start(
                &runtime.config.video,
                output,
                preset.target_bitrate_1080p(),
                frames_tx,
            )
        })
        .map(|pipeline| (pipeline, frames_rx))
    };

    let output = runtime.output.load(Ordering::Relaxed);
    let (pipeline, frames_rx) = match open(output) {
        // L'écran configuré ou choisi a été débranché : se rabattre sur le
        // principal vaut mieux qu'une session sans image ni moyen d'en changer.
        Err(e) if output != 0 && is_output_missing(&e) => {
            tracing::warn!(output, "écran introuvable, repli sur le premier");
            runtime.output.store(0, Ordering::Relaxed);
            open(0)?
        }
        other => other?,
    };
    let desktop = pipeline.desktop();
    let feedback = pipeline.feedback();
    let stats = Arc::clone(pipeline.stats());

    apply_geometry(runtime, desktop, enumerate_outputs());
    let ceiling = runtime.dispatcher.lock().bitrate_for(preset);
    *runtime.bitrate.lock() = BitrateController::new(ceiling);
    *runtime.pipeline.lock() = Some(pipeline);

    runtime
        .session
        .spawn_video_sender(frames_rx, runtime.config.video.framerate);
    spawn_stats_reporter(Arc::clone(runtime), Arc::clone(&stats));
    spawn_feedback_forwarder(Arc::clone(runtime), feedback, stats);

    announce(runtime).await;

    tracing::info!(
        width = desktop.width,
        height = desktop.height,
        output = desktop.output_index,
        "diffusion démarrée"
    );
    Ok(())
}

/// Arrête le pipeline courant, s'il existe.
fn stop_pipeline(runtime: &SessionRuntime) {
    let pipeline = runtime.pipeline.lock().take();
    // La destruction attend la fin du thread de capture.
    tokio::task::block_in_place(|| drop(pipeline));
}

/// Liste les sorties vidéo de l'hôte, vide si l'énumération échoue.
fn enumerate_outputs() -> Vec<OutputInfo> {
    tokio::task::block_in_place(sidgate_capture::enumerate_outputs).unwrap_or_else(|e| {
        tracing::warn!(error = %e, "énumération des écrans impossible");
        Vec::new()
    })
}

/// Aligne le dispatcher et l'injection d'entrées sur le bureau capturé.
fn apply_geometry(runtime: &SessionRuntime, desktop: DesktopInfo, outputs: Vec<OutputInfo>) {
    let rects: Vec<ScreenRect> = outputs.iter().map(output_rect).collect();
    // La place de la sortie dans le bureau virtuel se lit dans l'énumération
    // quand elle y figure : c'est la source la plus fraîche si les écrans
    // viennent d'être réarrangés.
    let target = outputs
        .iter()
        .find(|output| output.index == desktop.output_index)
        .map(output_rect)
        .unwrap_or(ScreenRect {
            left: desktop.left,
            top: desktop.top,
            width: desktop.width,
            height: desktop.height,
        });

    runtime
        .dispatcher
        .lock()
        .set_geometry(desktop.width, desktop.height, outputs.len() as u32);
    runtime
        .sink
        .lock()
        .set_mapping(Some(AbsoluteMapping::new(target, &rects)));
    *runtime.outputs.lock() = outputs;
}

/// Reprend la disposition des écrans si elle a changé.
///
/// La capture ne signale que ce qui touche la sortie capturée. Qu'un *autre*
/// écran soit débranché ou déplacé change pourtant le bureau virtuel, donc
/// l'endroit où tombe un clic : sans cette relecture, la projection des
/// positions garderait les dimensions d'un bureau qui n'existe plus.
async fn refresh_outputs(runtime: &SessionRuntime) {
    let outputs = enumerate_outputs();
    if outputs.is_empty() || *runtime.outputs.lock() == outputs {
        return;
    }
    let Some(desktop) = runtime
        .pipeline
        .lock()
        .as_ref()
        .map(|pipeline| pipeline.desktop())
    else {
        return;
    };
    tracing::info!(displays = outputs.len(), "disposition des écrans changée");
    apply_geometry(runtime, desktop, outputs);
    announce(runtime).await;
}

fn output_rect(output: &OutputInfo) -> ScreenRect {
    ScreenRect {
        left: output.left,
        top: output.top,
        width: output.width,
        height: output.height,
    }
}

/// Annonce au client l'état courant : capacités, écrans, forme du curseur.
///
/// Appelée au démarrage du pipeline *et* à l'ouverture du canal de contrôle :
/// l'ordre des deux n'est pas garanti, et le premier arrivé n'a pas encore de
/// quoi parler ou pas encore à qui. Le client traite l'annonce comme un état,
/// pas comme un événement : la recevoir deux fois est sans effet.
async fn announce(runtime: &SessionRuntime) {
    let Some((desktop, shape)) = runtime.pipeline.lock().as_ref().map(|pipeline| {
        let shape = pipeline.feedback().shape.borrow().clone();
        (pipeline.desktop(), shape)
    }) else {
        return;
    };

    let displays = runtime
        .outputs
        .lock()
        .iter()
        .map(|output| DisplayInfo {
            index: output.index,
            width: output.width,
            height: output.height,
            primary: output.is_primary(),
        })
        .collect();
    let security = &runtime.config.security;
    // Lu avant l'émission : un garde de verrou ne doit pas survivre à un
    // point d'attente.
    let quality = *runtime.preset.lock();

    runtime
        .emit(ControlEvent::Hello {
            version: env!("CARGO_PKG_VERSION").to_string(),
            capabilities: Capabilities {
                power_actions: security.allow_power_actions,
                input_injection: security.allow_input,
                clipboard: security.allow_clipboard,
                video_codec: "H264".to_string(),
                width: desktop.width,
                height: desktop.height,
                display: desktop.output_index,
                displays,
                quality,
            },
        })
        .await;

    if let Some(shape) = shape {
        emit_pointer_shape(runtime, &shape).await;
    }
    announce_pointer(runtime).await;
}

/// Envoie la position courante du curseur, sans attendre qu'il bouge.
///
/// Les positions ne sont publiées qu'à leur changement : un client qui arrive
/// devant un curseur immobile ne saurait pas où le dessiner.
async fn announce_pointer(runtime: &SessionRuntime) {
    let pointer = runtime
        .pipeline
        .lock()
        .as_ref()
        .map(|pipeline| *pipeline.feedback().pointer.borrow());
    if let Some(pointer) = pointer {
        runtime.send_pointer(pointer).await;
    }
}

/// Transmet une forme de curseur, si elle tient dans un message.
async fn emit_pointer_shape(runtime: &SessionRuntime, shape: &PointerShape) {
    if shape.width > MAX_SENT_POINTER_SIDE || shape.height > MAX_SENT_POINTER_SIDE {
        tracing::debug!(
            width = shape.width,
            height = shape.height,
            "curseur trop grand pour être transmis, forme précédente conservée"
        );
        return;
    }
    runtime
        .emit(ControlEvent::PointerShape {
            width: shape.width as u16,
            height: shape.height as u16,
            hot_x: shape.hot_x as u16,
            hot_y: shape.hot_y as u16,
            rgba: data_encoding::BASE64.encode(&shape.rgba),
        })
        .await;
}

/// Relaie vers le client ce que le thread de capture publie hors vidéo.
///
/// La tâche vit aussi longtemps que le pipeline dont elle écoute les
/// publications. Quand elles cessent, le thread de capture s'est arrêté : si
/// personne ne le lui a demandé, c'est une panne, et la capture est relancée.
fn spawn_feedback_forwarder(
    runtime: Arc<SessionRuntime>,
    mut feedback: PipelineFeedback,
    stats: Arc<PipelineStats>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            tokio::select! {
                changed = feedback.pointer.changed() => {
                    if changed.is_err() { break }
                    let pointer = *feedback.pointer.borrow_and_update();
                    runtime.send_pointer(pointer).await;
                    // Les positions arrivées entre-temps se résument à la
                    // dernière : c'est la seule qui sera lue au réveil.
                    tokio::time::sleep(POINTER_MIN_INTERVAL).await;
                }
                changed = feedback.shape.changed() => {
                    if changed.is_err() { break }
                    let shape = feedback.shape.borrow_and_update().clone();
                    if let Some(shape) = shape {
                        emit_pointer_shape(&runtime, &shape).await;
                    }
                }
                changed = feedback.desktop.changed() => {
                    if changed.is_err() { break }
                    let desktop = *feedback.desktop.borrow_and_update();
                    on_display_changed(&runtime, desktop).await;
                }
            }
        }
        on_pipeline_ended(&runtime, &stats).await;
    })
}

/// Le thread de capture d'un pipeline s'est arrêté.
///
/// Arrêté par nous — changement d'écran, fermeture — le pipeline a déjà quitté
/// l'état de session et il n'y a rien à faire. S'il y figure encore, il est
/// tombé seul : erreur de l'encodeur, pilote graphique réinitialisé. Le laisser
/// en place figerait l'image jusqu'à la fin de la session, tout en faisant
/// croire au reste de l'agent que la capture tourne.
async fn on_pipeline_ended(runtime: &Arc<SessionRuntime>, stats: &Arc<PipelineStats>) {
    let _starting = runtime.starting.lock().await;
    if runtime.closed.load(Ordering::Acquire) || !runtime.owns(stats) {
        return;
    }
    tracing::error!("le pipeline de capture s'est arrêté de lui-même, relance");
    stop_pipeline(runtime);
    ensure_capture_retry(runtime);
    runtime
        .emit(ControlEvent::CaptureUnavailable {
            message: "la capture s'est interrompue".into(),
            transient: true,
        })
        .await;
}

/// La résolution de la sortie capturée a changé en cours de session.
async fn on_display_changed(runtime: &SessionRuntime, desktop: DesktopInfo) {
    apply_geometry(runtime, desktop, enumerate_outputs());

    // Le palier choisi vaut pour une surface : la nouvelle a un autre plafond.
    let preset = *runtime.preset.lock();
    let ceiling = runtime.dispatcher.lock().bitrate_for(preset);
    let bitrate = runtime.bitrate.lock().set_ceiling(ceiling);
    if let Some(pipeline) = runtime.pipeline.lock().as_ref() {
        pipeline.set_bitrate(bitrate);
    }

    tracing::info!(
        width = desktop.width,
        height = desktop.height,
        "géométrie du bureau changée"
    );
    runtime
        .emit(ControlEvent::DisplayChanged {
            index: desktop.output_index,
            width: desktop.width,
            height: desktop.height,
        })
        .await;
}

/// Libère tout : entrées maintenues, pipeline, transport, et verrouillage.
async fn teardown(
    runtime: &Arc<SessionRuntime>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
    session_id: &str,
    reason: EndReason,
) {
    // D'abord interdire tout nouveau démarrage, ensuite seulement arrêter ce
    // qui tourne : dans l'autre ordre, un démarrage en cours — changement
    // d'écran, reprise de capture — s'achèverait après l'arrêt et laisserait
    // derrière lui un pipeline que plus personne ne détient.
    runtime.closed.store(true, Ordering::Release);
    for task in tasks {
        task.abort();
    }
    if let Some(retry) = runtime.retry.lock().take() {
        retry.abort();
    }

    // Relâcher avant de verrouiller : une touche restée enfoncée survivrait au
    // verrouillage et gênerait l'utilisateur physique de la machine.
    if let Err(e) = runtime.sink.lock().release_all() {
        tracing::debug!(error = %e, "relâchement des entrées");
    }

    // Le pipeline part ici, ce qui rend la VRAM, arrête le thread de capture et
    // ramène l'agent à sa consommation de repos. Le verrou attend la fin d'un
    // démarrage déjà engagé.
    {
        let _starting = runtime.starting.lock().await;
        stop_pipeline(runtime);
    }
    *runtime.control.lock() = None;
    *runtime.input.lock() = None;
    runtime.session.close().await;

    // La politique est lue sur le dispatcher : c'est lui qui détient les
    // garde-fous de la session, et une seule source évite qu'ils divergent.
    if reason.triggers_killswitch() && runtime.dispatcher.lock().lock_on_disconnect() {
        match sidgate_input::system::lock_session() {
            Ok(()) => tracing::warn!(session = %session_id, "killswitch: session verrouillée"),
            Err(e) => tracing::error!(session = %session_id, error = %e, "killswitch en échec"),
        }
    }
    let rejected = runtime.rejected_inputs.load(Ordering::Relaxed);
    tracing::info!(session = %session_id, ?reason, rejected_inputs = rejected, "session close");
}

/// Consomme un canal de données jusqu'à sa fermeture.
fn spawn_channel(
    channel: Arc<dyn DataChannel>,
    runtime: Arc<SessionRuntime>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let label = channel.label().await.unwrap_or_default();
        let is_control = label == CHANNEL_CONTROL;
        if !is_control && label != CHANNEL_INPUT {
            tracing::warn!(%label, "canal inattendu, ignoré");
            return;
        }
        tracing::info!(%label, "canal de données ouvert");

        // Le pipeline a pu démarrer avant ce canal : lui redire où il en est,
        // chacun pour ce qu'il transporte.
        if is_control {
            *runtime.control.lock() = Some(Arc::clone(&channel));
            announce(&runtime).await;
        } else {
            *runtime.input.lock() = Some(Arc::clone(&channel));
            announce_pointer(&runtime).await;
        }

        while let Some(event) = channel.poll().await {
            match event {
                DataChannelEvent::OnMessage(message) => match (is_control, message.is_string) {
                    (true, true) => handle_control(&message.data, &runtime).await,
                    // Appuis, relâchements et texte : fiables et ordonnés,
                    // donc sans numéro de séquence à vérifier.
                    (true, false) => handle_input(&message.data, &runtime, Delivery::Ordered),
                    (false, false) => handle_input(&message.data, &runtime, Delivery::Lossy),
                    (false, true) => {}
                },
                DataChannelEvent::OnClose | DataChannelEvent::OnError => break,
                _ => {}
            }
        }
        tracing::info!(%label, "canal de données fermé");
    })
}

/// Garanties du canal par lequel une trame d'entrées est arrivée.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Delivery {
    /// Canal fiable et ordonné.
    Ordered,
    /// Canal sans ordre ni retransmission.
    Lossy,
}

/// Décode et applique une trame d'entrées.
fn handle_input(payload: &BytesMut, runtime: &SessionRuntime, delivery: Delivery) {
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
    // ramènerait le pointeur en arrière.
    if delivery == Delivery::Lossy && !runtime.seq.lock().accept(frame.seq) {
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

    let name = command.name();
    let decision = runtime.dispatcher.lock().dispatch(command);
    let outcome = match decision {
        Ok(effect) => {
            if let ControlCommand::SetQuality { preset } = command {
                *runtime.preset.lock() = preset;
            }
            apply(effect, runtime).await
        }
        Err(reason) => Err(reason),
    };

    match outcome {
        // Une réponse de sonde n'appelle pas d'accusé de réception : il
        // doublerait le trafic du canal pour ne rien apprendre au client.
        Ok(()) if matches!(command, ControlCommand::Pong { .. }) => {}
        Ok(()) => {
            runtime
                .emit(ControlEvent::CommandAccepted {
                    command: name.to_string(),
                })
                .await;
        }
        Err(reason) => {
            runtime
                .emit(ControlEvent::CommandRejected {
                    command: name.to_string(),
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
        Effect::Bitrate(ceiling) => {
            let bitrate = runtime.bitrate.lock().set_ceiling(ceiling);
            with_pipeline(runtime, |p| p.set_bitrate(bitrate))?;
        }
        Effect::SendStats => {
            let stats = (*runtime.last_stats.lock()).ok_or(RejectReason::WrongState)?;
            runtime.emit(ControlEvent::Stats(stats)).await;
        }
        Effect::Pong(seq) => runtime.probe.lock().complete(seq, Instant::now()),
        Effect::SelectDisplay(index) => select_display(runtime, index).await?,
        Effect::SendClipboard => {
            let read = tokio::task::spawn_blocking(|| {
                sidgate_input::clipboard::read_text(MAX_CLIPBOARD_BYTES)
            })
            .await;
            match read {
                Ok(Ok((text, truncated))) => {
                    runtime.emit(clipboard_event(text, truncated)).await;
                }
                Ok(Err(e)) => {
                    tracing::warn!(error = %e, "presse-papiers illisible");
                    return Err(RejectReason::Failed);
                }
                Err(_) => return Err(RejectReason::Failed),
            }
        }
        Effect::Lock => sidgate_input::system::lock_session().map_err(|_| RejectReason::Failed)?,
        Effect::Sleep => sidgate_input::system::sleep().map_err(|_| RejectReason::Failed)?,
        Effect::Reboot => sidgate_input::system::reboot().map_err(|_| RejectReason::Failed)?,
        Effect::Shutdown => sidgate_input::system::shutdown().map_err(|_| RejectReason::Failed)?,
    }
    Ok(())
}

/// Bascule la capture sur une autre sortie vidéo.
///
/// Si la nouvelle sortie ne s'ouvre pas — écran débranché entre l'annonce et
/// la demande — la capture revient à la précédente plutôt que de laisser le
/// client devant une image figée.
async fn select_display(runtime: &Arc<SessionRuntime>, index: u32) -> Result<(), RejectReason> {
    // Arrêt et redémarrage d'un seul tenant : une reprise de capture qui
    // s'intercalerait rouvrirait l'ancien écran sous le nouveau numéro.
    let _starting = runtime.starting.lock().await;

    let previous = runtime.output.swap(index, Ordering::Relaxed);
    if previous == index && runtime.pipeline.lock().is_some() {
        return Ok(());
    }

    // Les touches tenues appartiennent à l'écran que l'on quitte.
    if let Err(e) = runtime.sink.lock().release_all() {
        tracing::debug!(error = %e, "relâchement des entrées");
    }
    stop_pipeline(runtime);

    match start_pipeline_locked(runtime).await {
        Ok(()) => Ok(()),
        Err(e) if is_desktop_unavailable(&e) => {
            // La session hôte est verrouillée : la reprise de capture ouvrira
            // la sortie demandée dès que le bureau reviendra.
            capture_failed(runtime, &e).await;
            Ok(())
        }
        Err(e) => {
            tracing::warn!(output = index, error = %e, "écran inaccessible, retour au précédent");
            runtime.output.store(previous, Ordering::Relaxed);
            if let Err(e) = start_pipeline_locked(runtime).await {
                capture_failed(runtime, &e).await;
            }
            Err(RejectReason::Failed)
        }
    }
}

/// Construit l'événement de presse-papiers, réduit s'il le faut à la taille
/// d'un message.
///
/// La borne porte sur le message *sérialisé* : un texte fait de caractères de
/// contrôle sextuple à l'échappement JSON, et c'est le message qui doit passer.
fn clipboard_event(mut text: String, mut truncated: bool) -> ControlEvent {
    loop {
        let event = ControlEvent::Clipboard {
            text: text.clone(),
            truncated,
        };
        let size = serde_json::to_string(&event).map_or(0, |json| json.len());
        if size <= MAX_CONTROL_MESSAGE || text.is_empty() {
            return event;
        }
        let half = text.len() / 2;
        text = sidgate_input::truncate_utf8(text, half).0;
        truncated = true;
    }
}

fn with_pipeline<F>(runtime: &SessionRuntime, action: F) -> Result<(), RejectReason>
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

/// Émet la télémétrie à intervalle régulier, tant que son pipeline tourne.
fn spawn_stats_reporter(
    runtime: Arc<SessionRuntime>,
    stats: Arc<PipelineStats>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut meter = ProcessMeter::new();
        meter.sample();
        let mut previous = stats.snapshot();
        let mut last = Instant::now();
        let mut ticker = tokio::time::interval(STATS_INTERVAL);
        ticker.tick().await;

        loop {
            ticker.tick().await;
            if !runtime.owns(&stats) {
                break;
            }
            let current = stats.snapshot();
            let delta = current.delta(&previous);
            let elapsed = last.elapsed();
            previous = current;
            last = Instant::now();

            // La sonde précède la télémétrie : la réponse du client arrive
            // avant le relevé suivant, qui l'annonce.
            let (seq, rtt_ms) = {
                let mut probe = runtime.probe.lock();
                let rtt_ms = probe.rtt_ms;
                (probe.begin(Instant::now()), rtt_ms)
            };
            runtime.emit(ControlEvent::Ping { seq }).await;

            let report = stats_from(&delta, elapsed, meter.sample(), rtt_ms);
            *runtime.last_stats.lock() = Some(report);
            runtime.emit(ControlEvent::Stats(report)).await;

            refresh_outputs(&runtime).await;
        }
    })
}

fn stats_from(
    delta: &StatsSnapshot,
    elapsed: Duration,
    process: ProcessSample,
    rtt_ms: Option<f32>,
) -> Stats {
    Stats {
        frames_captured: delta.captured,
        frames_encoded: delta.encoded,
        frames_submitted: delta.submitted,
        frames_dropped: delta.dropped,
        frames_idle: delta.idle,
        bitrate_bps: delta.bitrate_bps(elapsed),
        fps: delta.fps(elapsed),
        encode_ms: delta.encode_ms(),
        cpu_percent: process.cpu_percent,
        rss_mb: process.rss_mb,
        rtt_ms,
    }
}

fn random_nonce() -> anyhow::Result<[u8; NONCE_LEN]> {
    let mut nonce = [0u8; NONCE_LEN];
    rand::rngs::OsRng
        .try_fill_bytes(&mut nonce)
        .map_err(|e| anyhow::anyhow!("générateur aléatoire indisponible: {e}"))?;
    Ok(nonce)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stats_are_derived_from_the_interval() {
        let delta = StatsSnapshot {
            captured: 120,
            encoded: 118,
            submitted: 120,
            dropped: 2,
            idle: 5,
            bytes: 2_000_000,
            encode_us: 120_000,
        };
        let stats = stats_from(
            &delta,
            Duration::from_secs(2),
            ProcessSample {
                cpu_percent: Some(1.5),
                rss_mb: Some(140.0),
            },
            Some(12.0),
        );
        assert_eq!(stats.fps, 59.0);
        assert_eq!(stats.bitrate_bps, 8_000_000);
        assert_eq!(stats.frames_dropped, 2);
        assert!((stats.encode_ms - 1.0).abs() < 0.001);
        assert_eq!(stats.cpu_percent, Some(1.5));
        assert_eq!(stats.rss_mb, Some(140.0));
        assert_eq!(stats.rtt_ms, Some(12.0));
    }

    #[test]
    fn what_was_not_measured_is_reported_absent() {
        let stats = stats_from(
            &StatsSnapshot::default(),
            Duration::from_secs(2),
            ProcessSample::default(),
            None,
        );
        assert_eq!(stats.cpu_percent, None);
        assert_eq!(stats.rss_mb, None);
        assert_eq!(stats.rtt_ms, None);
    }

    #[test]
    fn nonces_are_unique_and_full_length() {
        let a = random_nonce().unwrap();
        let b = random_nonce().unwrap();
        assert_eq!(a.len(), NONCE_LEN);
        assert_ne!(a, b);
        assert_ne!(a, [0u8; NONCE_LEN]);
    }

    #[test]
    fn mdns_candidates_are_recognised() {
        assert!(is_mdns_candidate(
            "candidate:1 1 udp 2113937151 56a5d85d-7c01-4f1b-8de2-9deb74a60dcb.local 54321 typ host"
        ));
        assert!(is_mdns_candidate(
            "candidate:1 1 UDP 1 ABCD.LOCAL 1 typ host"
        ));
        assert!(!is_mdns_candidate(
            "candidate:1 1 udp 2113937151 100.64.0.7 54321 typ host generation 0"
        ));
        assert!(!is_mdns_candidate(
            "candidate:1 1 udp 1 fd7a:115c:a1e0::7 1 typ host"
        ));
        // Trop courte pour porter une adresse : ce n'est pas à ce filtre de
        // la refuser, la pile ICE s'en charge.
        assert!(!is_mdns_candidate("candidate:1 1 udp"));
        assert!(!is_mdns_candidate(""));
    }

    fn state() -> AppState {
        let dir = std::env::temp_dir().join(format!(
            "sidgate-signaling-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let identity = Identity::load_or_create(&dir, 10).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        AppState::new(identity, Config::default())
    }

    fn address(last: u8) -> IpAddr {
        IpAddr::from([100, 64, 0, last])
    }

    #[test]
    fn one_source_cannot_hold_every_handshake_slot() {
        let state = state();
        let held: Vec<_> = (0..MAX_PENDING_PER_SOURCE)
            .map(|_| state.reserve_handshake(address(1)).expect("place libre"))
            .collect();
        assert!(
            state.reserve_handshake(address(1)).is_none(),
            "au-delà de son quota, une adresse est refusée"
        );
        assert!(
            state.reserve_handshake(address(2)).is_some(),
            "sans que cela ferme la porte aux autres"
        );

        drop(held);
        assert!(
            state.reserve_handshake(address(1)).is_some(),
            "une place rendue se reprend"
        );
        assert!(
            state.pending.lock().is_empty(),
            "et le compte ne garde aucune adresse inactive"
        );
    }

    #[test]
    fn the_global_handshake_limit_still_applies() {
        let state = state();
        let held: Vec<_> = (0..MAX_PENDING_HANDSHAKES as u8)
            .filter_map(|n| state.reserve_handshake(address(n)))
            .collect();
        assert_eq!(held.len(), MAX_PENDING_HANDSHAKES);
        assert!(state.reserve_handshake(address(200)).is_none());
        assert!(
            !state.pending.lock().contains_key(&address(200)),
            "un refus ne laisse pas de trace dans le compte"
        );
    }

    #[test]
    fn only_a_takeover_spares_the_killswitch() {
        for reason in [
            EndReason::ClientLeft,
            EndReason::SignalingClosed,
            EndReason::TransportLost,
            EndReason::Revoked,
            EndReason::Failed,
        ] {
            assert!(
                reason.triggers_killswitch(),
                "{reason:?} doit verrouiller le poste"
            );
        }
        assert!(!EndReason::Replaced.triggers_killswitch());
    }

    #[test]
    fn a_probe_measures_the_round_trip() {
        let start = Instant::now();
        let mut probe = Probe::default();
        let seq = probe.begin(start);
        assert_eq!(probe.rtt_ms, None, "rien n'est mesuré avant la réponse");

        probe.complete(seq, start + Duration::from_millis(24));
        let rtt = probe.rtt_ms.unwrap();
        assert!((rtt - 24.0).abs() < 0.01, "{rtt}");
    }

    #[test]
    fn an_answer_to_another_probe_is_ignored() {
        let start = Instant::now();
        let mut probe = Probe::default();
        let first = probe.begin(start);
        let second = probe.begin(start + Duration::from_secs(2));
        assert_ne!(first, second);

        probe.complete(first, start + Duration::from_secs(3));
        assert_eq!(
            probe.rtt_ms, None,
            "la réponse tardive ne vaut pas pour la sonde en cours"
        );
        probe.complete(99, start + Duration::from_secs(3));
        assert_eq!(probe.rtt_ms, None);
    }

    #[test]
    fn an_unanswered_probe_expires_the_last_measure() {
        let start = Instant::now();
        let mut probe = Probe::default();
        let seq = probe.begin(start);
        probe.complete(seq, start + Duration::from_millis(10));
        assert!(probe.rtt_ms.is_some());

        // Deux sondes de suite sans réponse entre les deux.
        probe.begin(start + Duration::from_secs(2));
        assert!(
            probe.rtt_ms.is_some(),
            "la mesure reste valable tant qu'une sonde est attendue"
        );
        probe.begin(start + Duration::from_secs(4));
        assert_eq!(
            probe.rtt_ms, None,
            "une valeur périmée ne reste pas affichée"
        );
    }

    fn clipboard_size(event: &ControlEvent) -> usize {
        serde_json::to_string(event).unwrap().len()
    }

    #[test]
    fn a_short_clipboard_passes_untouched() {
        let event = clipboard_event("bonjour".into(), false);
        assert_eq!(
            event,
            ControlEvent::Clipboard {
                text: "bonjour".into(),
                truncated: false
            }
        );
    }

    #[test]
    fn a_clipboard_that_swells_when_escaped_is_cut_to_fit() {
        // 32 Ko de caractères de contrôle : six fois plus une fois échappés.
        let text = "\u{1}".repeat(MAX_CLIPBOARD_BYTES);
        let event = clipboard_event(text, false);
        assert!(clipboard_size(&event) <= MAX_CONTROL_MESSAGE);
        let ControlEvent::Clipboard { text, truncated } = event else {
            panic!("événement inattendu");
        };
        assert!(truncated);
        assert!(!text.is_empty(), "couper n'est pas vider");
    }

    #[test]
    fn a_clipboard_at_the_read_limit_fits_in_one_message() {
        let event = clipboard_event("é".repeat(MAX_CLIPBOARD_BYTES / 2), true);
        assert!(clipboard_size(&event) <= MAX_CONTROL_MESSAGE);
        assert!(matches!(
            event,
            ControlEvent::Clipboard {
                truncated: true,
                ..
            }
        ));
    }

    #[test]
    fn the_largest_pointer_shape_fits_in_one_message() {
        let side = MAX_SENT_POINTER_SIDE as usize;
        let event = ControlEvent::PointerShape {
            width: side as u16,
            height: side as u16,
            hot_x: 0,
            hot_y: 0,
            rgba: data_encoding::BASE64.encode(&vec![0xFFu8; side * side * 4]),
        };
        assert!(serde_json::to_string(&event).unwrap().len() <= MAX_CONTROL_MESSAGE);
    }
}
