//! Session WebRTC : négociation, piste vidéo, canaux de données, killswitch.
//!
//! L'agent est toujours le *répondeur* : c'est le client qui émet l'offre et qui
//! crée les deux canaux de données. L'agent n'ajoute qu'une piste vidéo sortante
//! avant de composer sa réponse.
//!
//! Le pipeline de capture n'est démarré qu'une fois le transport `Connected`, et
//! détruit dès qu'il ne l'est plus. Entre deux sessions, il n'existe pas : c'est
//! littéralement ce qui donne 0,0 % de CPU au repos.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::mpsc;

use rtc::media::Sample;
use rtc::media_stream::MediaStreamTrack;
use rtc::rtp_transceiver::rtp_sender::{
    RTCRtpCodec, RTCRtpCodingParameters, RTCRtpEncodingParameters, RtpCodecKind,
};
use webrtc::data_channel::DataChannel;
use webrtc::media_stream::track_local::static_sample::TrackLocalStaticSample;
use webrtc::media_stream::track_local::TrackLocal;
use webrtc::peer_connection::{
    MediaEngine, PeerConnection, PeerConnectionBuilder, PeerConnectionEventHandler,
    RTCConfigurationBuilder, RTCIceCandidateInit, RTCIceServer, RTCPeerConnectionIceEvent,
    RTCPeerConnectionState, RTCSessionDescription,
};

use sidgate_encode::EncodedFrame;

/// Identifiant du flux média annoncé dans le SDP.
const STREAM_ID: &str = "sidgate";
/// Identifiant de la piste vidéo.
const TRACK_ID: &str = "desktop";
/// Horloge RTP de la vidéo, imposée par la spécification pour H.264.
const VIDEO_CLOCK_RATE: u32 = 90_000;

/// Événements remontés par la connexion vers la boucle de signalisation.
pub enum SessionEvent {
    /// Un candidat ICE local a été collecté, à transmettre au client.
    IceCandidate(RTCIceCandidateInit),
    /// L'état du transport a changé.
    ConnectionState(RTCPeerConnectionState),
    /// Le client a ouvert un canal de données.
    DataChannel(Arc<dyn DataChannel>),
}

impl std::fmt::Debug for SessionEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IceCandidate(init) => f
                .debug_tuple("IceCandidate")
                .field(&init.candidate)
                .finish(),
            Self::ConnectionState(state) => f.debug_tuple("ConnectionState").field(state).finish(),
            // `DataChannel` est un objet-trait sans `Debug` ; son étiquette ne
            // se lit qu'en asynchrone, ce qui n'a pas sa place ici.
            Self::DataChannel(_) => f.write_str("DataChannel(..)"),
        }
    }
}

/// Passerelle entre les rappels de `webrtc-rs` et notre boucle principale.
///
/// Les rappels ne font que poster dans un canal : toute la logique reste dans
/// une seule tâche, ce qui évite d'avoir à verrouiller l'état de session depuis
/// plusieurs contextes asynchrones.
struct EventBridge {
    events: mpsc::Sender<SessionEvent>,
}

#[async_trait::async_trait]
impl PeerConnectionEventHandler for EventBridge {
    async fn on_ice_candidate(&self, event: RTCPeerConnectionIceEvent) {
        if let Ok(init) = event.candidate.to_json() {
            let _ = self.events.send(SessionEvent::IceCandidate(init)).await;
        }
    }

    async fn on_connection_state_change(&self, state: RTCPeerConnectionState) {
        tracing::info!(?state, "état du transport");
        let _ = self.events.send(SessionEvent::ConnectionState(state)).await;
    }

    async fn on_data_channel(&self, data_channel: Arc<dyn DataChannel>) {
        let _ = self
            .events
            .send(SessionEvent::DataChannel(data_channel))
            .await;
    }
}

/// Une session WebRTC en cours de négociation ou établie.
pub struct Session {
    peer: Arc<dyn PeerConnection>,
    track: Arc<TrackLocalStaticSample>,
    ssrc: u32,
    /// Fixé à la négociation, lu par la tâche d'émission : atomique pour que
    /// la session reste partageable entre tâches sans verrou.
    payload_type: AtomicU8,
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("ssrc", &self.ssrc)
            .field("payload_type", &self.payload_type.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

impl Session {
    /// Construit la connexion et y attache la piste vidéo.
    ///
    /// `bind` est l'adresse sur laquelle collecter les candidats ICE : la même
    /// que celle d'écoute, de sorte que l'agent ne divulgue pas d'adresse sur
    /// une interface qu'il n'est pas censé utiliser.
    pub async fn new(
        bind: SocketAddr,
        stun_servers: &[String],
        framerate: u32,
    ) -> anyhow::Result<(Self, mpsc::Receiver<SessionEvent>)> {
        let (events_tx, events_rx) = mpsc::channel(64);

        let mut media_engine = MediaEngine::default();
        media_engine
            .register_default_codecs()
            .map_err(|e| anyhow::anyhow!("codecs par défaut indisponibles: {e}"))?;

        let mut builder = RTCConfigurationBuilder::default();
        if !stun_servers.is_empty() {
            builder = builder.with_ice_servers(vec![RTCIceServer {
                urls: stun_servers.to_vec(),
                ..Default::default()
            }]);
        }

        let peer = PeerConnectionBuilder::new()
            .with_configuration(builder.build())
            .with_media_engine(media_engine)
            .with_handler(Arc::new(EventBridge { events: events_tx }))
            .with_udp_addrs(vec![bind])
            .build()
            .await
            .map_err(|e| anyhow::anyhow!("connexion WebRTC impossible: {e}"))?;

        let ssrc = random_ssrc();
        let track = Arc::new(
            TrackLocalStaticSample::new(MediaStreamTrack::new(
                STREAM_ID.to_owned(),
                TRACK_ID.to_owned(),
                "Bureau".to_owned(),
                RtpCodecKind::Video,
                vec![RTCRtpEncodingParameters {
                    rtp_coding_parameters: RTCRtpCodingParameters {
                        ssrc: Some(ssrc),
                        ..Default::default()
                    },
                    codec: h264_codec(),
                    max_framerate: Some(f64::from(framerate)),
                    ..Default::default()
                }],
            ))
            .map_err(|e| anyhow::anyhow!("piste vidéo invalide: {e}"))?,
        );

        let sender = peer
            .add_track(Arc::clone(&track) as Arc<dyn TrackLocal>)
            .await
            .map_err(|e| anyhow::anyhow!("ajout de la piste impossible: {e}"))?;

        // Type de charge utile provisoire : il est relu après la négociation,
        // puisque c'est le client qui fixe la correspondance dans son offre.
        let payload_type = sender
            .get_parameters()
            .await
            .ok()
            .and_then(|p| p.rtp_parameters.codecs.first().map(|c| c.payload_type))
            .unwrap_or(96);

        Ok((
            Self {
                peer: Arc::new(peer),
                track,
                ssrc,
                payload_type: AtomicU8::new(payload_type),
            },
            events_rx,
        ))
    }

    /// Applique l'offre du client et renvoie la réponse à lui transmettre.
    pub async fn accept_offer(&self, sdp: String) -> anyhow::Result<String> {
        let offer = RTCSessionDescription::offer(sdp)
            .map_err(|e| anyhow::anyhow!("offre illisible: {e}"))?;
        self.peer
            .set_remote_description(offer)
            .await
            .map_err(|e| anyhow::anyhow!("offre refusée: {e}"))?;

        let answer = self
            .peer
            .create_answer(None)
            .await
            .map_err(|e| anyhow::anyhow!("réponse impossible: {e}"))?;
        let sdp = answer.sdp.clone();
        self.peer
            .set_local_description(answer)
            .await
            .map_err(|e| anyhow::anyhow!("réponse non appliquée: {e}"))?;

        // La correspondance de type de charge utile est celle de l'offre : s'en
        // remettre à notre valeur par défaut produirait des paquets que le
        // navigateur jetterait sans rien dire.
        if let Some(negotiated) = self.negotiated_payload_type().await {
            let previous = self.payload_type.swap(negotiated, Ordering::Relaxed);
            if negotiated != previous {
                tracing::info!(from = previous, to = negotiated, "type de charge utile négocié");
            }
        }

        Ok(sdp)
    }

    async fn negotiated_payload_type(&self) -> Option<u8> {
        let senders = self.peer.get_senders().await;
        let sender = senders.first()?;
        let parameters = sender.get_parameters().await.ok()?;
        parameters
            .rtp_parameters
            .codecs
            .iter()
            .find(|c| c.rtp_codec.mime_type.eq_ignore_ascii_case("video/H264"))
            .or_else(|| parameters.rtp_parameters.codecs.first())
            .map(|c| c.payload_type)
    }

    /// Ajoute un candidat ICE distant.
    pub async fn add_candidate(&self, candidate: RTCIceCandidateInit) -> anyhow::Result<()> {
        self.peer
            .add_ice_candidate(candidate)
            .await
            .map_err(|e| anyhow::anyhow!("candidat refusé: {e}"))
    }

    /// Ferme la connexion.
    pub async fn close(&self) {
        if let Err(e) = self.peer.close().await {
            tracing::debug!(error = %e, "fermeture de la connexion");
        }
    }

    /// Démarre la tâche qui pousse les images encodées sur la piste.
    ///
    /// La tâche s'arrête d'elle-même quand le canal se ferme, c'est-à-dire quand
    /// le pipeline est détruit.
    pub fn spawn_video_sender(
        &self,
        mut frames: mpsc::Receiver<EncodedFrame>,
        framerate: u32,
    ) -> tokio::task::JoinHandle<()> {
        let track = Arc::clone(&self.track);
        let ssrc = self.ssrc;
        let payload_type = self.payload_type.load(Ordering::Relaxed);
        let nominal = Duration::from_nanos(1_000_000_000 / u64::from(framerate.max(1)));

        tokio::spawn(async move {
            let mut previous: Option<Duration> = None;
            while let Some(frame) = frames.recv().await {
                // La durée transmise sert à faire avancer l'horodatage RTP.
                // L'écart réel entre deux images vaut mieux que la cadence
                // nominale : sur un bureau immobile, les images sont espacées
                // de plusieurs secondes et un pas figé décalerait l'horloge.
                let duration = previous
                    .map(|p| frame.timestamp.saturating_sub(p))
                    .filter(|d| !d.is_zero())
                    .unwrap_or(nominal);
                previous = Some(frame.timestamp);

                let sample = Sample {
                    data: frame.data,
                    duration,
                    ..Default::default()
                };
                if let Err(e) = track
                    .sample_writer(ssrc, payload_type)
                    .write_sample(&sample)
                    .await
                {
                    tracing::warn!(error = %e, "émission vidéo interrompue");
                    break;
                }
            }
            tracing::info!("émission vidéo terminée");
        })
    }
}

/// Description du codec H.264 tel que nous l'émettons.
///
/// `packetization-mode=1` autorise les NALU fragmentées, indispensable au-delà
/// du MTU. `level-asymmetry-allowed=1` laisse le navigateur annoncer un niveau
/// différent du nôtre, ce que font tous les navigateurs.
fn h264_codec() -> RTCRtpCodec {
    RTCRtpCodec {
        mime_type: "video/H264".to_owned(),
        clock_rate: VIDEO_CLOCK_RATE,
        channels: 0,
        sdp_fmtp_line:
            "level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42e01f".to_owned(),
        rtcp_feedback: Vec::new(),
    }
}

/// Tire un SSRC non nul.
fn random_ssrc() -> u32 {
    use rand::Rng;
    rand::rng().random_range(1..=u32::MAX)
}

/// Le changement d'état doit-il déclencher le killswitch ?
///
/// `Disconnected` en fait partie : WebRTC peut en sortir tout seul après
/// quelques secondes, mais attendre cette éventualité laisserait la session de
/// l'hôte déverrouillée pendant ce temps. Verrouiller est réversible en deux
/// secondes ; ne pas verrouiller ne l'est pas.
pub fn is_terminal(state: RTCPeerConnectionState) -> bool {
    matches!(
        state,
        RTCPeerConnectionState::Disconnected
            | RTCPeerConnectionState::Failed
            | RTCPeerConnectionState::Closed
    )
}

/// Le transport est-il utilisable ?
pub fn is_connected(state: RTCPeerConnectionState) -> bool {
    matches!(state, RTCPeerConnectionState::Connected)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn terminal_states_trigger_the_killswitch() {
        for state in [
            RTCPeerConnectionState::Disconnected,
            RTCPeerConnectionState::Failed,
            RTCPeerConnectionState::Closed,
        ] {
            assert!(is_terminal(state), "{state:?} doit verrouiller la session");
        }
    }

    #[test]
    fn transient_states_do_not_trigger_it() {
        for state in [
            RTCPeerConnectionState::New,
            RTCPeerConnectionState::Connecting,
            RTCPeerConnectionState::Connected,
        ] {
            assert!(!is_terminal(state), "{state:?} ne doit pas verrouiller");
        }
    }

    #[test]
    fn only_connected_starts_the_pipeline() {
        assert!(is_connected(RTCPeerConnectionState::Connected));
        assert!(!is_connected(RTCPeerConnectionState::Connecting));
        assert!(!is_connected(RTCPeerConnectionState::New));
    }

    #[test]
    fn ssrc_is_never_zero() {
        for _ in 0..1000 {
            assert_ne!(random_ssrc(), 0, "un SSRC nul est invalide en RTP");
        }
    }

    #[test]
    fn codec_line_allows_fragmentation() {
        let codec = h264_codec();
        assert_eq!(codec.clock_rate, VIDEO_CLOCK_RATE);
        assert!(
            codec.sdp_fmtp_line.contains("packetization-mode=1"),
            "sans mode 1, toute image dépassant le MTU serait injectable"
        );
        assert!(codec.sdp_fmtp_line.contains("level-asymmetry-allowed=1"));
    }
}
