//! Types partagés entre l'agent sidgate et ses clients.
//!
//! Ce crate ne dépend d'aucune API système : il définit uniquement le format
//! des messages qui circulent sur les deux DataChannels WebRTC et sur le canal
//! de signalisation.
//!
//! - [`input`] : codec binaire compact, canal `input-raw` (non ordonné, non fiable)
//! - [`control`] : commandes typées, canal `control-secure` (fiable, ordonné)
//! - [`signaling`] : handshake d'authentification mutuelle et échange SDP/ICE

#![forbid(unsafe_code)]

pub mod control;
pub mod input;
pub mod signaling;

/// Identifiant du canal de données temps réel (souris, clavier, molette).
pub const CHANNEL_INPUT: &str = "input-raw";
/// Identifiant du canal de données fiable (commandes système, télémétrie).
pub const CHANNEL_CONTROL: &str = "control-secure";

/// Version du protocole applicatif. Un client annonçant une version différente
/// est rejeté au handshake.
pub const PROTOCOL_VERSION: u16 = 1;

/// Erreurs de décodage des messages.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ProtoError {
    /// Le tampon est plus court que ce que l'en-tête annonce.
    #[error("tampon tronqué: {need} octets requis, {have} disponibles")]
    Truncated {
        /// Octets nécessaires.
        need: usize,
        /// Octets réellement disponibles.
        have: usize,
    },
    /// Octet de type d'événement inconnu.
    #[error("type d'événement inconnu: 0x{0:02x}")]
    UnknownEvent(u8),
    /// Version de trame non supportée.
    #[error("version de trame non supportée: {0}")]
    BadVersion(u8),
    /// Nombre d'événements au-delà de la limite dure.
    #[error("trame trop dense: {0} événements (max {max})", max = input::MAX_EVENTS_PER_FRAME)]
    TooManyEvents(usize),
    /// Octets résiduels après décodage complet de la trame.
    #[error("{0} octets résiduels après la trame")]
    TrailingBytes(usize),
}
