//! Types partagés entre l'agent sidgate et ses clients.
//!
//! Ce crate ne dépend d'aucune API système : il définit uniquement le format
//! des messages qui circulent sur les deux DataChannels WebRTC et sur le canal
//! de signalisation.
//!
//! - [`input`] : codec binaire compact des entrées
//! - [`pointer`] : position réelle du curseur, de l'agent vers le client
//! - [`control`] : commandes typées, canal `control-secure` (fiable, ordonné)
//! - [`signaling`] : handshake d'authentification mutuelle et échange SDP/ICE

#![forbid(unsafe_code)]

pub mod control;
pub mod input;
pub mod pointer;
pub mod signaling;

/// Identifiant du canal de données temps réel, non ordonné et non fiable :
/// mouvements et défilement à l'aller, position du pointeur au retour.
pub const CHANNEL_INPUT: &str = "input-raw";
/// Identifiant du canal de données fiable et ordonné : commandes et télémétrie
/// en texte, appuis, relâchements et saisie de texte en binaire.
pub const CHANNEL_CONTROL: &str = "control-secure";

/// Version du protocole applicatif. Un client annonçant une version différente
/// est rejeté au handshake.
pub const PROTOCOL_VERSION: u16 = 2;

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
