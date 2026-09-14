//! Canal de signalisation : authentification mutuelle puis échange SDP/ICE.
//!
//! Le tunnel WireGuard et le TLS du transport ne sont pas considérés comme
//! suffisants : la signalisation porte sa propre authentification mutuelle, de
//! sorte qu'un attaquant déjà présent sur le réseau privé ne puisse ni ouvrir de
//! session ni se faire passer pour l'agent.
//!
//! # Déroulé
//!
//! ```text
//! agent  ──► Challenge      { protocol, server_nonce, agent_key }
//! client ──► Authenticate   { client_key, client_nonce, signature }   (déjà appairé)
//!        ou  Pair           { code, client_key, client_nonce, signature }
//! agent  ──► AuthOk         { agent_signature, session_id }
//! client ──► Offer / Candidate …
//! agent  ──► Answer / Candidate …
//! ```
//!
//! Le client signe avec ECDSA P-256 (`SHA-256`), disponible dans WebCrypto sur
//! tous les navigateurs ; l'agent signe avec Ed25519. Les deux signatures
//! portent sur la même transcription, qui inclut les deux aléas et la clé
//! publique du client : rejouer une signature capturée sur une autre session ou
//! avec une autre identité échoue.

use serde::{Deserialize, Serialize};

/// Longueur d'un aléa de handshake, en octets.
pub const NONCE_LEN: usize = 32;

const DOMAIN_CLIENT_AUTH: &[u8] = b"sidgate/auth/client/v1";
const DOMAIN_CLIENT_PAIR: &[u8] = b"sidgate/pair/client/v1";
const DOMAIN_AGENT: &[u8] = b"sidgate/auth/agent/v1";

/// Construit la transcription que signe un client déjà appairé.
pub fn client_auth_transcript(
    server_nonce: &[u8],
    client_nonce: &[u8],
    client_key: &[u8],
) -> Vec<u8> {
    transcript(DOMAIN_CLIENT_AUTH, server_nonce, client_nonce, client_key)
}

/// Construit la transcription que signe un client en cours d'appairage.
pub fn client_pair_transcript(
    server_nonce: &[u8],
    client_nonce: &[u8],
    client_key: &[u8],
) -> Vec<u8> {
    transcript(DOMAIN_CLIENT_PAIR, server_nonce, client_nonce, client_key)
}

/// Construit la transcription que signe l'agent pour se prouver au client.
pub fn agent_transcript(server_nonce: &[u8], client_nonce: &[u8], client_key: &[u8]) -> Vec<u8> {
    transcript(DOMAIN_AGENT, server_nonce, client_nonce, client_key)
}

/// Chaque champ est préfixé de sa longueur : sans cela, un découpage différent
/// des mêmes octets produirait la même transcription.
fn transcript(domain: &[u8], server_nonce: &[u8], client_nonce: &[u8], client_key: &[u8]) -> Vec<u8> {
    let mut out =
        Vec::with_capacity(domain.len() + server_nonce.len() + client_nonce.len() + client_key.len() + 16);
    for part in [domain, server_nonce, client_nonce, client_key] {
        out.extend_from_slice(&(part.len() as u32).to_le_bytes());
        out.extend_from_slice(part);
    }
    out
}

/// Messages du client vers l'agent.
///
/// Étiquetage adjacent (`{"type": …, "payload": {…}}`) pour la même raison que
/// [`crate::control::ControlCommand`] : `deny_unknown_fields` n'a aucun effet sur
/// une énumération à étiquette interne.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "type",
    content = "payload",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum ClientMessage {
    /// Authentification d'un client déjà appairé.
    Authenticate {
        /// Version de protocole parlée par le client.
        protocol: u16,
        /// Clé publique ECDSA P-256, format SEC1 non compressé, en hexadécimal.
        client_key: String,
        /// Aléa du client, en hexadécimal.
        client_nonce: String,
        /// Signature `r || s` de [`client_auth_transcript`], en hexadécimal.
        signature: String,
    },
    /// Premier appairage, protégé par le code affiché sur l'hôte.
    Pair {
        /// Version de protocole parlée par le client.
        protocol: u16,
        /// Code d'appairage lu sur la console de l'agent.
        code: String,
        /// Clé publique ECDSA P-256, format SEC1 non compressé, en hexadécimal.
        client_key: String,
        /// Aléa du client, en hexadécimal.
        client_nonce: String,
        /// Signature `r || s` de [`client_pair_transcript`], en hexadécimal.
        signature: String,
        /// Nom lisible de l'appareil, conservé pour l'audit et la révocation.
        label: String,
    },
    /// Offre SDP du client.
    Offer {
        /// Description de session, format SDP.
        sdp: String,
    },
    /// Candidat ICE du client.
    Candidate {
        /// Ligne `candidate:` telle que produite par le navigateur.
        candidate: String,
        /// Identifiant du média associé.
        sdp_mid: Option<String>,
        /// Index du média associé.
        sdp_mline_index: Option<u16>,
    },
    /// Fermeture volontaire de la session.
    Bye,
}

/// Messages de l'agent vers le client.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "payload", rename_all = "snake_case")]
pub enum ServerMessage {
    /// Premier message émis à l'ouverture de la connexion.
    Challenge {
        /// Version de protocole parlée par l'agent.
        protocol: u16,
        /// Aléa de l'agent, en hexadécimal.
        server_nonce: String,
        /// Clé publique Ed25519 de l'agent, en hexadécimal. Le client l'épingle
        /// au premier appairage et refuse ensuite toute autre valeur.
        agent_key: String,
        /// Un appairage est-il ouvert en ce moment ?
        pairing_open: bool,
    },
    /// Authentification réussie dans les deux sens.
    AuthOk {
        /// Signature Ed25519 de [`agent_transcript`], en hexadécimal.
        agent_signature: String,
        /// Identifiant de session, pour la corrélation des journaux.
        session_id: String,
    },
    /// Authentification refusée.
    AuthFailed {
        /// Motif du refus.
        reason: AuthError,
    },
    /// Réponse SDP de l'agent.
    Answer {
        /// Description de session, format SDP.
        sdp: String,
    },
    /// Candidat ICE de l'agent.
    Candidate {
        /// Ligne `candidate:`.
        candidate: String,
        /// Identifiant du média associé.
        sdp_mid: Option<String>,
        /// Index du média associé.
        sdp_mline_index: Option<u16>,
    },
    /// Erreur applicative hors authentification.
    Error {
        /// Message court, sans détail interne.
        message: String,
    },
}

/// Motifs de refus d'authentification.
///
/// Délibérément grossiers : distinguer « clé inconnue » de « signature invalide »
/// renseignerait un attaquant sur la validité d'une clé.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthError {
    /// Version de protocole incompatible.
    ProtocolMismatch,
    /// Identité inconnue, signature invalide ou code erroné.
    Rejected,
    /// Aucun appairage n'est ouvert sur l'hôte.
    PairingClosed,
    /// Trop de tentatives depuis cette source.
    RateLimited,
    /// Message inattendu à cette étape du handshake.
    UnexpectedMessage,
}

/// Encode des octets en hexadécimal minuscule.
pub fn to_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(DIGITS[(b >> 4) as usize] as char);
        out.push(DIGITS[(b & 0x0f) as usize] as char);
    }
    out
}

/// Décode une chaîne hexadécimale. Refuse toute longueur impaire ou tout
/// caractère hors `[0-9a-fA-F]`.
pub fn from_hex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(s.len() / 2);
    for pair in bytes.chunks_exact(2) {
        let hi = (pair[0] as char).to_digit(16)?;
        let lo = (pair[1] as char).to_digit(16)?;
        out.push((hi * 16 + lo) as u8);
    }
    Some(out)
}

/// Décode une chaîne hexadécimale de longueur attendue exacte.
pub fn from_hex_exact<const N: usize>(s: &str) -> Option<[u8; N]> {
    let bytes = from_hex(s)?;
    bytes.try_into().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_roundtrips() {
        let data = [0x00u8, 0x0f, 0xff, 0xa5, 0x10];
        assert_eq!(to_hex(&data), "000fffa510");
        assert_eq!(from_hex("000fffa510").unwrap(), data);
        assert_eq!(from_hex(&to_hex(&data)).unwrap(), data);
    }

    #[test]
    fn hex_rejects_malformed_input() {
        assert!(from_hex("abc").is_none(), "longueur impaire");
        assert!(from_hex("zz").is_none(), "caractère hors alphabet");
        assert!(from_hex("00 11").is_none(), "espace");
        assert!(from_hex("ＡＢ").is_none(), "hors ASCII");
    }

    #[test]
    fn hex_exact_enforces_length() {
        assert!(from_hex_exact::<4>("aabbccdd").is_some());
        assert!(from_hex_exact::<4>("aabbcc").is_none());
        assert!(from_hex_exact::<4>("aabbccddee").is_none());
    }

    #[test]
    fn transcripts_are_domain_separated() {
        let (sn, cn, ck) = (&[1u8; 32][..], &[2u8; 32][..], &[3u8; 65][..]);
        let auth = client_auth_transcript(sn, cn, ck);
        let pair = client_pair_transcript(sn, cn, ck);
        let agent = agent_transcript(sn, cn, ck);
        assert_ne!(auth, pair);
        assert_ne!(auth, agent);
        assert_ne!(pair, agent);
    }

    #[test]
    fn transcript_is_unambiguous_across_field_boundaries() {
        // Sans préfixe de longueur, ces deux découpages produiraient les mêmes
        // octets et une signature vaudrait pour les deux.
        let a = client_auth_transcript(&[1, 2, 3], &[4, 5], &[6]);
        let b = client_auth_transcript(&[1, 2], &[3, 4], &[5, 6]);
        assert_ne!(a, b);
    }

    #[test]
    fn transcript_changes_with_every_input() {
        let base = client_auth_transcript(&[1; 32], &[2; 32], &[3; 65]);
        assert_ne!(base, client_auth_transcript(&[9; 32], &[2; 32], &[3; 65]));
        assert_ne!(base, client_auth_transcript(&[1; 32], &[9; 32], &[3; 65]));
        assert_ne!(base, client_auth_transcript(&[1; 32], &[2; 32], &[9; 65]));
    }

    #[test]
    fn client_messages_roundtrip() {
        let message = ClientMessage::Pair {
            protocol: crate::PROTOCOL_VERSION,
            code: "K7M4-P2QX".into(),
            client_key: to_hex(&[4u8; 65]),
            client_nonce: to_hex(&[5u8; NONCE_LEN]),
            signature: to_hex(&[6u8; 64]),
            label: "Pixel 8".into(),
        };
        let json = serde_json::to_string(&message).unwrap();
        assert_eq!(
            serde_json::from_str::<ClientMessage>(&json).unwrap(),
            message
        );
    }

    #[test]
    fn client_messages_reject_unknown_shapes() {
        for payload in [
            r#"{"type":"admin"}"#,
            r#"{"type":"bye","exec":"x"}"#,
            r#"{"type":"offer","payload":{"sdp":"v=0","exec":"x"}}"#,
            r#"{"type":"offer"}"#,
        ] {
            assert!(
                serde_json::from_str::<ClientMessage>(payload).is_err(),
                "aurait dû être rejeté: {payload}"
            );
        }
    }

    #[test]
    fn server_messages_roundtrip() {
        let message = ServerMessage::Challenge {
            protocol: crate::PROTOCOL_VERSION,
            server_nonce: to_hex(&[7u8; NONCE_LEN]),
            agent_key: to_hex(&[8u8; 32]),
            pairing_open: true,
        };
        let json = serde_json::to_string(&message).unwrap();
        assert_eq!(
            serde_json::from_str::<ServerMessage>(&json).unwrap(),
            message
        );
    }
}
