//! Retour de pointeur, de l'agent vers le client.
//!
//! Le bureau capturé ne contient pas le curseur : le compositeur le livre à
//! part, et c'est le client qui le dessine. Il lui faut donc sa position réelle
//! — celle que le système a calculée après accélération, butée sur les bords et
//! déplacements faits par les applications — et non une estimation locale, qui
//! dérive dès le premier geste rapide.
//!
//! Ces mises à jour remontent par `input-raw`, dans le sens inverse des
//! entrées : non ordonné, sans retransmission. Une position perdue est
//! remplacée par la suivante ; une position en retard est écartée par son
//! numéro de séquence, exactement comme une trame d'entrée.
//!
//! ```text
//! octet 0      version (= POINTER_VERSION)
//! octets 1..5  numéro de séquence, u32 little-endian
//! octets 5..7  abscisse du coin haut-gauche de l'image du curseur, i16
//! octets 7..9  ordonnée, i16
//! octet 9      drapeaux : bit 0 = visible
//! ```
//!
//! Les coordonnées sont en pixels du bureau capturé. Elles peuvent être
//! négatives : c'est le point chaud qui reste dans l'écran, pas l'image.

use crate::ProtoError;

/// Version du format.
pub const POINTER_VERSION: u8 = 1;
/// Taille d'une mise à jour, en octets.
pub const POINTER_LEN: usize = 10;

const FLAG_VISIBLE: u8 = 0b0000_0001;

/// Position du pointeur à un instant donné.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PointerUpdate {
    /// Numéro de séquence, croissant et cyclique.
    pub seq: u32,
    /// Abscisse du coin haut-gauche de l'image du curseur.
    pub x: i16,
    /// Ordonnée du coin haut-gauche de l'image du curseur.
    pub y: i16,
    /// Le curseur est-il affiché sur cette sortie ?
    pub visible: bool,
}

impl PointerUpdate {
    /// Sérialise la mise à jour.
    pub fn encode(&self) -> [u8; POINTER_LEN] {
        let mut out = [0u8; POINTER_LEN];
        out[0] = POINTER_VERSION;
        out[1..5].copy_from_slice(&self.seq.to_le_bytes());
        out[5..7].copy_from_slice(&self.x.to_le_bytes());
        out[7..9].copy_from_slice(&self.y.to_le_bytes());
        out[9] = if self.visible { FLAG_VISIBLE } else { 0 };
        out
    }

    /// Décode une mise à jour reçue.
    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        if buf.len() < POINTER_LEN {
            return Err(ProtoError::Truncated {
                need: POINTER_LEN,
                have: buf.len(),
            });
        }
        if buf.len() > POINTER_LEN {
            return Err(ProtoError::TrailingBytes(buf.len() - POINTER_LEN));
        }
        if buf[0] != POINTER_VERSION {
            return Err(ProtoError::BadVersion(buf[0]));
        }
        Ok(Self {
            seq: u32::from_le_bytes([buf[1], buf[2], buf[3], buf[4]]),
            x: i16::from_le_bytes([buf[5], buf[6]]),
            y: i16::from_le_bytes([buf[7], buf[8]]),
            visible: buf[9] & FLAG_VISIBLE != 0,
        })
    }
}

/// Ramène une coordonnée de bureau dans l'intervalle transportable.
///
/// Aucun écran n'approche 32 767 pixels ; l'écrêtage n'existe que pour qu'une
/// valeur aberrante remontée par un pilote ne devienne pas, par troncature, une
/// position plausible à l'autre bout de l'écran.
pub fn clamp_coordinate(value: i32) -> i16 {
    value.clamp(i32::from(i16::MIN), i32::from(i16::MAX)) as i16
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_preserves_every_field() {
        let update = PointerUpdate {
            seq: 0xCAFE_F00D,
            x: -12,
            y: 1079,
            visible: true,
        };
        assert_eq!(PointerUpdate::decode(&update.encode()).unwrap(), update);

        let hidden = PointerUpdate {
            visible: false,
            ..update
        };
        assert_eq!(PointerUpdate::decode(&hidden.encode()).unwrap(), hidden);
    }

    #[test]
    fn wire_layout_is_stable() {
        let update = PointerUpdate {
            seq: 1,
            x: 2,
            y: -1,
            visible: true,
        };
        assert_eq!(update.encode(), [1, 1, 0, 0, 0, 2, 0, 0xFF, 0xFF, 1]);
    }

    #[test]
    fn rejects_wrong_sizes_and_versions() {
        let good = PointerUpdate::default().encode();
        assert!(matches!(
            PointerUpdate::decode(&good[..9]),
            Err(ProtoError::Truncated { .. })
        ));
        let mut long = good.to_vec();
        long.push(0);
        assert_eq!(
            PointerUpdate::decode(&long),
            Err(ProtoError::TrailingBytes(1))
        );
        let mut bad = good;
        bad[0] = 9;
        assert_eq!(PointerUpdate::decode(&bad), Err(ProtoError::BadVersion(9)));
    }

    #[test]
    fn unknown_flag_bits_are_ignored() {
        let mut buf = PointerUpdate::default().encode();
        buf[9] = 0b1111_1110;
        assert!(!PointerUpdate::decode(&buf).unwrap().visible);
    }

    #[test]
    fn coordinates_saturate_instead_of_wrapping() {
        assert_eq!(clamp_coordinate(100_000), i16::MAX);
        assert_eq!(clamp_coordinate(-100_000), i16::MIN);
        assert_eq!(clamp_coordinate(-7), -7);
    }
}
