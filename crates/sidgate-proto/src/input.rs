//! Codec binaire du canal `input-raw`.
//!
//! Le canal est configuré non ordonné et sans retransmission : une trame peut
//! arriver en retard ou jamais. Chaque trame porte donc un numéro de séquence
//! et le récepteur rejette les trames périmées ([`SeqTracker`]) plutôt que de
//! rejouer des événements dans le désordre — un relâchement rejoué après un
//! appui laisserait une touche enfoncée.
//!
//! Le format est de taille fixe : une trame de huit mouvements souris tient en
//! 46 octets, contre environ 500 en JSON.
//!
//! ```text
//! octet 0      version (= FRAME_VERSION)
//! octets 1..5  numéro de séquence, u32 little-endian
//! octet 5      nombre d'événements
//! octets 6..   événements, chacun préfixé de son octet de type
//! ```

use crate::ProtoError;

/// Version du format de trame.
pub const FRAME_VERSION: u8 = 1;
/// Taille de l'en-tête de trame en octets.
pub const FRAME_HEADER_LEN: usize = 6;
/// Limite dure d'événements par trame. Borne le travail du récepteur face à
/// une trame hostile et couvre largement une coalescence à 120 Hz.
pub const MAX_EVENTS_PER_FRAME: usize = 64;

const KIND_MOUSE_MOVE_REL: u8 = 0x01;
const KIND_MOUSE_MOVE_ABS: u8 = 0x02;
const KIND_MOUSE_BUTTON: u8 = 0x03;
const KIND_MOUSE_SCROLL: u8 = 0x04;
const KIND_KEY: u8 = 0x05;

const FLAG_PRESSED: u8 = 0b0000_0001;
const FLAG_EXTENDED: u8 = 0b0000_0010;

/// Boutons de souris transportables. Toute autre valeur est refusée au
/// décodage : le dispatcher n'a jamais à valider un entier libre.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MouseButton {
    /// Bouton gauche.
    Left = 0,
    /// Bouton droit.
    Right = 1,
    /// Bouton du milieu.
    Middle = 2,
    /// Premier bouton latéral.
    X1 = 3,
    /// Second bouton latéral.
    X2 = 4,
}

impl MouseButton {
    fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            0 => Self::Left,
            1 => Self::Right,
            2 => Self::Middle,
            3 => Self::X1,
            4 => Self::X2,
            _ => return None,
        })
    }
}

/// Un événement d'entrée unitaire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputEvent {
    /// Déplacement relatif, en pixels logiques. Mode trackpad.
    MouseMoveRelative {
        /// Déplacement horizontal.
        dx: i16,
        /// Déplacement vertical.
        dy: i16,
    },
    /// Position absolue normalisée sur `0..=u16::MAX`, indépendante de la
    /// résolution de l'hôte.
    MouseMoveAbsolute {
        /// Abscisse normalisée.
        x: u16,
        /// Ordonnée normalisée.
        y: u16,
    },
    /// Appui ou relâchement d'un bouton de souris.
    MouseButton {
        /// Bouton concerné.
        button: MouseButton,
        /// `true` à l'appui, `false` au relâchement.
        pressed: bool,
    },
    /// Défilement, en multiples d'un cran de molette (120 unités).
    MouseScroll {
        /// Défilement horizontal.
        dx: i16,
        /// Défilement vertical.
        dy: i16,
    },
    /// Appui ou relâchement d'une touche, en scancode PS/2 jeu 1.
    ///
    /// Le client convertit `KeyboardEvent.code` en scancode : l'agent injecte
    /// le scancode tel quel, ce qui reste correct quelle que soit la
    /// disposition clavier configurée sur l'hôte.
    Key {
        /// Scancode PS/2 jeu 1.
        scancode: u16,
        /// `true` à l'appui, `false` au relâchement.
        pressed: bool,
        /// Préfixe `0xE0` : flèches, pavé numérique étendu, touches Windows.
        extended: bool,
    },
}

impl InputEvent {
    fn encoded_len(&self) -> usize {
        1 + match self {
            Self::MouseMoveRelative { .. }
            | Self::MouseMoveAbsolute { .. }
            | Self::MouseScroll { .. } => 4,
            Self::MouseButton { .. } => 2,
            Self::Key { .. } => 3,
        }
    }

    fn encode_into(&self, out: &mut Vec<u8>) {
        match *self {
            Self::MouseMoveRelative { dx, dy } => {
                out.push(KIND_MOUSE_MOVE_REL);
                out.extend_from_slice(&dx.to_le_bytes());
                out.extend_from_slice(&dy.to_le_bytes());
            }
            Self::MouseMoveAbsolute { x, y } => {
                out.push(KIND_MOUSE_MOVE_ABS);
                out.extend_from_slice(&x.to_le_bytes());
                out.extend_from_slice(&y.to_le_bytes());
            }
            Self::MouseButton { button, pressed } => {
                out.push(KIND_MOUSE_BUTTON);
                out.push(button as u8);
                out.push(u8::from(pressed));
            }
            Self::MouseScroll { dx, dy } => {
                out.push(KIND_MOUSE_SCROLL);
                out.extend_from_slice(&dx.to_le_bytes());
                out.extend_from_slice(&dy.to_le_bytes());
            }
            Self::Key {
                scancode,
                pressed,
                extended,
            } => {
                out.push(KIND_KEY);
                out.extend_from_slice(&scancode.to_le_bytes());
                let mut flags = 0u8;
                if pressed {
                    flags |= FLAG_PRESSED;
                }
                if extended {
                    flags |= FLAG_EXTENDED;
                }
                out.push(flags);
            }
        }
    }
}

/// Lot d'événements partageant un numéro de séquence.
///
/// Le client coalesce ses événements sur un tick d'affichage avant d'émettre,
/// ce qui amortit l'en-tête SCTP sur plusieurs mouvements.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct InputFrame {
    /// Numéro de séquence, croissant et cyclique.
    pub seq: u32,
    /// Événements, dans l'ordre d'émission.
    pub events: Vec<InputEvent>,
}

impl InputFrame {
    /// Sérialise la trame dans `out`, qui est vidé au préalable.
    ///
    /// Réutiliser le même tampon d'un appel à l'autre évite toute allocation
    /// dans la boucle d'émission.
    pub fn encode_into(&self, out: &mut Vec<u8>) {
        out.clear();
        out.reserve(
            FRAME_HEADER_LEN
                + self
                    .events
                    .iter()
                    .take(MAX_EVENTS_PER_FRAME)
                    .map(InputEvent::encoded_len)
                    .sum::<usize>(),
        );
        out.push(FRAME_VERSION);
        out.extend_from_slice(&self.seq.to_le_bytes());
        out.push(self.events.len().min(MAX_EVENTS_PER_FRAME) as u8);
        for event in self.events.iter().take(MAX_EVENTS_PER_FRAME) {
            event.encode_into(out);
        }
    }

    /// Sérialise la trame dans un nouveau vecteur.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.encode_into(&mut out);
        out
    }

    /// Décode une trame reçue.
    ///
    /// Rejette toute entrée malformée sans paniquer : le tampon provient du
    /// réseau et n'est jamais supposé bien formé.
    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        if buf.len() < FRAME_HEADER_LEN {
            return Err(ProtoError::Truncated {
                need: FRAME_HEADER_LEN,
                have: buf.len(),
            });
        }
        if buf[0] != FRAME_VERSION {
            return Err(ProtoError::BadVersion(buf[0]));
        }
        let seq = u32::from_le_bytes([buf[1], buf[2], buf[3], buf[4]]);
        let count = buf[5] as usize;
        if count > MAX_EVENTS_PER_FRAME {
            return Err(ProtoError::TooManyEvents(count));
        }

        let mut cursor = FRAME_HEADER_LEN;
        let mut events = Vec::with_capacity(count);
        for _ in 0..count {
            let (event, consumed) = decode_event(&buf[cursor..])?;
            events.push(event);
            cursor += consumed;
        }
        if cursor != buf.len() {
            return Err(ProtoError::TrailingBytes(buf.len() - cursor));
        }
        Ok(Self { seq, events })
    }
}

fn decode_event(buf: &[u8]) -> Result<(InputEvent, usize), ProtoError> {
    let need = |n: usize| -> Result<(), ProtoError> {
        if buf.len() < n {
            Err(ProtoError::Truncated {
                need: n,
                have: buf.len(),
            })
        } else {
            Ok(())
        }
    };
    need(1)?;
    let i16_at = |o: usize| i16::from_le_bytes([buf[o], buf[o + 1]]);
    let u16_at = |o: usize| u16::from_le_bytes([buf[o], buf[o + 1]]);

    let event = match buf[0] {
        KIND_MOUSE_MOVE_REL => {
            need(5)?;
            (
                InputEvent::MouseMoveRelative {
                    dx: i16_at(1),
                    dy: i16_at(3),
                },
                5,
            )
        }
        KIND_MOUSE_MOVE_ABS => {
            need(5)?;
            (
                InputEvent::MouseMoveAbsolute {
                    x: u16_at(1),
                    y: u16_at(3),
                },
                5,
            )
        }
        KIND_MOUSE_BUTTON => {
            need(3)?;
            let button =
                MouseButton::from_u8(buf[1]).ok_or(ProtoError::UnknownEvent(KIND_MOUSE_BUTTON))?;
            (
                InputEvent::MouseButton {
                    button,
                    pressed: buf[2] != 0,
                },
                3,
            )
        }
        KIND_MOUSE_SCROLL => {
            need(5)?;
            (
                InputEvent::MouseScroll {
                    dx: i16_at(1),
                    dy: i16_at(3),
                },
                5,
            )
        }
        KIND_KEY => {
            need(4)?;
            (
                InputEvent::Key {
                    scancode: u16_at(1),
                    pressed: buf[3] & FLAG_PRESSED != 0,
                    extended: buf[3] & FLAG_EXTENDED != 0,
                },
                4,
            )
        }
        other => return Err(ProtoError::UnknownEvent(other)),
    };
    Ok(event)
}

/// Fenêtre d'acceptation des numéros de séquence.
///
/// Sur un canal non ordonné, une trame peut doubler la précédente. Le tracker
/// n'accepte que ce qui est strictement plus récent, en comparaison cyclique :
/// `seq` est plus récent que `last` si `seq.wrapping_sub(last)` tombe dans la
/// moitié basse de l'espace, ce qui reste correct au rebouclage de `u32`.
#[derive(Debug, Clone, Copy, Default)]
pub struct SeqTracker {
    last: Option<u32>,
}

impl SeqTracker {
    /// Nouveau tracker, sans trame vue.
    pub fn new() -> Self {
        Self::default()
    }

    /// Indique si la trame doit être appliquée, et mémorise le cas échéant.
    pub fn accept(&mut self, seq: u32) -> bool {
        match self.last {
            None => {
                self.last = Some(seq);
                true
            }
            Some(last) => {
                let delta = seq.wrapping_sub(last);
                if delta != 0 && delta < u32::MAX / 2 {
                    self.last = Some(seq);
                    true
                } else {
                    false
                }
            }
        }
    }

    /// Dernier numéro accepté.
    pub fn last(&self) -> Option<u32> {
        self.last
    }

    /// Réinitialise la fenêtre, à la reconnexion d'un client.
    pub fn reset(&mut self) {
        self.last = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_frame() -> InputFrame {
        InputFrame {
            seq: 0xDEAD_BEEF,
            events: vec![
                InputEvent::MouseMoveRelative { dx: -3, dy: 12 },
                InputEvent::MouseMoveAbsolute { x: 0, y: u16::MAX },
                InputEvent::MouseButton {
                    button: MouseButton::X2,
                    pressed: true,
                },
                InputEvent::MouseScroll { dx: 0, dy: -120 },
                InputEvent::Key {
                    scancode: 0x4B,
                    pressed: false,
                    extended: true,
                },
            ],
        }
    }

    #[test]
    fn roundtrip_preserves_every_event() {
        let frame = sample_frame();
        assert_eq!(InputFrame::decode(&frame.encode()).unwrap(), frame);
    }

    #[test]
    fn frame_stays_compact() {
        // 6 octets d'en-tête + 5 + 5 + 3 + 5 + 4
        assert_eq!(sample_frame().encode().len(), 28);
    }

    #[test]
    fn encode_into_reuses_buffer_without_growing_it() {
        let frame = sample_frame();
        let mut buf = Vec::new();
        frame.encode_into(&mut buf);
        let capacity = buf.capacity();
        for _ in 0..100 {
            frame.encode_into(&mut buf);
        }
        assert_eq!(buf.capacity(), capacity);
        assert_eq!(InputFrame::decode(&buf).unwrap(), frame);
    }

    #[test]
    fn rejects_wrong_version() {
        let mut buf = sample_frame().encode();
        buf[0] = 0xFF;
        assert_eq!(InputFrame::decode(&buf), Err(ProtoError::BadVersion(0xFF)));
    }

    #[test]
    fn rejects_unknown_event_kind() {
        let buf = [FRAME_VERSION, 0, 0, 0, 0, 1, 0x7F, 0, 0, 0, 0];
        assert_eq!(InputFrame::decode(&buf), Err(ProtoError::UnknownEvent(0x7F)));
    }

    #[test]
    fn rejects_unknown_mouse_button() {
        let buf = [FRAME_VERSION, 0, 0, 0, 0, 1, KIND_MOUSE_BUTTON, 99, 1];
        assert!(matches!(
            InputFrame::decode(&buf),
            Err(ProtoError::UnknownEvent(_))
        ));
    }

    #[test]
    fn rejects_truncated_payload() {
        let buf = [FRAME_VERSION, 0, 0, 0, 0, 1, KIND_MOUSE_MOVE_REL, 1, 2];
        assert!(matches!(
            InputFrame::decode(&buf),
            Err(ProtoError::Truncated { .. })
        ));
    }

    #[test]
    fn rejects_declared_count_above_hard_limit() {
        let buf = [FRAME_VERSION, 0, 0, 0, 0, 200];
        assert_eq!(InputFrame::decode(&buf), Err(ProtoError::TooManyEvents(200)));
    }

    #[test]
    fn rejects_trailing_bytes() {
        let mut buf = sample_frame().encode();
        buf.push(0x00);
        assert_eq!(InputFrame::decode(&buf), Err(ProtoError::TrailingBytes(1)));
    }

    #[test]
    fn rejects_empty_and_short_buffers() {
        assert!(matches!(
            InputFrame::decode(&[]),
            Err(ProtoError::Truncated { .. })
        ));
        assert!(matches!(
            InputFrame::decode(&[FRAME_VERSION, 0, 0]),
            Err(ProtoError::Truncated { .. })
        ));
    }

    #[test]
    fn empty_frame_is_valid() {
        let frame = InputFrame {
            seq: 7,
            events: vec![],
        };
        assert_eq!(InputFrame::decode(&frame.encode()).unwrap(), frame);
    }

    #[test]
    fn encoding_caps_events_at_hard_limit() {
        let frame = InputFrame {
            seq: 1,
            events: vec![InputEvent::MouseMoveRelative { dx: 1, dy: 1 }; MAX_EVENTS_PER_FRAME + 10],
        };
        let decoded = InputFrame::decode(&frame.encode()).unwrap();
        assert_eq!(decoded.events.len(), MAX_EVENTS_PER_FRAME);
    }

    #[test]
    fn tracker_drops_stale_and_duplicate_frames() {
        let mut tracker = SeqTracker::new();
        assert!(tracker.accept(10));
        assert!(tracker.accept(11));
        assert!(!tracker.accept(11), "doublon");
        assert!(!tracker.accept(9), "périmée");
        assert!(tracker.accept(12));
    }

    #[test]
    fn tracker_survives_u32_wraparound() {
        let mut tracker = SeqTracker::new();
        assert!(tracker.accept(u32::MAX - 1));
        assert!(tracker.accept(u32::MAX));
        assert!(tracker.accept(0), "rebouclage accepté");
        assert!(tracker.accept(1));
        assert!(!tracker.accept(u32::MAX), "pré-rebouclage rejeté");
    }

    #[test]
    fn tracker_resets_for_a_new_session() {
        let mut tracker = SeqTracker::new();
        assert!(tracker.accept(500));
        assert!(!tracker.accept(1));
        tracker.reset();
        assert!(tracker.accept(1));
    }
}
