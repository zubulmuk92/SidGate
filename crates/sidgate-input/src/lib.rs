//! Injection d'entrées et actions système de l'hôte.
//!
//! Deux surfaces bien distinctes :
//!
//! - [`InputSink`] applique les événements de souris et de clavier venus du
//!   canal temps réel. Aucun de ces événements ne porte de chaîne de caractères,
//!   et tous sont bornés par le codec de `sidgate-proto`.
//! - [`system`] regroupe le verrouillage de session et les actions
//!   d'alimentation. Aucune de ces fonctions ne construit de ligne de commande :
//!   ce sont des appels système directs, sans interpréteur intermédiaire.

#![cfg_attr(not(windows), allow(dead_code))]

use sidgate_proto::input::{InputEvent, InputFrame};

#[cfg(windows)]
pub mod send_input;
#[cfg(windows)]
pub mod system;

#[cfg(windows)]
pub use send_input::SendInputSink as Sink;

/// Erreurs d'injection.
#[derive(Debug, thiserror::Error)]
pub enum InputError {
    /// Le système a refusé l'injection.
    ///
    /// Survient notamment lorsque le bureau actif est le bureau sécurisé
    /// (UAC, écran de verrouillage) : un processus utilisateur ne peut pas y
    /// injecter d'entrées, par conception.
    #[error("injection refusée: {0}")]
    Refused(String),
    /// Le privilège requis n'a pas pu être obtenu.
    #[error("privilège {0} indisponible")]
    MissingPrivilege(&'static str),
    /// Erreur remontée par l'API système.
    #[error("erreur système: {0}")]
    System(String),
}

/// Destination des événements d'entrée.
pub trait InputSink {
    /// Applique un lot d'événements.
    ///
    /// Le lot est injecté d'un bloc lorsque la plateforme le permet, afin que
    /// le système ne puisse pas intercaler les entrées physiques de l'utilisateur
    /// au milieu d'une séquence distante.
    fn apply(&mut self, frame: &InputFrame) -> Result<(), InputError>;

    /// Relâche toute touche ou tout bouton encore enfoncé.
    ///
    /// Indispensable à la fermeture d'une session : une touche modificatrice
    /// restée enfoncée après une coupure réseau rendrait la machine
    /// inutilisable pour son utilisateur physique.
    fn release_all(&mut self) -> Result<(), InputError>;
}

/// Suivi des touches et boutons enfoncés par le client distant.
///
/// Ne mémorise que ce que *nous* avons enfoncé : relâcher une touche que
/// l'utilisateur physique tient enfoncée serait tout aussi gênant.
#[derive(Debug, Default, Clone)]
pub struct PressedState {
    keys: Vec<(u16, bool)>,
    buttons: Vec<u8>,
}

impl PressedState {
    /// Nouvel état, rien d'enfoncé.
    pub fn new() -> Self {
        Self::default()
    }

    /// Met à jour l'état à partir d'un événement.
    pub fn observe(&mut self, event: &InputEvent) {
        match *event {
            InputEvent::Key {
                scancode,
                pressed,
                extended,
            } => {
                let entry = (scancode, extended);
                if pressed {
                    if !self.keys.contains(&entry) {
                        self.keys.push(entry);
                    }
                } else {
                    self.keys.retain(|k| *k != entry);
                }
            }
            InputEvent::MouseButton { button, pressed } => {
                let code = button as u8;
                if pressed {
                    if !self.buttons.contains(&code) {
                        self.buttons.push(code);
                    }
                } else {
                    self.buttons.retain(|b| *b != code);
                }
            }
            _ => {}
        }
    }

    /// Touches encore enfoncées, sous forme de scancode et d'indicateur étendu.
    pub fn keys(&self) -> &[(u16, bool)] {
        &self.keys
    }

    /// Boutons de souris encore enfoncés.
    pub fn buttons(&self) -> &[u8] {
        &self.buttons
    }

    /// Y a-t-il quelque chose à relâcher ?
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty() && self.buttons.is_empty()
    }

    /// Vide l'état.
    pub fn clear(&mut self) {
        self.keys.clear();
        self.buttons.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sidgate_proto::input::MouseButton;

    fn key(scancode: u16, pressed: bool) -> InputEvent {
        InputEvent::Key {
            scancode,
            pressed,
            extended: false,
        }
    }

    #[test]
    fn tracks_keys_until_released() {
        let mut state = PressedState::new();
        state.observe(&key(0x1D, true));
        state.observe(&key(0x2A, true));
        assert_eq!(state.keys().len(), 2);
        state.observe(&key(0x1D, false));
        assert_eq!(state.keys(), &[(0x2A, false)]);
    }

    #[test]
    fn ignores_repeated_press_of_the_same_key() {
        let mut state = PressedState::new();
        for _ in 0..10 {
            state.observe(&key(0x1D, true));
        }
        assert_eq!(state.keys().len(), 1);
        state.observe(&key(0x1D, false));
        assert!(state.is_empty());
    }

    #[test]
    fn distinguishes_extended_keys_from_their_base_scancode() {
        let mut state = PressedState::new();
        state.observe(&InputEvent::Key {
            scancode: 0x1D,
            pressed: true,
            extended: false,
        });
        state.observe(&InputEvent::Key {
            scancode: 0x1D,
            pressed: true,
            extended: true,
        });
        assert_eq!(state.keys().len(), 2, "Ctrl gauche et Ctrl droit");
    }

    #[test]
    fn tracks_mouse_buttons() {
        let mut state = PressedState::new();
        state.observe(&InputEvent::MouseButton {
            button: MouseButton::Left,
            pressed: true,
        });
        state.observe(&InputEvent::MouseButton {
            button: MouseButton::X1,
            pressed: true,
        });
        assert_eq!(state.buttons().len(), 2);
        state.observe(&InputEvent::MouseButton {
            button: MouseButton::Left,
            pressed: false,
        });
        assert_eq!(state.buttons(), &[MouseButton::X1 as u8]);
    }

    #[test]
    fn movement_does_not_affect_pressed_state() {
        let mut state = PressedState::new();
        state.observe(&InputEvent::MouseMoveRelative { dx: 5, dy: -5 });
        state.observe(&InputEvent::MouseScroll { dx: 0, dy: 120 });
        assert!(state.is_empty());
    }

    #[test]
    fn releasing_a_key_never_pressed_is_harmless() {
        let mut state = PressedState::new();
        state.observe(&key(0x1D, false));
        assert!(state.is_empty());
    }
}
