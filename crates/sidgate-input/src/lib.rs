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
//! - [`clipboard`] lit le texte du presse-papiers, à la demande et sans jamais
//!   y écrire.

#![cfg_attr(not(windows), allow(dead_code))]

use sidgate_proto::input::{InputEvent, InputFrame};

#[cfg(windows)]
pub mod clipboard;
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

/// Un rectangle du bureau virtuel, en pixels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScreenRect {
    /// Abscisse du coin haut-gauche.
    pub left: i32,
    /// Ordonnée du coin haut-gauche.
    pub top: i32,
    /// Largeur.
    pub width: u32,
    /// Hauteur.
    pub height: u32,
}

/// Projection des coordonnées du client sur le bureau virtuel de l'hôte.
///
/// Le client pointe dans l'image qu'il voit : une sortie vidéo. Le système,
/// lui, attend une position normalisée sur le bureau *virtuel*, qui réunit tous
/// les écrans. Sans cette projection, un clic au centre de l'image d'un second
/// écran atterrirait au centre de l'ensemble des écrans — c'est-à-dire, avec
/// deux écrans côte à côte, sur la jointure entre les deux.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AbsoluteMapping {
    target: ScreenRect,
    desktop: ScreenRect,
}

impl AbsoluteMapping {
    /// Projection vers `target`, au sein du bureau formé par `outputs`.
    ///
    /// `target` est toujours compté dans le bureau, même absent de `outputs` :
    /// la liste peut dater d'avant un branchement d'écran.
    pub fn new(target: ScreenRect, outputs: &[ScreenRect]) -> Self {
        let mut left = target.left;
        let mut top = target.top;
        let mut right = target.left.saturating_add_unsigned(target.width);
        let mut bottom = target.top.saturating_add_unsigned(target.height);
        for output in outputs {
            left = left.min(output.left);
            top = top.min(output.top);
            right = right.max(output.left.saturating_add_unsigned(output.width));
            bottom = bottom.max(output.top.saturating_add_unsigned(output.height));
        }
        Self {
            target,
            desktop: ScreenRect {
                left,
                top,
                width: right.abs_diff(left),
                height: bottom.abs_diff(top),
            },
        }
    }

    /// Convertit une position normalisée sur la sortie en position normalisée
    /// sur le bureau virtuel, toutes deux sur `0..=65535`.
    pub fn map(&self, x: u16, y: u16) -> (i32, i32) {
        (
            project(
                x,
                self.target.left,
                self.target.width,
                self.desktop.left,
                self.desktop.width,
            ),
            project(
                y,
                self.target.top,
                self.target.height,
                self.desktop.top,
                self.desktop.height,
            ),
        )
    }
}

/// Projette un axe : du normalisé sur la sortie au normalisé sur le bureau.
///
/// La valeur reçue désigne un pixel de la sortie ; la valeur rendue vise le
/// *centre* du pixel correspondant du bureau. Viser le centre plutôt que le
/// bord est ce qui rend le résultat insensible à la façon dont le système
/// arrondit en retour : la position tombe sur le bon pixel dans les deux
/// conventions d'arrondi que l'on rencontre.
fn project(value: u16, origin: i32, extent: u32, desktop_origin: i32, desktop_extent: u32) -> i32 {
    const SCALE: i64 = 65_536;
    if extent == 0 || desktop_extent == 0 {
        return 0;
    }
    let local = i64::from(value) * i64::from(extent) / SCALE;
    let pixel = i64::from(origin) - i64::from(desktop_origin) + local;
    ((2 * pixel + 1) * (SCALE / 2) / i64::from(desktop_extent)).clamp(0, SCALE - 1) as i32
}

/// Coupe une chaîne à `max_bytes` octets, sans scinder un caractère.
///
/// Renvoie la chaîne et un indicateur de troncature.
pub fn truncate_utf8(mut text: String, max_bytes: usize) -> (String, bool) {
    if text.len() <= max_bytes {
        return (text, false);
    }
    let mut end = max_bytes;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text.truncate(end);
    (text, true)
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

    #[test]
    fn typed_text_leaves_nothing_held() {
        let mut state = PressedState::new();
        state.observe(&InputEvent::Text { unit: 0x00E9 });
        assert!(state.is_empty());
    }

    fn rect(left: i32, top: i32, width: u32, height: u32) -> ScreenRect {
        ScreenRect {
            left,
            top,
            width,
            height,
        }
    }

    /// Pixel du bureau désigné par une position normalisée, tel que le
    /// système le calcule à la réception.
    fn pixel_of((x, y): (i32, i32), desktop: (i64, i64)) -> (i64, i64) {
        (
            i64::from(x) * desktop.0 / 65_536,
            i64::from(y) * desktop.1 / 65_536,
        )
    }

    /// Valeur normalisée qu'un client envoie pour désigner un pixel donné.
    fn normalized(pixel: i64, extent: i64) -> u16 {
        ((2 * pixel + 1) * 32_768 / extent) as u16
    }

    #[test]
    fn a_single_screen_maps_onto_itself() {
        let screen = rect(0, 0, 1920, 1080);
        let mapping = AbsoluteMapping::new(screen, &[screen]);
        let size = (1920, 1080);
        assert_eq!(pixel_of(mapping.map(0, 0), size), (0, 0));
        assert_eq!(
            pixel_of(mapping.map(u16::MAX, u16::MAX), size),
            (1919, 1079)
        );
        assert_eq!(pixel_of(mapping.map(32_768, 32_768), size), (960, 540));
    }

    #[test]
    fn a_second_screen_on_the_right_maps_to_the_right_half() {
        let primary = rect(0, 0, 1920, 1080);
        let secondary = rect(1920, 0, 1920, 1080);
        let mapping = AbsoluteMapping::new(secondary, &[primary, secondary]);
        let size = (3840, 1080);

        // Bord gauche de la sortie : premier pixel du second écran.
        assert_eq!(pixel_of(mapping.map(0, 0), size), (1920, 0));
        // Bord droit : dernier pixel du bureau.
        assert_eq!(pixel_of(mapping.map(u16::MAX, 0), size), (3839, 0));
        // Le centre du second écran, pas la jointure entre les deux.
        assert_eq!(pixel_of(mapping.map(32_768, 32_768), size), (2880, 540));
    }

    #[test]
    fn a_screen_at_negative_coordinates_is_handled() {
        // Écran secondaire à gauche et plus haut que le principal.
        let primary = rect(0, 0, 2560, 1440);
        let left = rect(-1920, -200, 1920, 1080);
        let on_primary = AbsoluteMapping::new(primary, &[primary, left]);
        let on_left = AbsoluteMapping::new(left, &[primary, left]);

        // Bureau virtuel : 4480 x 1640, origine en (-1920, -200).
        let size = (4480, 1640);
        assert_eq!(pixel_of(on_primary.map(0, 0), size), (1920, 200));
        assert_eq!(pixel_of(on_left.map(0, 0), size), (0, 0));
        assert_eq!(
            pixel_of(on_left.map(u16::MAX, u16::MAX), size),
            (1919, 1079)
        );
    }

    #[test]
    fn every_pixel_of_the_target_is_reachable() {
        let primary = rect(0, 0, 1920, 1080);
        let secondary = rect(1920, 0, 1280, 1024);
        let mapping = AbsoluteMapping::new(secondary, &[primary, secondary]);
        for pixel in 0..1280i64 {
            let hit = pixel_of(mapping.map(normalized(pixel, 1280), 0), (3200, 1080));
            assert_eq!(hit.0, 1920 + pixel, "pixel {pixel}");
        }
        for pixel in 0..1024i64 {
            let hit = pixel_of(mapping.map(0, normalized(pixel, 1024)), (3200, 1080));
            assert_eq!(hit.1, pixel, "ligne {pixel}");
        }
    }

    #[test]
    fn a_target_missing_from_the_list_still_counts() {
        let primary = rect(0, 0, 1920, 1080);
        let newly_plugged = rect(1920, 0, 1920, 1080);
        let mapping = AbsoluteMapping::new(newly_plugged, &[primary]);
        assert_eq!(pixel_of(mapping.map(u16::MAX, 0), (3840, 1080)).0, 3839);
        assert_eq!(pixel_of(mapping.map(0, 0), (3840, 1080)).0, 1920);
    }

    #[test]
    fn degenerate_geometry_does_not_divide_by_zero() {
        let empty = rect(0, 0, 0, 0);
        assert_eq!(
            AbsoluteMapping::new(empty, &[]).map(u16::MAX, u16::MAX),
            (0, 0)
        );
        let dot = rect(5, 5, 1, 1);
        let mapped = AbsoluteMapping::new(dot, &[dot]).map(40_000, 40_000);
        assert_eq!(pixel_of(mapped, (1, 1)), (0, 0));
    }

    #[test]
    fn truncation_never_splits_a_character() {
        assert_eq!(truncate_utf8("abc".into(), 3), ("abc".into(), false));
        assert_eq!(truncate_utf8("abcd".into(), 3), ("abc".into(), true));
        // « é » occupe deux octets : couper au milieu le retire en entier.
        assert_eq!(truncate_utf8("aé".into(), 2), ("a".into(), true));
        assert_eq!(truncate_utf8("😀".into(), 3), (String::new(), true));
        assert_eq!(truncate_utf8("😀".into(), 0), (String::new(), true));
        assert_eq!(truncate_utf8(String::new(), 0), (String::new(), false));
    }
}
