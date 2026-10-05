//! Injection d'entrées Windows via `SendInput`.
//!
//! Les touches sont injectées en **scancode** et non en code virtuel : le
//! système applique alors lui-même la disposition clavier de l'hôte, et les
//! applications qui lisent le clavier au plus bas niveau — les jeux, surtout —
//! voient exactement ce qu'elles verraient d'un clavier physique.
//!
//! # Invariants des blocs `unsafe`
//!
//! 1. `SendInput` reçoit une tranche vivante de `INPUT` entièrement initialisés,
//!    accompagnée de la taille exacte d'un élément.
//! 2. Le tampon d'injection appartient au puits et est réutilisé d'un lot à
//!    l'autre : aucune allocation dans le chemin chaud.
//! 3. Aucun pointeur n'est conservé après l'appel : `SendInput` copie tout.

use windows::Win32::UI::Input::KeyboardAndMouse::{
    GetKeyboardLayout, MapVirtualKeyExW, SendInput, VkKeyScanExW, INPUT, INPUT_0, INPUT_KEYBOARD,
    INPUT_MOUSE, KEYBDINPUT, KEYBD_EVENT_FLAGS, KEYEVENTF_EXTENDEDKEY, KEYEVENTF_KEYUP,
    KEYEVENTF_SCANCODE, KEYEVENTF_UNICODE, MAPVK_VK_TO_VSC, MOUSEEVENTF_ABSOLUTE,
    MOUSEEVENTF_HWHEEL, MOUSEEVENTF_LEFTDOWN, MOUSEEVENTF_LEFTUP, MOUSEEVENTF_MIDDLEDOWN,
    MOUSEEVENTF_MIDDLEUP, MOUSEEVENTF_MOVE, MOUSEEVENTF_RIGHTDOWN, MOUSEEVENTF_RIGHTUP,
    MOUSEEVENTF_VIRTUALDESK, MOUSEEVENTF_WHEEL, MOUSEEVENTF_XDOWN, MOUSEEVENTF_XUP, MOUSEINPUT,
    MOUSE_EVENT_FLAGS, VIRTUAL_KEY,
};

use windows::Win32::UI::WindowsAndMessaging::{GetForegroundWindow, GetWindowThreadProcessId};

/// Code du premier bouton latéral dans `MOUSEINPUT::mouseData`.
///
/// `windows-rs` n'expose pas ces deux constantes de `winuser.h`.
const XBUTTON1: i32 = 0x0001;
/// Code du second bouton latéral.
const XBUTTON2: i32 = 0x0002;

use sidgate_proto::input::{InputEvent, InputFrame, MouseButton, MAX_EVENTS_PER_FRAME};

use crate::{AbsoluteMapping, InputError, InputSink, PressedState};

/// Puits d'entrées s'appuyant sur `SendInput`.
pub struct SendInputSink {
    buffer: Vec<INPUT>,
    pressed: PressedState,
    /// Projection des positions absolues vers la sortie capturée.
    mapping: Option<AbsoluteMapping>,
    /// Touches enfoncées par caractère, avec le scancode retenu à l'appui.
    ///
    /// Le relâchement réutilise ce scancode au lieu de refaire la recherche :
    /// si la disposition a changé entre-temps — la fenêtre active n'est plus
    /// la même — c'est la touche réellement enfoncée qu'il faut relâcher.
    char_keys: Vec<(u16, u16)>,
}

impl std::fmt::Debug for SendInputSink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // `INPUT` est une union sans `Debug` : on n'expose que ce qui a du sens.
        f.debug_struct("SendInputSink")
            .field("buffered", &self.buffer.len())
            .field("pressed", &self.pressed)
            .finish()
    }
}

impl Default for SendInputSink {
    fn default() -> Self {
        Self::new()
    }
}

impl SendInputSink {
    /// Nouveau puits, tampon préalloué à la taille maximale d'une trame.
    pub fn new() -> Self {
        Self {
            // Une trame peut porter jusqu'à `MAX_EVENTS_PER_FRAME` événements,
            // dont certains se traduisent par deux `INPUT` : défilement sur les
            // deux axes, ou caractère tapé puis relâché.
            buffer: Vec::with_capacity(MAX_EVENTS_PER_FRAME * 2),
            pressed: PressedState::new(),
            mapping: None,
            char_keys: Vec::new(),
        }
    }

    /// Fixe la sortie vidéo que désignent les positions absolues.
    ///
    /// Sans projection, une position absolue porte sur le bureau virtuel
    /// entier — correct tant que l'hôte n'a qu'un écran.
    pub fn set_mapping(&mut self, mapping: Option<AbsoluteMapping>) {
        self.mapping = mapping;
    }

    /// Ce que le client distant maintient enfoncé.
    pub fn pressed(&self) -> &PressedState {
        &self.pressed
    }

    /// Envoie le contenu du tampon puis le vide.
    fn flush(&mut self) -> Result<(), InputError> {
        if self.buffer.is_empty() {
            return Ok(());
        }
        let expected = self.buffer.len() as u32;
        // SAFETY: `buffer` est une tranche vivante d'`INPUT` initialisés et
        // `size_of::<INPUT>()` en décrit exactement la foulée.
        let sent = unsafe { SendInput(&self.buffer, std::mem::size_of::<INPUT>() as i32) };
        self.buffer.clear();

        if sent != expected {
            // Cause la plus fréquente : le bureau sécurisé a le focus. Ce n'est
            // pas une anomalie de notre côté, et cela se résout tout seul.
            return Err(InputError::Refused(format!(
                "{sent}/{expected} événements acceptés"
            )));
        }
        Ok(())
    }

    fn push_mouse(&mut self, flags: MOUSE_EVENT_FLAGS, dx: i32, dy: i32, data: i32) {
        self.buffer.push(INPUT {
            r#type: INPUT_MOUSE,
            Anonymous: INPUT_0 {
                mi: MOUSEINPUT {
                    dx,
                    dy,
                    mouseData: data as u32,
                    dwFlags: flags,
                    time: 0,
                    dwExtraInfo: 0,
                },
            },
        });
    }

    fn push_key(&mut self, scancode: u16, pressed: bool, extended: bool) {
        let mut flags = KEYEVENTF_SCANCODE;
        if !pressed {
            flags |= KEYEVENTF_KEYUP;
        }
        if extended {
            flags |= KEYEVENTF_EXTENDEDKEY;
        }
        self.push_keyboard(scancode, flags);
    }

    /// Tape une unité de code UTF-16 : un appui, puis son relâchement.
    ///
    /// `KEYEVENTF_UNICODE` court-circuite la disposition clavier : le système
    /// livre le caractère tel quel à l'application qui a le focus. Les deux
    /// moitiés d'une paire de substitution arrivent l'une après l'autre et
    /// sont recollées par le système.
    fn push_text(&mut self, unit: u16) {
        self.push_keyboard(unit, KEYEVENTF_UNICODE);
        self.push_keyboard(unit, KEYEVENTF_UNICODE | KEYEVENTF_KEYUP);
    }

    /// Appuie ou relâche la touche qui produit `unit` sur la disposition de la
    /// fenêtre active.
    ///
    /// Un caractère qu'aucune touche ne produit sur cette disposition est
    /// ignoré : mieux vaut un raccourci sans effet qu'une touche prise au
    /// hasard.
    fn push_key_char(&mut self, unit: u16, pressed: bool) {
        let scancode = if pressed {
            let Some(scancode) = scancode_for_char(unit) else {
                tracing::debug!(unit, "aucune touche ne produit ce caractère sur l'hôte");
                return;
            };
            self.char_keys.retain(|(held, _)| *held != unit);
            self.char_keys.push((unit, scancode));
            scancode
        } else {
            let Some(index) = self.char_keys.iter().position(|(held, _)| *held == unit) else {
                return;
            };
            self.char_keys.swap_remove(index).1
        };
        // Suivie comme une touche ordinaire : `release_all` saura la relâcher.
        self.pressed.observe(&InputEvent::Key {
            scancode,
            pressed,
            extended: false,
        });
        self.push_key(scancode, pressed, false);
    }

    fn push_keyboard(&mut self, scan: u16, flags: KEYBD_EVENT_FLAGS) {
        self.buffer.push(INPUT {
            r#type: INPUT_KEYBOARD,
            Anonymous: INPUT_0 {
                ki: KEYBDINPUT {
                    wVk: VIRTUAL_KEY(0),
                    wScan: scan,
                    dwFlags: flags,
                    time: 0,
                    dwExtraInfo: 0,
                },
            },
        });
    }

    fn push_event(&mut self, event: &InputEvent) {
        match *event {
            InputEvent::MouseMoveRelative { dx, dy } => {
                self.push_mouse(MOUSEEVENTF_MOVE, i32::from(dx), i32::from(dy), 0);
            }
            InputEvent::MouseMoveAbsolute { x, y } => {
                // `MOUSEEVENTF_VIRTUALDESK` étend les coordonnées normalisées à
                // l'ensemble des écrans, et non au seul écran principal ; la
                // projection y replace la sortie que le client regarde.
                let (x, y) = match &self.mapping {
                    Some(mapping) => mapping.map(x, y),
                    None => (i32::from(x), i32::from(y)),
                };
                self.push_mouse(
                    MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_VIRTUALDESK,
                    x,
                    y,
                    0,
                );
            }
            InputEvent::MouseButton { button, pressed } => {
                let (flags, data) = match (button, pressed) {
                    (MouseButton::Left, true) => (MOUSEEVENTF_LEFTDOWN, 0),
                    (MouseButton::Left, false) => (MOUSEEVENTF_LEFTUP, 0),
                    (MouseButton::Right, true) => (MOUSEEVENTF_RIGHTDOWN, 0),
                    (MouseButton::Right, false) => (MOUSEEVENTF_RIGHTUP, 0),
                    (MouseButton::Middle, true) => (MOUSEEVENTF_MIDDLEDOWN, 0),
                    (MouseButton::Middle, false) => (MOUSEEVENTF_MIDDLEUP, 0),
                    (MouseButton::X1, true) => (MOUSEEVENTF_XDOWN, XBUTTON1),
                    (MouseButton::X1, false) => (MOUSEEVENTF_XUP, XBUTTON1),
                    (MouseButton::X2, true) => (MOUSEEVENTF_XDOWN, XBUTTON2),
                    (MouseButton::X2, false) => (MOUSEEVENTF_XUP, XBUTTON2),
                };
                self.push_mouse(flags, 0, 0, data);
            }
            InputEvent::MouseScroll { dx, dy } => {
                if dy != 0 {
                    self.push_mouse(MOUSEEVENTF_WHEEL, 0, 0, i32::from(dy));
                }
                if dx != 0 {
                    self.push_mouse(MOUSEEVENTF_HWHEEL, 0, 0, i32::from(dx));
                }
            }
            InputEvent::Key {
                scancode,
                pressed,
                extended,
            } => self.push_key(scancode, pressed, extended),
            InputEvent::Text { unit } => self.push_text(unit),
            InputEvent::KeyChar { unit, pressed } => self.push_key_char(unit, pressed),
        }
    }
}

/// Scancode de la touche qui produit `unit` sur la disposition clavier de la
/// fenêtre active.
fn scancode_for_char(unit: u16) -> Option<u16> {
    // SAFETY: appels de lecture sans pointeur conservé. Une fenêtre nulle —
    // aucune fenêtre active — donne le fil 0, c'est-à-dire la disposition du
    // fil courant, repli raisonnable.
    let layout = unsafe {
        let thread = GetWindowThreadProcessId(GetForegroundWindow(), None);
        GetKeyboardLayout(thread)
    };
    // SAFETY: `layout` vient d'être obtenu du système.
    let scan = unsafe { VkKeyScanExW(unit, layout) };
    if scan == -1 {
        return None;
    }
    // L'octet bas est le code virtuel ; l'octet haut dit quelles modificatrices
    // la disposition exige, ce qui regarde l'appelant.
    let virtual_key = u32::from(scan as u16 & 0x00FF);
    // SAFETY: simple table de correspondance du système.
    let scancode = unsafe { MapVirtualKeyExW(virtual_key, MAPVK_VK_TO_VSC, Some(layout)) };
    (scancode != 0).then_some(scancode as u16)
}

impl InputSink for SendInputSink {
    fn apply(&mut self, frame: &InputFrame) -> Result<(), InputError> {
        self.buffer.clear();
        for event in &frame.events {
            self.pressed.observe(event);
            self.push_event(event);
        }
        self.flush()
    }

    fn release_all(&mut self) -> Result<(), InputError> {
        if self.pressed.is_empty() {
            return Ok(());
        }
        self.buffer.clear();

        let keys: Vec<(u16, bool)> = self.pressed.keys().to_vec();
        for (scancode, extended) in keys {
            self.push_key(scancode, false, extended);
        }
        let buttons: Vec<u8> = self.pressed.buttons().to_vec();
        for code in buttons {
            let flags = match code {
                0 => MOUSEEVENTF_LEFTUP,
                1 => MOUSEEVENTF_RIGHTUP,
                2 => MOUSEEVENTF_MIDDLEUP,
                _ => MOUSEEVENTF_XUP,
            };
            let data = match code {
                3 => XBUTTON1,
                4 => XBUTTON2,
                _ => 0,
            };
            self.push_mouse(flags, 0, 0, data);
        }

        let count = self.buffer.len();
        self.pressed.clear();
        self.char_keys.clear();
        let result = self.flush();
        tracing::info!(count, "entrées maintenues relâchées");
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Construit le tampon sans l'envoyer, pour vérifier la traduction.
    fn encode(events: &[InputEvent]) -> Vec<INPUT> {
        let mut sink = SendInputSink::new();
        for event in events {
            sink.pressed.observe(event);
            sink.push_event(event);
        }
        std::mem::take(&mut sink.buffer)
    }

    #[test]
    fn scroll_on_both_axes_produces_two_inputs() {
        let buffer = encode(&[InputEvent::MouseScroll { dx: 120, dy: -120 }]);
        assert_eq!(buffer.len(), 2);
    }

    #[test]
    fn scroll_with_no_movement_produces_nothing() {
        assert!(encode(&[InputEvent::MouseScroll { dx: 0, dy: 0 }]).is_empty());
    }

    #[test]
    fn keys_are_injected_as_scancodes_not_virtual_keys() {
        let buffer = encode(&[InputEvent::Key {
            scancode: 0x1E,
            pressed: true,
            extended: false,
        }]);
        assert_eq!(buffer.len(), 1);
        // SAFETY: l'union est un clavier, comme l'indique `r#type`.
        let ki = unsafe { buffer[0].Anonymous.ki };
        assert_eq!(buffer[0].r#type, INPUT_KEYBOARD);
        assert_eq!(ki.wScan, 0x1E);
        assert_eq!(
            ki.wVk,
            VIRTUAL_KEY(0),
            "aucun code virtuel ne doit être posé"
        );
        assert!(ki.dwFlags.contains(KEYEVENTF_SCANCODE));
        assert!(!ki.dwFlags.contains(KEYEVENTF_KEYUP));
    }

    #[test]
    fn extended_keys_carry_their_flag() {
        let buffer = encode(&[InputEvent::Key {
            scancode: 0x4B,
            pressed: false,
            extended: true,
        }]);
        // SAFETY: l'union est un clavier.
        let ki = unsafe { buffer[0].Anonymous.ki };
        assert!(ki.dwFlags.contains(KEYEVENTF_EXTENDEDKEY));
        assert!(ki.dwFlags.contains(KEYEVENTF_KEYUP));
    }

    #[test]
    fn absolute_moves_span_the_whole_virtual_desktop() {
        let buffer = encode(&[InputEvent::MouseMoveAbsolute { x: 32768, y: 100 }]);
        // SAFETY: l'union est une souris.
        let mi = unsafe { buffer[0].Anonymous.mi };
        assert!(mi.dwFlags.contains(MOUSEEVENTF_ABSOLUTE));
        assert!(mi.dwFlags.contains(MOUSEEVENTF_VIRTUALDESK));
        assert_eq!(mi.dx, 32768);
    }

    #[test]
    fn absolute_moves_are_projected_onto_the_captured_output() {
        use crate::ScreenRect;
        let primary = ScreenRect {
            left: 0,
            top: 0,
            width: 1920,
            height: 1080,
        };
        let secondary = ScreenRect {
            left: 1920,
            ..primary
        };
        let mut sink = SendInputSink::new();
        sink.set_mapping(Some(AbsoluteMapping::new(secondary, &[primary, secondary])));
        sink.push_event(&InputEvent::MouseMoveAbsolute { x: 0, y: 0 });
        // SAFETY: l'union est une souris.
        let mi = unsafe { sink.buffer[0].Anonymous.mi };
        assert!(
            mi.dx > 32_000,
            "le bord gauche du second écran est au milieu du bureau, pas à 0"
        );
    }

    #[test]
    fn text_is_typed_as_unicode_press_and_release() {
        let buffer = encode(&[InputEvent::Text { unit: 0x00E9 }]);
        assert_eq!(buffer.len(), 2);
        // SAFETY: les deux entrées sont des claviers.
        let (down, up) = unsafe { (buffer[0].Anonymous.ki, buffer[1].Anonymous.ki) };
        assert_eq!((down.wScan, up.wScan), (0x00E9, 0x00E9));
        assert_eq!(down.wVk, VIRTUAL_KEY(0));
        assert!(down.dwFlags.contains(KEYEVENTF_UNICODE));
        assert!(!down.dwFlags.contains(KEYEVENTF_KEYUP));
        assert!(
            !down.dwFlags.contains(KEYEVENTF_SCANCODE),
            "ce n'est pas un scancode"
        );
        assert!(up.dwFlags.contains(KEYEVENTF_UNICODE | KEYEVENTF_KEYUP));
    }

    #[test]
    fn a_letter_is_resolved_to_a_key_of_the_host_layout() {
        // Toute disposition latine possède une touche A ; son emplacement
        // dépend de la machine de test, d'où une vérification de forme.
        let Some(scancode) = scancode_for_char(u16::from(b'a')) else {
            return;
        };
        assert!(
            (1..0x80).contains(&scancode),
            "scancode invraisemblable: {scancode:#x}"
        );

        let mut sink = SendInputSink::new();
        sink.push_event(&InputEvent::KeyChar {
            unit: u16::from(b'a'),
            pressed: true,
        });
        assert_eq!(sink.buffer.len(), 1);
        // SAFETY: l'union est un clavier.
        let ki = unsafe { sink.buffer[0].Anonymous.ki };
        assert_eq!(ki.wScan, scancode);
        assert!(ki.dwFlags.contains(KEYEVENTF_SCANCODE));
        assert_eq!(
            sink.pressed.keys(),
            &[(scancode, false)],
            "la touche est suivie"
        );

        sink.push_event(&InputEvent::KeyChar {
            unit: u16::from(b'a'),
            pressed: false,
        });
        // SAFETY: l'union est un clavier.
        let ki = unsafe { sink.buffer[1].Anonymous.ki };
        assert_eq!(ki.wScan, scancode);
        assert!(ki.dwFlags.contains(KEYEVENTF_KEYUP));
        assert!(sink.pressed.is_empty());
        assert!(sink.char_keys.is_empty());
    }

    #[test]
    fn releasing_a_character_never_pressed_sends_nothing() {
        let mut sink = SendInputSink::new();
        sink.push_event(&InputEvent::KeyChar {
            unit: u16::from(b'a'),
            pressed: false,
        });
        assert!(sink.buffer.is_empty());
    }

    #[test]
    fn a_character_without_a_key_is_ignored() {
        // Un idéogramme n'est produit par aucune touche d'une disposition
        // latine ; sur une machine où il le serait, le test ne dit rien.
        if scancode_for_char(0x4E2D).is_some() {
            return;
        }
        let mut sink = SendInputSink::new();
        sink.push_event(&InputEvent::KeyChar {
            unit: 0x4E2D,
            pressed: true,
        });
        assert!(sink.buffer.is_empty());
        assert!(sink.pressed.is_empty());
    }

    #[test]
    fn side_buttons_select_the_right_button_code() {
        let buffer = encode(&[InputEvent::MouseButton {
            button: MouseButton::X2,
            pressed: true,
        }]);
        // SAFETY: l'union est une souris.
        let mi = unsafe { buffer[0].Anonymous.mi };
        assert!(mi.dwFlags.contains(MOUSEEVENTF_XDOWN));
        assert_eq!(mi.mouseData, XBUTTON2 as u32);
    }

    #[test]
    fn release_all_emits_one_event_per_held_input() {
        let mut sink = SendInputSink::new();
        for event in [
            InputEvent::Key {
                scancode: 0x1D,
                pressed: true,
                extended: false,
            },
            InputEvent::Key {
                scancode: 0x2A,
                pressed: true,
                extended: false,
            },
            InputEvent::MouseButton {
                button: MouseButton::Left,
                pressed: true,
            },
        ] {
            sink.pressed.observe(&event);
        }

        // Rejoue la construction de `release_all` sans toucher au système.
        let keys: Vec<(u16, bool)> = sink.pressed.keys().to_vec();
        for (scancode, extended) in keys {
            sink.push_key(scancode, false, extended);
        }
        assert_eq!(sink.buffer.len(), 2);
        // SAFETY: les deux entrées sont des claviers.
        assert!(unsafe { sink.buffer[0].Anonymous.ki }
            .dwFlags
            .contains(KEYEVENTF_KEYUP));
        assert_eq!(sink.pressed.buttons(), &[0]);
    }

    #[test]
    fn buffer_capacity_covers_a_full_frame_without_reallocating() {
        let mut sink = SendInputSink::new();
        let capacity = sink.buffer.capacity();
        for _ in 0..MAX_EVENTS_PER_FRAME {
            sink.push_event(&InputEvent::MouseScroll { dx: 1, dy: 1 });
        }
        assert_eq!(sink.buffer.len(), MAX_EVENTS_PER_FRAME * 2);
        assert_eq!(sink.buffer.capacity(), capacity, "aucune réallocation");

        sink.buffer.clear();
        for _ in 0..MAX_EVENTS_PER_FRAME {
            sink.push_event(&InputEvent::Text { unit: 0x41 });
        }
        assert_eq!(sink.buffer.len(), MAX_EVENTS_PER_FRAME * 2);
        assert_eq!(sink.buffer.capacity(), capacity, "aucune réallocation");
    }
}
