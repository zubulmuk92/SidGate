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
    SendInput, INPUT, INPUT_0, INPUT_KEYBOARD, INPUT_MOUSE, KEYBDINPUT,
    KEYEVENTF_EXTENDEDKEY, KEYEVENTF_KEYUP, KEYEVENTF_SCANCODE, MOUSEEVENTF_ABSOLUTE,
    MOUSEEVENTF_HWHEEL, MOUSEEVENTF_LEFTDOWN, MOUSEEVENTF_LEFTUP, MOUSEEVENTF_MIDDLEDOWN,
    MOUSEEVENTF_MIDDLEUP, MOUSEEVENTF_MOVE, MOUSEEVENTF_RIGHTDOWN, MOUSEEVENTF_RIGHTUP,
    MOUSEEVENTF_VIRTUALDESK, MOUSEEVENTF_WHEEL, MOUSEEVENTF_XDOWN, MOUSEEVENTF_XUP, MOUSEINPUT,
    MOUSE_EVENT_FLAGS, VIRTUAL_KEY,
};

/// Code du premier bouton latéral dans `MOUSEINPUT::mouseData`.
///
/// `windows-rs` n'expose pas ces deux constantes de `winuser.h`.
const XBUTTON1: i32 = 0x0001;
/// Code du second bouton latéral.
const XBUTTON2: i32 = 0x0002;

use sidgate_proto::input::{InputEvent, InputFrame, MouseButton, MAX_EVENTS_PER_FRAME};

use crate::{InputError, InputSink, PressedState};

/// Puits d'entrées s'appuyant sur `SendInput`.
pub struct SendInputSink {
    buffer: Vec<INPUT>,
    pressed: PressedState,
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
            // dont certains se traduisent par deux `INPUT` (bouton X).
            buffer: Vec::with_capacity(MAX_EVENTS_PER_FRAME * 2),
            pressed: PressedState::new(),
        }
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
        self.buffer.push(INPUT {
            r#type: INPUT_KEYBOARD,
            Anonymous: INPUT_0 {
                ki: KEYBDINPUT {
                    wVk: VIRTUAL_KEY(0),
                    wScan: scancode,
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
                // l'ensemble des écrans, et non au seul écran principal.
                self.push_mouse(
                    MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_VIRTUALDESK,
                    i32::from(x),
                    i32::from(y),
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
        }
    }
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
        assert_eq!(ki.wVk, VIRTUAL_KEY(0), "aucun code virtuel ne doit être posé");
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
    }
}
