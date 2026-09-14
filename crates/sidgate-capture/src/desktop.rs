//! Rattachement au bureau d'entrée courant.
//!
//! Windows ne possède pas un bureau mais plusieurs, au sein d'une même station.
//! Le bureau *interactif* — celui qui reçoit réellement les frappes — change
//! sans prévenir : `Default` en usage normal, `Winlogon` à l'écran de
//! verrouillage et pendant Ctrl+Alt+Suppr, un bureau éphémère à chaque
//! élévation UAC.
//!
//! Un thread reste attaché au bureau où il a été créé. S'il n'est pas déplacé,
//! la duplication échoue dès la première bascule, et c'est exactement ce que
//! l'on observe sous la forme d'un `E_ACCESSDENIED`.
//!
//! # Ce que le privilège change
//!
//! Un processus tournant sous l'utilisateur connecté peut s'attacher à son
//! propre bureau `Default`, jamais à `Winlogon` : son descripteur de sécurité
//! ne l'autorise pas. Seul un processus **SYSTEM** dans la session interactive
//! y parvient. C'est toute la raison d'être du service : sans lui, un écran
//! verrouillé reste incapturable, quoi qu'on fasse.
//!
//! # Invariants des blocs `unsafe`
//!
//! 1. Le descripteur de bureau ouvert est détenu par [`DesktopGuard`] et fermé
//!    par son `Drop`, après que le thread a été rendu à son bureau d'origine.
//! 2. `SetThreadDesktop` échoue si le thread possède des fenêtres ou des
//!    crochets. Le thread de capture n'en crée aucun, ce qui est une condition
//!    d'appel et non une supposition.

use windows::Win32::System::StationsAndDesktops::{
    CloseDesktop, GetThreadDesktop, OpenInputDesktop, SetThreadDesktop, DESKTOP_ACCESS_FLAGS,
    DESKTOP_READOBJECTS, DESKTOP_WRITEOBJECTS, HDESK,
};
use windows::Win32::System::Threading::GetCurrentThreadId;

use crate::CaptureError;

/// Rattache le thread courant au bureau d'entrée, et l'y maintient.
///
/// Le rattachement dure aussi longtemps que la valeur renvoyée. À sa
/// destruction, le thread revient à son bureau d'origine : sans ce retour, le
/// descripteur du bureau précédent resterait référencé et le système ne
/// pourrait pas le libérer.
#[derive(Debug)]
pub struct DesktopGuard {
    previous: HDESK,
    current: HDESK,
}

impl DesktopGuard {
    /// Attache le thread courant au bureau qui reçoit les entrées.
    ///
    /// Renvoie [`CaptureError::DesktopUnavailable`] lorsque le bureau d'entrée
    /// est hors de portée du processus — le cas nominal d'un agent non
    /// privilégié devant un écran verrouillé.
    pub fn attach_to_input_desktop() -> Result<Self, CaptureError> {
        // SAFETY: lecture du bureau courant du thread ; le descripteur renvoyé
        // appartient au système et ne doit pas être fermé.
        let previous = unsafe { GetThreadDesktop(GetCurrentThreadId()) }
            .map_err(|e| CaptureError::System(format!("bureau courant illisible: {e}")))?;

        // SAFETY: ouvre le bureau d'entrée sans héritage. Les droits demandés
        // se limitent à la lecture et à l'écriture d'objets : demander un accès
        // total ferait échouer l'ouverture là où la capture serait possible.
        let current = unsafe {
            OpenInputDesktop(
                Default::default(),
                false,
                DESKTOP_ACCESS_FLAGS(DESKTOP_READOBJECTS.0 | DESKTOP_WRITEOBJECTS.0),
            )
        }
        .map_err(|_| CaptureError::DesktopUnavailable)?;

        // SAFETY: le thread de capture ne crée ni fenêtre ni crochet, condition
        // d'appel de `SetThreadDesktop`.
        if let Err(e) = unsafe { SetThreadDesktop(current) } {
            // SAFETY: le descripteur vient d'être ouvert et n'est plus utilisé.
            let _ = unsafe { CloseDesktop(current) };
            return Err(CaptureError::System(format!(
                "rattachement au bureau impossible: {e}"
            )));
        }

        tracing::debug!("thread rattaché au bureau d'entrée");
        Ok(Self { previous, current })
    }
}

impl Drop for DesktopGuard {
    fn drop(&mut self) {
        // SAFETY: rend le thread à son bureau d'origine avant de fermer celui
        // que nous avons ouvert ; l'inverse laisserait un descripteur référencé.
        unsafe {
            let _ = SetThreadDesktop(self.previous);
            let _ = CloseDesktop(self.current);
        }
    }
}
