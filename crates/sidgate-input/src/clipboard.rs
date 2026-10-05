//! Lecture du presse-papiers de l'hôte.
//!
//! Lecture seule, texte seul, et uniquement à la demande : l'agent ne s'abonne
//! à aucune notification et ne garde aucune copie. Ce module ne sait pas
//! écrire dans le presse-papiers — un client qui veut y déposer du texte le
//! tape, par le même chemin que n'importe quelle frappe.
//!
//! # Invariants des blocs `unsafe`
//!
//! 1. `OpenClipboard` et `CloseClipboard` s'appellent strictement par paires :
//!    le presse-papiers est une ressource globale du poste, et un processus qui
//!    oublie de le refermer en prive toutes les applications.
//! 2. La poignée rendue par `GetClipboardData` appartient au presse-papiers.
//!    Elle n'est ni libérée ni conservée ; elle est verrouillée le temps de la
//!    copie, puis déverrouillée avant la fermeture.
//! 3. La lecture est bornée par `GlobalSize`, jamais par la seule recherche du
//!    zéro terminal : le bloc vient d'une autre application.
//! 4. Un seul thread du processus touche au presse-papiers à la fois.
//!    `OpenClipboard` sans fenêtre propriétaire n'exclut que les *autres*
//!    processus : deux threads du même processus l'ouvrent tous les deux, puis
//!    verrouillent et déverrouillent le même bloc chacun de leur côté, ce qui
//!    corrompt le tas. [`ACCESS`] rend cette exclusion explicite.

use std::time::Duration;

use windows::Win32::Foundation::HGLOBAL;
use windows::Win32::System::DataExchange::{
    CloseClipboard, GetClipboardData, IsClipboardFormatAvailable, OpenClipboard,
};
use windows::Win32::System::Memory::{GlobalLock, GlobalSize, GlobalUnlock};

use crate::{truncate_utf8, InputError};

/// Format « texte Unicode » du presse-papiers (`CF_UNICODETEXT`).
const CF_UNICODETEXT: u32 = 13;
/// Tentatives d'ouverture avant d'abandonner.
///
/// Le presse-papiers n'admet qu'un lecteur à la fois ; un gestionnaire
/// d'historique ou un antivirus le tient souvent quelques millisecondes juste
/// après une copie.
const OPEN_ATTEMPTS: u32 = 5;
const OPEN_RETRY_DELAY: Duration = Duration::from_millis(15);

/// Exclusion des lectures concurrentes au sein du processus.
static ACCESS: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Referme le presse-papiers à la sortie de portée.
struct ClipboardGuard;

impl ClipboardGuard {
    fn open() -> Result<Self, InputError> {
        let mut last = None;
        for attempt in 0..OPEN_ATTEMPTS {
            if attempt > 0 {
                std::thread::sleep(OPEN_RETRY_DELAY);
            }
            // SAFETY: aucune fenêtre propriétaire ; la paire est refermée par
            // le `Drop` du garde renvoyé.
            match unsafe { OpenClipboard(None) } {
                Ok(()) => return Ok(Self),
                Err(e) => last = Some(e),
            }
        }
        Err(InputError::System(format!(
            "presse-papiers occupé: {}",
            last.map(|e| e.message()).unwrap_or_default()
        )))
    }
}

impl Drop for ClipboardGuard {
    fn drop(&mut self) {
        // SAFETY: ce garde n'existe que si `OpenClipboard` a réussi.
        let _ = unsafe { CloseClipboard() };
    }
}

/// Lit le texte du presse-papiers, coupé à `max_bytes` octets d'UTF-8.
///
/// Renvoie le texte et un indicateur de troncature. Un presse-papiers vide, ou
/// qui contient autre chose que du texte, donne une chaîne vide : ce n'est pas
/// une erreur.
pub fn read_text(max_bytes: usize) -> Result<(String, bool), InputError> {
    // Un verrou empoisonné ne protège aucune donnée : il se reprend tel quel.
    let _exclusive = ACCESS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);

    // SAFETY: simple interrogation, sans paramètre de sortie.
    if unsafe { IsClipboardFormatAvailable(CF_UNICODETEXT) }.is_err() {
        return Ok((String::new(), false));
    }

    let _guard = ClipboardGuard::open()?;

    // SAFETY: le presse-papiers est ouvert par ce thread.
    let Ok(handle) = (unsafe { GetClipboardData(CF_UNICODETEXT) }) else {
        return Ok((String::new(), false));
    };
    let memory = HGLOBAL(handle.0);

    // SAFETY: `memory` est un bloc global valide tant que le presse-papiers
    // reste ouvert ; `GlobalSize` en donne la taille allouée.
    let (pointer, size) = unsafe { (GlobalLock(memory), GlobalSize(memory)) };
    if pointer.is_null() {
        return Err(InputError::System("presse-papiers illisible".into()));
    }

    // Inutile de copier plus que ce qui pourra être transmis : une unité
    // UTF-16 donne au moins un octet d'UTF-8.
    let units = (size / 2).min(max_bytes.saturating_add(1));
    // SAFETY: le bloc fait au moins `size` octets, donc `units` unités de
    // seize bits ; il reste verrouillé jusqu'à `GlobalUnlock` ci-dessous, et la
    // tranche n'est plus utilisée après la conversion.
    let (text, terminated) = unsafe {
        let slice = std::slice::from_raw_parts(pointer.cast::<u16>(), units);
        let end = slice.iter().position(|unit| *unit == 0);
        (
            String::from_utf16_lossy(&slice[..end.unwrap_or(units)]),
            end.is_some(),
        )
    };
    // SAFETY: appariement du `GlobalLock` réussi ci-dessus. L'erreur renvoyée
    // quand le compteur de verrous retombe à zéro n'en est pas une.
    let _ = unsafe { GlobalUnlock(memory) };

    // Sans zéro terminal dans la fenêtre lue, le texte continuait au-delà.
    let cut_at_source = !terminated && units < size / 2;
    let (text, cut) = truncate_utf8(text, max_bytes);
    Ok((text, cut || cut_at_source))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reading_never_panics_and_respects_the_limit() {
        // Le contenu du presse-papiers de la machine de test est inconnu : on
        // vérifie la borne, pas la valeur.
        if let Ok((text, _)) = read_text(64) {
            assert!(text.len() <= 64);
        }
    }

    #[test]
    fn concurrent_readers_do_not_corrupt_the_heap() {
        // Régression : sans exclusion, deux lectures simultanées faisaient
        // tomber le processus sur une corruption de tas, une fois sur deux.
        let readers: Vec<_> = (0..8)
            .map(|_| {
                std::thread::spawn(|| {
                    for _ in 0..50 {
                        let _ = read_text(256);
                    }
                })
            })
            .collect();
        for reader in readers {
            reader.join().expect("un lecteur a paniqué");
        }
    }

    #[test]
    fn a_zero_limit_returns_nothing() {
        if let Ok((text, _)) = read_text(0) {
            assert!(text.is_empty());
        }
    }
}
