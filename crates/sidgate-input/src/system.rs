//! Actions système : verrouillage de session et alimentation.
//!
//! Toutes passent par un appel système direct. Aucune ne construit de ligne de
//! commande, n'invoque `shutdown.exe`, `rundll32` ou quoi que ce soit d'autre :
//! il n'existe aucun point du programme où une valeur venue du réseau puisse
//! atteindre un interpréteur.
//!
//! # Invariants des blocs `unsafe`
//!
//! 1. Les jetons de processus ouverts sont refermés par `CloseHandle` sur tous
//!    les chemins, réussite comme échec.
//! 2. `AdjustTokenPrivileges` reçoit une structure entièrement initialisée dont
//!    le champ `PrivilegeCount` correspond au tableau fourni.

use windows::core::w;
use windows::Win32::Foundation::{CloseHandle, HANDLE, LUID};
use windows::Win32::Security::{
    AdjustTokenPrivileges, LookupPrivilegeValueW, LUID_AND_ATTRIBUTES, SE_PRIVILEGE_ENABLED,
    TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_QUERY,
};
use windows::Win32::System::Power::SetSuspendState;
use windows::Win32::System::Shutdown::{
    ExitWindowsEx, LockWorkStation, EWX_REBOOT, EWX_SHUTDOWN, SHTDN_REASON_FLAG_PLANNED,
    SHTDN_REASON_MAJOR_OTHER, SHTDN_REASON_MINOR_OTHER,
};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

use crate::InputError;

/// Verrouille la session interactive.
///
/// C'est le killswitch : il est déclenché dès que le transport WebRTC tombe, de
/// sorte qu'une coupure réseau ne laisse jamais une session ouverte derrière
/// elle.
pub fn lock_session() -> Result<(), InputError> {
    // SAFETY: appel sans paramètre, sans effet sur la mémoire du processus.
    unsafe { LockWorkStation() }.map_err(|e| InputError::System(format!("verrouillage: {e}")))?;
    tracing::warn!("session verrouillée");
    Ok(())
}

/// Met la machine en veille.
///
/// `bforce = false` laisse les applications refuser la mise en veille, ce qui
/// évite de perdre un travail non enregistré sur une commande envoyée par
/// erreur depuis un téléphone.
pub fn sleep() -> Result<(), InputError> {
    // SAFETY: appel sans pointeur ; la valeur de retour indique la réussite.
    let ok = unsafe { SetSuspendState(false, false, false) };
    if ok {
        tracing::warn!("mise en veille demandée");
        Ok(())
    } else {
        Err(InputError::System("mise en veille refusée".into()))
    }
}

/// Redémarre la machine.
pub fn reboot() -> Result<(), InputError> {
    exit_windows(EWX_REBOOT, "redémarrage")
}

/// Éteint la machine.
pub fn shutdown() -> Result<(), InputError> {
    exit_windows(EWX_SHUTDOWN, "extinction")
}

fn exit_windows(
    flags: windows::Win32::System::Shutdown::EXIT_WINDOWS_FLAGS,
    label: &'static str,
) -> Result<(), InputError> {
    enable_shutdown_privilege()?;
    // SAFETY: les deux paramètres sont des constantes de l'API.
    unsafe {
        ExitWindowsEx(
            flags,
            SHTDN_REASON_MAJOR_OTHER | SHTDN_REASON_MINOR_OTHER | SHTDN_REASON_FLAG_PLANNED,
        )
    }
    .map_err(|e| InputError::System(format!("{label}: {e}")))?;
    tracing::warn!(action = label, "action d'alimentation demandée");
    Ok(())
}

/// Active `SeShutdownPrivilege` sur le processus courant.
///
/// Le privilège est présent mais désactivé par défaut dans le jeton d'un
/// processus utilisateur ; sans cette activation, `ExitWindowsEx` échoue.
fn enable_shutdown_privilege() -> Result<(), InputError> {
    let mut token = HANDLE::default();
    // SAFETY: `token` vit pendant l'appel et est refermé plus bas.
    unsafe {
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &mut token,
        )
    }
    .map_err(|e| InputError::System(format!("ouverture du jeton: {e}")))?;

    let result = adjust_shutdown_privilege(token);
    // SAFETY: `token` a été ouvert avec succès juste au-dessus et n'est plus
    // utilisé après cette fermeture.
    let _ = unsafe { CloseHandle(token) };
    result
}

fn adjust_shutdown_privilege(token: HANDLE) -> Result<(), InputError> {
    let mut luid = LUID::default();
    // SAFETY: `luid` vit pendant l'appel ; le nom est une constante statique
    // terminée par un zéro.
    unsafe { LookupPrivilegeValueW(None, w!("SeShutdownPrivilege"), &mut luid) }
        .map_err(|_| InputError::MissingPrivilege("SeShutdownPrivilege"))?;

    let privileges = TOKEN_PRIVILEGES {
        PrivilegeCount: 1,
        Privileges: [LUID_AND_ATTRIBUTES {
            Luid: luid,
            Attributes: SE_PRIVILEGE_ENABLED,
        }],
    };

    // SAFETY: `privileges` est entièrement initialisé et `PrivilegeCount`
    // correspond exactement au tableau qu'il contient.
    unsafe {
        AdjustTokenPrivileges(
            token,
            false,
            Some(&privileges),
            std::mem::size_of::<TOKEN_PRIVILEGES>() as u32,
            None,
            None,
        )
    }
    .map_err(|_| InputError::MissingPrivilege("SeShutdownPrivilege"))
}
