//! Service Windows : superviseur du travailleur interactif.
//!
//! Le service est délibérément minuscule. Il n'ouvre aucun socket, ne parse
//! rien venant du réseau, et ne connaît ni WebRTC ni capture. Il fait une seule
//! chose : maintenir un travailleur vivant dans la session interactive, et le
//! relancer quand celle-ci change.
//!
//! Cette pauvreté est le point : c'est le seul processus du projet qui tourne
//! en permanence sous le compte système. Tout ce qui touche au réseau vit dans
//! le travailleur, qui peut être tué et remplacé sans conséquence.
//!
//! # Invariants des blocs `unsafe`
//!
//! 1. Le gestionnaire de contrôle est appelé par le système sur un thread qui
//!    n'est pas le nôtre. Il ne fait que poster dans un canal : aucune donnée
//!    n'est partagée sans synchronisation.
//! 2. `SERVICE_STATUS_HANDLE` n'est ni `Send` ni `Sync` ; il est conservé sous
//!    forme d'entier dans un atomique et reconstruit à l'usage.
//! 3. Les chaînes passées à la table de dispatch restent vivantes pendant tout
//!    l'appel à `StartServiceCtrlDispatcherW`, qui ne rend la main qu'à l'arrêt.

pub mod launcher;
pub mod manager;

use std::ffi::c_void;
use std::sync::atomic::{AtomicIsize, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use windows::core::PWSTR;
use windows::Win32::System::Services::{
    RegisterServiceCtrlHandlerExW, SetServiceStatus, StartServiceCtrlDispatcherW,
    SERVICE_ACCEPT_SESSIONCHANGE, SERVICE_ACCEPT_SHUTDOWN, SERVICE_ACCEPT_STOP,
    SERVICE_CONTROL_INTERROGATE, SERVICE_CONTROL_SESSIONCHANGE, SERVICE_CONTROL_SHUTDOWN,
    SERVICE_CONTROL_STOP, SERVICE_RUNNING, SERVICE_START_PENDING, SERVICE_STATUS,
    SERVICE_STATUS_CURRENT_STATE, SERVICE_STATUS_HANDLE, SERVICE_STOPPED, SERVICE_STOP_PENDING,
    SERVICE_TABLE_ENTRYW, SERVICE_WIN32_OWN_PROCESS,
};

use launcher::{Worker, WorkerIdentity};

/// Nom interne du service, celui qu'attend le gestionnaire.
pub const SERVICE_NAME: &str = "sidgate";
/// Nom affiché dans la console des services.
pub const DISPLAY_NAME: &str = "sidgate — accès distant";

/// Période de vérification en l'absence d'événement.
///
/// Les bascules de session arrivent par notification ; ce réveil ne sert qu'à
/// repérer un travailleur mort de sa belle mort.
const SUPERVISION_PERIOD: Duration = Duration::from_secs(2);
/// Attente maximale entre deux tentatives de lancement après échec.
const MAX_BACKOFF: Duration = Duration::from_secs(30);

/// Descripteur d'état, sous forme d'entier faute d'être partageable.
static STATUS_HANDLE: AtomicIsize = AtomicIsize::new(0);
/// Canal par lequel le gestionnaire de contrôle parle à la boucle.
static EVENTS: OnceLock<Mutex<Sender<ServiceEvent>>> = OnceLock::new();

/// Ce que le système demande au service.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ServiceEvent {
    /// Arrêt demandé.
    Stop,
    /// La session interactive a changé.
    SessionChanged,
}

/// Point d'entrée appelé lorsque le gestionnaire de services démarre le
/// processus. Ne rend la main qu'à l'arrêt du service.
pub fn dispatch() -> anyhow::Result<()> {
    let mut name = wide(SERVICE_NAME);
    let table = [
        SERVICE_TABLE_ENTRYW {
            lpServiceName: PWSTR(name.as_mut_ptr()),
            lpServiceProc: Some(service_main),
        },
        SERVICE_TABLE_ENTRYW::default(),
    ];

    // SAFETY: `name` et `table` vivent jusqu'au retour de l'appel, qui ne se
    // produit qu'à l'arrêt du service.
    unsafe { StartServiceCtrlDispatcherW(table.as_ptr()) }.map_err(|e| {
        anyhow::anyhow!(
            "ce processus n'a pas été démarré par le gestionnaire de services ({e}). \
             Utilisez « sidgate service start » ou la console des services."
        )
    })
}

/// Corps du service, appelé par le gestionnaire sur son propre thread.
unsafe extern "system" fn service_main(_argc: u32, _argv: *mut PWSTR) {
    let mut name = wide(SERVICE_NAME);
    // SAFETY: `name` vit pendant l'appel ; le gestionnaire copie ce qu'il garde.
    let handle = match unsafe {
        RegisterServiceCtrlHandlerExW(PWSTR(name.as_mut_ptr()), Some(control_handler), None)
    } {
        Ok(handle) => handle,
        // Sans descripteur d'état, le service ne peut rien signaler : le seul
        // comportement correct est de disparaître.
        Err(_) => return,
    };
    STATUS_HANDLE.store(handle.0 as isize, Ordering::SeqCst);

    let (sender, receiver) = std::sync::mpsc::channel();
    let _ = EVENTS.set(Mutex::new(sender));

    report(SERVICE_START_PENDING, 3_000);
    report(SERVICE_RUNNING, 0);

    supervise(receiver);

    report(SERVICE_STOP_PENDING, 5_000);
    report(SERVICE_STOPPED, 0);
}

/// Reçoit les ordres du système. S'exécute sur un thread du gestionnaire : tout
/// travail réel est renvoyé à la boucle de supervision.
unsafe extern "system" fn control_handler(
    control: u32,
    _event_type: u32,
    _event_data: *mut c_void,
    _context: *mut c_void,
) -> u32 {
    /// Code de retour signifiant « ordre accepté ».
    const NO_ERROR: u32 = 0;
    /// Code de retour signifiant « ordre non pris en charge ».
    const ERROR_CALL_NOT_IMPLEMENTED: u32 = 120;

    let event = match control {
        SERVICE_CONTROL_STOP | SERVICE_CONTROL_SHUTDOWN => Some(ServiceEvent::Stop),
        SERVICE_CONTROL_SESSIONCHANGE => Some(ServiceEvent::SessionChanged),
        // Le gestionnaire interroge périodiquement l'état ; il suffit de le
        // reconfirmer.
        SERVICE_CONTROL_INTERROGATE => {
            report(SERVICE_RUNNING, 0);
            None
        }
        _ => return ERROR_CALL_NOT_IMPLEMENTED,
    };

    if let Some(event) = event {
        if event == ServiceEvent::Stop {
            report(SERVICE_STOP_PENDING, 5_000);
        }
        if let Some(sender) = EVENTS.get() {
            if let Ok(sender) = sender.lock() {
                let _ = sender.send(event);
            }
        }
    }
    NO_ERROR
}

/// Maintient un travailleur vivant dans la session interactive.
fn supervise(events: Receiver<ServiceEvent>) {
    let executable = match std::env::current_exe() {
        Ok(path) => path,
        Err(_) => return,
    };
    let identity = worker_identity();
    let mut worker: Option<Worker> = None;
    let mut backoff = Duration::from_secs(1);

    loop {
        reconcile(&executable, identity, &mut worker, &mut backoff);

        match events.recv_timeout(SUPERVISION_PERIOD) {
            Ok(ServiceEvent::Stop) => break,
            // Une bascule de session invalide le travailleur courant : le tour
            // suivant s'en aperçoit en comparant les identifiants.
            Ok(ServiceEvent::SessionChanged) => continue,
            Err(RecvTimeoutError::Timeout) => continue,
            Err(RecvTimeoutError::Disconnected) => break,
        }
    }

    if let Some(worker) = worker {
        worker.terminate();
    }
}

/// Rapproche l'état réel de l'état voulu : un travailleur, dans la bonne
/// session, vivant.
fn reconcile(
    executable: &std::path::Path,
    identity: WorkerIdentity,
    worker: &mut Option<Worker>,
    backoff: &mut Duration,
) {
    let session = launcher::active_console_session();

    match (worker.as_ref(), session) {
        // Plus de session interactive : rien à superviser.
        (Some(running), None) => {
            running.terminate();
            *worker = None;
        }
        // La session a changé sous nos pieds, ou le travailleur est mort.
        (Some(running), Some(current)) if running.session != current || !running.is_running() => {
            running.terminate();
            *worker = None;
        }
        _ => {}
    }

    let Some(session) = session else { return };
    if worker.is_some() {
        *backoff = Duration::from_secs(1);
        return;
    }

    match launcher::launch(executable, "worker", session, identity) {
        Ok(started) => {
            *worker = Some(started);
            *backoff = Duration::from_secs(1);
        }
        Err(_) => {
            // Une session qui vient de s'ouvrir n'a pas encore de jeton
            // exploitable : réessayer tout de suite en boucle ne ferait que
            // remplir le journal d'événements.
            std::thread::sleep(*backoff);
            *backoff = (*backoff * 2).min(MAX_BACKOFF);
        }
    }
}

/// Identité demandée pour le travailleur.
///
/// Le pré-connexion se réclame explicitement : faire tourner en SYSTEM un
/// processus qui écoute le réseau ne doit jamais être un effet de bord.
fn worker_identity() -> WorkerIdentity {
    match std::env::var("SIDGATE_WORKER_IDENTITY").as_deref() {
        Ok("system") => WorkerIdentity::System,
        _ => WorkerIdentity::User,
    }
}

/// Signale l'état courant au gestionnaire de services.
fn report(state: SERVICE_STATUS_CURRENT_STATE, wait_hint_ms: u32) {
    let raw = STATUS_HANDLE.load(Ordering::SeqCst);
    if raw == 0 {
        return;
    }

    let accepted = if state == SERVICE_RUNNING {
        SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN | SERVICE_ACCEPT_SESSIONCHANGE
    } else {
        0
    };

    let status = SERVICE_STATUS {
        dwServiceType: SERVICE_WIN32_OWN_PROCESS,
        dwCurrentState: state,
        dwControlsAccepted: accepted,
        dwWin32ExitCode: 0,
        dwServiceSpecificExitCode: 0,
        dwCheckPoint: 0,
        dwWaitHint: wait_hint_ms,
    };

    // SAFETY: le descripteur provient de `RegisterServiceCtrlHandlerExW` et
    // reste valide jusqu'à la fin du processus ; `status` est local et complet.
    let _ = unsafe { SetServiceStatus(SERVICE_STATUS_HANDLE(raw as *mut c_void), &status) };
}

/// Convertit en chaîne UTF-16 terminée par un zéro.
fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_defaults_to_the_logged_in_user() {
        // Le moindre privilège est le défaut : le pré-connexion ne s'obtient
        // que par une demande explicite.
        std::env::remove_var("SIDGATE_WORKER_IDENTITY");
        assert_eq!(worker_identity(), WorkerIdentity::User);

        std::env::set_var("SIDGATE_WORKER_IDENTITY", "utilisateur");
        assert_eq!(worker_identity(), WorkerIdentity::User);

        std::env::set_var("SIDGATE_WORKER_IDENTITY", "SYSTEM");
        assert_eq!(
            worker_identity(),
            WorkerIdentity::User,
            "la valeur est sensible à la casse, pour éviter une élévation par inadvertance"
        );

        std::env::set_var("SIDGATE_WORKER_IDENTITY", "system");
        assert_eq!(worker_identity(), WorkerIdentity::System);
        std::env::remove_var("SIDGATE_WORKER_IDENTITY");
    }

    #[test]
    fn wide_strings_are_null_terminated() {
        assert_eq!(*wide(SERVICE_NAME).last().unwrap(), 0);
        assert_eq!(wide("ab").len(), 3);
    }

    #[test]
    fn only_the_running_state_accepts_controls() {
        // Un service qui annonce accepter un arrêt alors qu'il démarre encore
        // reçoit des ordres qu'il ne peut pas honorer.
        for state in [SERVICE_START_PENDING, SERVICE_STOP_PENDING, SERVICE_STOPPED] {
            assert_ne!(state, SERVICE_RUNNING);
        }
        assert_eq!(
            SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN | SERVICE_ACCEPT_SESSIONCHANGE,
            SERVICE_ACCEPT_STOP + SERVICE_ACCEPT_SHUTDOWN + SERVICE_ACCEPT_SESSIONCHANGE,
            "les drapeaux acceptés doivent être disjoints"
        );
    }
}
