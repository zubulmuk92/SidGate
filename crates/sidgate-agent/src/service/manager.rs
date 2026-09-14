//! Installation et pilotage du service auprès du gestionnaire Windows.
//!
//! Toutes ces opérations exigent une élévation. Le message d'erreur le dit
//! plutôt que de laisser un code Win32 nu : « accès refusé » sur une commande
//! d'installation n'aide personne.
//!
//! # Invariants des blocs `unsafe`
//!
//! 1. Chaque `SC_HANDLE` est détenu par [`ScHandle`] et fermé par son `Drop`.
//! 2. Les chaînes UTF-16 passées aux appels vivent jusqu'à leur retour.
//! 3. `QueryServiceStatusEx` reçoit un tampon de la taille exacte de la
//!    structure attendue, et sa taille lui est communiquée.

use std::time::{Duration, Instant};

use windows::core::PCWSTR;
use windows::Win32::Foundation::ERROR_ACCESS_DENIED;
use windows::Win32::System::Services::{
    ChangeServiceConfig2W, CloseServiceHandle, ControlService, CreateServiceW, DeleteService,
    OpenSCManagerW, OpenServiceW, QueryServiceStatusEx, StartServiceW, SC_HANDLE,
    SC_MANAGER_CONNECT, SC_MANAGER_CREATE_SERVICE, SC_STATUS_PROCESS_INFO, SERVICE_ALL_ACCESS,
    SERVICE_AUTO_START, SERVICE_CONFIG_DESCRIPTION, SERVICE_CONTROL_STOP, SERVICE_DESCRIPTIONW,
    SERVICE_ERROR_NORMAL, SERVICE_QUERY_STATUS, SERVICE_RUNNING, SERVICE_START, SERVICE_STATUS,
    SERVICE_STATUS_PROCESS, SERVICE_STOP, SERVICE_STOPPED, SERVICE_WIN32_OWN_PROCESS,
};

use super::{DISPLAY_NAME, SERVICE_NAME};

/// Description affichée dans la console des services.
const DESCRIPTION: &str = "Supervise l'accès distant sidgate dans la session interactive. \
                           Ce service n'écoute sur aucun port.";

/// Descripteur du gestionnaire de services, refermé automatiquement.
struct ScHandle(SC_HANDLE);

impl Drop for ScHandle {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            // SAFETY: descripteur valide, détenu exclusivement par la structure.
            let _ = unsafe { CloseServiceHandle(self.0) };
        }
    }
}

/// Installe le service en démarrage automatique.
pub fn install() -> anyhow::Result<()> {
    let executable = std::env::current_exe()?;
    let manager = open_manager(SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE)?;

    let name = wide(SERVICE_NAME);
    let display = wide(DISPLAY_NAME);
    // Le chemin est mis entre guillemets : sans cela, un dossier contenant un
    // espace laisse Windows exécuter le premier fragment du chemin, ce qui est
    // une élévation de privilèges classique par chemin non cité.
    let binary = wide(&format!("\"{}\" service run", executable.display()));

    // SAFETY: toutes les chaînes vivent jusqu'au retour de l'appel.
    let service = unsafe {
        CreateServiceW(
            manager.0,
            PCWSTR(name.as_ptr()),
            PCWSTR(display.as_ptr()),
            SERVICE_ALL_ACCESS,
            SERVICE_WIN32_OWN_PROCESS,
            SERVICE_AUTO_START,
            SERVICE_ERROR_NORMAL,
            PCWSTR(binary.as_ptr()),
            PCWSTR::null(),
            None,
            PCWSTR::null(),
            // Compte système : seul lui peut replacer un jeton dans une autre
            // session, ce dont dépend l'accès pré-connexion.
            PCWSTR::null(),
            PCWSTR::null(),
        )
    }
    .map_err(explain)?;
    let service = ScHandle(service);

    let mut description = wide(DESCRIPTION);
    let info = SERVICE_DESCRIPTIONW {
        lpDescription: windows::core::PWSTR(description.as_mut_ptr()),
    };
    // SAFETY: `info` et le tampon qu'il référence vivent pendant l'appel.
    let _ = unsafe {
        ChangeServiceConfig2W(
            service.0,
            SERVICE_CONFIG_DESCRIPTION,
            Some(&info as *const _ as *const _),
        )
    };

    println!("service installé : {DISPLAY_NAME}");
    println!("  binaire   : {} service run", executable.display());
    println!("  démarrage : automatique, sous le compte système");
    println!();
    println!("Démarrer maintenant :  sidgate service start");
    Ok(())
}

/// Retire le service. Le stoppe d'abord s'il tourne.
pub fn uninstall() -> anyhow::Result<()> {
    let manager = open_manager(SC_MANAGER_CONNECT)?;
    let service = open_service(&manager, SERVICE_ALL_ACCESS)?;

    let mut status = SERVICE_STATUS::default();
    // SAFETY: `status` vit pendant l'appel ; un service déjà arrêté fait
    // simplement échouer l'ordre.
    let _ = unsafe { ControlService(service.0, SERVICE_CONTROL_STOP, &mut status) };

    // SAFETY: descripteur détenu par `service`.
    unsafe { DeleteService(service.0) }.map_err(explain)?;
    println!("service retiré");
    Ok(())
}

/// Démarre le service et attend qu'il soit réellement en marche.
pub fn start() -> anyhow::Result<()> {
    let manager = open_manager(SC_MANAGER_CONNECT)?;
    let service = open_service(&manager, SERVICE_START | SERVICE_QUERY_STATUS)?;

    // SAFETY: descripteur détenu par `service` ; aucun argument transmis.
    unsafe { StartServiceW(service.0, None) }.map_err(explain)?;

    match wait_for(&service, SERVICE_RUNNING.0, Duration::from_secs(15)) {
        true => println!("service démarré"),
        false => println!("service démarré, mais toujours pas signalé en marche après 15 s"),
    }
    Ok(())
}

/// Arrête le service et attend son extinction.
pub fn stop() -> anyhow::Result<()> {
    let manager = open_manager(SC_MANAGER_CONNECT)?;
    let service = open_service(&manager, SERVICE_STOP | SERVICE_QUERY_STATUS)?;

    let mut status = SERVICE_STATUS::default();
    // SAFETY: `status` vit pendant l'appel.
    unsafe { ControlService(service.0, SERVICE_CONTROL_STOP, &mut status) }.map_err(explain)?;

    match wait_for(&service, SERVICE_STOPPED.0, Duration::from_secs(15)) {
        true => println!("service arrêté"),
        false => println!("arrêt demandé, mais le service n'a pas confirmé après 15 s"),
    }
    Ok(())
}

/// Affiche l'état du service.
pub fn status() -> anyhow::Result<()> {
    let manager = match open_manager(SC_MANAGER_CONNECT) {
        Ok(manager) => manager,
        Err(e) => {
            println!("gestionnaire de services inaccessible : {e}");
            return Ok(());
        }
    };
    let service = match open_service(&manager, SERVICE_QUERY_STATUS) {
        Ok(service) => service,
        Err(_) => {
            println!("service non installé");
            println!("Installer :  sidgate service install   (invite élevée requise)");
            return Ok(());
        }
    };

    let state = query_state(&service).unwrap_or(0);
    let label = match SERVICE_STATUS_CURRENT(state) {
        s if s == SERVICE_RUNNING.0 => "en marche",
        s if s == SERVICE_STOPPED.0 => "arrêté",
        _ => "en transition",
    };
    println!("service : {label}");
    if let Some(session) = super::launcher::active_console_session() {
        println!("session interactive : {session}");
    } else {
        println!("session interactive : aucune");
    }
    Ok(())
}

/// Rend la comparaison d'état lisible sans exposer le type Win32.
#[allow(non_snake_case)]
fn SERVICE_STATUS_CURRENT(value: u32) -> u32 {
    value
}

fn open_manager(access: u32) -> anyhow::Result<ScHandle> {
    // SAFETY: aucune chaîne transmise ; le descripteur obtenu est possédé.
    let handle = unsafe { OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), access) }.map_err(explain)?;
    Ok(ScHandle(handle))
}

fn open_service(manager: &ScHandle, access: u32) -> anyhow::Result<ScHandle> {
    let name = wide(SERVICE_NAME);
    // SAFETY: `name` vit pendant l'appel.
    let handle =
        unsafe { OpenServiceW(manager.0, PCWSTR(name.as_ptr()), access) }.map_err(explain)?;
    Ok(ScHandle(handle))
}

/// Interroge l'état courant du service.
fn query_state(service: &ScHandle) -> Option<u32> {
    let mut buffer = [0u8; std::mem::size_of::<SERVICE_STATUS_PROCESS>()];
    let mut needed = 0u32;
    // SAFETY: le tampon fait exactement la taille de la structure attendue, et
    // sa taille est transmise à l'appel.
    unsafe {
        QueryServiceStatusEx(
            service.0,
            SC_STATUS_PROCESS_INFO,
            Some(&mut buffer),
            &mut needed,
        )
    }
    .ok()?;
    // SAFETY: l'appel a rempli le tampon avec une `SERVICE_STATUS_PROCESS`
    // correctement alignée, le tampon étant issu d'un tableau d'octets aligné
    // au moins autant que la structure (composée d'entiers 32 bits).
    let status: SERVICE_STATUS_PROCESS =
        unsafe { std::ptr::read_unaligned(buffer.as_ptr() as *const _) };
    Some(status.dwCurrentState.0)
}

/// Attend que le service atteigne l'état voulu.
fn wait_for(service: &ScHandle, target: u32, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if query_state(service) == Some(target) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    false
}

/// Traduit les erreurs opaques du gestionnaire en conseils exploitables.
fn explain(error: windows::core::Error) -> anyhow::Error {
    if error.code() == ERROR_ACCESS_DENIED.to_hresult() {
        return anyhow::anyhow!(
            "accès refusé : ouvrez une invite de commandes en tant qu'administrateur"
        );
    }
    anyhow::anyhow!("{error}")
}

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_binary_path_is_quoted() {
        // Un chemin non cité contenant un espace laisse Windows exécuter le
        // premier fragment : la faille classique du « unquoted service path ».
        let path = std::path::Path::new(r"C:\Program Files\sidgate\sidgate.exe");
        let command = format!("\"{}\" service run", path.display());
        assert!(command.starts_with('"'));
        assert!(command.contains("\" service run"));
    }

    #[test]
    fn access_denied_becomes_actionable_advice() {
        let error = windows::core::Error::from(ERROR_ACCESS_DENIED);
        let message = explain(error).to_string();
        assert!(
            message.contains("administrateur"),
            "le message doit dire quoi faire, pas seulement ce qui a échoué : {message}"
        );
    }

    #[test]
    fn other_errors_keep_their_original_text() {
        let error = windows::core::Error::from(windows::Win32::Foundation::ERROR_FILE_NOT_FOUND);
        let message = explain(error).to_string();
        assert!(!message.contains("administrateur"));
    }

    #[test]
    fn wide_strings_are_null_terminated() {
        assert_eq!(*wide(DESCRIPTION).last().unwrap(), 0);
    }
}
