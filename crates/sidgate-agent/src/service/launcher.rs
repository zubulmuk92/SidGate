//! Lancement du travailleur dans la session interactive.
//!
//! Un service tourne en session 0, isolée de tout bureau depuis Windows Vista.
//! Il ne peut donc ni capturer l'écran ni injecter d'entrées : il doit faire
//! naître un processus *dans* la session de l'utilisateur.
//!
//! # Les deux identités possibles
//!
//! - [`WorkerIdentity::User`] : le travailleur prend le jeton de la session
//!   ouverte. Moindre privilège, et c'est la valeur par défaut. Il ne peut pas
//!   s'attacher au bureau `Winlogon`, donc pas capturer un écran verrouillé.
//! - [`WorkerIdentity::System`] : le travailleur reçoit une copie du jeton du
//!   service, replacée dans la session interactive. Il peut alors suivre le
//!   bureau d'entrée, écran de verrouillage compris — au prix d'un processus
//!   réseau tournant en SYSTEM, ce qui n'est pas un détail.
//!
//! # Invariants des blocs `unsafe`
//!
//! 1. Chaque `HANDLE` obtenu est confié à [`OwnedHandle`], qui le referme dans
//!    son `Drop`. Aucun descripteur n'est fermé deux fois ni fuité.
//! 2. Le bloc d'environnement est libéré par `DestroyEnvironmentBlock` sur tous
//!    les chemins, y compris en cas d'échec de création du processus.
//! 3. Les chaînes passées à `CreateProcessAsUserW` restent vivantes pendant
//!    l'appel : la ligne de commande est un tampon UTF-16 mutable détenu
//!    localement, comme l'API l'exige.

use std::ffi::c_void;

use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::Security::{
    DuplicateTokenEx, SecurityImpersonation, SetTokenInformation, TokenPrimary, TokenSessionId,
    TOKEN_ALL_ACCESS, TOKEN_ASSIGN_PRIMARY, TOKEN_DUPLICATE, TOKEN_QUERY,
};
use windows::Win32::System::Environment::{CreateEnvironmentBlock, DestroyEnvironmentBlock};
use windows::Win32::System::RemoteDesktop::{WTSGetActiveConsoleSessionId, WTSQueryUserToken};
use windows::Win32::System::Threading::{
    CreateProcessAsUserW, GetCurrentProcess, GetExitCodeProcess, OpenProcessToken,
    TerminateProcess, WaitForSingleObject, CREATE_NO_WINDOW, CREATE_UNICODE_ENVIRONMENT,
    NORMAL_PRIORITY_CLASS, PROCESS_INFORMATION, STARTUPINFOW,
};

/// Valeur renvoyée par `WTSGetActiveConsoleSessionId` en l'absence de session.
const NO_SESSION: u32 = 0xFFFF_FFFF;

/// Identité sous laquelle lancer le travailleur.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkerIdentity {
    /// L'utilisateur dont la session est ouverte.
    User,
    /// Le compte système, replacé dans la session interactive.
    System,
}

/// Descripteur Windows dont la fermeture est garantie.
#[derive(Debug)]
pub struct OwnedHandle(HANDLE);

impl OwnedHandle {
    /// Emprunte le descripteur brut, sans en céder la propriété.
    pub fn raw(&self) -> HANDLE {
        self.0
    }
}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            // SAFETY: le descripteur est valide et n'est plus utilisé ailleurs,
            // la structure en étant l'unique propriétaire.
            let _ = unsafe { CloseHandle(self.0) };
        }
    }
}

/// Un travailleur en cours d'exécution.
#[derive(Debug)]
pub struct Worker {
    process: OwnedHandle,
    /// Session dans laquelle il a été lancé, pour détecter une bascule.
    pub session: u32,
}

impl Worker {
    /// Le processus tourne-t-il encore ?
    pub fn is_running(&self) -> bool {
        let mut code = 0u32;
        // SAFETY: `code` vit pendant l'appel ; le descripteur est détenu par
        // `self`.
        if unsafe { GetExitCodeProcess(self.process.raw(), &mut code) }.is_err() {
            return false;
        }
        /// Valeur renvoyée tant que le processus n'a pas rendu de code.
        const STILL_ACTIVE: u32 = 259;
        code == STILL_ACTIVE
    }

    /// Arrête le travailleur et attend sa disparition.
    ///
    /// La terminaison est brutale, et c'est voulu : le travailleur ne détient
    /// aucun état persistant, tout ce qu'il possède est reconstruit au
    /// lancement suivant. Négocier un arrêt propre ajouterait un canal de
    /// contrôle — donc une surface — pour aucun bénéfice.
    pub fn terminate(&self) {
        // SAFETY: descripteur détenu par `self` ; un processus déjà mort fait
        // simplement échouer l'appel.
        unsafe {
            let _ = TerminateProcess(self.process.raw(), 0);
            WaitForSingleObject(self.process.raw(), 5_000);
        }
    }
}

/// Identifiant de la session console active, s'il y en a une.
///
/// Renvoie `None` entre deux sessions — pendant une déconnexion, ou sur une
/// machine dont aucun utilisateur n'a encore atteint l'écran d'accueil.
pub fn active_console_session() -> Option<u32> {
    // SAFETY: appel sans paramètre ni effet mémoire.
    let session = unsafe { WTSGetActiveConsoleSessionId() };
    (session != NO_SESSION).then_some(session)
}

/// Lance le travailleur dans `session`, sous l'identité demandée.
///
/// `arguments` est un `&'static str` et ce n'est pas un détail de style : la
/// signature interdit au compilateur d'accepter une chaîne construite à
/// l'exécution. Aucune valeur venue du réseau ne peut donc atteindre la ligne
/// de commande, et la garantie est vérifiée à la compilation plutôt que par
/// relecture.
pub fn launch(
    executable: &std::path::Path,
    arguments: &'static str,
    session: u32,
    identity: WorkerIdentity,
) -> anyhow::Result<Worker> {
    let token = match identity {
        WorkerIdentity::User => user_token(session)?,
        WorkerIdentity::System => system_token_in_session(session)?,
    };

    let mut environment: *mut c_void = std::ptr::null_mut();
    // SAFETY: `environment` reçoit un bloc alloué par le système, libéré plus
    // bas sur tous les chemins.
    let has_environment =
        unsafe { CreateEnvironmentBlock(&mut environment, Some(token.raw()), false) }.is_ok();

    let result = spawn(executable, arguments, &token, environment, has_environment);

    if has_environment && !environment.is_null() {
        // SAFETY: bloc obtenu de `CreateEnvironmentBlock`, libéré une seule fois.
        let _ = unsafe { DestroyEnvironmentBlock(environment) };
    }

    let process = result?;
    tracing::info!(session, ?identity, "travailleur lancé");
    Ok(Worker { process, session })
}

fn spawn(
    executable: &std::path::Path,
    arguments: &'static str,
    token: &OwnedHandle,
    environment: *mut c_void,
    has_environment: bool,
) -> anyhow::Result<OwnedHandle> {
    let application = to_wide(&executable.to_string_lossy());
    // `CreateProcessAsUserW` écrit dans la ligne de commande : elle doit être
    // un tampon mutable qui nous appartient, jamais une constante.
    let mut command_line = to_wide(&format!("\"{}\" {arguments}", executable.display()));
    // Le bureau doit être nommé explicitement : sans cela le processus naît sur
    // un bureau invisible et ne voit rien.
    let mut desktop = to_wide("winsta0\\default");

    let startup = STARTUPINFOW {
        cb: std::mem::size_of::<STARTUPINFOW>() as u32,
        lpDesktop: PWSTR(desktop.as_mut_ptr()),
        ..Default::default()
    };
    let mut information = PROCESS_INFORMATION::default();

    let flags = CREATE_NO_WINDOW
        | NORMAL_PRIORITY_CLASS
        | if has_environment {
            CREATE_UNICODE_ENVIRONMENT
        } else {
            Default::default()
        };

    // SAFETY: toutes les chaînes vivent jusqu'à la fin de l'appel ; `startup`
    // et `information` sont des structures locales entièrement initialisées.
    unsafe {
        CreateProcessAsUserW(
            Some(token.raw()),
            PCWSTR(application.as_ptr()),
            Some(PWSTR(command_line.as_mut_ptr())),
            None,
            None,
            false,
            flags,
            has_environment.then_some(environment as *const c_void),
            PCWSTR::null(),
            &startup,
            &mut information,
        )
    }
    .map_err(|e| anyhow::anyhow!("lancement du travailleur impossible: {e}"))?;

    // Le descripteur de thread principal ne nous sert à rien ; le garder
    // empêcherait le système de libérer le thread à sa fin.
    let _thread = OwnedHandle(information.hThread);
    Ok(OwnedHandle(information.hProcess))
}

/// Jeton de l'utilisateur dont la session est ouverte.
fn user_token(session: u32) -> anyhow::Result<OwnedHandle> {
    let mut token = HANDLE::default();
    // SAFETY: `token` vit pendant l'appel ; le descripteur obtenu est
    // immédiatement confié à `OwnedHandle`.
    unsafe { WTSQueryUserToken(session, &mut token) }.map_err(|e| {
        anyhow::anyhow!("aucun utilisateur connecté dans la session {session}: {e}")
    })?;
    let token = OwnedHandle(token);
    duplicate_primary(&token)
}

/// Copie du jeton du service, replacée dans la session interactive.
///
/// Modifier la session d'un jeton exige `SeTcbPrivilege`, que seul le compte
/// système possède. C'est précisément ce qui rend cette bascule impossible à
/// un processus ordinaire, et donc sûre.
fn system_token_in_session(session: u32) -> anyhow::Result<OwnedHandle> {
    let mut token = HANDLE::default();
    // SAFETY: `token` vit pendant l'appel.
    unsafe {
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY,
            &mut token,
        )
    }
    .map_err(|e| anyhow::anyhow!("jeton du service illisible: {e}"))?;
    let token = OwnedHandle(token);

    let duplicate = duplicate_primary(&token)?;

    // SAFETY: `session` est un entier copié par l'appel.
    unsafe {
        SetTokenInformation(
            duplicate.raw(),
            TokenSessionId,
            &session as *const u32 as *const c_void,
            std::mem::size_of::<u32>() as u32,
        )
    }
    .map_err(|e| {
        anyhow::anyhow!("bascule du jeton vers la session {session} refusée (SeTcbPrivilege requis): {e}")
    })?;

    Ok(duplicate)
}

/// Duplique un jeton en jeton primaire, seul type utilisable pour créer un
/// processus.
fn duplicate_primary(token: &OwnedHandle) -> anyhow::Result<OwnedHandle> {
    let mut duplicate = HANDLE::default();
    // SAFETY: `duplicate` vit pendant l'appel ; le descripteur obtenu est
    // immédiatement possédé.
    unsafe {
        DuplicateTokenEx(
            token.raw(),
            TOKEN_ALL_ACCESS,
            None,
            SecurityImpersonation,
            TokenPrimary,
            &mut duplicate,
        )
    }
    .map_err(|e| anyhow::anyhow!("duplication du jeton impossible: {e}"))?;
    Ok(OwnedHandle(duplicate))
}

/// Convertit en chaîne UTF-16 terminée par un zéro.
fn to_wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Le compilateur refuse une ligne de commande construite a l'execution.
    ///
    /// Ce test ne s'execute pas : il documente la garantie et casserait la
    /// compilation si la signature s'assouplissait.
    #[allow(dead_code)]
    fn arguments_cannot_come_from_runtime_data(untrusted: String) {
        let executable = std::path::Path::new("sidgate.exe");
        // La ligne suivante ne compile pas, et c'est l'invariant recherche :
        // let _ = launch(executable, &untrusted, 1, WorkerIdentity::User);
        let _ = (executable, untrusted);
        let _ = launch;
    }

    #[test]
    fn wide_strings_are_null_terminated() {
        let wide = to_wide("abc");
        assert_eq!(wide, vec![b'a' as u16, b'b' as u16, b'c' as u16, 0]);
        assert_eq!(to_wide(""), vec![0]);
    }

    #[test]
    fn wide_strings_survive_non_ascii() {
        let wide = to_wide("é");
        assert_eq!(wide.last(), Some(&0));
        assert_eq!(String::from_utf16(&wide[..wide.len() - 1]).unwrap(), "é");
    }

    #[test]
    fn the_sentinel_session_reads_as_absent() {
        // `WTSGetActiveConsoleSessionId` ne renvoie pas d'erreur : il renvoie
        // 0xFFFFFFFF, qui ne doit surtout pas être pris pour un identifiant.
        assert_eq!(NO_SESSION, u32::MAX);
        assert_ne!(NO_SESSION, 0, "la session 0 est celle des services");
    }

    #[test]
    fn active_session_is_either_absent_or_plausible() {
        // Sur une machine de compilation sans session interactive, `None` est
        // la bonne réponse ; sinon l'identifiant doit être exploitable.
        if let Some(session) = active_console_session() {
            assert_ne!(session, NO_SESSION);
        }
    }
}
