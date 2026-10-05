//! Fermeture du répertoire de données aux autres comptes de la machine.
//!
//! Ce répertoire contient la clé privée de l'agent, le registre des clients
//! autorisés et, le temps d'un appairage, le code en attente. Qui peut y écrire
//! peut s'inscrire comme client ; qui peut y lire peut se faire passer pour
//! l'agent.
//!
//! Or un dossier créé sous `%PROGRAMDATA%` hérite d'un contrôle d'accès qui
//! laisse tout utilisateur de la machine y lire et y créer des fichiers. Sur un
//! poste partagé, c'est une élévation de privilèges à portée de n'importe quel
//! compte : déposer une demande d'appairage, puis piloter la session du voisin.
//!
//! À sa création, le répertoire reçoit donc une liste d'accès *protégée* — qui
//! n'hérite plus de rien — réduite à trois entrées : le système, les
//! administrateurs, et le compte qui l'a créé.
//!
//! Un répertoire qui existait déjà n'est jamais modifié d'office : il peut
//! appartenir à un autre compte, et lui retirer ses droits casserait une
//! installation qui fonctionne. Il est signalé, et `sidgate protect` le ferme
//! sur demande.
//!
//! # Invariants des blocs `unsafe`
//!
//! 1. Toute mémoire rendue par le système — descripteur de sécurité, chaîne
//!    SDDL, chaîne de SID — est libérée par `LocalFree` sur tous les chemins,
//!    par le `Drop` de [`LocalMemory`].
//! 2. Les pointeurs extraits d'un descripteur (`ACL`, `SID`) ne sont utilisés
//!    que tant que le descripteur dont ils sont issus est vivant.

use std::path::Path;

/// État du contrôle d'accès d'un répertoire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Exposure {
    /// Seuls le système, les administrateurs et des comptes nommés y accèdent.
    Private,
    /// Un groupe large — tous les utilisateurs de la machine — y a accès.
    Shared,
    /// L'état n'a pas pu être lu, ou la plateforme n'a pas cette notion.
    Unknown,
}

/// Crée le répertoire s'il n'existe pas, et le ferme s'il vient d'être créé.
///
/// Renvoie `true` si le répertoire a été créé par cet appel.
pub fn create_private_dir(path: &Path) -> std::io::Result<bool> {
    if path.is_dir() {
        return Ok(false);
    }
    std::fs::create_dir_all(path)?;
    if let Err(e) = restrict(path) {
        // Le répertoire existe et reste utilisable ; l'avertissement de
        // démarrage dira qu'il est exposé.
        tracing::warn!(path = %path.display(), error = %e, "contrôle d'accès non appliqué");
    }
    Ok(true)
}

/// Les trustees SDDL désignant un groupe auquel tout compte local appartient.
const BROAD_TRUSTEES: &[&str] = &[
    "WD", // Tout le monde
    "S-1-1-0",
    "AU", // Utilisateurs authentifiés
    "S-1-5-11",
    "BU", // Utilisateurs
    "S-1-5-32-545",
    "IU", // Utilisateurs interactifs
    "S-1-5-4",
    "BG", // Invités
    "S-1-5-32-546",
    "AN", // Anonyme
    "S-1-5-7",
];

/// La liste d'accès décrite en SDDL accorde-t-elle quelque chose à un groupe
/// large ?
///
/// Seules les entrées d'autorisation comptent : un refus adressé à tout le
/// monde ne donne accès à personne.
pub fn grants_broad_access(sddl: &str) -> bool {
    let Some(dacl) = sddl.split("D:").nth(1) else {
        // Pas de liste d'accès du tout : le système accorde alors tout à tous.
        return true;
    };
    // La liste s'arrête à la section suivante, s'il y en a une.
    let dacl = dacl.split("S:").next().unwrap_or(dacl);

    dacl.split('(')
        .skip(1)
        .filter_map(|ace| ace.split(')').next())
        .any(|ace| {
            let fields: Vec<&str> = ace.split(';').collect();
            // Autorisation simple, sur objet, ou conditionnelle. Les entrées
            // d'audit (`AU`) et d'alarme (`AL`) commencent aussi par un A.
            let allows = matches!(fields.first().copied(), Some("A" | "OA" | "XA" | "ZA"));
            let trustee = fields.get(5).copied().unwrap_or_default();
            allows && BROAD_TRUSTEES.contains(&trustee)
        })
}

/// Liste d'accès appliquée à un répertoire fermé, pour le compte `user_sid`.
///
/// `P` : protégée, plus d'héritage du parent. `OICI` : les entrées se
/// propagent aux fichiers et aux sous-dossiers. `FA` : accès complet.
pub fn private_sddl(user_sid: &str) -> String {
    format!("D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;{user_sid})")
}

#[cfg(windows)]
pub use windows_impl::{exposure, restrict};

#[cfg(not(windows))]
pub fn exposure(_path: &Path) -> Exposure {
    Exposure::Unknown
}

#[cfg(not(windows))]
pub fn restrict(_path: &Path) -> anyhow::Result<()> {
    Ok(())
}

#[cfg(windows)]
mod windows_impl {
    use std::os::windows::ffi::OsStrExt;
    use std::path::Path;

    use windows::core::{PCWSTR, PWSTR};
    use windows::Win32::Foundation::{CloseHandle, LocalFree, ERROR_SUCCESS, HANDLE, HLOCAL};
    use windows::Win32::Security::Authorization::{
        ConvertSecurityDescriptorToStringSecurityDescriptorW, ConvertSidToStringSidW,
        ConvertStringSecurityDescriptorToSecurityDescriptorW, GetNamedSecurityInfoW,
        SetNamedSecurityInfoW, SDDL_REVISION_1, SE_FILE_OBJECT,
    };
    use windows::Win32::Security::{
        GetSecurityDescriptorDacl, GetTokenInformation, TokenUser, ACL, DACL_SECURITY_INFORMATION,
        PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, TOKEN_QUERY, TOKEN_USER,
    };
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    use super::{grants_broad_access, private_sddl, Exposure};

    /// Bloc alloué par le système, à rendre par `LocalFree`.
    struct LocalMemory(*mut core::ffi::c_void);

    impl Drop for LocalMemory {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: le pointeur vient d'une API documentée comme
                // allouant par `LocalAlloc`, et n'est libéré qu'ici.
                let _ = unsafe { LocalFree(Some(HLOCAL(self.0))) };
            }
        }
    }

    fn wide(path: &Path) -> Vec<u16> {
        path.as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    /// Réduit l'accès au répertoire au système, aux administrateurs et au
    /// compte courant.
    pub fn restrict(path: &Path) -> anyhow::Result<()> {
        let sddl: Vec<u16> = private_sddl(&current_user_sid()?)
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        let mut descriptor = PSECURITY_DESCRIPTOR::default();
        // SAFETY: `sddl` est terminée par un zéro ; `descriptor` est un local
        // vivant, rempli par l'appel et libéré par `_descriptor_memory`.
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                PCWSTR(sddl.as_ptr()),
                SDDL_REVISION_1,
                &mut descriptor,
                None,
            )
        }?;
        let _descriptor_memory = LocalMemory(descriptor.0);

        let mut present = windows::core::BOOL::default();
        let mut defaulted = windows::core::BOOL::default();
        let mut dacl: *mut ACL = std::ptr::null_mut();
        // SAFETY: `descriptor` est vivant ; les trois sorties sont des locaux.
        unsafe { GetSecurityDescriptorDacl(descriptor, &mut present, &mut dacl, &mut defaulted) }?;
        anyhow::ensure!(present.as_bool() && !dacl.is_null(), "liste d'accès vide");

        let name = wide(path);
        // SAFETY: `name` est terminé par un zéro ; `dacl` pointe dans
        // `descriptor`, vivant jusqu'à la fin de la fonction. L'appel copie la
        // liste d'accès dans le descripteur du répertoire.
        let status = unsafe {
            SetNamedSecurityInfoW(
                PCWSTR(name.as_ptr()),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                None,
                None,
                Some(dacl),
                None,
            )
        };
        anyhow::ensure!(
            status == ERROR_SUCCESS,
            "modification du contrôle d'accès refusée (erreur {})",
            status.0
        );
        Ok(())
    }

    /// Lit le contrôle d'accès du répertoire et dit s'il est ouvert à un
    /// groupe large.
    pub fn exposure(path: &Path) -> Exposure {
        match read_sddl(path) {
            Some(sddl) if grants_broad_access(&sddl) => Exposure::Shared,
            Some(_) => Exposure::Private,
            None => Exposure::Unknown,
        }
    }

    /// Liste d'accès du répertoire, en SDDL.
    fn read_sddl(path: &Path) -> Option<String> {
        let name = wide(path);
        let mut descriptor = PSECURITY_DESCRIPTOR::default();
        // SAFETY: `name` est terminé par un zéro ; seul le descripteur complet
        // est demandé, et il est libéré par `_descriptor_memory`.
        let status = unsafe {
            GetNamedSecurityInfoW(
                PCWSTR(name.as_ptr()),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                None,
                None,
                None,
                None,
                &mut descriptor,
            )
        };
        if status != ERROR_SUCCESS {
            return None;
        }
        let _descriptor_memory = LocalMemory(descriptor.0);

        let mut text = PWSTR::null();
        // SAFETY: `descriptor` est vivant ; `text` reçoit une chaîne allouée
        // par le système, libérée par `_text_memory`.
        unsafe {
            ConvertSecurityDescriptorToStringSecurityDescriptorW(
                descriptor,
                SDDL_REVISION_1,
                DACL_SECURITY_INFORMATION,
                &mut text,
                None,
            )
        }
        .ok()?;
        let _text_memory = LocalMemory(text.0.cast());
        // SAFETY: `text` est une chaîne terminée par un zéro, vivante jusqu'à
        // la libération ci-dessus.
        unsafe { text.to_string() }.ok()
    }

    /// SID du compte sous lequel tourne le processus, en notation textuelle.
    fn current_user_sid() -> anyhow::Result<String> {
        let mut token = HANDLE::default();
        // SAFETY: `token` est un local vivant, refermé plus bas.
        unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) }?;
        let sid = token_user_sid(token);
        // SAFETY: `token` a été ouvert juste au-dessus et n'est plus utilisé.
        let _ = unsafe { CloseHandle(token) };
        sid
    }

    fn token_user_sid(token: HANDLE) -> anyhow::Result<String> {
        let mut needed = 0u32;
        // SAFETY: premier appel sans tampon, pour connaître la taille requise ;
        // il échoue par construction et renseigne `needed`.
        let _ = unsafe { GetTokenInformation(token, TokenUser, None, 0, &mut needed) };
        anyhow::ensure!(
            needed as usize >= std::mem::size_of::<TOKEN_USER>(),
            "jeton illisible"
        );

        // Tampon aligné comme la structure qu'il va contenir.
        let mut buffer = vec![0u64; (needed as usize).div_ceil(8)];
        // SAFETY: le tampon fait au moins `needed` octets et est aligné sur
        // huit, ce qui suffit à `TOKEN_USER`.
        unsafe {
            GetTokenInformation(
                token,
                TokenUser,
                Some(buffer.as_mut_ptr().cast()),
                needed,
                &mut needed,
            )
        }?;
        // SAFETY: l'appel a réussi : le tampon commence par un `TOKEN_USER`
        // dont le SID pointe dans ce même tampon, vivant jusqu'à la fin de la
        // fonction.
        let user = unsafe { &*buffer.as_ptr().cast::<TOKEN_USER>() };

        let mut text = PWSTR::null();
        // SAFETY: le SID est valide tant que `buffer` vit ; `text` reçoit une
        // chaîne allouée par le système, libérée par `_text_memory`.
        unsafe { ConvertSidToStringSidW(user.User.Sid, &mut text) }?;
        let _text_memory = LocalMemory(text.0.cast());
        // SAFETY: chaîne terminée par un zéro, vivante jusqu'à sa libération.
        Ok(unsafe { text.to_string() }?)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn temp_dir(tag: &str) -> std::path::PathBuf {
            let dir =
                std::env::temp_dir().join(format!("sidgate-acl-{tag}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            dir
        }

        #[test]
        fn the_current_account_has_a_well_formed_sid() {
            let sid = current_user_sid().unwrap();
            assert!(sid.starts_with("S-1-"), "{sid}");
        }

        #[test]
        fn a_freshly_created_directory_is_private_and_still_usable() {
            let dir = temp_dir("create");
            assert!(crate::acl::create_private_dir(&dir).unwrap());
            assert_eq!(exposure(&dir), Exposure::Private);

            // Le compte courant garde tous ses droits, y compris sur ce qu'il
            // crée dedans.
            let file = dir.join("secret");
            std::fs::write(&file, b"x").unwrap();
            assert_eq!(std::fs::read(&file).unwrap(), b"x");
            std::fs::create_dir(dir.join("sous-dossier")).unwrap();
            std::fs::remove_dir_all(&dir).unwrap();
        }

        #[test]
        fn an_existing_directory_is_left_untouched() {
            let dir = temp_dir("existing");
            std::fs::create_dir_all(&dir).unwrap();
            let before = read_sddl(&dir).unwrap();
            assert!(!crate::acl::create_private_dir(&dir).unwrap());
            assert_eq!(read_sddl(&dir).unwrap(), before);
            std::fs::remove_dir_all(&dir).unwrap();
        }

        #[test]
        fn restricting_removes_inheritance_and_names_three_trustees() {
            let dir = temp_dir("restrict");
            std::fs::create_dir_all(&dir).unwrap();
            restrict(&dir).unwrap();

            let sddl = read_sddl(&dir).unwrap();
            assert!(sddl.contains("D:P"), "la liste doit être protégée: {sddl}");
            assert!(sddl.contains(";;;SY)"), "{sddl}");
            assert!(sddl.contains(";;;BA)"), "{sddl}");
            assert_eq!(
                sddl.matches('(').count(),
                3,
                "trois entrées, pas une de plus: {sddl}"
            );
            assert!(!grants_broad_access(&sddl));
            std::fs::remove_dir_all(&dir).unwrap();
        }

        #[test]
        fn a_missing_path_has_an_unknown_exposure() {
            assert_eq!(exposure(&temp_dir("absent")), Exposure::Unknown);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_private_list_grants_nothing_to_broad_groups() {
        let sddl = private_sddl("S-1-5-21-1-2-3-1001");
        assert!(!grants_broad_access(&sddl));
        assert!(
            sddl.starts_with("D:P"),
            "sans protection, l'héritage reviendrait"
        );
    }

    #[test]
    fn inherited_program_data_permissions_are_recognised_as_shared() {
        // Ce que reçoit un dossier créé sous %PROGRAMDATA% sans précaution.
        let inherited = "D:AI(A;OICIID;FA;;;SY)(A;OICIID;FA;;;BA)(A;OICIIOID;GA;;;CO)\
                         (A;OICIID;0x1200a9;;;BU)(A;CIID;DCLCRPCR;;;BU)";
        assert!(grants_broad_access(inherited));
    }

    #[test]
    fn every_broad_trustee_is_detected_in_alias_and_numeric_form() {
        for trustee in BROAD_TRUSTEES {
            let sddl = format!("D:P(A;OICI;FA;;;SY)(A;;FR;;;{trustee})");
            assert!(grants_broad_access(&sddl), "{trustee}");
        }
    }

    #[test]
    fn a_denial_addressed_to_everyone_grants_nothing() {
        assert!(!grants_broad_access("D:P(D;;FA;;;WD)(A;OICI;FA;;;SY)"));
    }

    #[test]
    fn a_named_account_is_not_a_broad_group() {
        assert!(!grants_broad_access(
            "O:BAG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;S-1-5-21-1-2-3-1001)"
        ));
    }

    #[test]
    fn a_descriptor_without_an_access_list_is_wide_open() {
        assert!(grants_broad_access("O:BAG:SY"));
    }

    #[test]
    fn a_trailing_audit_list_is_not_read_as_access() {
        // La section d'audit suit la liste d'accès et nomme volontiers « tout
        // le monde » : ce n'est pas un droit.
        assert!(!grants_broad_access(
            "D:P(A;OICI;FA;;;SY)S:(AU;SAFA;FA;;;WD)"
        ));
    }
}
