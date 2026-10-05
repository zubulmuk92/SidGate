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
//! # Ce que « fermé » veut dire
//!
//! Un répertoire n'est tenu pour fermé que si **tout** ce qui permet d'y entrer
//! désigne l'un de ces trois comptes : chaque entrée d'autorisation, et le
//! propriétaire, qui peut toujours réécrire la liste d'accès. Chercher
//! seulement les groupes larges ne suffirait pas : il est possible de créer le
//! dossier avant l'installation et de s'y réserver une entrée nominative, qui
//! ne ressemble à rien de suspect.
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
//!    par le `Drop` de `LocalMemory`.
//! 2. Les pointeurs extraits d'un descripteur (`ACL`, `SID`) ne sont utilisés
//!    que tant que le descripteur dont ils sont issus est vivant.

use std::path::Path;

/// État du contrôle d'accès d'un répertoire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Exposure {
    /// Seuls le système, les administrateurs et le compte courant y accèdent.
    Private,
    /// Un autre compte, ou un groupe, y a accès ou en est propriétaire.
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

/// Système et administrateurs, en notation SDDL.
const SYSTEM: &str = "SY";
const ADMINISTRATORS: &str = "BA";
/// Pseudo-comptes « créateur propriétaire » et « droits du propriétaire ».
///
/// Ils ne désignent personne par eux-mêmes : ils renvoient au propriétaire de
/// l'objet, qui est vérifié à part.
const OWNER_PLACEHOLDERS: &[&str] = &["CO", "OW"];

/// Découpe un descripteur SDDL en sections `(étiquette, contenu)`.
///
/// Les sections se suivent sans séparateur — `O:…G:…D:…S:…` — mais ni un SID ni
/// une entrée de liste ne contient de deux-points : chacun marque donc une
/// étiquette, portée par le caractère qui le précède.
fn sections(sddl: &str) -> Vec<(char, &str)> {
    let colons: Vec<usize> = sddl.match_indices(':').map(|(index, _)| index).collect();
    colons
        .iter()
        .enumerate()
        .filter_map(|(position, &colon)| {
            let tag = sddl[..colon].chars().next_back()?;
            let end = colons
                .get(position + 1)
                .map_or(sddl.len(), |next| next.saturating_sub(1));
            Some((tag, sddl.get(colon + 1..end.max(colon + 1))?))
        })
        .collect()
}

/// Le descripteur réserve-t-il l'objet au système, aux administrateurs et à
/// `account` ?
///
/// `account` est le compte courant, dans la notation que le système emploie
/// lui-même pour ce descripteur. Seules les entrées d'autorisation comptent :
/// un refus ne donne accès à personne.
pub fn is_reserved_to(sddl: &str, account: &str) -> bool {
    let sections = sections(sddl);
    let section = |tag| {
        sections
            .iter()
            .find(|(found, _)| *found == tag)
            .map(|(_, content)| *content)
    };
    let trusted = |trustee: &str| [SYSTEM, ADMINISTRATORS, account].contains(&trustee);

    // Le propriétaire peut toujours réécrire la liste d'accès : s'il n'est pas
    // de confiance, ce qu'elle dit aujourd'hui ne vaut rien demain.
    if !section('O').is_some_and(trusted) {
        return false;
    }
    // Sans liste d'accès, ou avec une liste « nulle », le système accorde tout
    // à tous.
    let Some(dacl) = section('D') else {
        return false;
    };
    if dacl.contains("NO_ACCESS_CONTROL") {
        return false;
    }

    dacl.split('(')
        .skip(1)
        .filter_map(|ace| ace.split(')').next())
        .all(|ace| {
            let fields: Vec<&str> = ace.split(';').collect();
            // Autorisation simple, sur objet, ou conditionnelle. Les entrées
            // de refus, d'audit et d'alarme n'ouvrent rien.
            let allows = matches!(fields.first().copied(), Some("A" | "OA" | "XA" | "ZA"));
            let trustee = fields.get(5).copied().unwrap_or_default();
            !allows || trusted(trustee) || OWNER_PLACEHOLDERS.contains(&trustee)
        })
}

/// Descripteur appliqué à un répertoire fermé, pour le compte `user_sid`.
///
/// `O:` en fait le propriétaire. `P` : liste protégée, plus d'héritage du
/// parent. `OICI` : les entrées se propagent aux fichiers et aux sous-dossiers.
/// `FA` : accès complet.
pub fn private_sddl(user_sid: &str) -> String {
    format!("O:{user_sid}D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;{user_sid})")
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
        GetSecurityDescriptorDacl, GetSecurityDescriptorOwner, GetTokenInformation, TokenUser, ACL,
        DACL_SECURITY_INFORMATION, OBJECT_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION,
        PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, TOKEN_QUERY, TOKEN_USER,
    };
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    use super::{is_reserved_to, private_sddl, Exposure};

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

    /// Descripteur de sécurité construit à partir de sa forme SDDL.
    struct Descriptor {
        raw: PSECURITY_DESCRIPTOR,
        _memory: LocalMemory,
    }

    impl Descriptor {
        fn parse(sddl: &str) -> anyhow::Result<Self> {
            let wide: Vec<u16> = sddl.encode_utf16().chain(std::iter::once(0)).collect();
            let mut raw = PSECURITY_DESCRIPTOR::default();
            // SAFETY: `wide` est terminée par un zéro ; `raw` est un local
            // vivant, rempli par l'appel et libéré par `_memory`.
            unsafe {
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    PCWSTR(wide.as_ptr()),
                    SDDL_REVISION_1,
                    &mut raw,
                    None,
                )
            }?;
            Ok(Self {
                raw,
                _memory: LocalMemory(raw.0),
            })
        }

        /// Liste d'accès du descripteur. Le pointeur vit autant que `self`.
        fn dacl(&self) -> anyhow::Result<*mut ACL> {
            let mut present = windows::core::BOOL::default();
            let mut defaulted = windows::core::BOOL::default();
            let mut dacl: *mut ACL = std::ptr::null_mut();
            // SAFETY: le descripteur est vivant ; les trois sorties sont des
            // locaux.
            unsafe {
                GetSecurityDescriptorDacl(self.raw, &mut present, &mut dacl, &mut defaulted)
            }?;
            anyhow::ensure!(present.as_bool() && !dacl.is_null(), "liste d'accès vide");
            Ok(dacl)
        }

        /// Propriétaire du descripteur. Le pointeur vit autant que `self`.
        fn owner(&self) -> anyhow::Result<PSID> {
            let mut defaulted = windows::core::BOOL::default();
            let mut owner = PSID::default();
            // SAFETY: le descripteur est vivant ; les sorties sont des locaux.
            unsafe { GetSecurityDescriptorOwner(self.raw, &mut owner, &mut defaulted) }?;
            anyhow::ensure!(!owner.0.is_null(), "descripteur sans propriétaire");
            Ok(owner)
        }
    }

    /// Rend un descripteur sous forme SDDL, pour les parties demandées.
    fn sddl_of(
        descriptor: PSECURITY_DESCRIPTOR,
        parts: OBJECT_SECURITY_INFORMATION,
    ) -> Option<String> {
        let mut text = PWSTR::null();
        // SAFETY: `descriptor` est vivant chez l'appelant ; `text` reçoit une
        // chaîne allouée par le système, libérée par `_text_memory`.
        unsafe {
            ConvertSecurityDescriptorToStringSecurityDescriptorW(
                descriptor,
                SDDL_REVISION_1,
                parts,
                &mut text,
                None,
            )
        }
        .ok()?;
        let _text_memory = LocalMemory(text.0.cast());
        // SAFETY: chaîne terminée par un zéro, vivante jusqu'à sa libération.
        unsafe { text.to_string() }.ok()
    }

    fn wide(path: &Path) -> Vec<u16> {
        path.as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    /// Applique une liste d'accès protégée au répertoire, et son propriétaire
    /// s'il est fourni. Renvoie `true` si le système l'a acceptée.
    fn apply(path: &Path, dacl: *mut ACL, owner: Option<PSID>) -> bool {
        let mut parts = DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION;
        if owner.is_some() {
            parts |= OWNER_SECURITY_INFORMATION;
        }
        let name = wide(path);
        // SAFETY: `name` est terminé par un zéro ; `dacl` et `owner` pointent
        // dans un descripteur que l'appelant garde vivant. L'appel copie ce
        // qu'il reçoit dans le descripteur du répertoire.
        let status = unsafe {
            SetNamedSecurityInfoW(
                PCWSTR(name.as_ptr()),
                SE_FILE_OBJECT,
                parts,
                owner,
                None,
                Some(dacl),
                None,
            )
        };
        status == ERROR_SUCCESS
    }

    /// Réserve le répertoire au système, aux administrateurs et au compte
    /// courant, qui en devient propriétaire.
    ///
    /// Échoue si le répertoire reste ouvert à un autre compte après coup —
    /// typiquement parce qu'il appartient à quelqu'un d'autre et que l'appelant
    /// n'a pas le droit d'en changer le propriétaire.
    pub fn restrict(path: &Path) -> anyhow::Result<()> {
        let descriptor = Descriptor::parse(&private_sddl(&current_user_sid()?))?;
        let dacl = descriptor.dacl()?;
        let owner = descriptor.owner()?;

        // La propriété d'abord, avec la liste : c'est elle qui empêche l'ancien
        // propriétaire de se rouvrir la porte. Un compte déjà propriétaire, ou
        // sans le droit d'en changer, se contente de la liste.
        if !apply(path, dacl, Some(owner)) {
            anyhow::ensure!(
                apply(path, dacl, None),
                "modification du contrôle d'accès refusée"
            );
        }

        anyhow::ensure!(
            exposure(path) != Exposure::Shared,
            "le répertoire appartient à un autre compte ; relancez depuis une invite \
             administrateur pour en reprendre la propriété"
        );
        Ok(())
    }

    /// Lit le contrôle d'accès du répertoire et dit s'il est réservé au
    /// système, aux administrateurs et au compte courant.
    pub fn exposure(path: &Path) -> Exposure {
        let (Some(sddl), Some(account)) = (read_sddl(path), current_account()) else {
            return Exposure::Unknown;
        };
        if is_reserved_to(&sddl, &account) {
            Exposure::Private
        } else {
            Exposure::Shared
        }
    }

    /// Propriétaire et liste d'accès du répertoire, en SDDL.
    fn read_sddl(path: &Path) -> Option<String> {
        let parts = OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
        let name = wide(path);
        let mut descriptor = PSECURITY_DESCRIPTOR::default();
        // SAFETY: `name` est terminé par un zéro ; seul le descripteur complet
        // est demandé, et il est libéré par `_descriptor_memory`.
        let status = unsafe {
            GetNamedSecurityInfoW(
                PCWSTR(name.as_ptr()),
                SE_FILE_OBJECT,
                parts,
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
        sddl_of(descriptor, parts)
    }

    /// Le compte courant, tel que le système l'écrit dans un descripteur.
    ///
    /// Un compte connu du système y figure sous un alias de deux lettres plutôt
    /// que sous son SID. Pour comparer sans tenir à jour une table d'alias, on
    /// demande au système d'écrire lui-même un descripteur dont ce compte est
    /// propriétaire.
    fn current_account() -> Option<String> {
        let sid = current_user_sid().ok()?;
        let descriptor = Descriptor::parse(&format!("O:{sid}")).ok()?;
        let sddl = sddl_of(descriptor.raw, OWNER_SECURITY_INFORMATION)?;
        Some(sddl.strip_prefix("O:")?.to_string())
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
            assert!(!current_account().unwrap().is_empty());
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
            let account = current_account().unwrap();
            assert!(sddl.contains("D:P"), "la liste doit être protégée: {sddl}");
            assert!(sddl.contains(";;;SY)"), "{sddl}");
            assert!(sddl.contains(";;;BA)"), "{sddl}");
            assert_eq!(
                sddl.matches('(').count(),
                3,
                "trois entrées, pas une de plus: {sddl}"
            );
            assert!(is_reserved_to(&sddl, &account), "{sddl} pour {account}");
            assert_eq!(exposure(&dir), Exposure::Private);
            std::fs::remove_dir_all(&dir).unwrap();
        }

        #[test]
        fn a_directory_opened_to_everyone_is_detected_then_closed_again() {
            let dir = temp_dir("open");
            std::fs::create_dir_all(&dir).unwrap();
            restrict(&dir).unwrap();

            // Rouvre le répertoire à tous, comme le ferait un héritage laxiste.
            let sid = current_user_sid().unwrap();
            let open = Descriptor::parse(&format!(
                "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;{sid})(A;OICI;FR;;;WD)"
            ))
            .unwrap();
            assert!(apply(&dir, open.dacl().unwrap(), None));
            assert_eq!(exposure(&dir), Exposure::Shared);

            restrict(&dir).unwrap();
            assert_eq!(exposure(&dir), Exposure::Private);
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

    /// Un compte ordinaire, tel qu'il apparaît dans un descripteur.
    const ME: &str = "S-1-5-21-1-2-3-1001";
    const OTHER: &str = "S-1-5-21-1-2-3-1002";

    #[test]
    fn sections_are_split_on_their_tags() {
        assert_eq!(
            sections("O:BAG:SYD:PAI(A;;FA;;;SY)S:(AU;SAFA;FA;;;WD)"),
            vec![
                ('O', "BA"),
                ('G', "SY"),
                ('D', "PAI(A;;FA;;;SY)"),
                ('S', "(AU;SAFA;FA;;;WD)"),
            ]
        );
        assert_eq!(sections("D:"), vec![('D', "")]);
        assert!(sections("").is_empty());
    }

    #[test]
    fn the_descriptor_we_apply_is_reserved_to_its_account() {
        assert!(is_reserved_to(&private_sddl(ME), ME));
        assert!(
            private_sddl(ME).contains("D:P"),
            "sans protection, l'héritage reviendrait"
        );
    }

    #[test]
    fn inherited_program_data_permissions_are_not_private() {
        // Ce que reçoit un dossier créé sous %PROGRAMDATA% sans précaution.
        let inherited = format!(
            "O:{ME}D:AI(A;OICIID;FA;;;SY)(A;OICIID;FA;;;BA)(A;OICIIOID;GA;;;CO)\
             (A;OICIID;0x1200a9;;;BU)(A;CIID;DCLCRPCR;;;BU)"
        );
        assert!(!is_reserved_to(&inherited, ME));
    }

    #[test]
    fn every_broad_group_opens_the_directory() {
        for trustee in ["WD", "AU", "BU", "IU", "BG", "AN", "S-1-1-0", "S-1-5-11"] {
            let sddl = format!("O:{ME}D:P(A;OICI;FA;;;SY)(A;;FR;;;{trustee})");
            assert!(!is_reserved_to(&sddl, ME), "{trustee}");
        }
    }

    #[test]
    fn a_named_entry_for_another_account_is_not_private() {
        // Le dossier créé d'avance par un autre compte du poste, qui s'y est
        // réservé une entrée : aucun groupe large, et pourtant ouvert.
        let sddl = format!("O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;{OTHER})");
        assert!(!is_reserved_to(&sddl, ME));
        assert!(
            is_reserved_to(&sddl, OTHER),
            "pour lui, en revanche, il l'est"
        );
    }

    #[test]
    fn a_foreign_owner_is_not_private_whatever_the_list_says() {
        let sddl = format!("O:{OTHER}D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;{ME})");
        assert!(
            !is_reserved_to(&sddl, ME),
            "le propriétaire peut réécrire la liste quand il veut"
        );
    }

    #[test]
    fn system_or_administrators_may_own_the_directory() {
        for owner in ["SY", "BA", ME] {
            let sddl = format!("O:{owner}D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)");
            assert!(is_reserved_to(&sddl, ME), "{owner}");
        }
    }

    #[test]
    fn a_missing_owner_is_not_taken_on_trust() {
        assert!(!is_reserved_to("D:P(A;OICI;FA;;;SY)", ME));
    }

    #[test]
    fn a_denial_addressed_to_everyone_grants_nothing() {
        let sddl = format!("O:{ME}D:P(D;;FA;;;WD)(A;OICI;FA;;;SY)");
        assert!(is_reserved_to(&sddl, ME));
    }

    #[test]
    fn owner_placeholders_are_harmless_once_the_owner_is_trusted() {
        let sddl = format!("O:{ME}D:P(A;OICI;FA;;;SY)(A;OICIIO;GA;;;CO)(A;;FA;;;OW)");
        assert!(is_reserved_to(&sddl, ME));
    }

    #[test]
    fn a_missing_or_null_access_list_is_wide_open() {
        assert!(!is_reserved_to(&format!("O:{ME}G:SY"), ME));
        assert!(!is_reserved_to(&format!("O:{ME}D:NO_ACCESS_CONTROL"), ME));
    }

    #[test]
    fn an_empty_access_list_admits_nobody() {
        // Liste présente mais vide : personne n'entre, pas même nous. Ce n'est
        // pas utilisable, mais ce n'est pas exposé.
        assert!(is_reserved_to(&format!("O:{ME}D:P"), ME));
    }

    #[test]
    fn a_trailing_audit_list_is_not_read_as_access() {
        // La section d'audit suit la liste d'accès et nomme volontiers « tout
        // le monde » : ce n'est pas un droit.
        let sddl = format!("O:{ME}D:P(A;OICI;FA;;;SY)S:(AU;SAFA;FA;;;WD)");
        assert!(is_reserved_to(&sddl, ME));
    }
}
