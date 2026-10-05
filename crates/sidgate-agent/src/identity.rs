//! Identité de l'agent, clients appairés et authentification mutuelle.
//!
//! # Modèle
//!
//! L'agent possède une identité Ed25519 créée au premier démarrage. Chaque
//! client possède une paire ECDSA P-256 générée dans le navigateur, non
//! exportable, conservée dans IndexedDB. Le choix de deux algorithmes
//! différents n'est pas un caprice : Ed25519 n'est pas encore disponible dans
//! WebCrypto sur tous les navigateurs, alors que P-256 l'est partout.
//!
//! L'appairage est une fenêtre courte, ouverte explicitement sur l'hôte, pendant
//! laquelle un code à huit caractères autorise l'enregistrement d'une clé
//! publique. Ensuite, chaque connexion est un défi-réponse signé **dans les deux
//! sens** : le client prouve son identité, et l'agent prouve la sienne pour que
//! le client détecte un imposteur sur le réseau privé.
//!
//! Ni le tunnel WireGuard ni le TLS du transport ne sont considérés comme
//! suffisants : ils protègent le lien, pas l'identité de ce qui se trouve au
//! bout.
//!
//! # Deux processus, un registre
//!
//! L'agent tourne en permanence ; les commandes `pair`, `clients` et `revoke`
//! sont des processus éphémères lancés à côté de lui. Ils ne se parlent pas :
//! ils partagent le répertoire de données. Une demande d'appairage y est
//! déposée sous forme de fichier, et le registre des clients est relu quand il
//! a changé. Les deux ne sont consultés qu'à l'arrivée d'une connexion — il
//! n'y a ni canal local à écouter ni fichier à surveiller, donc rien qui tourne
//! quand personne ne se connecte.
//!
//! Qui peut écrire dans ce répertoire peut s'appairer : c'est pourquoi il est
//! fermé aux autres comptes de la machine (voir le module `acl`).

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signer, SigningKey};
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature as ClientSignature, VerifyingKey as ClientVerifyingKey};
use rand::TryRngCore;
use serde::{Deserialize, Serialize};
use sidgate_proto::signaling::{self, AuthError};

/// Nom du fichier portant la clé privée de l'agent.
const KEY_FILE: &str = "agent.key";
/// Nom du fichier listant les clients appairés.
const CLIENTS_FILE: &str = "clients.json";
/// Nom du fichier portant une demande d'appairage déposée par `sidgate pair`.
const TICKET_FILE: &str = "pairing.json";
/// Nom du fichier servant de verrou aux écritures du registre.
const LOCK_FILE: &str = "clients.lock";
/// Durée de vie maximale d'une demande d'appairage, en secondes.
///
/// Une demande dont l'échéance est plus lointaine n'a pas pu être écrite par
/// `sidgate pair`, que la configuration borne à cette durée : elle est refusée,
/// pour qu'un fichier déposé un jour par quelqu'un qui avait accès au
/// répertoire ne reste pas valable indéfiniment.
pub const MAX_PAIRING_WINDOW_SECS: u64 = 3600;

/// Alphabet du code d'appairage.
///
/// Dérivé de Crockford base32 : ni `I`, ni `L`, ni `O`, ni `U`, pour qu'aucun
/// caractère ne puisse être confondu avec un chiffre ou avec un juron.
const CODE_ALPHABET: &[u8] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
/// Longueur du code, hors tiret de lisibilité. 8 caractères sur cet alphabet
/// donnent 40 bits, largement au-delà de ce qu'une fenêtre de deux minutes
/// limitée en tentatives permet de forcer.
const CODE_LEN: usize = 8;

/// Un client autorisé à ouvrir une session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairedClient {
    /// Clé publique ECDSA P-256, format SEC1 non compressé, en hexadécimal.
    pub key: String,
    /// Nom lisible donné par le client au moment de l'appairage.
    pub label: String,
    /// Date d'appairage, en secondes depuis l'époque Unix.
    pub paired_at: u64,
    /// Dernière connexion réussie, en secondes depuis l'époque Unix.
    pub last_seen: Option<u64>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct ClientStore {
    clients: Vec<PairedClient>,
}

/// Ce qu'un client présente pour prouver qu'il détient sa clé privée.
///
/// La signature porte sur une transcription qui inclut les deux aléas : elle
/// ne vaut que pour cette connexion.
#[derive(Debug, Clone, Copy)]
pub struct Proof<'a> {
    /// Clé publique ECDSA P-256 du client, en hexadécimal.
    pub client_key_hex: &'a str,
    /// Aléa tiré par l'agent pour cette connexion.
    pub server_nonce: &'a [u8],
    /// Aléa tiré par le client pour cette connexion.
    pub client_nonce: &'a [u8],
    /// Signature `r || s` de la transcription, en hexadécimal.
    pub signature_hex: &'a str,
}

/// Demande d'appairage déposée dans le répertoire de données.
#[derive(Debug, Serialize, Deserialize)]
struct PairingTicket {
    /// Code à saisir sur le client.
    code: String,
    /// Échéance, en secondes depuis l'époque Unix.
    expires_at: u64,
}

/// État d'un fichier, pour savoir s'il a changé sans le relire.
type FileStamp = Option<(SystemTime, u64)>;

/// Identité de l'agent et registre des clients.
#[derive(Debug)]
pub struct Identity {
    signing_key: SigningKey,
    clients: Vec<PairedClient>,
    clients_path: PathBuf,
    clients_stamp: FileStamp,
    ticket_path: PathBuf,
    lock_path: PathBuf,
    pairing: Option<PairingWindow>,
    attempts: HashMap<IpAddr, AttemptWindow>,
    attempts_per_minute: u32,
}

#[derive(Debug)]
struct PairingWindow {
    code: String,
    opened: Instant,
    ttl: Duration,
}

#[derive(Debug)]
struct AttemptWindow {
    start: Instant,
    count: u32,
}

impl Identity {
    /// Charge l'identité depuis `dir`, en la créant au besoin.
    pub fn load_or_create(dir: &Path, attempts_per_minute: u32) -> anyhow::Result<Self> {
        std::fs::create_dir_all(dir)?;
        let key_path = dir.join(KEY_FILE);
        let clients_path = dir.join(CLIENTS_FILE);

        let signing_key = match std::fs::read(&key_path) {
            Ok(bytes) if bytes.len() == 32 => {
                let array: [u8; 32] = bytes.as_slice().try_into().expect("longueur vérifiée");
                SigningKey::from_bytes(&array)
            }
            Ok(_) => anyhow::bail!(
                "{} est corrompu: une clé Ed25519 fait exactement 32 octets",
                key_path.display()
            ),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let key = generate_signing_key()?;
                write_private(&key_path, &key.to_bytes())?;
                tracing::info!(path = %key_path.display(), "identité de l'agent créée");
                key
            }
            Err(e) => return Err(e.into()),
        };

        let clients_stamp = stamp_of(&clients_path);
        let clients = match std::fs::read_to_string(&clients_path) {
            Ok(text) => serde_json::from_str::<ClientStore>(&text)?.clients,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(e) => return Err(e.into()),
        };

        Ok(Self {
            signing_key,
            clients,
            clients_path,
            clients_stamp,
            ticket_path: dir.join(TICKET_FILE),
            lock_path: dir.join(LOCK_FILE),
            pairing: None,
            attempts: HashMap::new(),
            attempts_per_minute,
        })
    }

    /// Clé publique de l'agent, en hexadécimal. C'est ce que le client épingle.
    pub fn public_key_hex(&self) -> String {
        signaling::to_hex(self.signing_key.verifying_key().as_bytes())
    }

    /// Empreinte courte, affichable sur la console de l'hôte pour comparaison
    /// visuelle avec ce qu'affiche le client.
    pub fn fingerprint(&self) -> String {
        let hex = self.public_key_hex();
        hex.as_bytes()
            .chunks(4)
            .take(4)
            .map(|c| String::from_utf8_lossy(c).to_uppercase())
            .collect::<Vec<_>>()
            .join("-")
    }

    /// Clients actuellement autorisés.
    pub fn clients(&self) -> &[PairedClient] {
        &self.clients
    }

    /// Retire un client. Renvoie `true` s'il existait.
    pub fn revoke(&mut self, key_hex: &str) -> anyhow::Result<bool> {
        let _lock = RegistryLock::acquire(&self.lock_path);
        self.refresh_clients();
        let before = self.clients.len();
        self.clients.retain(|c| c.key != key_hex);
        let removed = self.clients.len() != before;
        if removed {
            self.persist_clients()?;
            tracing::warn!(client = key_hex, "client révoqué");
        }
        Ok(removed)
    }

    /// Ouvre une fenêtre d'appairage et renvoie le code à saisir sur le client.
    pub fn open_pairing(&mut self, ttl: Duration) -> anyhow::Result<String> {
        let code = generate_pairing_code()?;
        self.pairing = Some(PairingWindow {
            code: code.clone(),
            opened: Instant::now(),
            ttl,
        });
        tracing::warn!(ttl_secs = ttl.as_secs(), "fenêtre d'appairage ouverte");
        Ok(code)
    }

    /// Ferme la fenêtre d'appairage, y compris une demande déposée sur disque.
    pub fn close_pairing(&mut self) {
        self.pairing = None;
        let _ = std::fs::remove_file(&self.ticket_path);
    }

    /// Une fenêtre d'appairage est-elle ouverte à cet instant ?
    pub fn pairing_open(&self) -> bool {
        self.console_code().is_some() || read_ticket(&self.ticket_path).is_some()
    }

    /// Code de la fenêtre ouverte depuis la console de cet agent, si elle
    /// n'a pas expiré.
    fn console_code(&self) -> Option<&str> {
        self.pairing
            .as_ref()
            .filter(|w| w.opened.elapsed() < w.ttl)
            .map(|w| w.code.as_str())
    }

    /// Le client est-il encore autorisé ?
    ///
    /// Relit le registre s'il a changé : c'est par là qu'une révocation faite
    /// depuis une autre invite atteint une session déjà ouverte.
    pub fn is_authorized(&mut self, client_key_hex: &str) -> bool {
        self.refresh_clients();
        self.clients.iter().any(|c| c.key == client_key_hex)
    }

    /// Recharge le registre des clients s'il a été modifié par un autre
    /// processus.
    ///
    /// Un fichier illisible ou corrompu laisse le registre en mémoire tel
    /// quel : ne plus reconnaître personne sur une écriture ratée serait pire
    /// que de garder la liste d'il y a une minute.
    fn refresh_clients(&mut self) {
        let stamp = stamp_of(&self.clients_path);
        if stamp == self.clients_stamp {
            return;
        }
        match std::fs::read_to_string(&self.clients_path) {
            Ok(text) => match serde_json::from_str::<ClientStore>(&text) {
                Ok(store) => {
                    self.clients = store.clients;
                    self.clients_stamp = stamp;
                    tracing::info!(clients = self.clients.len(), "registre des clients relu");
                }
                Err(e) => tracing::warn!(error = %e, "registre des clients illisible, ignoré"),
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                self.clients.clear();
                self.clients_stamp = stamp;
            }
            Err(e) => tracing::warn!(error = %e, "registre des clients inaccessible"),
        }
    }

    /// Signe la transcription d'authentification pour prouver l'identité de
    /// l'agent au client.
    pub fn sign_agent_transcript(
        &self,
        server_nonce: &[u8],
        client_nonce: &[u8],
        client_key: &[u8],
    ) -> String {
        let transcript = signaling::agent_transcript(server_nonce, client_nonce, client_key);
        signaling::to_hex(&self.signing_key.sign(&transcript).to_bytes())
    }

    /// Vérifie l'authentification d'un client déjà appairé.
    pub fn authenticate(&mut self, source: IpAddr, proof: Proof<'_>) -> Result<String, AuthError> {
        let Proof {
            client_key_hex,
            server_nonce,
            client_nonce,
            signature_hex,
        } = proof;
        self.check_rate_limit(source)?;
        self.refresh_clients();

        let client_key = decode_client_key(client_key_hex)?;
        if !self.clients.iter().any(|c| c.key == client_key_hex) {
            return Err(AuthError::Rejected);
        }

        let transcript =
            signaling::client_auth_transcript(server_nonce, client_nonce, &client_key.1);
        verify_client_signature(&client_key.0, &transcript, signature_hex)?;

        // Dater la visite réécrit le registre. Sous verrou, et depuis une
        // lecture fraîche : sans cela, une révocation faite à l'instant par
        // une autre invite serait écrasée par notre copie d'avant.
        let _lock = RegistryLock::acquire(&self.lock_path);
        self.refresh_clients();
        let Some(client) = self.clients.iter_mut().find(|c| c.key == client_key_hex) else {
            return Err(AuthError::Rejected);
        };
        client.last_seen = Some(unix_now());
        let _ = self.persist_clients();
        self.attempts.remove(&source);
        Ok(client_key_hex.to_string())
    }

    /// Vérifie un appairage et enregistre le client.
    pub fn pair(
        &mut self,
        source: IpAddr,
        code: &str,
        label: &str,
        proof: Proof<'_>,
    ) -> Result<String, AuthError> {
        let Proof {
            client_key_hex,
            server_nonce,
            client_nonce,
            signature_hex,
        } = proof;
        self.check_rate_limit(source)?;
        self.refresh_clients();

        // Deux origines possibles pour le code : la console de cet agent, ou
        // une demande déposée par `sidgate pair`. Les deux sont comparées sans
        // court-circuit, pour que la durée de l'appel ne dise pas laquelle
        // était ouverte.
        let ticket = read_ticket(&self.ticket_path);
        let from_console = self
            .console_code()
            .is_some_and(|expected| codes_match(expected, code));
        let from_ticket = ticket.as_ref().is_some_and(|t| codes_match(&t.code, code));
        if self.console_code().is_none() && ticket.is_none() {
            self.pairing = None;
            return Err(AuthError::PairingClosed);
        }
        if !(from_console | from_ticket) {
            tracing::warn!(%source, "code d'appairage incorrect");
            return Err(AuthError::Rejected);
        }

        let client_key = decode_client_key(client_key_hex)?;
        let transcript =
            signaling::client_pair_transcript(server_nonce, client_nonce, &client_key.1);
        verify_client_signature(&client_key.0, &transcript, signature_hex)?;

        self.attempts.remove(&source);

        {
            let _lock = RegistryLock::acquire(&self.lock_path);
            self.refresh_clients();
            let now = unix_now();
            self.clients.retain(|c| c.key != client_key_hex);
            self.clients.push(PairedClient {
                key: client_key_hex.to_string(),
                label: sanitize_label(label),
                paired_at: now,
                last_seen: Some(now),
            });
            let _ = self.persist_clients();
        }

        // Le code n'est valable qu'une fois : le conserver ouvert après un
        // appairage réussi laisserait une seconde fenêtre à quiconque l'a vu.
        // La demande n'est retirée qu'une fois le client inscrit : `sidgate
        // pair` lit sa disparition comme « c'est fait ».
        if from_console {
            self.pairing = None;
        }
        if from_ticket {
            let _ = std::fs::remove_file(&self.ticket_path);
        }
        tracing::warn!(%source, label = %sanitize_label(label), "nouveau client appairé");
        Ok(client_key_hex.to_string())
    }

    /// Compte les tentatives par source et refuse au-delà du quota.
    fn check_rate_limit(&mut self, source: IpAddr) -> Result<(), AuthError> {
        let window = self.attempts.entry(source).or_insert(AttemptWindow {
            start: Instant::now(),
            count: 0,
        });
        if window.start.elapsed() >= Duration::from_secs(60) {
            window.start = Instant::now();
            window.count = 0;
        }
        window.count += 1;
        if window.count > self.attempts_per_minute {
            tracing::warn!(%source, "trop de tentatives d'authentification");
            return Err(AuthError::RateLimited);
        }
        Ok(())
    }

    fn persist_clients(&mut self) -> anyhow::Result<()> {
        let store = ClientStore {
            clients: self.clients.clone(),
        };
        write_private(
            &self.clients_path,
            serde_json::to_vec_pretty(&store)?.as_slice(),
        )?;
        self.clients_stamp = stamp_of(&self.clients_path);
        Ok(())
    }
}

/// Dépose une demande d'appairage dans `dir` et renvoie le code à saisir.
///
/// C'est ce qu'exécute `sidgate pair` : l'agent en service n'a pas de console
/// où afficher un code, et n'écoute rien d'autre que le réseau. La demande est
/// un fichier ; l'agent la lit à la prochaine connexion d'un client, la
/// consomme au premier appairage réussi et l'efface à son échéance.
pub fn write_pairing_ticket(dir: &Path, ttl: Duration) -> anyhow::Result<String> {
    std::fs::create_dir_all(dir)?;
    let code = generate_pairing_code()?;
    let ticket = PairingTicket {
        code: code.clone(),
        expires_at: unix_now().saturating_add(ttl.as_secs()),
    };
    write_private(&dir.join(TICKET_FILE), &serde_json::to_vec(&ticket)?)?;
    Ok(code)
}

/// Retire une demande d'appairage. Renvoie `true` s'il y en avait une.
pub fn clear_pairing_ticket(dir: &Path) -> bool {
    std::fs::remove_file(dir.join(TICKET_FILE)).is_ok()
}

/// Une demande d'appairage attend-elle encore dans `dir` ?
pub fn pairing_ticket_pending(dir: &Path) -> bool {
    read_ticket(&dir.join(TICKET_FILE)).is_some()
}

/// Lit la demande d'appairage, si elle existe et n'a pas expiré.
///
/// Une demande expirée ou illisible est effacée au passage : elle ne doit pas
/// rester sur le disque à attendre qu'une horloge reculée la ressuscite.
fn read_ticket(path: &Path) -> Option<PairingTicket> {
    let bytes = std::fs::read(path).ok()?;
    let now = unix_now();
    let ticket = serde_json::from_slice::<PairingTicket>(&bytes)
        .ok()
        .filter(|ticket| (now + 1..=now + MAX_PAIRING_WINDOW_SECS).contains(&ticket.expires_at));
    if ticket.is_none() {
        let _ = std::fs::remove_file(path);
    }
    ticket
}

/// Exclusion entre processus pour un cycle lecture, modification, écriture du
/// registre.
///
/// L'agent et les commandes `revoke` et `pair` réécrivent le même fichier.
/// Sans exclusion, chacun pourrait écrire une liste lue avant la modification
/// de l'autre, et une révocation disparaître. Le verrou est un fichier ouvert
/// sans partage : le système le relâche de lui-même si le processus meurt.
struct RegistryLock(#[allow(dead_code)] Option<std::fs::File>);

impl RegistryLock {
    /// Attend le verrou une demi-seconde au plus.
    ///
    /// Passé ce délai, l'opération se poursuit sans lui : un verrou resté pris
    /// ne doit pas empêcher de révoquer un client.
    fn acquire(path: &Path) -> Self {
        for _ in 0..50 {
            if let Ok(file) = open_exclusive(path) {
                return Self(Some(file));
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        tracing::warn!(path = %path.display(), "verrou du registre indisponible, écriture sans lui");
        Self(None)
    }
}

#[cfg(windows)]
fn open_exclusive(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::windows::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .share_mode(0)
        .open(path)
}

#[cfg(not(windows))]
fn open_exclusive(path: &Path) -> std::io::Result<std::fs::File> {
    std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)
}

/// Date de modification et taille d'un fichier, ou `None` s'il n'existe pas.
fn stamp_of(path: &Path) -> FileStamp {
    let metadata = std::fs::metadata(path).ok()?;
    Some((metadata.modified().ok()?, metadata.len()))
}

/// Décode une clé publique de client et la renvoie avec sa forme binaire.
fn decode_client_key(hex: &str) -> Result<(ClientVerifyingKey, Vec<u8>), AuthError> {
    let bytes = signaling::from_hex(hex).ok_or(AuthError::Rejected)?;
    let key = ClientVerifyingKey::from_sec1_bytes(&bytes).map_err(|_| AuthError::Rejected)?;
    Ok((key, bytes))
}

/// Vérifie une signature ECDSA P-256 au format brut `r || s`.
///
/// C'est ce que produit WebCrypto ; le format DER n'est jamais accepté, pour ne
/// pas ouvrir la porte aux ambiguïtés d'encodage.
fn verify_client_signature(
    key: &ClientVerifyingKey,
    transcript: &[u8],
    signature_hex: &str,
) -> Result<(), AuthError> {
    let bytes = signaling::from_hex(signature_hex).ok_or(AuthError::Rejected)?;
    if bytes.len() != 64 {
        return Err(AuthError::Rejected);
    }
    let signature = ClientSignature::from_slice(&bytes).map_err(|_| AuthError::Rejected)?;
    key.verify(transcript, &signature)
        .map_err(|_| AuthError::Rejected)
}

/// Comparaison à temps constant des codes d'appairage.
///
/// Une comparaison naïve fuirait le nombre de caractères corrects par la durée
/// de l'appel, ce qui ramènerait la recherche de 32^8 à 8 x 32 essais.
fn codes_match(expected: &str, provided: &str) -> bool {
    let expected = normalize_code(expected);
    let provided = normalize_code(provided);
    if expected.len() != provided.len() {
        return false;
    }
    let mut difference = 0u8;
    for (a, b) in expected.bytes().zip(provided.bytes()) {
        difference |= a ^ b;
    }
    difference == 0
}

/// Retire la ponctuation de confort et harmonise la casse.
fn normalize_code(code: &str) -> String {
    code.chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_uppercase())
        .collect()
}

/// Limite le nom d'appareil à quelque chose d'inoffensif dans les journaux.
fn sanitize_label(label: &str) -> String {
    let cleaned: String = label
        .chars()
        .filter(|c| c.is_alphanumeric() || matches!(c, ' ' | '-' | '_' | '.'))
        .take(48)
        .collect();
    if cleaned.trim().is_empty() {
        "appareil sans nom".to_string()
    } else {
        cleaned.trim().to_string()
    }
}

/// Tire une clé Ed25519 depuis le générateur du système.
fn generate_signing_key() -> anyhow::Result<SigningKey> {
    let mut seed = [0u8; 32];
    rand::rngs::OsRng
        .try_fill_bytes(&mut seed)
        .map_err(|e| anyhow::anyhow!("générateur aléatoire indisponible: {e}"))?;
    Ok(SigningKey::from_bytes(&seed))
}

/// Tire un code d'appairage.
///
/// Le rejet des valeurs hors du plus grand multiple de la taille de l'alphabet
/// évite le biais qu'introduirait un simple modulo.
fn generate_pairing_code() -> anyhow::Result<String> {
    let alphabet_len = CODE_ALPHABET.len() as u8;
    let limit = u8::MAX - (u8::MAX % alphabet_len);
    let mut code = String::with_capacity(CODE_LEN + 1);
    let mut byte = [0u8; 1];
    while code.chars().filter(char::is_ascii_alphanumeric).count() < CODE_LEN {
        rand::rngs::OsRng
            .try_fill_bytes(&mut byte)
            .map_err(|e| anyhow::anyhow!("générateur aléatoire indisponible: {e}"))?;
        if byte[0] >= limit {
            continue;
        }
        code.push(CODE_ALPHABET[(byte[0] % alphabet_len) as usize] as char);
        if code.len() == 4 {
            code.push('-');
        }
    }
    Ok(code)
}

/// Écrit un fichier sensible, d'un seul tenant.
///
/// Le contenu passe par un fichier voisin, renommé ensuite : un autre processus
/// qui lit au même instant voit l'ancienne version ou la nouvelle, jamais un
/// fichier à moitié écrit. La confidentialité, elle, vient du répertoire, fermé
/// aux autres comptes à sa création.
fn write_private(path: &Path, contents: &[u8]) -> anyhow::Result<()> {
    // Nom de transit propre au processus : deux écrivains ne se marchent pas
    // dessus, même sans verrou.
    let mut staging = path.as_os_str().to_owned();
    staging.push(format!(".{}.tmp", std::process::id()));
    let staging = PathBuf::from(staging);
    std::fs::write(&staging, contents)?;
    if let Err(e) = std::fs::rename(&staging, path) {
        let _ = std::fs::remove_file(&staging);
        return Err(e.into());
    }
    Ok(())
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::SigningKey as ClientSigningKey;

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "sidgate-identity-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    struct TestClient {
        signing: ClientSigningKey,
        key_hex: String,
        key_bytes: Vec<u8>,
    }

    impl TestClient {
        fn new() -> Self {
            let signing = ClientSigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
            let key_bytes = signing
                .verifying_key()
                .to_encoded_point(false)
                .as_bytes()
                .to_vec();
            Self {
                key_hex: signaling::to_hex(&key_bytes),
                signing,
                key_bytes,
            }
        }

        fn sign(&self, transcript: &[u8]) -> String {
            let signature: ClientSignature = self.signing.sign(transcript);
            signaling::to_hex(&signature.to_bytes())
        }
    }

    const SOURCE: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 2));
    const SERVER_NONCE: [u8; 32] = [1u8; 32];
    const CLIENT_NONCE: [u8; 32] = [2u8; 32];

    fn pair_client(identity: &mut Identity, client: &TestClient) -> Result<String, AuthError> {
        let code = identity.open_pairing(Duration::from_secs(60)).unwrap();
        let transcript =
            signaling::client_pair_transcript(&SERVER_NONCE, &CLIENT_NONCE, &client.key_bytes);
        identity.pair(
            SOURCE,
            &code,
            "Banc d'essai",
            Proof {
                client_key_hex: &client.key_hex,
                server_nonce: &SERVER_NONCE,
                client_nonce: &CLIENT_NONCE,
                signature_hex: &client.sign(&transcript),
            },
        )
    }

    #[test]
    fn identity_persists_across_restarts() {
        let dir = temp_dir("persist");
        let first = Identity::load_or_create(&dir, 10).unwrap();
        let key = first.public_key_hex();
        drop(first);

        let second = Identity::load_or_create(&dir, 10).unwrap();
        assert_eq!(second.public_key_hex(), key);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn pairing_then_authentication_succeeds() {
        let dir = temp_dir("pair-ok");
        let mut identity = Identity::load_or_create(&dir, 100).unwrap();
        let client = TestClient::new();

        pair_client(&mut identity, &client).unwrap();
        assert_eq!(identity.clients().len(), 1);

        let transcript =
            signaling::client_auth_transcript(&SERVER_NONCE, &CLIENT_NONCE, &client.key_bytes);
        identity
            .authenticate(
                SOURCE,
                Proof {
                    client_key_hex: &client.key_hex,
                    server_nonce: &SERVER_NONCE,
                    client_nonce: &CLIENT_NONCE,
                    signature_hex: &client.sign(&transcript),
                },
            )
            .unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn unpaired_client_is_rejected() {
        let dir = temp_dir("unpaired");
        let mut identity = Identity::load_or_create(&dir, 100).unwrap();
        let client = TestClient::new();
        let transcript =
            signaling::client_auth_transcript(&SERVER_NONCE, &CLIENT_NONCE, &client.key_bytes);

        assert_eq!(
            identity.authenticate(
                SOURCE,
                Proof {
                    client_key_hex: &client.key_hex,
                    server_nonce: &SERVER_NONCE,
                    client_nonce: &CLIENT_NONCE,
                    signature_hex: &client.sign(&transcript),
                }
            ),
            Err(AuthError::Rejected)
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn signature_from_another_key_is_rejected() {
        let dir = temp_dir("wrong-key");
        let mut identity = Identity::load_or_create(&dir, 100).unwrap();
        let client = TestClient::new();
        let impostor = TestClient::new();
        pair_client(&mut identity, &client).unwrap();

        let transcript =
            signaling::client_auth_transcript(&SERVER_NONCE, &CLIENT_NONCE, &client.key_bytes);
        assert_eq!(
            identity.authenticate(
                SOURCE,
                Proof {
                    client_key_hex: &client.key_hex,
                    server_nonce: &SERVER_NONCE,
                    client_nonce: &CLIENT_NONCE,
                    signature_hex: &impostor.sign(&transcript),
                }
            ),
            Err(AuthError::Rejected)
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_signature_captured_on_another_session_does_not_replay() {
        let dir = temp_dir("replay");
        let mut identity = Identity::load_or_create(&dir, 100).unwrap();
        let client = TestClient::new();
        pair_client(&mut identity, &client).unwrap();

        let captured = client.sign(&signaling::client_auth_transcript(
            &SERVER_NONCE,
            &CLIENT_NONCE,
            &client.key_bytes,
        ));
        // Nouvelle session : l'agent tire un autre aléa.
        let fresh_nonce = [9u8; 32];
        assert_eq!(
            identity.authenticate(
                SOURCE,
                Proof {
                    client_key_hex: &client.key_hex,
                    server_nonce: &fresh_nonce,
                    client_nonce: &CLIENT_NONCE,
                    signature_hex: &captured,
                }
            ),
            Err(AuthError::Rejected)
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_pairing_signature_cannot_be_used_to_authenticate() {
        let dir = temp_dir("domain");
        let mut identity = Identity::load_or_create(&dir, 100).unwrap();
        let client = TestClient::new();
        pair_client(&mut identity, &client).unwrap();

        let pairing_signature = client.sign(&signaling::client_pair_transcript(
            &SERVER_NONCE,
            &CLIENT_NONCE,
            &client.key_bytes,
        ));
        assert_eq!(
            identity.authenticate(
                SOURCE,
                Proof {
                    client_key_hex: &client.key_hex,
                    server_nonce: &SERVER_NONCE,
                    client_nonce: &CLIENT_NONCE,
                    signature_hex: &pairing_signature,
                }
            ),
            Err(AuthError::Rejected),
            "la séparation de domaine doit empêcher la réutilisation"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn wrong_pairing_code_is_rejected_and_does_not_register() {
        let dir = temp_dir("bad-code");
        let mut identity = Identity::load_or_create(&dir, 100).unwrap();
        let client = TestClient::new();
        identity.open_pairing(Duration::from_secs(60)).unwrap();

        let transcript =
            signaling::client_pair_transcript(&SERVER_NONCE, &CLIENT_NONCE, &client.key_bytes);
        assert_eq!(
            identity.pair(
                SOURCE,
                "0000-0000",
                "x",
                Proof {
                    client_key_hex: &client.key_hex,
                    server_nonce: &SERVER_NONCE,
                    client_nonce: &CLIENT_NONCE,
                    signature_hex: &client.sign(&transcript),
                }
            ),
            Err(AuthError::Rejected)
        );
        assert!(identity.clients().is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn pairing_is_refused_when_no_window_is_open() {
        let dir = temp_dir("closed");
        let mut identity = Identity::load_or_create(&dir, 100).unwrap();
        let client = TestClient::new();
        let transcript =
            signaling::client_pair_transcript(&SERVER_NONCE, &CLIENT_NONCE, &client.key_bytes);

        assert_eq!(
            identity.pair(
                SOURCE,
                "ABCD-EFGH",
                "x",
                Proof {
                    client_key_hex: &client.key_hex,
                    server_nonce: &SERVER_NONCE,
                    client_nonce: &CLIENT_NONCE,
                    signature_hex: &client.sign(&transcript),
                }
            ),
            Err(AuthError::PairingClosed)
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_code_cannot_be_used_twice() {
        let dir = temp_dir("once");
        let mut identity = Identity::load_or_create(&dir, 100).unwrap();
        let first = TestClient::new();
        let second = TestClient::new();

        let code = identity.open_pairing(Duration::from_secs(60)).unwrap();
        let sign = |c: &TestClient| {
            c.sign(&signaling::client_pair_transcript(
                &SERVER_NONCE,
                &CLIENT_NONCE,
                &c.key_bytes,
            ))
        };
        identity
            .pair(
                SOURCE,
                &code,
                "premier",
                Proof {
                    client_key_hex: &first.key_hex,
                    server_nonce: &SERVER_NONCE,
                    client_nonce: &CLIENT_NONCE,
                    signature_hex: &sign(&first),
                },
            )
            .unwrap();
        assert_eq!(
            identity.pair(
                SOURCE,
                &code,
                "second",
                Proof {
                    client_key_hex: &second.key_hex,
                    server_nonce: &SERVER_NONCE,
                    client_nonce: &CLIENT_NONCE,
                    signature_hex: &sign(&second),
                }
            ),
            Err(AuthError::PairingClosed)
        );
        assert_eq!(identity.clients().len(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn expired_pairing_window_closes() {
        let dir = temp_dir("expired");
        let mut identity = Identity::load_or_create(&dir, 100).unwrap();
        identity.open_pairing(Duration::from_millis(1)).unwrap();
        std::thread::sleep(Duration::from_millis(20));
        assert!(!identity.pairing_open());
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn pair_with_code(
        identity: &mut Identity,
        client: &TestClient,
        code: &str,
    ) -> Result<String, AuthError> {
        let transcript =
            signaling::client_pair_transcript(&SERVER_NONCE, &CLIENT_NONCE, &client.key_bytes);
        identity.pair(
            SOURCE,
            code,
            "Banc d'essai",
            Proof {
                client_key_hex: &client.key_hex,
                server_nonce: &SERVER_NONCE,
                client_nonce: &CLIENT_NONCE,
                signature_hex: &client.sign(&transcript),
            },
        )
    }

    fn authenticate(identity: &mut Identity, client: &TestClient) -> Result<String, AuthError> {
        let transcript =
            signaling::client_auth_transcript(&SERVER_NONCE, &CLIENT_NONCE, &client.key_bytes);
        identity.authenticate(
            SOURCE,
            Proof {
                client_key_hex: &client.key_hex,
                server_nonce: &SERVER_NONCE,
                client_nonce: &CLIENT_NONCE,
                signature_hex: &client.sign(&transcript),
            },
        )
    }

    #[test]
    fn a_ticket_dropped_by_another_process_opens_pairing() {
        let dir = temp_dir("ticket");
        let mut identity = Identity::load_or_create(&dir, 100).unwrap();
        assert!(!identity.pairing_open());

        // Ce que fait `sidgate pair`, depuis un autre processus.
        let code = write_pairing_ticket(&dir, Duration::from_secs(60)).unwrap();
        assert!(identity.pairing_open());
        assert!(pairing_ticket_pending(&dir));

        let client = TestClient::new();
        pair_with_code(&mut identity, &client, &code).unwrap();
        assert_eq!(identity.clients().len(), 1);

        // Usage unique : la demande disparaît avec l'appairage.
        assert!(!pairing_ticket_pending(&dir));
        assert!(!identity.pairing_open());
        assert_eq!(
            pair_with_code(&mut identity, &TestClient::new(), &code),
            Err(AuthError::PairingClosed)
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_wrong_code_does_not_consume_the_ticket() {
        let dir = temp_dir("ticket-wrong");
        let mut identity = Identity::load_or_create(&dir, 100).unwrap();
        let code = write_pairing_ticket(&dir, Duration::from_secs(60)).unwrap();

        assert_eq!(
            pair_with_code(&mut identity, &TestClient::new(), "0000-0000"),
            Err(AuthError::Rejected)
        );
        assert!(identity.clients().is_empty());
        assert!(
            pairing_ticket_pending(&dir),
            "une faute de frappe ne ferme pas la fenêtre"
        );
        pair_with_code(&mut identity, &TestClient::new(), &code).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_expired_ticket_is_refused_and_erased() {
        let dir = temp_dir("ticket-expired");
        let mut identity = Identity::load_or_create(&dir, 100).unwrap();
        let ticket = PairingTicket {
            code: "ABCD-EFGH".into(),
            expires_at: unix_now() - 1,
        };
        std::fs::write(dir.join(TICKET_FILE), serde_json::to_vec(&ticket).unwrap()).unwrap();

        assert!(!identity.pairing_open());
        assert!(
            !dir.join(TICKET_FILE).exists(),
            "une demande expirée ne reste pas sur le disque"
        );
        assert_eq!(
            pair_with_code(&mut identity, &TestClient::new(), "ABCD-EFGH"),
            Err(AuthError::PairingClosed)
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_ticket_valid_for_too_long_is_refused_and_erased() {
        // Déposé à la main avec une échéance dans dix ans : `sidgate pair` ne
        // sait pas écrire cela.
        let dir = temp_dir("ticket-eternal");
        let mut identity = Identity::load_or_create(&dir, 100).unwrap();
        let ticket = PairingTicket {
            code: "ABCD-EFGH".into(),
            expires_at: unix_now() + 10 * 365 * 24 * 3600,
        };
        std::fs::write(dir.join(TICKET_FILE), serde_json::to_vec(&ticket).unwrap()).unwrap();

        assert!(!identity.pairing_open());
        assert!(!dir.join(TICKET_FILE).exists());
        assert_eq!(
            pair_with_code(&mut identity, &TestClient::new(), "ABCD-EFGH"),
            Err(AuthError::PairingClosed)
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_registry_lock_excludes_a_second_holder() {
        let dir = temp_dir("lock");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(LOCK_FILE);

        let held = RegistryLock::acquire(&path);
        assert!(held.0.is_some());
        #[cfg(windows)]
        assert!(
            open_exclusive(&path).is_err(),
            "le verrou doit refuser un second détenteur"
        );
        drop(held);
        assert!(
            open_exclusive(&path).is_ok(),
            "et se libérer avec le premier"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_client_revoked_between_two_reads_is_refused() {
        // L'agent a relu le registre, puis une autre invite révoque : la
        // connexion en cours de vérification ne doit ni aboutir ni réinscrire
        // le client en datant sa visite.
        let dir = temp_dir("revoke-race");
        let mut agent = Identity::load_or_create(&dir, 100).unwrap();
        let client = TestClient::new();
        pair_client(&mut agent, &client).unwrap();
        agent.refresh_clients();

        let mut cli = Identity::load_or_create(&dir, 100).unwrap();
        cli.revoke(&client.key_hex).unwrap();

        assert_eq!(authenticate(&mut agent, &client), Err(AuthError::Rejected));
        assert!(Identity::load_or_create(&dir, 100)
            .unwrap()
            .clients()
            .is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_malformed_ticket_opens_nothing() {
        let dir = temp_dir("ticket-garbage");
        let identity = Identity::load_or_create(&dir, 100).unwrap();
        std::fs::write(dir.join(TICKET_FILE), b"{\"code\":\"ABCD-EFGH\"}").unwrap();
        assert!(!identity.pairing_open());
        assert!(!dir.join(TICKET_FILE).exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn closing_pairing_from_the_console_also_withdraws_the_ticket() {
        let dir = temp_dir("ticket-close");
        let mut identity = Identity::load_or_create(&dir, 100).unwrap();
        write_pairing_ticket(&dir, Duration::from_secs(60)).unwrap();
        identity.open_pairing(Duration::from_secs(60)).unwrap();
        identity.close_pairing();
        assert!(!identity.pairing_open());
        assert!(!clear_pairing_ticket(&dir), "il n'y a plus rien à retirer");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_console_window_and_a_ticket_are_independent() {
        let dir = temp_dir("ticket-both");
        let mut identity = Identity::load_or_create(&dir, 100).unwrap();
        let from_console = identity.open_pairing(Duration::from_secs(60)).unwrap();
        let from_ticket = write_pairing_ticket(&dir, Duration::from_secs(60)).unwrap();

        pair_with_code(&mut identity, &TestClient::new(), &from_ticket).unwrap();
        assert!(
            identity.pairing_open(),
            "la fenêtre de la console reste ouverte"
        );
        pair_with_code(&mut identity, &TestClient::new(), &from_console).unwrap();
        assert!(!identity.pairing_open());
        assert_eq!(identity.clients().len(), 2);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_revocation_made_by_another_process_reaches_the_running_agent() {
        let dir = temp_dir("revoke-external");
        let mut agent = Identity::load_or_create(&dir, 100).unwrap();
        let client = TestClient::new();
        pair_client(&mut agent, &client).unwrap();
        authenticate(&mut agent, &client).unwrap();
        assert!(agent.is_authorized(&client.key_hex));

        // `sidgate revoke`, dans un autre processus : sa propre copie du
        // registre, écrite sur le disque.
        let mut cli = Identity::load_or_create(&dir, 100).unwrap();
        assert!(cli.revoke(&client.key_hex).unwrap());

        assert!(!agent.is_authorized(&client.key_hex));
        assert_eq!(authenticate(&mut agent, &client), Err(AuthError::Rejected));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_stale_agent_does_not_resurrect_a_revoked_client() {
        let dir = temp_dir("revoke-stale");
        let mut agent = Identity::load_or_create(&dir, 100).unwrap();
        let (kept, revoked) = (TestClient::new(), TestClient::new());
        pair_client(&mut agent, &kept).unwrap();
        pair_client(&mut agent, &revoked).unwrap();

        let mut cli = Identity::load_or_create(&dir, 100).unwrap();
        cli.revoke(&revoked.key_hex).unwrap();

        // L'agent réécrit le registre à chaque connexion réussie, pour dater
        // la dernière visite : il ne doit pas le faire depuis une copie
        // antérieure à la révocation.
        authenticate(&mut agent, &kept).unwrap();
        let reloaded = Identity::load_or_create(&dir, 100).unwrap();
        assert_eq!(reloaded.clients().len(), 1);
        assert_eq!(reloaded.clients()[0].key, kept.key_hex);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_corrupted_registry_keeps_the_known_clients() {
        let dir = temp_dir("registry-corrupt");
        let mut agent = Identity::load_or_create(&dir, 100).unwrap();
        let client = TestClient::new();
        pair_client(&mut agent, &client).unwrap();

        std::fs::write(dir.join(CLIENTS_FILE), b"{ pas du json").unwrap();
        assert!(agent.is_authorized(&client.key_hex));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn private_files_are_replaced_whole() {
        let dir = temp_dir("atomic");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("secret");
        write_private(&path, b"premier").unwrap();
        write_private(&path, b"second").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"second");
        let leftovers = std::fs::read_dir(&dir).unwrap().count();
        assert_eq!(leftovers, 1, "aucun fichier de transit ne doit rester");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn brute_force_is_rate_limited() {
        let dir = temp_dir("ratelimit");
        let mut identity = Identity::load_or_create(&dir, 3).unwrap();
        let client = TestClient::new();
        let transcript =
            signaling::client_auth_transcript(&SERVER_NONCE, &CLIENT_NONCE, &client.key_bytes);
        let signature = client.sign(&transcript);

        for _ in 0..3 {
            assert_eq!(
                identity.authenticate(
                    SOURCE,
                    Proof {
                        client_key_hex: &client.key_hex,
                        server_nonce: &SERVER_NONCE,
                        client_nonce: &CLIENT_NONCE,
                        signature_hex: &signature,
                    }
                ),
                Err(AuthError::Rejected)
            );
        }
        assert_eq!(
            identity.authenticate(
                SOURCE,
                Proof {
                    client_key_hex: &client.key_hex,
                    server_nonce: &SERVER_NONCE,
                    client_nonce: &CLIENT_NONCE,
                    signature_hex: &signature,
                }
            ),
            Err(AuthError::RateLimited)
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn revocation_removes_access() {
        let dir = temp_dir("revoke");
        let mut identity = Identity::load_or_create(&dir, 100).unwrap();
        let client = TestClient::new();
        pair_client(&mut identity, &client).unwrap();

        assert!(identity.revoke(&client.key_hex).unwrap());
        assert!(!identity.revoke(&client.key_hex).unwrap());

        let transcript =
            signaling::client_auth_transcript(&SERVER_NONCE, &CLIENT_NONCE, &client.key_bytes);
        assert_eq!(
            identity.authenticate(
                SOURCE,
                Proof {
                    client_key_hex: &client.key_hex,
                    server_nonce: &SERVER_NONCE,
                    client_nonce: &CLIENT_NONCE,
                    signature_hex: &client.sign(&transcript),
                }
            ),
            Err(AuthError::Rejected)
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn agent_signature_verifies_against_its_public_key() {
        let dir = temp_dir("agent-sig");
        let identity = Identity::load_or_create(&dir, 10).unwrap();
        let client_key = [7u8; 65];
        let signature_hex =
            identity.sign_agent_transcript(&SERVER_NONCE, &CLIENT_NONCE, &client_key);

        let public = signaling::from_hex_exact::<32>(&identity.public_key_hex()).unwrap();
        let verifying = ed25519_dalek::VerifyingKey::from_bytes(&public).unwrap();
        let signature =
            ed25519_dalek::Signature::from_slice(&signaling::from_hex(&signature_hex).unwrap())
                .unwrap();
        let transcript = signaling::agent_transcript(&SERVER_NONCE, &CLIENT_NONCE, &client_key);
        assert!(ed25519_dalek::Verifier::verify(&verifying, &transcript, &signature).is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn pairing_codes_are_readable_and_unbiased_in_alphabet() {
        for _ in 0..50 {
            let code = generate_pairing_code().unwrap();
            assert_eq!(code.len(), CODE_LEN + 1, "quatre, tiret, quatre");
            assert_eq!(code.as_bytes()[4], b'-');
            for c in code.bytes().filter(u8::is_ascii_alphanumeric) {
                assert!(CODE_ALPHABET.contains(&c), "caractère ambigu: {c}");
            }
        }
    }

    #[test]
    fn codes_compare_ignoring_case_and_punctuation() {
        assert!(codes_match("ABCD-EFGH", "abcdefgh"));
        assert!(codes_match("ABCD-EFGH", "ABCD EFGH"));
        assert!(!codes_match("ABCD-EFGH", "ABCD-EFGJ"));
        assert!(!codes_match("ABCD-EFGH", "ABCD-EFG"));
    }

    #[test]
    fn labels_are_sanitized() {
        assert_eq!(sanitize_label("Pixel 8"), "Pixel 8");
        assert_eq!(sanitize_label("  "), "appareil sans nom");
        assert_eq!(
            sanitize_label("<script>alert(1)</script>"),
            "scriptalert1script"
        );
        assert_eq!(sanitize_label(&"x".repeat(100)).len(), 48);
    }
}
