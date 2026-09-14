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

/// Identité de l'agent et registre des clients.
#[derive(Debug)]
pub struct Identity {
    signing_key: SigningKey,
    clients: Vec<PairedClient>,
    clients_path: PathBuf,
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

        let clients = match std::fs::read_to_string(&clients_path) {
            Ok(text) => serde_json::from_str::<ClientStore>(&text)?.clients,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(e) => return Err(e.into()),
        };

        Ok(Self {
            signing_key,
            clients,
            clients_path,
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

    /// Ferme la fenêtre d'appairage.
    pub fn close_pairing(&mut self) {
        self.pairing = None;
    }

    /// Une fenêtre d'appairage est-elle ouverte à cet instant ?
    pub fn pairing_open(&self) -> bool {
        self.pairing
            .as_ref()
            .is_some_and(|w| w.opened.elapsed() < w.ttl)
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
    pub fn authenticate(
        &mut self,
        source: IpAddr,
        client_key_hex: &str,
        server_nonce: &[u8],
        client_nonce: &[u8],
        signature_hex: &str,
    ) -> Result<String, AuthError> {
        self.check_rate_limit(source)?;

        let client_key = decode_client_key(client_key_hex)?;
        if !self.clients.iter().any(|c| c.key == client_key_hex) {
            return Err(AuthError::Rejected);
        }

        let transcript =
            signaling::client_auth_transcript(server_nonce, client_nonce, &client_key.1);
        verify_client_signature(&client_key.0, &transcript, signature_hex)?;

        let now = unix_now();
        if let Some(client) = self.clients.iter_mut().find(|c| c.key == client_key_hex) {
            client.last_seen = Some(now);
        }
        let _ = self.persist_clients();
        self.attempts.remove(&source);
        Ok(client_key_hex.to_string())
    }

    /// Vérifie un appairage et enregistre le client.
    pub fn pair(
        &mut self,
        source: IpAddr,
        code: &str,
        client_key_hex: &str,
        label: &str,
        server_nonce: &[u8],
        client_nonce: &[u8],
        signature_hex: &str,
    ) -> Result<String, AuthError> {
        self.check_rate_limit(source)?;

        let Some(window) = self.pairing.as_ref() else {
            return Err(AuthError::PairingClosed);
        };
        if window.opened.elapsed() >= window.ttl {
            self.pairing = None;
            return Err(AuthError::PairingClosed);
        }
        if !codes_match(&window.code, code) {
            tracing::warn!(%source, "code d'appairage incorrect");
            return Err(AuthError::Rejected);
        }

        let client_key = decode_client_key(client_key_hex)?;
        let transcript =
            signaling::client_pair_transcript(server_nonce, client_nonce, &client_key.1);
        verify_client_signature(&client_key.0, &transcript, signature_hex)?;

        // Le code n'est valable qu'une fois : le conserver ouvert après un
        // appairage réussi laisserait une seconde fenêtre à quiconque l'a vu.
        self.pairing = None;
        self.attempts.remove(&source);

        let now = unix_now();
        self.clients.retain(|c| c.key != client_key_hex);
        self.clients.push(PairedClient {
            key: client_key_hex.to_string(),
            label: sanitize_label(label),
            paired_at: now,
            last_seen: Some(now),
        });
        let _ = self.persist_clients();
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

    fn persist_clients(&self) -> anyhow::Result<()> {
        let store = ClientStore {
            clients: self.clients.clone(),
        };
        write_private(&self.clients_path, serde_json::to_vec_pretty(&store)?.as_slice())
    }
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

/// Écrit un fichier sensible.
fn write_private(path: &Path, contents: &[u8]) -> anyhow::Result<()> {
    std::fs::write(path, contents)?;
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
    use p256::ecdsa::signature::Signer as _;
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
            &client.key_hex,
            "Banc d'essai",
            &SERVER_NONCE,
            &CLIENT_NONCE,
            &client.sign(&transcript),
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
                &client.key_hex,
                &SERVER_NONCE,
                &CLIENT_NONCE,
                &client.sign(&transcript),
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
                &client.key_hex,
                &SERVER_NONCE,
                &CLIENT_NONCE,
                &client.sign(&transcript)
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
                &client.key_hex,
                &SERVER_NONCE,
                &CLIENT_NONCE,
                &impostor.sign(&transcript)
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
                &client.key_hex,
                &fresh_nonce,
                &CLIENT_NONCE,
                &captured
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
                &client.key_hex,
                &SERVER_NONCE,
                &CLIENT_NONCE,
                &pairing_signature
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
                &client.key_hex,
                "x",
                &SERVER_NONCE,
                &CLIENT_NONCE,
                &client.sign(&transcript)
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
                &client.key_hex,
                "x",
                &SERVER_NONCE,
                &CLIENT_NONCE,
                &client.sign(&transcript)
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
                &first.key_hex,
                "premier",
                &SERVER_NONCE,
                &CLIENT_NONCE,
                &sign(&first),
            )
            .unwrap();
        assert_eq!(
            identity.pair(
                SOURCE,
                &code,
                &second.key_hex,
                "second",
                &SERVER_NONCE,
                &CLIENT_NONCE,
                &sign(&second)
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
                    &client.key_hex,
                    &SERVER_NONCE,
                    &CLIENT_NONCE,
                    &signature
                ),
                Err(AuthError::Rejected)
            );
        }
        assert_eq!(
            identity.authenticate(
                SOURCE,
                &client.key_hex,
                &SERVER_NONCE,
                &CLIENT_NONCE,
                &signature
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
                &client.key_hex,
                &SERVER_NONCE,
                &CLIENT_NONCE,
                &client.sign(&transcript)
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
        let signature = ed25519_dalek::Signature::from_slice(
            &signaling::from_hex(&signature_hex).unwrap(),
        )
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
        assert_eq!(sanitize_label("<script>alert(1)</script>"), "scriptalert1script");
        assert_eq!(sanitize_label(&"x".repeat(100)).len(), 48);
    }
}
