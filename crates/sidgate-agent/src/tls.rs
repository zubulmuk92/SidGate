//! Certificat TLS de l'agent.
//!
//! Le HTTPS n'est pas une option : `RTCPeerConnection` et WebCrypto n'existent
//! que dans un contexte sécurisé. Servir la PWA en clair sur une adresse IP,
//! fût-elle privée, ne marcherait tout simplement pas.
//!
//! Le certificat est auto-signé et généré au premier démarrage. Son empreinte
//! SHA-256 est affichée sur la console de l'hôte : c'est elle que l'utilisateur
//! compare une fois, à la première visite, avant d'accepter l'avertissement du
//! navigateur. Une fois le nœud Raspberry Pi en place, Caddy fournit un vrai
//! certificat et cet avertissement disparaît.

use std::net::IpAddr;
use std::path::Path;

use sha2::{Digest, Sha256};

/// Nom du fichier de certificat.
const CERT_FILE: &str = "agent.crt";
/// Nom du fichier de clé privée.
const KEY_FILE: &str = "agent.key.pem";

/// Certificat et clé prêts à être servis.
#[derive(Debug, Clone)]
pub struct TlsMaterial {
    /// Certificat au format PEM.
    pub cert_pem: Vec<u8>,
    /// Clé privée au format PEM.
    pub key_pem: Vec<u8>,
    /// Empreinte SHA-256 du certificat, groupée par octets.
    pub fingerprint: String,
}

/// Charge le certificat, ou en fabrique un s'il manque.
///
/// `hosts` liste les noms et adresses sous lesquels l'agent sera joint : au
/// minimum `localhost`, plus l'adresse d'écoute effective, sinon le navigateur
/// refuse le certificat avant même de proposer l'exception.
pub fn load_or_create(dir: &Path, bind: IpAddr, extra_hosts: &[String]) -> anyhow::Result<TlsMaterial> {
    let cert_path = dir.join(CERT_FILE);
    let key_path = dir.join(KEY_FILE);

    if cert_path.exists() && key_path.exists() {
        let cert_pem = std::fs::read(&cert_path)?;
        let key_pem = std::fs::read(&key_path)?;
        let fingerprint = fingerprint_of(&cert_pem)?;
        return Ok(TlsMaterial {
            cert_pem,
            key_pem,
            fingerprint,
        });
    }

    let mut names = vec!["localhost".to_string(), "127.0.0.1".to_string()];
    if !bind.is_unspecified() {
        names.push(bind.to_string());
    }
    names.extend(extra_hosts.iter().cloned());
    names.sort();
    names.dedup();

    let certified = rcgen::generate_simple_self_signed(names.clone())?;
    let cert_pem = certified.cert.pem().into_bytes();
    let key_pem = certified.signing_key.serialize_pem().into_bytes();

    std::fs::create_dir_all(dir)?;
    std::fs::write(&cert_path, &cert_pem)?;
    std::fs::write(&key_path, &key_pem)?;

    let fingerprint = fingerprint_of(&cert_pem)?;
    tracing::info!(hosts = ?names, "certificat auto-signé généré");
    Ok(TlsMaterial {
        cert_pem,
        key_pem,
        fingerprint,
    })
}

/// Calcule l'empreinte SHA-256 du certificat DER contenu dans un PEM.
///
/// L'empreinte porte bien sur le DER, et non sur le texte PEM : c'est ce que
/// les navigateurs affichent, sans quoi la comparaison visuelle serait fausse.
fn fingerprint_of(cert_pem: &[u8]) -> anyhow::Result<String> {
    let der = pem_to_der(cert_pem)
        .ok_or_else(|| anyhow::anyhow!("certificat PEM illisible"))?;
    let digest = Sha256::digest(&der);
    Ok(digest
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(":"))
}

/// Extrait le premier bloc `CERTIFICATE` d'un PEM et le décode en base64.
fn pem_to_der(pem: &[u8]) -> Option<Vec<u8>> {
    let text = std::str::from_utf8(pem).ok()?;
    let body: String = text
        .lines()
        .skip_while(|l| !l.starts_with("-----BEGIN CERTIFICATE-----"))
        .skip(1)
        .take_while(|l| !l.starts_with("-----END CERTIFICATE-----"))
        .collect();
    // Un corps vide signifie qu'aucun bloc n'a été trouvé. Sans ce test,
    // base64 décoderait la chaîne vide sans broncher et l'on calculerait
    // sereinement l'empreinte de rien du tout.
    if body.is_empty() {
        return None;
    }
    data_encoding::BASE64.decode(body.as_bytes()).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("sidgate-tls-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn generates_then_reuses_the_same_certificate() {
        let dir = temp_dir("reuse");
        let bind = IpAddr::from([127, 0, 0, 1]);

        let first = load_or_create(&dir, bind, &[]).unwrap();
        let second = load_or_create(&dir, bind, &[]).unwrap();

        assert_eq!(
            first.fingerprint, second.fingerprint,
            "le certificat ne doit pas changer d'un démarrage à l'autre, \
             sinon l'exception acceptée par l'utilisateur serait invalidée"
        );
        assert_eq!(first.cert_pem, second.cert_pem);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn fingerprint_is_a_sha256_over_the_der() {
        let dir = temp_dir("fingerprint");
        let material = load_or_create(&dir, IpAddr::from([10, 0, 0, 1]), &[]).unwrap();

        let parts: Vec<&str> = material.fingerprint.split(':').collect();
        assert_eq!(parts.len(), 32, "SHA-256 fait 32 octets");
        assert!(parts.iter().all(|p| p.len() == 2));
        assert!(parts
            .iter()
            .all(|p| p.chars().all(|c| c.is_ascii_hexdigit() && !c.is_lowercase())));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn pem_decoding_rejects_garbage() {
        assert!(pem_to_der(b"pas un certificat").is_none());
        assert!(fingerprint_of(b"").is_err());
    }

    #[test]
    fn material_is_valid_pem() {
        let dir = temp_dir("pem");
        let material = load_or_create(&dir, IpAddr::from([127, 0, 0, 1]), &[]).unwrap();
        let cert = String::from_utf8(material.cert_pem).unwrap();
        let key = String::from_utf8(material.key_pem).unwrap();
        assert!(cert.starts_with("-----BEGIN CERTIFICATE-----"));
        assert!(key.contains("PRIVATE KEY"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
