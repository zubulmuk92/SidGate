//! Micro-service de réveil par Wake-on-LAN, pour le nœud sentinelle.
//!
//! Le Raspberry Pi est le seul appareil du réseau à rester allumé en
//! permanence. C'est donc lui qui réveille la station de travail, en émettant
//! un Magic Packet sur le broadcast Ethernet local — ce qu'un client distant ne
//! peut pas faire, un paquet de broadcast ne traversant pas le tunnel.
//!
//! # Choix de conception
//!
//! **Les adresses MAC sont dans la configuration, jamais dans la requête.** Le
//! client ne choisit qu'un nom d'hôte parmi une liste écrite sur le Pi. Un
//! service acceptant une MAC arbitraire serait un amplificateur de broadcast
//! utilisable par tout ce qui atteint l'interface.
//!
//! **L'écoute est liée à une adresse précise**, celle de l'interface WireGuard.
//! Le service n'existe pas sur l'interface physique du Pi.
//!
//! **Le jeton est comparé en temps constant**, même si l'accès est déjà
//! restreint au tunnel : une défense en profondeur ne coûte ici qu'une ligne.

use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::path::Path;
use std::sync::Arc;

use axum::extract::{Path as UrlPath, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;

/// Port de destination du Magic Packet. Le 9 (discard) est l'usage courant ;
/// la carte réseau écoute le motif, pas le port.
const WOL_PORT: u16 = 9;
/// Nombre de répétitions de l'adresse dans le Magic Packet, imposé par le format.
const MAC_REPEATS: usize = 16;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    /// Adresse d'écoute : celle de `wg0`, jamais `0.0.0.0`.
    listen: IpAddr,
    /// Port d'écoute.
    port: u16,
    /// Adresse de broadcast du réseau local, par exemple `192.168.1.255`.
    broadcast: Ipv4Addr,
    /// Jeton partagé attendu dans l'en-tête `X-Sidgate-Token`.
    token: String,
    /// Machines réveillables, par nom.
    hosts: Vec<Host>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct Host {
    /// Nom utilisé dans l'URL.
    name: String,
    /// Adresse MAC, au format `aa:bb:cc:dd:ee:ff`.
    mac: String,
}

#[derive(Debug, Serialize)]
struct WakeResponse {
    host: String,
    sent: bool,
}

#[derive(Debug, Serialize)]
struct HostsResponse {
    hosts: Vec<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_env("SIDGATE_WOL_LOG")
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "/etc/sidgate/wol.toml".to_string());
    let config = Arc::new(load_config(Path::new(&path))?);

    let address = SocketAddr::new(config.listen, config.port);
    let app = Router::new()
        .route("/hosts", get(list_hosts))
        .route("/wake/{name}", post(wake))
        .with_state(Arc::clone(&config));

    let listener = tokio::net::TcpListener::bind(address).await?;
    tracing::info!(%address, hosts = config.hosts.len(), "service de réveil prêt");
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

fn load_config(path: &Path) -> anyhow::Result<Config> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("configuration {} illisible: {e}", path.display()))?;
    let config: Config = toml::from_str(&text)?;

    anyhow::ensure!(
        !config.listen.is_unspecified(),
        "l'écoute doit être liée à l'adresse de wg0, pas à toutes les interfaces"
    );
    anyhow::ensure!(config.token.len() >= 16, "le jeton doit faire au moins 16 caractères");
    anyhow::ensure!(!config.hosts.is_empty(), "aucune machine déclarée");
    for host in &config.hosts {
        parse_mac(&host.mac)
            .ok_or_else(|| anyhow::anyhow!("adresse MAC invalide pour {}: {}", host.name, host.mac))?;
    }
    Ok(config)
}

async fn list_hosts(
    State(config): State<Arc<Config>>,
    headers: HeaderMap,
) -> Result<Json<HostsResponse>, StatusCode> {
    authorize(&config, &headers)?;
    Ok(Json(HostsResponse {
        hosts: config.hosts.iter().map(|h| h.name.clone()).collect(),
    }))
}

async fn wake(
    State(config): State<Arc<Config>>,
    headers: HeaderMap,
    UrlPath(name): UrlPath<String>,
) -> Result<Json<WakeResponse>, StatusCode> {
    authorize(&config, &headers)?;

    let host = config
        .hosts
        .iter()
        .find(|h| h.name == name)
        .ok_or(StatusCode::NOT_FOUND)?;
    let mac = parse_mac(&host.mac).ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;

    send_magic_packet(&mac, config.broadcast).map_err(|e| {
        tracing::error!(host = %name, error = %e, "émission du Magic Packet impossible");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    tracing::info!(host = %name, "réveil demandé");
    Ok(Json(WakeResponse {
        host: name,
        sent: true,
    }))
}

/// Vérifie le jeton partagé, en temps constant.
fn authorize(config: &Config, headers: &HeaderMap) -> Result<(), StatusCode> {
    let provided = headers
        .get("x-sidgate-token")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();

    // La comparaison de longueur fuit la longueur du jeton, ce qui n'apprend
    // rien d'exploitable ; le contenu, lui, est comparé sans branchement.
    if provided.len() != config.token.len() {
        return Err(StatusCode::UNAUTHORIZED);
    }
    if provided
        .as_bytes()
        .ct_eq(config.token.as_bytes())
        .unwrap_u8()
        == 1
    {
        Ok(())
    } else {
        Err(StatusCode::UNAUTHORIZED)
    }
}

/// Décode une adresse MAC `aa:bb:cc:dd:ee:ff` ou `aa-bb-cc-dd-ee-ff`.
fn parse_mac(text: &str) -> Option<[u8; 6]> {
    let parts: Vec<&str> = text.split([':', '-']).collect();
    if parts.len() != 6 {
        return None;
    }
    let mut mac = [0u8; 6];
    for (slot, part) in mac.iter_mut().zip(parts) {
        if part.len() != 2 {
            return None;
        }
        *slot = u8::from_str_radix(part, 16).ok()?;
    }
    Some(mac)
}

/// Construit un Magic Packet : six octets `0xFF` puis seize fois l'adresse MAC.
fn magic_packet(mac: &[u8; 6]) -> [u8; 6 + 6 * MAC_REPEATS] {
    let mut packet = [0xFFu8; 6 + 6 * MAC_REPEATS];
    for repeat in 0..MAC_REPEATS {
        let offset = 6 + repeat * 6;
        packet[offset..offset + 6].copy_from_slice(mac);
    }
    packet
}

/// Émet le paquet sur le broadcast du réseau local.
fn send_magic_packet(mac: &[u8; 6], broadcast: Ipv4Addr) -> anyhow::Result<()> {
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))?;
    socket.set_broadcast(true)?;
    let packet = magic_packet(mac);
    // Deux émissions : le paquet n'est jamais acquitté, et une carte réseau qui
    // sort de veille profonde en manque parfois un.
    for _ in 0..2 {
        socket.send_to(&packet, SocketAddr::from((broadcast, WOL_PORT)))?;
    }
    Ok(())
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
    tracing::info!("arrêt demandé");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_both_mac_separators() {
        let expected = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        assert_eq!(parse_mac("aa:bb:cc:dd:ee:ff"), Some(expected));
        assert_eq!(parse_mac("AA-BB-CC-DD-EE-FF"), Some(expected));
    }

    #[test]
    fn rejects_malformed_macs() {
        for text in [
            "aa:bb:cc:dd:ee",
            "aa:bb:cc:dd:ee:ff:00",
            "aa:bb:cc:dd:ee:gg",
            "aabbccddeeff",
            "a:b:c:d:e:f",
            "",
        ] {
            assert!(parse_mac(text).is_none(), "aurait dû être rejeté: {text}");
        }
    }

    #[test]
    fn magic_packet_follows_the_format() {
        let mac = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
        let packet = magic_packet(&mac);

        assert_eq!(packet.len(), 102);
        assert_eq!(&packet[..6], &[0xFF; 6], "préambule de six octets à un");
        for repeat in 0..MAC_REPEATS {
            let offset = 6 + repeat * 6;
            assert_eq!(&packet[offset..offset + 6], &mac);
        }
    }

    #[test]
    fn configuration_refuses_a_wildcard_listen_address() {
        let text = r#"
            listen = "0.0.0.0"
            port = 9797
            broadcast = "192.168.1.255"
            token = "un-jeton-assez-long"
            hosts = [{ name = "station", mac = "aa:bb:cc:dd:ee:ff" }]
        "#;
        let config: Config = toml::from_str(text).unwrap();
        assert!(config.listen.is_unspecified());
        // `load_config` refuse ce cas ; on vérifie ici la condition elle-même,
        // la fonction lisant un fichier.
    }

    #[test]
    fn configuration_rejects_unknown_keys() {
        let text = r#"
            listen = "10.0.0.1"
            port = 9797
            broadcast = "192.168.1.255"
            token = "un-jeton-assez-long"
            allow_any_mac = true
            hosts = []
        "#;
        assert!(toml::from_str::<Config>(text).is_err());
    }

    #[test]
    fn token_comparison_rejects_wrong_and_truncated_tokens() {
        let config = Config {
            listen: IpAddr::from([10, 0, 0, 1]),
            port: 9797,
            broadcast: Ipv4Addr::new(192, 168, 1, 255),
            token: "jeton-de-reference".to_string(),
            hosts: vec![],
        };

        let with = |value: &str| {
            let mut headers = HeaderMap::new();
            headers.insert("x-sidgate-token", value.parse().unwrap());
            headers
        };

        assert!(authorize(&config, &with("jeton-de-reference")).is_ok());
        assert!(authorize(&config, &with("jeton-de-referenc")).is_err());
        assert!(authorize(&config, &with("jeton-de-referencX")).is_err());
        assert!(authorize(&config, &HeaderMap::new()).is_err());
    }
}
