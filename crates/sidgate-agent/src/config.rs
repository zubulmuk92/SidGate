//! Configuration et emplacement des données persistantes.
//!
//! Tout est refusé par défaut : les actions d'alimentation sont désactivées et
//! l'écoute se limite à la boucle locale tant que la configuration n'a pas été
//! élargie explicitement. Un agent installé et jamais configuré n'expose rien.

use std::net::IpAddr;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sidgate_proto::control::QualityPreset;

/// Nom du fichier de configuration dans le répertoire de données.
pub const CONFIG_FILE: &str = "sidgate.toml";

/// Configuration complète de l'agent.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    /// Écoute réseau et signalisation.
    pub network: NetworkConfig,
    /// Capture et encodage.
    pub video: VideoConfig,
    /// Ce que l'agent s'autorise à faire.
    pub security: SecurityConfig,
}

/// Écoute réseau.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct NetworkConfig {
    /// Adresse d'écoute.
    ///
    /// Vaut la boucle locale par défaut. En production, on y met l'adresse de
    /// l'interface WireGuard : l'agent n'est alors joignable que depuis le
    /// tunnel, et aucune écoute n'existe sur l'interface physique.
    pub bind: IpAddr,
    /// Port d'écoute HTTPS et WSS.
    pub port: u16,
    /// Servir en TLS.
    ///
    /// Le désactiver n'est accepté que sur une adresse de boucle locale, et
    /// n'a d'intérêt que pour le développement : `http://localhost` est un
    /// contexte sécurisé au sens de la spécification, donc WebRTC et WebCrypto
    /// y fonctionnent sans certificat à accepter. Sur toute autre adresse, le
    /// navigateur refuserait purement et simplement d'ouvrir une connexion
    /// pair-à-pair.
    pub tls: bool,
    /// Serveurs STUN pour la collecte de candidats ICE.
    ///
    /// Vide par défaut : à l'intérieur d'un maillage WireGuard, les candidats
    /// hôtes suffisent et interroger un serveur public divulguerait l'existence
    /// de la machine.
    pub stun_servers: Vec<String>,
}

/// Capture et encodage.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct VideoConfig {
    /// Index de la sortie vidéo à dupliquer.
    pub output: u32,
    /// Cadence maximale, en images par seconde.
    pub framerate: u32,
    /// Palier de qualité initial.
    pub quality: QualityPreset,
}

/// Garde-fous de sécurité.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SecurityConfig {
    /// Autoriser `sleep`, `reboot` et `shutdown`.
    pub allow_power_actions: bool,
    /// Autoriser l'injection de souris et de clavier.
    pub allow_input: bool,
    /// Verrouiller la session dès la perte du transport.
    pub lock_on_disconnect: bool,
    /// Durée pendant laquelle un code d'appairage reste valable, en secondes.
    pub pairing_window_secs: u64,
    /// Tentatives d'authentification tolérées par minute et par adresse.
    pub auth_attempts_per_minute: u32,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            network: NetworkConfig::default(),
            video: VideoConfig::default(),
            security: SecurityConfig::default(),
        }
    }
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            bind: IpAddr::from([127, 0, 0, 1]),
            port: 8443,
            tls: true,
            stun_servers: Vec::new(),
        }
    }
}

impl Default for VideoConfig {
    fn default() -> Self {
        Self {
            output: 0,
            framerate: 60,
            quality: QualityPreset::Balanced,
        }
    }
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            allow_power_actions: false,
            allow_input: true,
            lock_on_disconnect: true,
            pairing_window_secs: 120,
            auth_attempts_per_minute: 10,
        }
    }
}

impl Config {
    /// Charge la configuration, ou écrit celle par défaut si le fichier est absent.
    pub fn load_or_create(dir: &Path) -> anyhow::Result<Self> {
        let path = dir.join(CONFIG_FILE);
        if !path.exists() {
            let config = Self::default();
            std::fs::create_dir_all(dir)?;
            std::fs::write(&path, toml::to_string_pretty(&config)?)?;
            tracing::info!(path = %path.display(), "configuration par défaut écrite");
            return Ok(config);
        }
        let text = std::fs::read_to_string(&path)?;
        let config: Self = toml::from_str(&text)?;
        config.validate()?;
        Ok(config)
    }

    /// Vérifie la cohérence des valeurs chargées.
    fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(self.network.port != 0, "le port d'écoute ne peut être nul");
        anyhow::ensure!(
            (1..=240).contains(&self.video.framerate),
            "la cadence doit être comprise entre 1 et 240 images par seconde"
        );
        anyhow::ensure!(
            self.security.pairing_window_secs >= 10,
            "une fenêtre d'appairage de moins de 10 secondes est inutilisable"
        );
        anyhow::ensure!(
            self.network.tls || self.network.bind.is_loopback(),
            "servir en clair n'est autorisé que sur la boucle locale ; sur {} un              navigateur refuserait WebRTC faute de contexte sécurisé",
            self.network.bind
        );
        Ok(())
    }
}

/// Détermine le répertoire des données de l'agent.
///
/// `SIDGATE_DATA_DIR` l'emporte sur tout, ce qui permet de faire tourner
/// plusieurs instances de test côte à côte. Sinon `%PROGRAMDATA%\sidgate`, qui
/// survit au changement d'utilisateur — nécessaire une fois l'agent enregistré
/// en service — avec repli sur `%LOCALAPPDATA%` quand il n'est pas accessible
/// en écriture, typiquement en développement sans élévation.
pub fn data_dir() -> PathBuf {
    if let Some(dir) = std::env::var_os("SIDGATE_DATA_DIR") {
        return PathBuf::from(dir);
    }
    for key in ["ProgramData", "LOCALAPPDATA", "HOME"] {
        if let Some(base) = std::env::var_os(key) {
            let candidate = PathBuf::from(base).join("sidgate");
            if std::fs::create_dir_all(&candidate).is_ok() {
                return candidate;
            }
        }
    }
    PathBuf::from("sidgate-data")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_closed() {
        let config = Config::default();
        assert!(
            !config.security.allow_power_actions,
            "les actions d'alimentation doivent être refusées par défaut"
        );
        assert!(config.security.lock_on_disconnect);
        assert!(
            config.network.bind.is_loopback(),
            "l'écoute par défaut ne doit pas sortir de la machine"
        );
        assert!(
            config.network.stun_servers.is_empty(),
            "aucun serveur tiers ne doit être contacté par défaut"
        );
    }

    #[test]
    fn defaults_roundtrip_through_toml() {
        let config = Config::default();
        let text = toml::to_string_pretty(&config).unwrap();
        assert_eq!(toml::from_str::<Config>(&text).unwrap(), config);
    }

    #[test]
    fn unknown_keys_are_rejected() {
        let text = "[security]\nallow_everything = true\n";
        assert!(toml::from_str::<Config>(text).is_err());
    }

    #[test]
    fn partial_files_keep_the_secure_defaults() {
        let config: Config = toml::from_str("[network]\nport = 9000\n").unwrap();
        assert_eq!(config.network.port, 9000);
        assert!(!config.security.allow_power_actions);
        assert_eq!(config.video.framerate, 60);
    }

    #[test]
    fn plain_http_is_confined_to_loopback() {
        let mut config = Config::default();
        config.network.tls = false;
        assert!(config.validate().is_ok(), "la boucle locale reste permise");

        config.network.bind = IpAddr::from([10, 0, 0, 5]);
        assert!(
            config.validate().is_err(),
            "servir en clair sur une adresse routable doit être refusé"
        );
    }

    #[test]
    fn tls_is_on_by_default() {
        assert!(Config::default().network.tls);
    }

    #[test]
    fn validation_rejects_impossible_values() {
        let mut config = Config::default();
        config.video.framerate = 0;
        assert!(config.validate().is_err());

        let mut config = Config::default();
        config.network.port = 0;
        assert!(config.validate().is_err());

        let mut config = Config::default();
        config.security.pairing_window_secs = 1;
        assert!(config.validate().is_err());
    }

    #[test]
    fn load_or_create_writes_then_reads_back() {
        let dir = std::env::temp_dir().join(format!("sidgate-config-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);

        let created = Config::load_or_create(&dir).unwrap();
        assert!(dir.join(CONFIG_FILE).exists());
        let reloaded = Config::load_or_create(&dir).unwrap();
        assert_eq!(created, reloaded);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
