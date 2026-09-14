//! Agent sidgate : capture, encodage matériel, transport WebRTC et injection
//! d'entrées, pour une station Windows.
//!
//! Voir le README pour l'architecture d'ensemble et la matrice de sécurité.

mod config;
mod control;
mod identity;
mod pipeline;
mod service;
mod session;
mod signaling;
mod tls;

use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Duration;

use clap::{Parser, Subcommand};
use parking_lot::Mutex;
use tokio::io::AsyncBufReadExt;

use crate::config::Config;
use crate::identity::Identity;
use crate::signaling::AppState;

/// Passerelle d'accès distant sécurisée.
#[derive(Debug, Parser)]
#[command(name = "sidgate", version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Démarre l'agent et attend une connexion.
    Run {
        /// Ouvre une fenêtre d'appairage dès le démarrage.
        #[arg(long)]
        pair: bool,
    },
    /// Démarre l'agent sans console, tel que le lance le service.
    ///
    /// Masqué : cette forme n'a de sens que pour le superviseur, qui la lance
    /// dans la session interactive.
    #[command(hide = true)]
    Worker,
    /// Installe, retire ou pilote le service Windows.
    Service {
        #[command(subcommand)]
        action: ServiceAction,
    },
    /// Affiche l'identité de l'agent et l'emplacement de ses données.
    Info,
    /// Liste les clients appairés.
    Clients,
    /// Révoque un client par sa clé publique.
    Revoke {
        /// Clé publique du client, telle qu'affichée par `clients`.
        key: String,
    },
}

/// Actions sur le service Windows. Toutes exigent une invite élevée, sauf
/// l'affichage de l'état.
#[derive(Debug, Subcommand)]
enum ServiceAction {
    /// Installe le service en démarrage automatique.
    Install,
    /// Retire le service.
    Uninstall,
    /// Démarre le service.
    Start,
    /// Arrête le service.
    Stop,
    /// Affiche l'état du service et de la session interactive.
    Status,
    /// Point d'entrée du gestionnaire de services.
    ///
    /// Masqué : invoquer cette commande à la main échoue, le processus devant
    /// être démarré par le gestionnaire lui-même.
    #[command(hide = true)]
    Run,
}

fn main() -> anyhow::Result<()> {
    init_tracing();
    install_crypto_provider()?;

    let cli = Cli::parse();

    // Les commandes de service ne touchent pas a la configuration de l'agent :
    // la charger ici ecrirait un fichier par defaut au premier « status », ce
    // qu'une commande de lecture n'a pas a faire.
    if let Some(Command::Service { action }) = &cli.command {
        return match action {
            ServiceAction::Install => service::manager::install(),
            ServiceAction::Uninstall => service::manager::uninstall(),
            ServiceAction::Start => service::manager::start(),
            ServiceAction::Stop => service::manager::stop(),
            ServiceAction::Status => service::manager::status(),
            ServiceAction::Run => service::dispatch(),
        };
    }

    let dir = config::data_dir();
    let config = Config::load_or_create(&dir)?;

    match cli.command.unwrap_or(Command::Run { pair: false }) {
        Command::Run { pair } => run(dir, config, pair, Console::Interactive),
        Command::Worker => run(dir, config, false, Console::None),
        Command::Service { .. } => unreachable!("traite plus haut"),
        Command::Info => info(dir, config),
        Command::Clients => clients(dir, config),
        Command::Revoke { key } => revoke(dir, config, &key),
    }
}

/// L'agent dispose-t-il d'une console avec laquelle dialoguer ?
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Console {
    /// Lancement à la main : bannière, commandes clavier, appairage possible.
    Interactive,
    /// Lancement par le service : personne pour lire ni pour taper.
    None,
}

/// Démarre le serveur et la boucle de commandes console.
///
/// Le `main` reste synchrone et construit le runtime ici : cela garde le
/// démarrage lisible et laisse la possibilité d'un enregistrement en service
/// Windows, qui impose sa propre entrée.
fn run(
    dir: std::path::PathBuf,
    config: Config,
    pair_now: bool,
    console: Console,
) -> anyhow::Result<()> {
    let identity = Identity::load_or_create(&dir, config.security.auth_attempts_per_minute)?;
    let tls = tls::load_or_create(&dir, config.network.bind, &[])?;

    let no_clients = identity.clients().is_empty();
    let state = Arc::new(AppState {
        identity: Mutex::new(identity),
        config: config.clone(),
        busy: AtomicBool::new(false),
    });

    if console == Console::Interactive {
        print_banner(&state, &tls, &dir);

        // Un agent sans client appairé n'est joignable par personne : ouvrir la
        // fenêtre d'emblée évite d'avoir à expliquer une deuxième étape.
        if pair_now || no_clients {
            open_pairing(&state);
        }
    } else if no_clients {
        // Sous service, personne ne peut lire un code : l'appairage se fait en
        // lançant l'agent à la main une première fois.
        tracing::warn!(
            "aucun client appairé ; lancez « sidgate run » depuis une session \
             interactive pour appairer un appareil"
        );
    }

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;

    runtime.block_on(async move {
        let reader = (console == Console::Interactive)
            .then(|| tokio::spawn(console_loop(Arc::clone(&state))));
        let result = signaling::serve(Arc::clone(&state), tls).await;
        if let Some(reader) = reader {
            reader.abort();
        }
        result
    })
}

/// Lit les commandes tapées sur la console de l'hôte.
///
/// L'appairage se déclenche depuis la machine elle-même, jamais depuis le
/// réseau : c'est ce qui garantit qu'un attaquant distant ne peut pas s'inviter,
/// même en connaissant le format du protocole.
async fn console_loop(state: Arc<AppState>) {
    let mut lines = tokio::io::BufReader::new(tokio::io::stdin()).lines();
    while let Ok(Some(line)) = lines.next_line().await {
        match line.trim() {
            "p" | "pair" => open_pairing(&state),
            "c" | "clients" => {
                for client in state.identity.lock().clients() {
                    println!("  {} — {}", client.label, client.key);
                }
            }
            "x" | "cancel" => {
                state.identity.lock().close_pairing();
                println!("fenêtre d'appairage refermée");
            }
            "" => {}
            other => {
                println!("commande inconnue: {other} (p = appairer, x = annuler, c = clients)");
            }
        }
    }
}

fn open_pairing(state: &Arc<AppState>) {
    let ttl = Duration::from_secs(state.config.security.pairing_window_secs);
    match state.identity.lock().open_pairing(ttl) {
        Ok(code) => {
            println!();
            println!("  ┌──────────────────────────────────┐");
            println!("  │  code d'appairage : {code}     │");
            println!("  └──────────────────────────────────┘");
            println!("  valable {} secondes, un seul usage", ttl.as_secs());
            println!();
        }
        Err(e) => eprintln!("appairage impossible: {e}"),
    }
}

fn print_banner(state: &Arc<AppState>, tls: &tls::TlsMaterial, dir: &std::path::Path) {
    let identity = state.identity.lock();
    println!("sidgate {}", env!("CARGO_PKG_VERSION"));
    println!("  données     : {}", dir.display());
    println!(
        "  écoute      : {}://{}:{}",
        if state.config.network.tls { "https" } else { "http" },
        state.config.network.bind,
        state.config.network.port
    );
    println!("  identité    : {}", identity.fingerprint());
    println!("  certificat  : {}", tls.fingerprint);
    println!("  clients     : {}", identity.clients().len());
    println!();
    println!("  tapez « p » puis Entrée pour ouvrir un appairage, « x » pour l'annuler");
    println!();
}

fn info(dir: std::path::PathBuf, config: Config) -> anyhow::Result<()> {
    let identity = Identity::load_or_create(&dir, config.security.auth_attempts_per_minute)?;
    let tls = tls::load_or_create(&dir, config.network.bind, &[])?;
    println!("répertoire de données : {}", dir.display());
    println!("configuration         : {}", dir.join(config::CONFIG_FILE).display());
    println!("clé publique          : {}", identity.public_key_hex());
    println!("empreinte identité    : {}", identity.fingerprint());
    println!("empreinte certificat  : {}", tls.fingerprint);
    println!(
        "écoute                : https://{}:{}",
        config.network.bind, config.network.port
    );
    println!(
        "actions alimentation  : {}",
        if config.security.allow_power_actions {
            "autorisées"
        } else {
            "refusées"
        }
    );
    Ok(())
}

fn clients(dir: std::path::PathBuf, config: Config) -> anyhow::Result<()> {
    let identity = Identity::load_or_create(&dir, config.security.auth_attempts_per_minute)?;
    if identity.clients().is_empty() {
        println!("aucun client appairé");
        return Ok(());
    }
    for client in identity.clients() {
        println!("{}", client.label);
        println!("  clé       : {}", client.key);
        println!("  appairé   : {}", format_unix(client.paired_at));
        println!("  vu le     : {}", client.last_seen.map(format_unix).unwrap_or_else(|| "jamais".into()));
    }
    Ok(())
}

fn revoke(dir: std::path::PathBuf, config: Config, key: &str) -> anyhow::Result<()> {
    let mut identity = Identity::load_or_create(&dir, config.security.auth_attempts_per_minute)?;
    if identity.revoke(key)? {
        println!("client révoqué");
    } else {
        println!("aucun client avec cette clé");
    }
    Ok(())
}

fn format_unix(seconds: u64) -> String {
    time::OffsetDateTime::from_unix_timestamp(seconds as i64)
        .ok()
        .and_then(|t| {
            t.format(&time::format_description::well_known::Rfc3339)
                .ok()
        })
        .unwrap_or_else(|| seconds.to_string())
}

/// Choisit explicitement l'implémentation cryptographique de rustls.
///
/// Plusieurs dépendances tirent des fournisseurs différents — `webrtc` amène
/// `ring`, la pile TLS peut amener `aws-lc-rs`. Sans choix explicite, rustls
/// refuse de deviner et panique au premier handshake, c'est-à-dire au pire
/// moment possible : à la première connexion d'un client.
fn install_crypto_provider() -> anyhow::Result<()> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|_| anyhow::anyhow!("fournisseur cryptographique déjà installé"))
}

fn init_tracing() {
    let filter = tracing_subscriber::EnvFilter::try_from_env("SIDGATE_LOG")
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("sidgate=info,warn"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(true)
        .init();
}
