//! Agent sidgate : capture, encodage matériel, transport WebRTC et injection
//! d'entrées, pour une station Windows.
//!
//! Voir le README pour l'architecture d'ensemble et la matrice de sécurité.

mod acl;
mod adapt;
mod config;
mod control;
mod identity;
mod pipeline;
mod process;
mod rtcp_forward;
mod service;
mod session;
mod signaling;
mod tls;

use std::sync::Arc;
use std::time::{Duration, Instant};

use clap::{Parser, Subcommand};
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
    /// Ouvre un appairage sur l'agent en cours d'exécution et affiche le code.
    ///
    /// À utiliser quand l'agent tourne en service, sans console où taper « p ».
    Pair,
    /// Affiche l'identité de l'agent et l'emplacement de ses données.
    Info,
    /// Ferme le répertoire de données aux autres comptes de la machine.
    ///
    /// Fait d'office à la création du répertoire ; utile pour une installation
    /// antérieure, dont le répertoire a hérité de droits trop larges.
    Protect,
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
    let cli = Cli::parse();

    // Le travailleur lancé par le service n'a ni console ni sortie d'erreur :
    // son journal va dans un fichier, sans quoi une panne en service ne
    // laisserait aucune trace à lire.
    let log_file = matches!(cli.command, Some(Command::Worker))
        .then(|| open_log_file(&config::data_dir()))
        .flatten();
    init_tracing(log_file);
    install_crypto_provider()?;
    declare_dpi_awareness();

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
        Command::Pair => pair(dir, config),
        Command::Info => info(dir, config),
        Command::Protect => protect(dir),
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

    if acl::exposure(&dir) == acl::Exposure::Shared {
        tracing::warn!(
            path = %dir.display(),
            "le répertoire de données est accessible à un autre compte que le système, les \
             administrateurs et celui de l'agent ; « sidgate protect » le ferme"
        );
    }

    let no_clients = identity.clients().is_empty();
    let state = Arc::new(AppState::new(identity, config));

    if console == Console::Interactive {
        print_banner(&state, &tls, &dir);

        // Un agent sans client appairé n'est joignable par personne : ouvrir la
        // fenêtre d'emblée évite d'avoir à expliquer une deuxième étape.
        if pair_now || no_clients {
            open_pairing(&state);
        }
    } else if no_clients {
        // Sous service, personne ne peut lire un code ici : il s'obtient
        // depuis une invite, qui le dépose dans le répertoire de données.
        tracing::warn!("aucun client appairé ; lancez « sidgate pair » pour appairer un appareil");
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
        Ok(code) => print_pairing_code(&code, ttl),
        Err(e) => eprintln!("appairage impossible: {e}"),
    }
}

fn print_pairing_code(code: &str, ttl: Duration) {
    println!();
    println!("  ┌──────────────────────────────────┐");
    println!("  │  code d'appairage : {code}    │");
    println!("  └──────────────────────────────────┘");
    println!("  valable {} secondes, un seul usage", ttl.as_secs());
    println!();
}

/// Ouvre un appairage sur l'agent en cours d'exécution, depuis une invite.
///
/// La demande est un fichier déposé dans le répertoire de données : l'agent la
/// découvre à la prochaine connexion d'un client. Rien ne transite par le
/// réseau, et pouvoir écrire dans ce répertoire est précisément ce qui prouve
/// que la demande vient de la machine elle-même.
fn pair(dir: std::path::PathBuf, config: Config) -> anyhow::Result<()> {
    // Vérifie au passage que l'identité et le registre sont lisibles.
    Identity::load_or_create(&dir, config.security.auth_attempts_per_minute)?;
    let since = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let address = std::net::SocketAddr::new(config.network.bind, config.network.port);
    if std::net::TcpStream::connect_timeout(&address, Duration::from_millis(400)).is_err() {
        println!("  aucun agent n'écoute sur {address} : le code ne servira que s'il démarre");
        println!("  avant son échéance ( sidgate service start, ou sidgate run ).");
    }

    let ttl = Duration::from_secs(config.security.pairing_window_secs);
    let code = identity::write_pairing_ticket(&dir, ttl)?;
    print_pairing_code(&code, ttl);
    println!("  en attente de l'appareil… ( Ctrl+C pour annuler )");

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let outcome = runtime.block_on(async {
        tokio::select! {
            outcome = wait_for_pairing(&dir, &config, since, ttl) => outcome,
            _ = tokio::signal::ctrl_c() => PairingOutcome::Cancelled,
        }
    });

    // Quelle que soit l'issue, le code ne doit pas lui survivre.
    identity::clear_pairing_ticket(&dir);
    match outcome {
        PairingOutcome::Paired(label) => println!("  appareil « {label} » appairé"),
        PairingOutcome::Expired => println!("  code expiré sans avoir été utilisé"),
        PairingOutcome::Cancelled => println!("  appairage annulé"),
    }
    Ok(())
}

enum PairingOutcome {
    Paired(String),
    Expired,
    Cancelled,
}

/// Attend que la demande déposée soit consommée par l'agent, ou qu'elle expire.
async fn wait_for_pairing(
    dir: &std::path::Path,
    config: &Config,
    since: u64,
    ttl: Duration,
) -> PairingOutcome {
    let deadline = Instant::now() + ttl;
    // Un appareil appairé depuis le dépôt de la demande. La date, et non la
    // nouveauté de la clé : un appareil déjà connu peut s'appairer de nouveau.
    let newcomer = || {
        Identity::load_or_create(dir, config.security.auth_attempts_per_minute)
            .ok()?
            .clients()
            .iter()
            .find(|client| client.paired_at >= since)
            .map(|client| client.label.clone())
    };

    while Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(500)).await;
        if let Some(label) = newcomer() {
            return PairingOutcome::Paired(label);
        }
        if !identity::pairing_ticket_pending(dir) {
            // Demande disparue sans client inscrit : expirée ou retirée.
            return PairingOutcome::Expired;
        }
    }
    newcomer().map_or(PairingOutcome::Expired, PairingOutcome::Paired)
}

/// Ferme le répertoire de données aux autres comptes de la machine.
fn protect(dir: std::path::PathBuf) -> anyhow::Result<()> {
    acl::restrict(&dir)?;
    // Une demande d'appairage déposée avant la fermeture a pu l'être par
    // n'importe qui : elle ne doit pas lui survivre.
    if identity::clear_pairing_ticket(&dir) {
        println!("une demande d'appairage en attente a été retirée.");
    }
    println!("répertoire fermé aux autres comptes : {}", dir.display());
    println!("y accèdent désormais le système, les administrateurs et le compte courant,");
    println!("qui en est propriétaire. Vérifiez la liste des appareils : sidgate clients");
    Ok(())
}

fn print_banner(state: &Arc<AppState>, tls: &tls::TlsMaterial, dir: &std::path::Path) {
    let identity = state.identity.lock();
    println!("sidgate {}", env!("CARGO_PKG_VERSION"));
    println!("  données     : {}", dir.display());
    println!(
        "  écoute      : {}://{}:{}",
        if state.config.network.tls {
            "https"
        } else {
            "http"
        },
        state.config.network.bind,
        state.config.network.port
    );
    println!("  identité    : {}", identity.fingerprint());
    println!("  certificat  : {}", tls.fingerprint);
    println!("  clients     : {}", identity.clients().len());
    println!();
    println!("  tapez « p » puis Entrée pour ouvrir un appairage, « x » pour l'annuler,");
    println!("  « c » pour lister les appareils autorisés");
    println!();
}

fn info(dir: std::path::PathBuf, config: Config) -> anyhow::Result<()> {
    let identity = Identity::load_or_create(&dir, config.security.auth_attempts_per_minute)?;
    let tls = tls::load_or_create(&dir, config.network.bind, &[])?;
    println!("répertoire de données : {}", dir.display());
    println!(
        "accès au répertoire   : {}",
        match acl::exposure(&dir) {
            acl::Exposure::Private => "réservé au système, aux administrateurs et à son compte",
            acl::Exposure::Shared =>
                "OUVERT à un autre compte — fermez-le avec « sidgate protect »",
            acl::Exposure::Unknown => "indéterminé",
        }
    );
    println!(
        "configuration         : {}",
        dir.join(config::CONFIG_FILE).display()
    );
    println!("clé publique          : {}", identity.public_key_hex());
    println!("empreinte identité    : {}", identity.fingerprint());
    println!("empreinte certificat  : {}", tls.fingerprint);
    println!(
        "écoute                : {}://{}:{}",
        if config.network.tls { "https" } else { "http" },
        config.network.bind,
        config.network.port
    );
    let yes_no = |value: bool| if value { "oui" } else { "non" };
    let security = &config.security;
    println!("clients appairés      : {}", identity.clients().len());
    println!("souris et clavier     : {}", yes_no(security.allow_input));
    println!(
        "veille et extinction  : {}",
        yes_no(security.allow_power_actions)
    );
    println!(
        "lecture presse-papiers: {}",
        yes_no(security.allow_clipboard)
    );
    println!(
        "verrouillage à la fin : {}",
        yes_no(security.lock_on_disconnect)
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
        println!(
            "  vu le     : {}",
            client
                .last_seen
                .map(format_unix)
                .unwrap_or_else(|| "jamais".into())
        );
    }
    Ok(())
}

fn revoke(dir: std::path::PathBuf, config: Config, key: &str) -> anyhow::Result<()> {
    let mut identity = Identity::load_or_create(&dir, config.security.auth_attempts_per_minute)?;
    if identity.revoke(key)? {
        println!("client révoqué ; une session en cours de ce client se ferme sous cinq secondes");
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

/// Déclare le processus conscient de la densité de chaque écran.
///
/// Sans cette déclaration, Windows lui présente une géométrie *virtualisée* :
/// les coordonnées des écrans sont remises à l'échelle comme si tous avaient la
/// densité du principal. La capture, elle, livre toujours des pixels réels. Sur
/// un poste mêlant un écran à 100 % et un autre à 150 %, les deux repères ne
/// coïncideraient plus et un clic distant tomberait à côté.
fn declare_dpi_awareness() {
    #[cfg(windows)]
    {
        use windows::Win32::UI::HiDpi::{
            SetProcessDpiAwarenessContext, DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2,
        };
        // SAFETY: appel sans pointeur, à faire avant toute fenêtre — l'agent
        // n'en crée aucune.
        let declared =
            unsafe { SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2) };
        if let Err(e) = declared {
            tracing::debug!(error = %e, "conscience de la densité d'écran non déclarée");
        }
    }
}

/// Nom du journal du travailleur, dans le répertoire de données.
const LOG_FILE: &str = "sidgate.log";
/// Taille au-delà de laquelle le journal est archivé au démarrage suivant.
const LOG_ROTATE_BYTES: u64 = 2 * 1024 * 1024;

/// Ouvre le journal du travailleur en ajout, après l'avoir archivé s'il a trop
/// grossi.
///
/// Une seule archive est conservée : deux fichiers bornent l'espace occupé
/// sans qu'il y ait de tâche de purge à faire tourner.
fn open_log_file(dir: &std::path::Path) -> Option<std::fs::File> {
    let _ = acl::create_private_dir(dir);
    let path = dir.join(LOG_FILE);
    if std::fs::metadata(&path).is_ok_and(|m| m.len() > LOG_ROTATE_BYTES) {
        let _ = std::fs::rename(&path, dir.join(format!("{LOG_FILE}.1")));
    }
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .ok()
}

/// Filtre de journalisation appliqué sans `SIDGATE_LOG`.
///
/// Trois modules de la pile WebRTC émettent un avertissement à chaque ouverture
/// de session, sur des situations normales pour un agent qui répond sans
/// connaître d'avance l'adresse du client. Ils sont ramenés au niveau erreur :
/// un journal où chaque session laisse trois fausses alertes apprend à ne plus
/// lire les vraies.
const DEFAULT_LOG_FILTER: &str =
    "warn,sidgate=info,rtc_ice::agent=error,rtc_sctp::endpoint=error,rtc_dtls::config=error";

fn init_tracing(log_file: Option<std::fs::File>) {
    let filter = tracing_subscriber::EnvFilter::try_from_env("SIDGATE_LOG")
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(DEFAULT_LOG_FILTER));
    let builder = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(true);
    match log_file {
        Some(file) => builder
            .with_ansi(false)
            .with_writer(std::sync::Mutex::new(file))
            .init(),
        // Sur la sortie d'erreur : la sortie standard reste celle des
        // commandes, qu'un script peut lire sans y trouver de journal.
        None => builder.with_writer(std::io::stderr).init(),
    }
}
