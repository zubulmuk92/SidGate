//! Chaîne capture → encodage, sur son propre thread.
//!
//! Le device D3D11 et la transformation Media Foundation ne sont ni `Send` ni
//! `Sync` : ils vivent sur un thread dédié, créé à l'ouverture d'une session et
//! détruit à sa fermeture. Rien n'est alloué en dehors d'une session — c'est ce
//! qui permet de tenir 0,0 % de CPU au repos, puisqu'il n'y a alors littéralement
//! aucune boucle en cours.
//!
//! Seuls des octets déjà compressés franchissent la frontière de thread, avec
//! trois valeurs minuscules que le client doit connaître : la position du
//! curseur, sa forme, et la géométrie du bureau.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, Sender, TryRecvError};
use std::sync::Arc;
use std::time::{Duration, Instant};

use sidgate_capture::{
    CaptureError, DesktopInfo, FrameSource, FrameStatus, PointerShape, PointerState,
};
use sidgate_encode::{EncodedFrame, EncoderConfig, Submission};
use tokio::sync::watch;

use crate::config::VideoConfig;

/// Délai d'attente d'une nouvelle image.
///
/// L'appel rend la main dès qu'une image est présentée ; ce délai ne borne que
/// l'attente sur un bureau immobile, où il fixe la réactivité aux commandes et
/// le rythme des remontées de télémétrie.
const ACQUIRE_TIMEOUT: Duration = Duration::from_millis(100);

/// Profondeur de la file de sortie.
///
/// Volontairement minuscule : accumuler des images encodées, c'est accumuler de
/// la latence. Au-delà, on jette — le client préfère toujours l'image suivante.
pub const FRAME_QUEUE_DEPTH: usize = 3;

/// Images écartées d'affilée en attendant une image clé avant de renoncer.
///
/// Deux secondes à 60 images par seconde. Un encodeur qui ignore la demande
/// d'image clé ne doit pas figer l'écran pour toujours : passé ce délai, mieux
/// vaut une image abîmée qu'une image arrêtée.
const KEYFRAME_PATIENCE: u32 = 120;

/// Ce que le thread de capture publie en dehors de la vidéo.
///
/// Trois valeurs « dernière écriture gagnante » : seul l'état courant compte,
/// et un lecteur en retard ne veut pas rejouer l'historique.
#[derive(Debug, Clone)]
pub struct PipelineFeedback {
    /// Position du curseur.
    pub pointer: watch::Receiver<PointerState>,
    /// Forme du curseur, absente tant que le compositeur n'en a livré aucune.
    pub shape: watch::Receiver<Option<Arc<PointerShape>>>,
    /// Géométrie du bureau capturé, qui change avec la résolution de l'hôte.
    pub desktop: watch::Receiver<DesktopInfo>,
}

/// Côté écriture de [`PipelineFeedback`], détenu par le thread de capture.
struct FeedbackSink {
    pointer: watch::Sender<PointerState>,
    shape: watch::Sender<Option<Arc<PointerShape>>>,
    desktop: watch::Sender<DesktopInfo>,
}

impl FeedbackSink {
    /// Publie ce qui a changé depuis le dernier tour.
    fn publish(&self, capturer: &mut sidgate_capture::Capturer) {
        let pointer = capturer.pointer();
        self.pointer.send_if_modified(|current| {
            let changed = *current != pointer;
            *current = pointer;
            changed
        });
        if let Some(shape) = capturer.take_pointer_shape() {
            self.shape.send_replace(Some(Arc::new(shape)));
        }
    }

    fn publish_desktop(&self, desktop: DesktopInfo) {
        self.desktop.send_if_modified(|current| {
            let changed = *current != desktop;
            *current = desktop;
            changed
        });
    }
}

/// Garde la chaîne de références de l'encodeur intacte côté client.
///
/// Le flux n'a pas d'images clés périodiques : chaque image s'appuie sur la
/// précédente. En écarter une après encodage — file pleine — casse donc toutes
/// les suivantes, sans que le client le sache : les paquets qu'il reçoit se
/// suivent, mais décrivent des différences avec une image qu'il n'a jamais vue.
///
/// Dès qu'une image encodée est perdue, plus rien ne passe jusqu'à la prochaine
/// image clé, que l'appelant doit réclamer à l'encodeur.
#[derive(Debug, Default)]
struct KeyframeGate {
    waiting: bool,
    discarded: u32,
}

impl KeyframeGate {
    /// L'image peut-elle être transmise ?
    fn admit(&mut self, keyframe: bool) -> bool {
        if !self.waiting || keyframe {
            return true;
        }
        self.discarded += 1;
        if self.discarded >= KEYFRAME_PATIENCE {
            tracing::warn!("aucune image clé obtenue de l'encodeur, reprise du flux tel quel");
            self.waiting = false;
            self.discarded = 0;
            return true;
        }
        false
    }

    /// L'image a été transmise.
    fn sent(&mut self, keyframe: bool) {
        if keyframe {
            self.waiting = false;
            self.discarded = 0;
        }
    }

    /// L'image a été perdue après encodage. Renvoie `true` s'il faut réclamer
    /// une image clé : à la première perte, et de nouveau si c'est l'image clé
    /// attendue qui vient d'être perdue.
    fn lost(&mut self, keyframe: bool) -> bool {
        let request = !self.waiting || keyframe;
        self.waiting = true;
        request
    }
}

/// Ordres adressés au thread de capture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PipelineCommand {
    /// Produire une image clé à la prochaine occasion.
    Keyframe,
    /// Changer le débit cible.
    Bitrate(u32),
    /// Terminer proprement.
    Stop,
}

/// Compteurs partagés avec le reste de l'agent.
#[derive(Debug, Default)]
pub struct PipelineStats {
    /// Images fournies par la capture.
    pub captured: AtomicU64,
    /// Images effectivement encodées.
    pub encoded: AtomicU64,
    /// Images abandonnées, encodeur saturé ou file pleine.
    pub dropped: AtomicU64,
    /// Images effectivement confiées à l'encodeur.
    ///
    /// Distinct de `captured` : la cadence est plafonnée, et une image en
    /// avance sur l'intervalle demandé est abandonnée avant conversion.
    pub submitted: AtomicU64,
    /// Cycles terminés sans nouvelle image.
    pub idle: AtomicU64,
    /// Octets compressés produits.
    pub bytes: AtomicU64,
    /// Temps cumulé passé dans la conversion et la soumission, en microsecondes.
    pub encode_us: AtomicU64,
}

/// Poignée sur le thread de capture.
///
/// Le laisser tomber arrête le thread et libère toutes les ressources GPU.
#[derive(Debug)]
pub struct Pipeline {
    commands: Sender<PipelineCommand>,
    join: Option<std::thread::JoinHandle<()>>,
    feedback: PipelineFeedback,
    stats: Arc<PipelineStats>,
}

impl Pipeline {
    /// Démarre la capture et l'encodage.
    ///
    /// L'initialisation matérielle a lieu sur le thread créé ici, et son
    /// résultat revient par un canal : un échec d'ouverture DXGI ou l'absence
    /// d'encodeur matériel est signalé à l'appelant plutôt que de laisser un
    /// thread mort derrière lui.
    pub fn start(
        video: &VideoConfig,
        output: u32,
        bitrate_1080p: u32,
        frames_tx: tokio::sync::mpsc::Sender<EncodedFrame>,
    ) -> anyhow::Result<Self> {
        let (commands_tx, commands_rx) = std::sync::mpsc::channel();
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let stats = Arc::new(PipelineStats::default());

        let video = video.clone();
        let thread_stats = Arc::clone(&stats);
        let join = std::thread::Builder::new()
            .name("sidgate-capture".into())
            .spawn(move || {
                run(
                    video,
                    output,
                    bitrate_1080p,
                    frames_tx,
                    commands_rx,
                    ready_tx,
                    thread_stats,
                );
            })?;

        match ready_rx.recv() {
            Ok(Ok(feedback)) => Ok(Self {
                commands: commands_tx,
                join: Some(join),
                feedback,
                stats,
            }),
            Ok(Err(e)) => {
                let _ = join.join();
                Err(e)
            }
            Err(_) => {
                let _ = join.join();
                Err(anyhow::anyhow!(
                    "le thread de capture s'est arrêté avant d'être prêt"
                ))
            }
        }
    }

    /// Géométrie courante du bureau capturé.
    pub fn desktop(&self) -> DesktopInfo {
        *self.feedback.desktop.borrow()
    }

    /// Curseur et géométrie, publiés par le thread de capture.
    pub fn feedback(&self) -> PipelineFeedback {
        self.feedback.clone()
    }

    /// Compteurs de la session en cours.
    pub fn stats(&self) -> &Arc<PipelineStats> {
        &self.stats
    }

    /// Demande une image clé.
    pub fn request_keyframe(&self) {
        let _ = self.commands.send(PipelineCommand::Keyframe);
    }

    /// Change le débit cible.
    pub fn set_bitrate(&self, bitrate: u32) {
        let _ = self.commands.send(PipelineCommand::Bitrate(bitrate));
    }
}

impl Drop for Pipeline {
    fn drop(&mut self) {
        let _ = self.commands.send(PipelineCommand::Stop);
        if let Some(join) = self.join.take() {
            // L'attente est bornée en pratique : le thread teste les ordres à
            // chaque tour, et un tour dure au plus `ACQUIRE_TIMEOUT`.
            let _ = join.join();
        }
        tracing::info!("pipeline arrêté, ressources GPU libérées");
    }
}

/// Corps du thread de capture.
fn run(
    video: VideoConfig,
    output: u32,
    bitrate_1080p: u32,
    frames_tx: tokio::sync::mpsc::Sender<EncodedFrame>,
    commands: Receiver<PipelineCommand>,
    ready: Sender<anyhow::Result<PipelineFeedback>>,
    stats: Arc<PipelineStats>,
) {
    let mut engine = match Engine::new(&video, output, bitrate_1080p) {
        Ok(engine) => engine,
        Err(e) => {
            let _ = ready.send(Err(e));
            return;
        }
    };

    let (pointer_tx, pointer_rx) = watch::channel(engine.capturer.pointer());
    let (shape_tx, shape_rx) = watch::channel(None);
    let (desktop_tx, desktop_rx) = watch::channel(engine.capturer.desktop());
    let feedback = FeedbackSink {
        pointer: pointer_tx,
        shape: shape_tx,
        desktop: desktop_tx,
    };
    let published = PipelineFeedback {
        pointer: pointer_rx,
        shape: shape_rx,
        desktop: desktop_rx,
    };
    if ready.send(Ok(published)).is_err() {
        return;
    }

    let start = Instant::now();
    let mut encoded = Vec::with_capacity(4);
    let mut gate = KeyframeGate::default();
    // Débit demandé en cours de session, à reconduire si l'encodeur est
    // reconstruit : sans cela, un changement de résolution ramènerait le
    // palier choisi par l'utilisateur à celui de la configuration.
    let mut bitrate_override: Option<u32> = None;
    // Intervalle minimal entre deux soumissions. Le compositeur peut presenter
    // bien plus vite que la cadence demandee ; convertir puis jeter ces images
    // couterait du GPU et du CPU pour rien.
    let frame_interval = Duration::from_secs_f64(1.0 / f64::from(video.framerate.max(1)));
    let mut last_submit = Instant::now() - frame_interval;
    // La texture du capteur porte-t-elle une image que le client n'a pas ?
    //
    // C'est le cas quand la dernière image capturée n'a pas été encodée —
    // arrivée en avance sur la cadence, ou devant un encodeur occupé — et
    // quand une image clé est demandée. Le compositeur ne présente rien tant
    // que rien ne bouge : sans cette dette, la fin d'un geste rapide ou une
    // image clé réclamée sur un bureau immobile n'arriveraient jamais.
    let mut owed = false;
    // La texture a-t-elle déjà reçu une image depuis l'ouverture du capteur ?
    let mut has_frame = false;

    while drain_commands(&commands, &mut engine, &mut bitrate_override, &mut owed)
        == ControlFlow::Continue
    {
        let timeout = acquire_timeout(owed && has_frame, last_submit.elapsed(), frame_interval);
        let acquired = engine.capturer.acquire(timeout);
        // Le curseur bouge aussi quand aucun pixel ne change : il se publie
        // quel que soit le résultat de l'acquisition.
        feedback.publish(&mut engine.capturer);

        let fresh = match acquired {
            Ok(FrameStatus::Ready { .. }) => {
                stats.captured.fetch_add(1, Ordering::Relaxed);
                has_frame = true;
                true
            }
            Ok(FrameStatus::Idle) => {
                stats.idle.fetch_add(1, Ordering::Relaxed);
                false
            }
            Err(CaptureError::Lost) => {
                // Bascule vers le bureau sécurisé, changement de résolution ou
                // passage en plein écran exclusif. On reconstruit tout : un
                // simple nouvel essai sur la même duplication échouerait.
                tracing::warn!("duplication perdue, reconstruction du pipeline");
                match Engine::new(&video, output, bitrate_1080p) {
                    Ok(fresh) => {
                        engine = fresh;
                        if let Some(bitrate) = bitrate_override {
                            engine.encoder.set_bitrate(bitrate);
                        }
                        engine.encoder.request_keyframe();
                        // Un encodeur neuf repart d'une image clé : ce qui
                        // restait à attendre de l'ancien n'a plus d'objet.
                        gate = KeyframeGate::default();
                        // Texture neuve, encore vide : plus rien n'est dû.
                        owed = false;
                        has_frame = false;
                        feedback.publish_desktop(engine.capturer.desktop());
                    }
                    Err(e) => {
                        tracing::error!(error = %e, "reconstruction impossible");
                        std::thread::sleep(Duration::from_millis(500));
                    }
                }
                continue;
            }
            Err(e) => {
                tracing::error!(error = %e, "capture interrompue");
                break;
            }
        };

        if (fresh || owed) && has_frame && last_submit.elapsed() >= frame_interval {
            // Le chronometre demarre ici, et non avant l'acquisition : y
            // inclure l'attente d'une nouvelle image ferait passer un bureau
            // immobile pour un encodeur lent.
            let mark = Instant::now();
            match submit_within(&mut engine, start.elapsed(), &mut encoded, frame_interval) {
                Ok(Submission::Accepted) => {
                    last_submit = Instant::now();
                    owed = false;
                    stats.submitted.fetch_add(1, Ordering::Relaxed);
                    stats
                        .encode_us
                        .fetch_add(mark.elapsed().as_micros() as u64, Ordering::Relaxed);
                }
                Ok(Submission::Busy) => {
                    owed = true;
                    stats.dropped.fetch_add(1, Ordering::Relaxed);
                }
                Err(e) => {
                    tracing::error!(error = %e, "encodage interrompu");
                    break;
                }
            }
        } else {
            if fresh {
                // Image en avance sur la cadence demandee : on ne paie pas sa
                // conversion maintenant, mais elle reste due si aucune autre
                // ne vient la remplacer.
                owed = true;
                stats.dropped.fetch_add(1, Ordering::Relaxed);
            }
            if let Err(e) = engine.encoder.poll(&mut encoded) {
                tracing::error!(error = %e, "drainage de l'encodeur interrompu");
                break;
            }
        }

        for frame in encoded.drain(..) {
            stats.encoded.fetch_add(1, Ordering::Relaxed);
            let keyframe = frame.keyframe;
            if !gate.admit(keyframe) {
                stats.dropped.fetch_add(1, Ordering::Relaxed);
                continue;
            }
            let size = frame.data.len() as u64;
            match frames_tx.try_send(frame) {
                Ok(()) => {
                    gate.sent(keyframe);
                    stats.bytes.fetch_add(size, Ordering::Relaxed);
                }
                Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                    stats.dropped.fetch_add(1, Ordering::Relaxed);
                    if gate.lost(keyframe) {
                        engine.encoder.request_keyframe();
                        owed = true;
                    }
                }
                Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                    tracing::info!("plus de destinataire, arrêt du pipeline");
                    return;
                }
            }
        }
    }
}

/// Soumet une image en laissant a l'encodeur le temps de reclamer une entree.
///
/// Un encodeur materiel asynchrone signale sa disponibilite par evenement. Un
/// unique sondage non bloquant au moment ou l'image arrive est un tirage au
/// sort : si l'evenement n'est pas encore dans la file, l'image est perdue
/// alors que l'ASIC etait libre un dixieme de milliseconde plus tard.
///
/// On reessaie donc jusqu'a l'echeance de la cadence. Attendre jusque-la ne
/// coute aucune latence : sans cela on ne ferait qu'attendre l'image suivante.
/// Au-dela de l'echeance, l'encodeur est reellement sature et l'image part a la
/// poubelle, ce qui reste le bon choix en direct.
fn submit_within(
    engine: &mut Engine,
    timestamp: Duration,
    out: &mut Vec<EncodedFrame>,
    budget: Duration,
) -> Result<Submission, sidgate_encode::EncodeError> {
    /// Pas d'attente entre deux tentatives. Assez court pour rester invisible,
    /// assez long pour ne pas transformer l'attente en attente active.
    const RETRY_STEP: Duration = Duration::from_micros(250);

    let deadline = Instant::now() + budget;
    loop {
        match engine.encoder.submit(timestamp, out)? {
            Submission::Accepted => return Ok(Submission::Accepted),
            Submission::Busy if Instant::now() >= deadline => return Ok(Submission::Busy),
            Submission::Busy => std::thread::sleep(RETRY_STEP),
        }
    }
}

#[derive(PartialEq, Eq)]
enum ControlFlow {
    Continue,
    Stop,
}

/// Durée d'attente de la prochaine image.
///
/// Quand une image est due au client, l'attente se réduit à ce qui reste avant
/// que la cadence n'autorise à l'envoyer : la fin d'un geste part au plus une
/// image plus tard, au lieu d'attendre un dixième de seconde qu'autre chose
/// bouge.
fn acquire_timeout(owed: bool, since_last_submit: Duration, frame_interval: Duration) -> Duration {
    if !owed {
        return ACQUIRE_TIMEOUT;
    }
    frame_interval
        .saturating_sub(since_last_submit)
        .clamp(Duration::from_millis(1), ACQUIRE_TIMEOUT)
}

fn drain_commands(
    commands: &Receiver<PipelineCommand>,
    engine: &mut Engine,
    bitrate_override: &mut Option<u32>,
    owed: &mut bool,
) -> ControlFlow {
    loop {
        match commands.try_recv() {
            Ok(PipelineCommand::Keyframe) => {
                engine.encoder.request_keyframe();
                // À émettre même si plus rien ne bouge à l'écran.
                *owed = true;
            }
            Ok(PipelineCommand::Bitrate(bitrate)) => {
                *bitrate_override = Some(bitrate);
                engine.encoder.set_bitrate(bitrate);
            }
            Ok(PipelineCommand::Stop) | Err(TryRecvError::Disconnected) => {
                return ControlFlow::Stop
            }
            Err(TryRecvError::Empty) => return ControlFlow::Continue,
        }
    }
}

/// Capteur et encodeur liés au même device GPU.
struct Engine {
    capturer: sidgate_capture::Capturer,
    encoder: sidgate_encode::Encoder,
}

impl Engine {
    fn new(video: &VideoConfig, output: u32, bitrate_1080p: u32) -> anyhow::Result<Self> {
        let capturer = sidgate_capture::Capturer::new(output)?;
        let desktop = capturer.desktop();
        let config = EncoderConfig {
            width: desktop.width,
            height: desktop.height,
            framerate: video.framerate,
            bitrate: 0,
        }
        .scale_bitrate_to_resolution(bitrate_1080p);

        let encoder = sidgate_encode::Encoder::new(
            capturer.device(),
            capturer.context(),
            capturer.target_texture(),
            config,
        )?;
        Ok(Self { capturer, encoder })
    }
}

/// Instantané des compteurs, pour la télémétrie.
#[derive(Debug, Clone, Copy, Default)]
pub struct StatsSnapshot {
    /// Images capturées.
    pub captured: u64,
    /// Images encodées.
    pub encoded: u64,
    /// Images soumises à l'encodeur.
    pub submitted: u64,
    /// Images abandonnées.
    pub dropped: u64,
    /// Cycles à vide.
    pub idle: u64,
    /// Octets compressés.
    pub bytes: u64,
    /// Temps d'encodage cumulé, en microsecondes.
    pub encode_us: u64,
}

impl PipelineStats {
    /// Lit tous les compteurs.
    pub fn snapshot(&self) -> StatsSnapshot {
        StatsSnapshot {
            captured: self.captured.load(Ordering::Relaxed),
            encoded: self.encoded.load(Ordering::Relaxed),
            submitted: self.submitted.load(Ordering::Relaxed),
            dropped: self.dropped.load(Ordering::Relaxed),
            idle: self.idle.load(Ordering::Relaxed),
            bytes: self.bytes.load(Ordering::Relaxed),
            encode_us: self.encode_us.load(Ordering::Relaxed),
        }
    }
}

impl StatsSnapshot {
    /// Différence entre deux instantanés, pour des valeurs instantanées plutôt
    /// que cumulées.
    pub fn delta(&self, previous: &StatsSnapshot) -> StatsSnapshot {
        StatsSnapshot {
            captured: self.captured.saturating_sub(previous.captured),
            encoded: self.encoded.saturating_sub(previous.encoded),
            submitted: self.submitted.saturating_sub(previous.submitted),
            dropped: self.dropped.saturating_sub(previous.dropped),
            idle: self.idle.saturating_sub(previous.idle),
            bytes: self.bytes.saturating_sub(previous.bytes),
            encode_us: self.encode_us.saturating_sub(previous.encode_us),
        }
    }

    /// Cadence sur l'intervalle écoulé.
    pub fn fps(&self, elapsed: Duration) -> f32 {
        if elapsed.is_zero() {
            return 0.0;
        }
        self.encoded as f32 / elapsed.as_secs_f32()
    }

    /// Débit sur l'intervalle écoulé, en bits par seconde.
    pub fn bitrate_bps(&self, elapsed: Duration) -> u32 {
        if elapsed.is_zero() {
            return 0;
        }
        ((self.bytes as f64 * 8.0) / elapsed.as_secs_f64()) as u32
    }

    /// Durée moyenne d'encodage par image soumise, en millisecondes.
    ///
    /// Rapportée aux images réellement soumises, et non à toutes celles
    /// capturées : une image écartée par le plafond de cadence n'a rien coûté
    /// à l'encodeur et fausserait la moyenne vers le bas.
    pub fn encode_ms(&self) -> f32 {
        if self.submitted == 0 {
            return 0.0;
        }
        self.encode_us as f32 / self.submitted as f32 / 1000.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snapshot(captured: u64, encoded: u64, bytes: u64, encode_us: u64) -> StatsSnapshot {
        StatsSnapshot {
            captured,
            encoded,
            submitted: captured,
            dropped: 0,
            idle: 0,
            bytes,
            encode_us,
        }
    }

    #[test]
    fn delta_reports_the_interval_not_the_total() {
        let previous = snapshot(100, 90, 1_000, 500);
        let current = snapshot(160, 150, 4_000, 1_100);
        let delta = current.delta(&previous);
        assert_eq!(delta.captured, 60);
        assert_eq!(delta.encoded, 60);
        assert_eq!(delta.bytes, 3_000);
        assert_eq!(delta.encode_us, 600);
    }

    #[test]
    fn delta_never_underflows_after_a_pipeline_restart() {
        // Les compteurs repartent de zéro quand le pipeline est reconstruit.
        let previous = snapshot(1_000, 900, 50_000, 9_000);
        let delta = snapshot(5, 4, 100, 20).delta(&previous);
        assert_eq!(delta.captured, 0);
        assert_eq!(delta.encoded, 0);
        assert_eq!(delta.bytes, 0);
    }

    #[test]
    fn rates_are_computed_over_the_interval() {
        let delta = snapshot(60, 60, 1_000_000, 0);
        assert_eq!(delta.fps(Duration::from_secs(1)), 60.0);
        assert_eq!(delta.bitrate_bps(Duration::from_secs(1)), 8_000_000);
        assert_eq!(delta.fps(Duration::from_secs(2)), 30.0);
    }

    #[test]
    fn rates_are_zero_over_a_zero_interval() {
        let delta = snapshot(60, 60, 1_000_000, 0);
        assert_eq!(delta.fps(Duration::ZERO), 0.0);
        assert_eq!(delta.bitrate_bps(Duration::ZERO), 0);
    }

    #[test]
    fn average_encode_time_handles_an_empty_interval() {
        assert_eq!(snapshot(0, 0, 0, 0).encode_ms(), 0.0);
        assert_eq!(snapshot(10, 10, 0, 20_000).encode_ms(), 2.0);
    }

    #[test]
    fn average_encode_time_ignores_frames_never_submitted() {
        // 100 images capturées, 10 seulement soumises : la moyenne porte sur
        // celles qui ont réellement traversé l'encodeur.
        let snap = StatsSnapshot {
            captured: 100,
            encoded: 10,
            submitted: 10,
            dropped: 90,
            idle: 0,
            bytes: 0,
            encode_us: 20_000,
        };
        assert_eq!(snap.encode_ms(), 2.0);
    }

    #[test]
    fn nothing_owed_waits_the_full_timeout() {
        let interval = Duration::from_millis(16);
        assert_eq!(
            acquire_timeout(false, Duration::ZERO, interval),
            ACQUIRE_TIMEOUT
        );
        assert_eq!(
            acquire_timeout(false, Duration::from_secs(5), interval),
            ACQUIRE_TIMEOUT
        );
    }

    #[test]
    fn an_owed_frame_waits_only_for_the_cadence() {
        let interval = Duration::from_millis(16);
        // Soumise il y a 6 ms : la cadence autorise la suivante dans 10 ms.
        assert_eq!(
            acquire_timeout(true, Duration::from_millis(6), interval),
            Duration::from_millis(10)
        );
        // Cadence déjà respectée : on ne laisse au compositeur qu'un instant
        // pour présenter mieux, sans jamais boucler à vide.
        assert_eq!(
            acquire_timeout(true, Duration::from_secs(3), interval),
            Duration::from_millis(1)
        );
    }

    #[test]
    fn an_owed_frame_never_waits_longer_than_an_idle_cycle() {
        // Une image par seconde : la dette ne doit pas rendre le thread sourd
        // aux commandes plus longtemps qu'un cycle ordinaire.
        let interval = Duration::from_secs(1);
        assert_eq!(
            acquire_timeout(true, Duration::ZERO, interval),
            ACQUIRE_TIMEOUT
        );
    }

    #[test]
    fn the_gate_is_open_until_a_frame_is_lost() {
        let mut gate = KeyframeGate::default();
        assert!(gate.admit(true));
        gate.sent(true);
        for _ in 0..10 {
            assert!(gate.admit(false));
            gate.sent(false);
        }
    }

    #[test]
    fn a_lost_frame_blocks_everything_until_the_next_keyframe() {
        let mut gate = KeyframeGate::default();
        assert!(gate.lost(false), "la première perte réclame une image clé");

        // Les images déjà dans l'encodeur dépendent de celle qui manque.
        assert!(!gate.admit(false));
        assert!(!gate.admit(false));

        assert!(gate.admit(true));
        gate.sent(true);
        assert!(gate.admit(false), "le flux reprend derrière l'image clé");
    }

    #[test]
    fn further_losses_while_waiting_do_not_pile_up_requests() {
        let mut gate = KeyframeGate::default();
        assert!(gate.lost(false));
        assert!(!gate.lost(false), "une demande est déjà en route");
    }

    #[test]
    fn losing_the_awaited_keyframe_requests_another() {
        let mut gate = KeyframeGate::default();
        assert!(gate.lost(false));
        assert!(gate.admit(true));
        // L'image clé attendue arrive, mais la file est encore pleine.
        assert!(
            gate.lost(true),
            "sans nouvelle demande, l'attente serait sans fin"
        );
        assert!(!gate.admit(false));
    }

    #[test]
    fn the_gate_gives_up_on_an_encoder_that_never_delivers() {
        let mut gate = KeyframeGate::default();
        gate.lost(false);
        for _ in 0..KEYFRAME_PATIENCE - 1 {
            assert!(!gate.admit(false));
        }
        assert!(
            gate.admit(false),
            "une image abîmée vaut mieux qu'un écran figé"
        );
        assert!(gate.admit(false));
    }

    #[test]
    fn stats_snapshot_reads_every_counter() {
        let stats = PipelineStats::default();
        stats.captured.store(7, Ordering::Relaxed);
        stats.dropped.store(2, Ordering::Relaxed);
        stats.idle.store(41, Ordering::Relaxed);
        let snap = stats.snapshot();
        assert_eq!((snap.captured, snap.dropped, snap.idle), (7, 2, 41));
    }
}
