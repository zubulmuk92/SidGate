//! Chaîne capture → encodage, sur son propre thread.
//!
//! Le device D3D11 et la transformation Media Foundation ne sont ni `Send` ni
//! `Sync` : ils vivent sur un thread dédié, créé à l'ouverture d'une session et
//! détruit à sa fermeture. Rien n'est alloué en dehors d'une session — c'est ce
//! qui permet de tenir 0,0 % de CPU au repos, puisqu'il n'y a alors littéralement
//! aucune boucle en cours.
//!
//! Seuls des octets déjà compressés franchissent la frontière de thread.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, Sender, TryRecvError};
use std::sync::Arc;
use std::time::{Duration, Instant};

use sidgate_capture::{CaptureError, DesktopInfo, FrameSource, FrameStatus};
use sidgate_encode::{EncodedFrame, EncoderConfig, Submission};

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
    desktop: DesktopInfo,
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
                run(video, bitrate_1080p, frames_tx, commands_rx, ready_tx, thread_stats);
            })?;

        match ready_rx.recv() {
            Ok(Ok(desktop)) => Ok(Self {
                commands: commands_tx,
                join: Some(join),
                desktop,
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

    /// Géométrie du bureau capturé.
    pub fn desktop(&self) -> DesktopInfo {
        self.desktop
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
    bitrate_1080p: u32,
    frames_tx: tokio::sync::mpsc::Sender<EncodedFrame>,
    commands: Receiver<PipelineCommand>,
    ready: Sender<anyhow::Result<DesktopInfo>>,
    stats: Arc<PipelineStats>,
) {
    let mut engine = match Engine::new(&video, bitrate_1080p) {
        Ok(engine) => engine,
        Err(e) => {
            let _ = ready.send(Err(e));
            return;
        }
    };
    let desktop = engine.capturer.desktop();
    if ready.send(Ok(desktop)).is_err() {
        return;
    }

    let start = Instant::now();
    let mut encoded = Vec::with_capacity(4);

    loop {
        match drain_commands(&commands, &mut engine) {
            ControlFlow::Continue => {}
            ControlFlow::Stop => break,
        }

        let mark = Instant::now();
        match engine.capturer.acquire(ACQUIRE_TIMEOUT) {
            Ok(FrameStatus::Ready { .. }) => {
                stats.captured.fetch_add(1, Ordering::Relaxed);
                match engine.encoder.submit(start.elapsed(), &mut encoded) {
                    Ok(Submission::Accepted) => {}
                    Ok(Submission::Busy) => {
                        stats.dropped.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(e) => {
                        tracing::error!(error = %e, "encodage interrompu");
                        break;
                    }
                }
                stats
                    .encode_us
                    .fetch_add(mark.elapsed().as_micros() as u64, Ordering::Relaxed);
            }
            Ok(FrameStatus::Idle) => {
                stats.idle.fetch_add(1, Ordering::Relaxed);
                if let Err(e) = engine.encoder.poll(&mut encoded) {
                    tracing::error!(error = %e, "drainage de l'encodeur interrompu");
                    break;
                }
            }
            Err(CaptureError::Lost) => {
                // Bascule vers le bureau sécurisé, changement de résolution ou
                // passage en plein écran exclusif. On reconstruit tout : un
                // simple nouvel essai sur la même duplication échouerait.
                tracing::warn!("duplication perdue, reconstruction du pipeline");
                match Engine::new(&video, bitrate_1080p) {
                    Ok(fresh) => {
                        engine = fresh;
                        engine.encoder.request_keyframe();
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
        }

        for frame in encoded.drain(..) {
            stats.encoded.fetch_add(1, Ordering::Relaxed);
            stats
                .bytes
                .fetch_add(frame.data.len() as u64, Ordering::Relaxed);
            match frames_tx.try_send(frame) {
                Ok(()) => {}
                Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                    stats.dropped.fetch_add(1, Ordering::Relaxed);
                }
                Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                    tracing::info!("plus de destinataire, arrêt du pipeline");
                    return;
                }
            }
        }
    }
}

enum ControlFlow {
    Continue,
    Stop,
}

fn drain_commands(commands: &Receiver<PipelineCommand>, engine: &mut Engine) -> ControlFlow {
    loop {
        match commands.try_recv() {
            Ok(PipelineCommand::Keyframe) => engine.encoder.request_keyframe(),
            Ok(PipelineCommand::Bitrate(bitrate)) => engine.encoder.set_bitrate(bitrate),
            Ok(PipelineCommand::Stop) | Err(TryRecvError::Disconnected) => return ControlFlow::Stop,
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
    fn new(video: &VideoConfig, bitrate_1080p: u32) -> anyhow::Result<Self> {
        let capturer = sidgate_capture::Capturer::new(video.output)?;
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

    /// Durée moyenne d'encodage par image, en millisecondes.
    pub fn encode_ms(&self) -> f32 {
        if self.captured == 0 {
            return 0.0;
        }
        self.encode_us as f32 / self.captured as f32 / 1000.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snapshot(captured: u64, encoded: u64, bytes: u64, encode_us: u64) -> StatsSnapshot {
        StatsSnapshot {
            captured,
            encoded,
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
    fn stats_snapshot_reads_every_counter() {
        let stats = PipelineStats::default();
        stats.captured.store(7, Ordering::Relaxed);
        stats.dropped.store(2, Ordering::Relaxed);
        stats.idle.store(41, Ordering::Relaxed);
        let snap = stats.snapshot();
        assert_eq!((snap.captured, snap.dropped, snap.idle), (7, 2, 41));
    }
}
