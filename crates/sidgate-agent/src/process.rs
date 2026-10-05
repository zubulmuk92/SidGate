//! Ce que l'agent coûte à la machine, mesuré sur lui-même.
//!
//! La télémétrie annonce une charge CPU et une empreinte mémoire. Les deux
//! viennent d'ici, lues sur le processus courant, ou ne sont pas annoncées du
//! tout : une valeur que le système refuse de donner reste absente plutôt que
//! de devenir un zéro.
//!
//! Rien n'est mesuré hors session — il n'y a alors personne à qui le dire, et
//! mesurer coûte.

use std::time::{Duration, Instant};

/// Mesure instantanée du processus.
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct ProcessSample {
    /// Charge CPU depuis le relevé précédent, en pourcentage de la machine.
    pub cpu_percent: Option<f32>,
    /// Mémoire résidente, en mébioctets.
    pub rss_mb: Option<f32>,
}

/// Relève la consommation du processus d'un appel à l'autre.
#[derive(Debug)]
pub struct ProcessMeter {
    previous: Option<(Instant, Duration)>,
    cores: u32,
}

impl Default for ProcessMeter {
    fn default() -> Self {
        Self::new()
    }
}

impl ProcessMeter {
    /// Nouveau compteur. Le premier relevé n'a pas de charge CPU : il manque
    /// encore un point de comparaison.
    pub fn new() -> Self {
        Self {
            previous: None,
            cores: std::thread::available_parallelism()
                .map(|n| n.get() as u32)
                .unwrap_or(1),
        }
    }

    /// Relève la consommation depuis l'appel précédent.
    pub fn sample(&mut self) -> ProcessSample {
        let now = Instant::now();
        let cpu = cpu_time();
        let cpu_percent = match (self.previous, cpu) {
            (Some((then, before)), Some(after)) => cpu_percent(
                after.saturating_sub(before),
                now.duration_since(then),
                self.cores,
            ),
            _ => None,
        };
        self.previous = cpu.map(|cpu| (now, cpu));

        ProcessSample {
            cpu_percent,
            rss_mb: resident_bytes().map(|bytes| bytes as f32 / (1024.0 * 1024.0)),
        }
    }
}

/// Part de la machine consommée sur un intervalle.
///
/// Rapportée à l'ensemble des cœurs, comme l'affiche le gestionnaire des
/// tâches : un thread qui occupe un cœur entier sur une machine qui en compte
/// douze vaut 8,3 %, pas 100 %.
pub fn cpu_percent(cpu: Duration, wall: Duration, cores: u32) -> Option<f32> {
    if wall.is_zero() || cores == 0 {
        return None;
    }
    let share = cpu.as_secs_f64() / (wall.as_secs_f64() * f64::from(cores));
    Some((share * 100.0) as f32)
}

/// Temps processeur cumulé du processus, noyau et utilisateur confondus.
#[cfg(windows)]
fn cpu_time() -> Option<Duration> {
    use windows::Win32::Foundation::FILETIME;
    use windows::Win32::System::Threading::{GetCurrentProcess, GetProcessTimes};

    let mut creation = FILETIME::default();
    let mut exit = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();
    // SAFETY: les quatre structures sont des locaux vivants pendant l'appel ;
    // la pseudo-poignée du processus courant n'a pas à être refermée.
    unsafe {
        GetProcessTimes(
            GetCurrentProcess(),
            &mut creation,
            &mut exit,
            &mut kernel,
            &mut user,
        )
    }
    .ok()?;

    // Un FILETIME compte des intervalles de 100 nanosecondes.
    let ticks = |t: FILETIME| (u64::from(t.dwHighDateTime) << 32) | u64::from(t.dwLowDateTime);
    Some(Duration::from_nanos(
        (ticks(kernel) + ticks(user)).saturating_mul(100),
    ))
}

/// Mémoire résidente du processus, en octets.
#[cfg(windows)]
fn resident_bytes() -> Option<u64> {
    use windows::Win32::System::ProcessStatus::{K32GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS};
    use windows::Win32::System::Threading::GetCurrentProcess;

    let mut counters = PROCESS_MEMORY_COUNTERS::default();
    let size = std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32;
    counters.cb = size;
    // SAFETY: `counters` est un local vivant dont `size` est la taille exacte.
    let ok = unsafe { K32GetProcessMemoryInfo(GetCurrentProcess(), &mut counters, size) };
    ok.as_bool().then_some(counters.WorkingSetSize as u64)
}

#[cfg(not(windows))]
fn cpu_time() -> Option<Duration> {
    None
}

#[cfg(not(windows))]
fn resident_bytes() -> Option<u64> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_is_reported_against_the_whole_machine() {
        let second = Duration::from_secs(1);
        assert_eq!(cpu_percent(second, second, 1), Some(100.0));
        assert_eq!(cpu_percent(second, second, 4), Some(25.0));
        assert_eq!(
            cpu_percent(Duration::from_millis(30), Duration::from_secs(2), 1),
            Some(1.5)
        );
        assert_eq!(cpu_percent(Duration::ZERO, second, 12), Some(0.0));
    }

    #[test]
    fn an_empty_interval_measures_nothing() {
        assert_eq!(cpu_percent(Duration::from_secs(1), Duration::ZERO, 4), None);
        assert_eq!(
            cpu_percent(Duration::from_secs(1), Duration::from_secs(1), 0),
            None
        );
    }

    #[test]
    fn the_first_sample_has_no_load_yet() {
        let mut meter = ProcessMeter::new();
        assert_eq!(meter.sample().cpu_percent, None);
    }

    #[cfg(windows)]
    #[test]
    fn the_system_answers_for_the_current_process() {
        let mut meter = ProcessMeter::new();
        meter.sample();

        // Un peu de travail réel, pour que le temps processeur avance.
        let mut sum = 0u64;
        let start = Instant::now();
        while start.elapsed() < Duration::from_millis(60) {
            sum = sum.wrapping_add(std::hint::black_box(1));
        }
        std::hint::black_box(sum);

        let sample = meter.sample();
        let cpu = sample
            .cpu_percent
            .expect("le système donne le temps processeur");
        assert!(cpu > 0.0 && cpu <= 100.0, "charge invraisemblable: {cpu}");
        let rss = sample
            .rss_mb
            .expect("le système donne la mémoire résidente");
        assert!(rss > 0.5, "mémoire invraisemblable: {rss} Mo");
    }
}
