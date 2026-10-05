//! Adaptation du débit aux pertes constatées par le client.
//!
//! Le palier de qualité choisi par l'utilisateur est un *plafond*. Sur un lien
//! qui ne le supporte pas — une 4G faible derrière WireGuard — s'y tenir ne
//! donne pas une meilleure image mais une image trouée : chaque paquet perdu
//! se paie d'une retransmission ou d'une image clé, qui chargent encore le
//! lien.
//!
//! Le client rapporte la part de paquets perdus dans ses rapports de réception
//! RTCP. Le débit baisse vite quand elle monte, et remonte lentement quand elle
//! disparaît : c'est la seule asymétrie qui converge, puisque remonter trop tôt
//! recrée la perte qu'on vient d'éponger.
//!
//! Les décisions se comptent en temps, pas en rapports : un navigateur en
//! envoie un par seconde ou cinq, selon son humeur et le débit du flux, et la
//! vitesse de réaction ne doit pas en dépendre.
//!
//! Le contrôleur **décide** ; il ne parle ni à l'encodeur ni au réseau.

use std::time::{Duration, Instant};

/// Part de pertes au-delà de laquelle le débit baisse, sur 256.
///
/// Environ 8 %. En dessous, la retransmission suffit à réparer.
const LOSS_HIGH: u8 = 20;
/// Part de pertes en deçà de laquelle le lien est jugé sain, sur 256.
///
/// Environ 2 %. Entre les deux seuils, le débit ne bouge pas.
const LOSS_LOW: u8 = 5;
/// Délai minimal entre deux baisses.
///
/// Le temps qu'une baisse produise son effet et que le client en rende
/// compte : sans lui, une même rafale de pertes, rapportée trois fois, ferait
/// baisser trois fois.
const DECREASE_INTERVAL: Duration = Duration::from_secs(1);
/// Durée sans perte exigée avant chaque remontée.
const INCREASE_INTERVAL: Duration = Duration::from_secs(4);
/// Débit plancher, en bits par seconde.
///
/// En dessous, un bureau en 1080p n'est plus lisible : autant garder ce débit
/// et perdre des images que descendre encore.
const FLOOR_BPS: u32 = 500_000;

/// Décide du débit de l'encodeur à partir des pertes rapportées.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BitrateController {
    ceiling: u32,
    current: u32,
    last_decrease: Option<Instant>,
    /// Début de la période sans perte en cours.
    clean_since: Option<Instant>,
}

impl BitrateController {
    /// Nouveau contrôleur, au débit du plafond.
    pub fn new(ceiling: u32) -> Self {
        Self {
            ceiling,
            current: ceiling,
            last_decrease: None,
            clean_since: None,
        }
    }

    /// Débit actuellement visé.
    #[cfg(test)]
    pub fn current(&self) -> u32 {
        self.current
    }

    /// Change le plafond et y ramène le débit.
    ///
    /// L'utilisateur vient de choisir un palier : il s'attend à le voir
    /// appliqué tout de suite. Si le lien ne suit pas, les rapports suivants
    /// le feront redescendre.
    pub fn set_ceiling(&mut self, ceiling: u32) -> u32 {
        *self = Self::new(ceiling);
        ceiling
    }

    /// Prend en compte un rapport de réception reçu à l'instant `now`.
    ///
    /// `fraction_lost` est la part de paquets perdus depuis le rapport
    /// précédent, sur 256, telle que RTCP la transporte. Renvoie le nouveau
    /// débit s'il doit changer.
    pub fn on_report(&mut self, fraction_lost: u8, now: Instant) -> Option<u32> {
        let target = if fraction_lost >= LOSS_HIGH {
            self.clean_since = None;
            if self
                .last_decrease
                .is_some_and(|at| now.duration_since(at) < DECREASE_INTERVAL)
            {
                return None;
            }
            self.last_decrease = Some(now);
            // Baisse proportionnelle à la perte, bornée : 8 % de perte retire
            // 15 %, une perte massive retire la moitié.
            let lost = f64::from(fraction_lost) / 256.0;
            let factor = (1.0 - lost * 2.0).clamp(0.5, 0.85);
            let floor = FLOOR_BPS.min(self.ceiling);
            ((f64::from(self.current) * factor) as u32).max(floor)
        } else if fraction_lost <= LOSS_LOW {
            let since = *self.clean_since.get_or_insert(now);
            if now.duration_since(since) < INCREASE_INTERVAL {
                return None;
            }
            self.clean_since = Some(now);
            // Remontée de 8 % toutes les quatre secondes : il faut une
            // demi-minute sans perte pour doubler, là où une seconde de perte
            // suffit à diviser.
            self.current
                .saturating_add(self.current / 12)
                .min(self.ceiling)
        } else {
            self.clean_since = None;
            return None;
        };

        if target == self.current {
            return None;
        }
        self.current = target;
        Some(target)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CEILING: u32 = 8_000_000;

    /// Horloge de test : des rapports à cadence régulière.
    struct Clock {
        now: Instant,
        step: Duration,
    }

    impl Clock {
        /// Un rapport toutes les `millis` millisecondes.
        fn every(millis: u64) -> Self {
            Self {
                now: Instant::now(),
                step: Duration::from_millis(millis),
            }
        }

        /// Rapporte `count` fois la même perte et renvoie le dernier changement.
        fn feed(
            &mut self,
            controller: &mut BitrateController,
            fraction: u8,
            count: u32,
        ) -> Option<u32> {
            let mut last = None;
            for _ in 0..count {
                self.now += self.step;
                if let Some(changed) = controller.on_report(fraction, self.now) {
                    last = Some(changed);
                }
            }
            last
        }

        /// Nombre de rapports couvrant `duration`.
        fn reports_in(&self, duration: Duration) -> u32 {
            (duration.as_millis() / self.step.as_millis()) as u32
        }
    }

    #[test]
    fn a_clean_link_stays_at_the_ceiling() {
        let mut controller = BitrateController::new(CEILING);
        assert_eq!(Clock::every(300).feed(&mut controller, 0, 200), None);
        assert_eq!(controller.current(), CEILING);
    }

    #[test]
    fn heavy_loss_lowers_the_bitrate_at_once() {
        let mut controller = BitrateController::new(CEILING);
        let lowered = Clock::every(300)
            .feed(&mut controller, 64, 1)
            .expect("25 % de pertes doit faire baisser dès le premier rapport");
        assert_eq!(lowered, CEILING / 2);
    }

    #[test]
    fn moderate_loss_lowers_it_gently() {
        let mut controller = BitrateController::new(CEILING);
        let lowered = Clock::every(300)
            .feed(&mut controller, LOSS_HIGH, 1)
            .unwrap();
        assert!(lowered < CEILING);
        assert!(
            lowered >= CEILING * 8 / 10,
            "8 % de pertes ne doit pas tout couper: {lowered}"
        );
    }

    #[test]
    fn one_burst_reported_several_times_lowers_it_once() {
        // Trois rapports en une demi-seconde décrivent la même rafale.
        let mut controller = BitrateController::new(CEILING);
        let mut clock = Clock::every(150);
        clock.feed(&mut controller, 64, 3);
        assert_eq!(controller.current(), CEILING / 2);
    }

    #[test]
    fn the_reaction_does_not_depend_on_how_often_the_client_reports() {
        // Dix secondes de fortes pertes, vues par un client bavard et par un
        // client avare de rapports : même débit à l'arrivée.
        let after = |millis| {
            let mut controller = BitrateController::new(64_000_000);
            let mut clock = Clock::every(millis);
            let reports = clock.reports_in(Duration::from_millis(5_000));
            clock.feed(&mut controller, 64, reports);
            controller.current()
        };
        assert_eq!(after(200), after(1_000));
    }

    #[test]
    fn loss_between_the_thresholds_changes_nothing() {
        let mut controller = BitrateController::new(CEILING);
        let mut clock = Clock::every(300);
        clock.feed(&mut controller, 64, 1);
        let held = controller.current();
        assert_eq!(clock.feed(&mut controller, LOSS_LOW + 1, 100), None);
        assert_eq!(controller.current(), held);
    }

    #[test]
    fn the_bitrate_never_falls_below_the_floor() {
        let mut controller = BitrateController::new(CEILING);
        let mut clock = Clock::every(1_000);
        clock.feed(&mut controller, 255, 50);
        assert_eq!(controller.current(), FLOOR_BPS);
        assert_eq!(
            clock.feed(&mut controller, 255, 5),
            None,
            "déjà au plancher"
        );
    }

    #[test]
    fn a_ceiling_under_the_floor_is_respected() {
        let mut controller = BitrateController::new(300_000);
        Clock::every(1_000).feed(&mut controller, 255, 10);
        assert_eq!(
            controller.current(),
            300_000,
            "le plafond l'emporte sur le plancher"
        );
    }

    #[test]
    fn recovery_waits_for_a_sustained_clean_period() {
        let mut controller = BitrateController::new(CEILING);
        let mut clock = Clock::every(500);
        clock.feed(&mut controller, 64, 1);
        let low = controller.current();

        // Un peu moins de quatre secondes sans perte : rien ne bouge encore.
        let almost = clock.reports_in(INCREASE_INTERVAL);
        assert_eq!(clock.feed(&mut controller, 0, almost), None);
        let raised = clock
            .feed(&mut controller, 0, 1)
            .expect("le lien est redevenu sain");
        assert!(raised > low && raised < CEILING);
    }

    #[test]
    fn a_single_lossy_report_restarts_the_wait() {
        let mut controller = BitrateController::new(CEILING);
        let mut clock = Clock::every(500);
        clock.feed(&mut controller, 64, 1);
        let almost = clock.reports_in(INCREASE_INTERVAL);
        clock.feed(&mut controller, 0, almost);
        clock.feed(&mut controller, LOSS_LOW + 1, 1);
        assert_eq!(
            clock.feed(&mut controller, 0, almost),
            None,
            "la période saine d'avant la perte ne compte plus"
        );
    }

    #[test]
    fn recovery_is_slower_than_the_drop_and_stops_at_the_ceiling() {
        let mut controller = BitrateController::new(CEILING);
        let mut clock = Clock::every(500);
        let start = clock.now;
        clock.feed(&mut controller, 64, 1);
        assert_eq!(controller.current(), CEILING / 2);

        while controller.current() < CEILING {
            clock.feed(&mut controller, 0, 1);
            assert!(
                clock.now - start < Duration::from_secs(600),
                "la remontée ne converge pas"
            );
        }
        let recovery = clock.now - start;
        assert!(
            recovery > Duration::from_secs(20),
            "une demi-seconde a divisé, {recovery:?} ont suffi à doubler"
        );
        assert_eq!(clock.feed(&mut controller, 0, 100), None);
        assert_eq!(controller.current(), CEILING);
    }

    #[test]
    fn choosing_a_preset_applies_it_immediately() {
        let mut controller = BitrateController::new(CEILING);
        Clock::every(1_000).feed(&mut controller, 255, 10);
        assert_eq!(controller.set_ceiling(20_000_000), 20_000_000);
        assert_eq!(controller.current(), 20_000_000);
    }
}
