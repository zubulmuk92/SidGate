//! Dispatcher du canal `control-secure`.
//!
//! Le dispatcher **décide** ; il n'exécute rien. Il traduit une commande reçue
//! en un [`Effect`], que l'appelant applique. Cette séparation a une raison
//! précise : toute la logique d'autorisation devient testable sans jamais
//! éteindre la machine de test.
//!
//! Aucun chemin de ce module ne construit de commande système. Les seules
//! valeurs qu'il manipule viennent d'une énumération fermée, validée par Serde
//! avant d'arriver ici.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use sidgate_proto::control::{ControlCommand, QualityPreset, RejectReason};

use crate::config::SecurityConfig;

/// Fenêtre de limitation de débit des commandes.
const RATE_WINDOW: Duration = Duration::from_secs(10);
/// Commandes tolérées dans la fenêtre.
///
/// Large pour l'usage normal — régler la qualité en faisant glisser un curseur
/// en produit une poignée — mais suffisamment bas pour qu'un client compromis
/// ne puisse pas marteler l'agent.
const RATE_LIMIT: usize = 40;

/// Ce que l'appelant doit faire une fois la commande autorisée.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Effect {
    /// Demander une image clé au pipeline.
    Keyframe,
    /// Changer le débit cible.
    Bitrate(u32),
    /// Émettre une remontée de télémétrie.
    SendStats,
    /// Enregistrer la réponse à une sonde de latence.
    Pong(u32),
    /// Basculer la capture sur une autre sortie vidéo.
    SelectDisplay(u32),
    /// Envoyer le texte du presse-papiers de l'hôte.
    SendClipboard,
    /// Verrouiller la session.
    Lock,
    /// Mettre en veille.
    Sleep,
    /// Redémarrer.
    Reboot,
    /// Éteindre.
    Shutdown,
}

/// Traducteur de commandes en effets, sous contrainte de configuration.
#[derive(Debug)]
pub struct Dispatcher {
    security: SecurityConfig,
    width: u32,
    height: u32,
    displays: u32,
    recent: VecDeque<Instant>,
}

impl Dispatcher {
    /// Nouveau dispatcher pour une session sur un bureau de taille donnée.
    pub fn new(security: SecurityConfig, width: u32, height: u32) -> Self {
        Self {
            security,
            width,
            height,
            displays: 1,
            recent: VecDeque::with_capacity(RATE_LIMIT),
        }
    }

    /// Met à jour la géométrie du bureau capturé et le nombre de sorties.
    ///
    /// L'historique de limitation de débit est conservé : changer d'écran ne
    /// remet pas le compteur à zéro.
    pub fn set_geometry(&mut self, width: u32, height: u32, displays: u32) {
        self.width = width;
        self.height = height;
        self.displays = displays.max(1);
    }

    /// Autorise ou refuse une commande.
    pub fn dispatch(&mut self, command: ControlCommand) -> Result<Effect, RejectReason> {
        self.check_rate(Instant::now())?;

        if command.is_power_action() && !self.security.allow_power_actions {
            tracing::warn!(
                command = command.name(),
                "action d'alimentation refusée par la configuration"
            );
            return Err(RejectReason::NotPermitted);
        }
        if matches!(command, ControlCommand::RequestClipboard) && !self.security.allow_clipboard {
            tracing::warn!("lecture du presse-papiers refusée par la configuration");
            return Err(RejectReason::NotPermitted);
        }

        let effect = match command {
            ControlCommand::Lock => Effect::Lock,
            ControlCommand::Sleep => Effect::Sleep,
            ControlCommand::Reboot => Effect::Reboot,
            ControlCommand::Shutdown => Effect::Shutdown,
            ControlCommand::RequestKeyframe => Effect::Keyframe,
            ControlCommand::SetQuality { preset } => Effect::Bitrate(self.bitrate_for(preset)),
            ControlCommand::RequestStats => Effect::SendStats,
            ControlCommand::Pong { seq } => Effect::Pong(seq),
            ControlCommand::SelectDisplay { index } => {
                let index = u32::from(index);
                if index >= self.displays {
                    return Err(RejectReason::WrongState);
                }
                Effect::SelectDisplay(index)
            }
            ControlCommand::RequestClipboard => Effect::SendClipboard,
        };

        // Les réponses aux sondes reviennent toutes les deux secondes : les
        // journaliser noierait tout le reste.
        if !matches!(command, ControlCommand::Pong { .. }) {
            tracing::info!(command = command.name(), "commande acceptée");
        }
        Ok(effect)
    }

    /// Mise à l'échelle du palier de qualité sur la surface réelle du bureau.
    pub fn bitrate_for(&self, preset: QualityPreset) -> u32 {
        const REFERENCE_PIXELS: u64 = 1920 * 1080;
        let pixels = u64::from(self.width) * u64::from(self.height);
        let scaled = u64::from(preset.target_bitrate_1080p()) * pixels.max(1) / REFERENCE_PIXELS;
        scaled.clamp(500_000, 100_000_000) as u32
    }

    /// Limite le nombre de commandes par fenêtre glissante.
    fn check_rate(&mut self, now: Instant) -> Result<(), RejectReason> {
        while self
            .recent
            .front()
            .is_some_and(|t| now.duration_since(*t) >= RATE_WINDOW)
        {
            self.recent.pop_front();
        }
        if self.recent.len() >= RATE_LIMIT {
            tracing::warn!("flux de commandes limité");
            return Err(RejectReason::RateLimited);
        }
        self.recent.push_back(now);
        Ok(())
    }

    /// L'injection d'entrées est-elle autorisée ?
    pub fn input_allowed(&self) -> bool {
        self.security.allow_input
    }

    /// Faut-il verrouiller la session à la perte du transport ?
    pub fn lock_on_disconnect(&self) -> bool {
        self.security.lock_on_disconnect
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn permissive() -> SecurityConfig {
        SecurityConfig {
            allow_power_actions: true,
            ..SecurityConfig::default()
        }
    }

    fn dispatcher(security: SecurityConfig) -> Dispatcher {
        Dispatcher::new(security, 1920, 1080)
    }

    #[test]
    fn power_actions_are_refused_by_default() {
        let mut d = dispatcher(SecurityConfig::default());
        for command in [
            ControlCommand::Sleep,
            ControlCommand::Reboot,
            ControlCommand::Shutdown,
        ] {
            assert_eq!(d.dispatch(command), Err(RejectReason::NotPermitted));
        }
    }

    #[test]
    fn locking_is_always_allowed() {
        let mut d = dispatcher(SecurityConfig::default());
        assert_eq!(d.dispatch(ControlCommand::Lock), Ok(Effect::Lock));
    }

    #[test]
    fn power_actions_pass_once_enabled() {
        let mut d = dispatcher(permissive());
        assert_eq!(d.dispatch(ControlCommand::Reboot), Ok(Effect::Reboot));
        assert_eq!(d.dispatch(ControlCommand::Shutdown), Ok(Effect::Shutdown));
        assert_eq!(d.dispatch(ControlCommand::Sleep), Ok(Effect::Sleep));
    }

    #[test]
    fn quality_presets_scale_with_the_desktop_surface() {
        let mut hd = Dispatcher::new(permissive(), 1920, 1080);
        let mut uhd = Dispatcher::new(permissive(), 3840, 2160);
        let preset = QualityPreset::Balanced;

        let Ok(Effect::Bitrate(hd_bitrate)) = hd.dispatch(ControlCommand::SetQuality { preset })
        else {
            panic!("débit attendu");
        };
        let Ok(Effect::Bitrate(uhd_bitrate)) = uhd.dispatch(ControlCommand::SetQuality { preset })
        else {
            panic!("débit attendu");
        };
        assert_eq!(hd_bitrate, 8_000_000);
        assert_eq!(uhd_bitrate, 32_000_000);
    }

    #[test]
    fn bitrate_stays_bounded_on_absurd_geometry() {
        let mut tiny = Dispatcher::new(permissive(), 1, 1);
        assert_eq!(
            tiny.dispatch(ControlCommand::SetQuality {
                preset: QualityPreset::Low
            }),
            Ok(Effect::Bitrate(500_000))
        );

        let mut huge = Dispatcher::new(permissive(), 15360, 8640);
        assert_eq!(
            huge.dispatch(ControlCommand::SetQuality {
                preset: QualityPreset::Ultra
            }),
            Ok(Effect::Bitrate(100_000_000))
        );
    }

    #[test]
    fn command_flooding_is_rate_limited() {
        let mut d = dispatcher(SecurityConfig::default());
        for _ in 0..RATE_LIMIT {
            assert!(d.dispatch(ControlCommand::RequestStats).is_ok());
        }
        assert_eq!(
            d.dispatch(ControlCommand::RequestStats),
            Err(RejectReason::RateLimited)
        );
    }

    #[test]
    fn the_rate_window_slides() {
        let mut d = dispatcher(SecurityConfig::default());
        let past = Instant::now() - RATE_WINDOW - Duration::from_secs(1);
        for _ in 0..RATE_LIMIT {
            d.recent.push_back(past);
        }
        assert!(
            d.dispatch(ControlCommand::RequestStats).is_ok(),
            "les commandes anciennes doivent sortir de la fenêtre"
        );
    }

    #[test]
    fn rate_limiting_applies_before_permission_checks() {
        // Un client qui martèle une commande interdite doit être freiné, pas
        // seulement refusé : le refus lui-même coûte du travail.
        let mut d = dispatcher(SecurityConfig::default());
        for _ in 0..RATE_LIMIT {
            let _ = d.dispatch(ControlCommand::Reboot);
        }
        assert_eq!(
            d.dispatch(ControlCommand::Reboot),
            Err(RejectReason::RateLimited)
        );
    }

    #[test]
    fn probe_answers_pass_through() {
        let mut d = dispatcher(SecurityConfig::default());
        assert_eq!(
            d.dispatch(ControlCommand::Pong { seq: 17 }),
            Ok(Effect::Pong(17))
        );
    }

    #[test]
    fn clipboard_reading_is_refused_by_default() {
        let mut d = dispatcher(SecurityConfig::default());
        assert_eq!(
            d.dispatch(ControlCommand::RequestClipboard),
            Err(RejectReason::NotPermitted)
        );

        let mut d = dispatcher(SecurityConfig {
            allow_clipboard: true,
            ..SecurityConfig::default()
        });
        assert_eq!(
            d.dispatch(ControlCommand::RequestClipboard),
            Ok(Effect::SendClipboard)
        );
    }

    #[test]
    fn only_existing_displays_can_be_selected() {
        let mut d = dispatcher(SecurityConfig::default());
        assert_eq!(
            d.dispatch(ControlCommand::SelectDisplay { index: 0 }),
            Ok(Effect::SelectDisplay(0))
        );
        assert_eq!(
            d.dispatch(ControlCommand::SelectDisplay { index: 1 }),
            Err(RejectReason::WrongState),
            "un seul écran connu"
        );

        d.set_geometry(2560, 1440, 3);
        assert_eq!(
            d.dispatch(ControlCommand::SelectDisplay { index: 2 }),
            Ok(Effect::SelectDisplay(2))
        );
        assert_eq!(
            d.dispatch(ControlCommand::SelectDisplay { index: 3 }),
            Err(RejectReason::WrongState)
        );
    }

    #[test]
    fn a_geometry_change_rescales_presets_and_keeps_the_rate_window() {
        let mut d = Dispatcher::new(permissive(), 1920, 1080);
        for _ in 0..RATE_LIMIT - 1 {
            let _ = d.dispatch(ControlCommand::RequestStats);
        }
        d.set_geometry(3840, 2160, 1);
        assert_eq!(
            d.dispatch(ControlCommand::SetQuality {
                preset: QualityPreset::Balanced
            }),
            Ok(Effect::Bitrate(32_000_000))
        );
        assert_eq!(
            d.dispatch(ControlCommand::RequestStats),
            Err(RejectReason::RateLimited),
            "changer de géométrie ne doit pas effacer l'historique"
        );
    }

    #[test]
    fn input_permission_is_reported_from_the_configuration() {
        let strict = SecurityConfig {
            allow_input: false,
            ..SecurityConfig::default()
        };
        assert!(!dispatcher(strict).input_allowed());
        assert!(dispatcher(SecurityConfig::default()).input_allowed());
    }
}
