//! Messages du canal `control-secure` (fiable, ordonné).
//!
//! Surface d'attaque volontairement close : [`ControlCommand`] est une énumération
//! étiquetée dont **aucune variante ne porte de chaîne libre**. Il n'existe donc
//! aucun chemin par lequel une valeur venue du réseau pourrait atteindre un
//! interpréteur de commandes — le dispatcher n'a que des variantes à filtrer, pas
//! des arguments à assainir. Un test du crate `sidgate-agent` vérifie par ailleurs
//! qu'aucun `Command::new` n'existe dans les sources.

use serde::{Deserialize, Serialize};

/// Commandes client vers agent.
///
/// L'étiquetage est *adjacent* (`{"cmd": …, "args": {…}}`) et non interne, parce
/// que `deny_unknown_fields` est silencieusement inopérant sur les énumérations à
/// étiquette interne : serde doit y bufferiser le contenu avant de connaître la
/// variante, et ne peut donc plus refuser les clés en trop. Avec l'étiquetage
/// adjacent la contrainte s'applique pour de bon, et tout champ inattendu fait
/// échouer le décodage au lieu d'être ignoré.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "cmd",
    content = "args",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum ControlCommand {
    /// Verrouille la session de l'hôte.
    Lock,
    /// Met l'hôte en veille.
    Sleep,
    /// Redémarre l'hôte.
    Reboot,
    /// Éteint l'hôte.
    Shutdown,
    /// Demande une image clé immédiate, après une perte visible.
    RequestKeyframe,
    /// Change le compromis débit/qualité de l'encodeur.
    SetQuality {
        /// Palier demandé.
        preset: QualityPreset,
    },
    /// Change le mode de pointage.
    SetCursorMode {
        /// Mode demandé.
        mode: CursorMode,
    },
    /// Demande une remontée de télémétrie immédiate.
    RequestStats,
    /// Réponse à un [`ControlEvent::Ping`], pour mesurer le RTT applicatif.
    Pong {
        /// Numéro repris du ping.
        seq: u32,
    },
}

impl ControlCommand {
    /// Indique si la commande modifie l'état d'alimentation de l'hôte.
    ///
    /// Ces commandes sont refusées sauf si la configuration les autorise
    /// explicitement : elles restent les plus destructrices de la surface.
    pub fn is_power_action(&self) -> bool {
        matches!(self, Self::Sleep | Self::Reboot | Self::Shutdown)
    }

    /// Nom stable de la commande, pour la journalisation et l'audit.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Lock => "lock",
            Self::Sleep => "sleep",
            Self::Reboot => "reboot",
            Self::Shutdown => "shutdown",
            Self::RequestKeyframe => "request_keyframe",
            Self::SetQuality { .. } => "set_quality",
            Self::SetCursorMode { .. } => "set_cursor_mode",
            Self::RequestStats => "request_stats",
            Self::Pong { .. } => "pong",
        }
    }
}

/// Paliers de qualité vidéo.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QualityPreset {
    /// Réseau contraint : 4G faible, partage de connexion.
    Low,
    /// Réglage par défaut.
    Balanced,
    /// Wi-Fi 5/6 ou 4G stable.
    High,
    /// LAN filaire.
    Ultra,
}

impl QualityPreset {
    /// Débit cible en bits par seconde, pour une capture 1080p60.
    ///
    /// La valeur est mise à l'échelle du nombre réel de pixels par l'encodeur ;
    /// ces constantes servent de référence à 1920x1080.
    pub fn target_bitrate_1080p(&self) -> u32 {
        match self {
            Self::Low => 2_500_000,
            Self::Balanced => 8_000_000,
            Self::High => 20_000_000,
            Self::Ultra => 50_000_000,
        }
    }
}

impl Default for QualityPreset {
    fn default() -> Self {
        Self::Balanced
    }
}

/// Mode de pointage demandé par le client.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CursorMode {
    /// Trackpad : déplacements relatifs, adapté au tactile.
    Relative,
    /// Pointage direct : coordonnées absolues normalisées.
    Absolute,
}

impl Default for CursorMode {
    fn default() -> Self {
        Self::Relative
    }
}

/// Motif de refus d'une commande. Fermé, pour éviter de renvoyer au client un
/// message d'erreur interne exploitable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RejectReason {
    /// Commande syntaxiquement invalide ou inconnue.
    Malformed,
    /// Commande valide mais désactivée par la configuration de l'hôte.
    NotPermitted,
    /// Trop de commandes dans la fenêtre de limitation.
    RateLimited,
    /// L'agent n'est pas dans un état où la commande a un sens.
    WrongState,
    /// L'exécution a échoué côté système.
    Failed,
}

/// Capacités annoncées par l'agent au moment du `Hello`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Capabilities {
    /// Les commandes d'alimentation sont-elles autorisées ?
    pub power_actions: bool,
    /// L'injection d'entrées est-elle autorisée ?
    pub input_injection: bool,
    /// Codec vidéo négocié, en notation RTP (`H264`, `AV1`).
    pub video_codec: String,
    /// Largeur du bureau capturé, en pixels.
    pub width: u32,
    /// Hauteur du bureau capturé, en pixels.
    pub height: u32,
}

/// Télémétrie remontée périodiquement par l'agent.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize, Default)]
pub struct Stats {
    /// Images capturées depuis le début de la session.
    pub frames_captured: u64,
    /// Images encodées et émises.
    pub frames_encoded: u64,
    /// Images écartées par le canal borné, sous pression réseau.
    pub frames_dropped: u64,
    /// Cycles de capture s'étant terminés sans nouvelle image (bureau statique).
    pub frames_idle: u64,
    /// Débit vidéo instantané, en bits par seconde.
    pub bitrate_bps: u32,
    /// Cadence instantanée, en images par seconde.
    pub fps: f32,
    /// Durée moyenne capture + encodage, en millisecondes.
    pub encode_ms: f32,
    /// Charge CPU du processus agent, en pourcentage d'un cœur.
    pub cpu_percent: f32,
    /// Mémoire résidente du processus agent, en mébioctets.
    pub rss_mb: f32,
}

/// Messages agent vers client.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "evt", rename_all = "snake_case")]
pub enum ControlEvent {
    /// Premier message émis à l'ouverture du canal.
    Hello {
        /// Version de l'agent.
        version: String,
        /// Ce que cet agent accepte de faire.
        capabilities: Capabilities,
    },
    /// La commande a été exécutée.
    CommandAccepted {
        /// Nom de la commande concernée.
        command: String,
    },
    /// La commande a été refusée.
    CommandRejected {
        /// Nom de la commande concernée.
        command: String,
        /// Motif du refus.
        reason: RejectReason,
    },
    /// Remontée de télémétrie.
    Stats(Stats),
    /// La géométrie du bureau capturé a changé.
    DisplayChanged {
        /// Nouvelle largeur, en pixels.
        width: u32,
        /// Nouvelle hauteur, en pixels.
        height: u32,
    },
    /// Sonde de latence applicative ; le client répond par [`ControlCommand::Pong`].
    Ping {
        /// Numéro à reprendre dans la réponse.
        seq: u32,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commands_roundtrip_through_json() {
        let cases = [
            ControlCommand::Lock,
            ControlCommand::Sleep,
            ControlCommand::Reboot,
            ControlCommand::Shutdown,
            ControlCommand::RequestKeyframe,
            ControlCommand::SetQuality {
                preset: QualityPreset::Ultra,
            },
            ControlCommand::SetCursorMode {
                mode: CursorMode::Absolute,
            },
            ControlCommand::RequestStats,
            ControlCommand::Pong { seq: 42 },
        ];
        for case in cases {
            let json = serde_json::to_string(&case).unwrap();
            assert_eq!(serde_json::from_str::<ControlCommand>(&json).unwrap(), case);
        }
    }

    #[test]
    fn command_wire_format_is_stable() {
        assert_eq!(
            serde_json::to_string(&ControlCommand::Lock).unwrap(),
            r#"{"cmd":"lock"}"#
        );
        assert_eq!(
            serde_json::to_string(&ControlCommand::SetQuality {
                preset: QualityPreset::Low
            })
            .unwrap(),
            r#"{"cmd":"set_quality","args":{"preset":"low"}}"#
        );
    }

    #[test]
    fn unknown_command_is_rejected() {
        for payload in [
            r#"{"cmd":"exec"}"#,
            r#"{"cmd":"run_shell","program":"cmd.exe"}"#,
            r#"{"cmd":"LOCK"}"#,
            r#"{}"#,
            r#"{"cmd":42}"#,
        ] {
            assert!(
                serde_json::from_str::<ControlCommand>(payload).is_err(),
                "aurait dû être rejeté: {payload}"
            );
        }
    }

    #[test]
    fn extra_fields_are_rejected() {
        for payload in [
            r#"{"cmd":"lock","argv":["cmd.exe"]}"#,
            r#"{"cmd":"set_quality","args":{"preset":"low"},"extra":1}"#,
            r#"{"cmd":"set_quality","args":{"preset":"low","program":"cmd.exe"}}"#,
        ] {
            assert!(
                serde_json::from_str::<ControlCommand>(payload).is_err(),
                "champ en trop accepté: {payload}"
            );
        }
    }

    #[test]
    fn unknown_enum_values_are_rejected() {
        assert!(serde_json::from_str::<ControlCommand>(
            r#"{"cmd":"set_quality","args":{"preset":"insane"}}"#
        )
        .is_err());
        assert!(serde_json::from_str::<ControlCommand>(
            r#"{"cmd":"set_cursor_mode","args":{"mode":"warp"}}"#
        )
        .is_err());
    }

    #[test]
    fn struct_variants_require_their_arguments() {
        assert!(serde_json::from_str::<ControlCommand>(r#"{"cmd":"set_quality"}"#).is_err());
        assert!(serde_json::from_str::<ControlCommand>(r#"{"cmd":"pong"}"#).is_err());
    }

    #[test]
    fn power_actions_are_correctly_classified() {
        assert!(ControlCommand::Reboot.is_power_action());
        assert!(ControlCommand::Shutdown.is_power_action());
        assert!(ControlCommand::Sleep.is_power_action());
        assert!(!ControlCommand::Lock.is_power_action());
        assert!(!ControlCommand::RequestStats.is_power_action());
    }

    #[test]
    fn bitrate_presets_are_ordered() {
        let bitrates: Vec<u32> = [
            QualityPreset::Low,
            QualityPreset::Balanced,
            QualityPreset::High,
            QualityPreset::Ultra,
        ]
        .iter()
        .map(QualityPreset::target_bitrate_1080p)
        .collect();
        assert!(bitrates.windows(2).all(|w| w[0] < w[1]));
    }

    #[test]
    fn events_roundtrip_through_json() {
        let event = ControlEvent::Hello {
            version: "0.1.0".into(),
            capabilities: Capabilities {
                power_actions: false,
                input_injection: true,
                video_codec: "H264".into(),
                width: 1920,
                height: 1080,
            },
        };
        let json = serde_json::to_string(&event).unwrap();
        assert_eq!(serde_json::from_str::<ControlEvent>(&json).unwrap(), event);
    }
}
