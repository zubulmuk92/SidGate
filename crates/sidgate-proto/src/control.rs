//! Messages du canal `control-secure` (fiable, ordonné).
//!
//! Surface d'attaque volontairement close : [`ControlCommand`] est une énumération
//! étiquetée dont **aucune variante ne porte de chaîne libre**. Il n'existe donc
//! aucun chemin par lequel une valeur venue du réseau pourrait atteindre un
//! interpréteur de commandes — le dispatcher n'a que des variantes à filtrer, pas
//! des arguments à assainir. Un test du crate `sidgate-agent` vérifie par ailleurs
//! qu'aucun `Command::new` n'existe dans les sources.
//!
//! Le texte ne circule que dans l'autre sens : [`ControlEvent`] peut porter le
//! presse-papiers de l'hôte ou un message à afficher, parce que ce qui *sort* de
//! la machine ne peut rien y exécuter.

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
    /// Demande une remontée de télémétrie immédiate.
    RequestStats,
    /// Réponse à un [`ControlEvent::Ping`], pour mesurer le RTT applicatif.
    Pong {
        /// Numéro repris du ping.
        seq: u32,
    },
    /// Bascule la capture sur une autre sortie vidéo.
    SelectDisplay {
        /// Index de la sortie, tel qu'annoncé dans [`Capabilities::displays`].
        index: u8,
    },
    /// Demande le texte du presse-papiers de l'hôte.
    ///
    /// Tirée par le client, jamais poussée par l'agent : rien ne quitte l'hôte
    /// sans un geste explicite, et l'agent n'a aucun presse-papiers à surveiller
    /// entre deux demandes.
    RequestClipboard,
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
            Self::RequestStats => "request_stats",
            Self::Pong { .. } => "pong",
            Self::SelectDisplay { .. } => "select_display",
            Self::RequestClipboard => "request_clipboard",
        }
    }
}

/// Paliers de qualité vidéo.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QualityPreset {
    /// Réseau contraint : 4G faible, partage de connexion.
    Low,
    /// Réglage par défaut.
    #[default]
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

/// Une sortie vidéo de l'hôte.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DisplayInfo {
    /// Index à passer à [`ControlCommand::SelectDisplay`].
    pub index: u32,
    /// Largeur, en pixels.
    pub width: u32,
    /// Hauteur, en pixels.
    pub height: u32,
    /// Est-ce l'écran principal ?
    pub primary: bool,
}

/// Capacités annoncées par l'agent au moment du `Hello`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Capabilities {
    /// Les commandes d'alimentation sont-elles autorisées ?
    pub power_actions: bool,
    /// L'injection d'entrées est-elle autorisée ?
    pub input_injection: bool,
    /// La lecture du presse-papiers de l'hôte est-elle autorisée ?
    pub clipboard: bool,
    /// Codec vidéo négocié, en notation RTP (`H264`, `AV1`).
    pub video_codec: String,
    /// Largeur du bureau capturé, en pixels.
    pub width: u32,
    /// Hauteur du bureau capturé, en pixels.
    pub height: u32,
    /// Index de la sortie capturée.
    pub display: u32,
    /// Sorties vidéo disponibles sur l'hôte.
    pub displays: Vec<DisplayInfo>,
    /// Palier de qualité en vigueur.
    pub quality: QualityPreset,
}

/// Télémétrie remontée périodiquement par l'agent.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize, Default)]
pub struct Stats {
    /// Images capturées depuis le début de la session.
    pub frames_captured: u64,
    /// Images encodées et émises.
    pub frames_encoded: u64,
    /// Images confiées à l'encodeur, plafond de cadence appliqué.
    pub frames_submitted: u64,
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
    /// Charge CPU du processus agent sur l'intervalle, en pourcentage de la
    /// machine entière. Absente si le système ne l'a pas fournie : jamais un
    /// zéro de remplissage.
    pub cpu_percent: Option<f32>,
    /// Mémoire résidente du processus agent, en mébioctets.
    pub rss_mb: Option<f32>,
    /// Aller-retour applicatif mesuré par la dernière sonde, en millisecondes.
    pub rtt_ms: Option<f32>,
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
    /// La capture est momentanément impossible.
    ///
    /// Le cas courant est une session hôte verrouillée : le bureau de
    /// verrouillage appartient à Winlogon et reste hors de portée d'un
    /// processus utilisateur. La session reste ouverte et la vidéo reprend
    /// d'elle-même.
    CaptureUnavailable {
        /// Explication destinée à l'utilisateur.
        message: String,
        /// L'agent retente-t-il de lui-même ? Faux quand la cause ne passera
        /// pas toute seule — pas d'encodeur matériel, par exemple.
        transient: bool,
    },
    /// La capture a repris après une interruption.
    CaptureResumed,
    /// La sortie capturée ou sa géométrie a changé.
    DisplayChanged {
        /// Index de la sortie capturée.
        index: u32,
        /// Nouvelle largeur, en pixels.
        width: u32,
        /// Nouvelle hauteur, en pixels.
        height: u32,
    },
    /// Le curseur de l'hôte a changé de forme.
    ///
    /// La position voyage à part, sur le canal non fiable ; la forme passe ici
    /// parce qu'elle ne doit pas se perdre, et qu'elle change rarement.
    PointerShape {
        /// Largeur de l'image, en pixels.
        width: u16,
        /// Hauteur de l'image, en pixels.
        height: u16,
        /// Abscisse du point chaud dans l'image.
        hot_x: u16,
        /// Ordonnée du point chaud dans l'image.
        hot_y: u16,
        /// Pixels RGBA non prémultipliés, ligne par ligne, en base64.
        rgba: String,
    },
    /// Texte du presse-papiers de l'hôte, en réponse à
    /// [`ControlCommand::RequestClipboard`].
    Clipboard {
        /// Contenu textuel. Vide si le presse-papiers ne contient pas de texte.
        text: String,
        /// Le contenu a-t-il été coupé à la taille maximale transportée ?
        truncated: bool,
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
            ControlCommand::RequestStats,
            ControlCommand::Pong { seq: 42 },
            ControlCommand::SelectDisplay { index: 1 },
            ControlCommand::RequestClipboard,
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
        assert!(
            serde_json::from_str::<ControlCommand>(
                r#"{"cmd":"set_cursor_mode","args":{"mode":"absolute"}}"#
            )
            .is_err(),
            "le mode de pointage n'est plus une commande : il ne regarde que le client"
        );
    }

    #[test]
    fn struct_variants_require_their_arguments() {
        assert!(serde_json::from_str::<ControlCommand>(r#"{"cmd":"set_quality"}"#).is_err());
        assert!(serde_json::from_str::<ControlCommand>(r#"{"cmd":"pong"}"#).is_err());
        assert!(serde_json::from_str::<ControlCommand>(r#"{"cmd":"select_display"}"#).is_err());
    }

    #[test]
    fn display_index_is_a_bounded_integer() {
        for payload in [
            r#"{"cmd":"select_display","args":{"index":256}}"#,
            r#"{"cmd":"select_display","args":{"index":-1}}"#,
            r#"{"cmd":"select_display","args":{"index":"0"}}"#,
        ] {
            assert!(
                serde_json::from_str::<ControlCommand>(payload).is_err(),
                "aurait dû être rejeté: {payload}"
            );
        }
    }

    #[test]
    fn no_command_carries_free_text() {
        // Une commande sérialisée ne contient que des identifiants connus et
        // des entiers. Une variante à champ `String` ferait échouer ce test, et
        // c'est à ce moment qu'il faudrait se demander pourquoi elle existe.
        let allowed = [
            "cmd",
            "args",
            "preset",
            "mode",
            "seq",
            "index",
            "lock",
            "sleep",
            "reboot",
            "shutdown",
            "request_keyframe",
            "set_quality",
            "request_stats",
            "pong",
            "select_display",
            "request_clipboard",
            "ultra",
        ];
        for command in [
            ControlCommand::Lock,
            ControlCommand::Sleep,
            ControlCommand::Reboot,
            ControlCommand::Shutdown,
            ControlCommand::RequestKeyframe,
            ControlCommand::SetQuality {
                preset: QualityPreset::Ultra,
            },
            ControlCommand::RequestStats,
            ControlCommand::Pong { seq: 1 },
            ControlCommand::SelectDisplay { index: 1 },
            ControlCommand::RequestClipboard,
        ] {
            let json = serde_json::to_string(&command).unwrap();
            for word in json.split(|c: char| !c.is_ascii_alphanumeric() && c != '_') {
                if word.is_empty() || word.chars().all(|c| c.is_ascii_digit()) {
                    continue;
                }
                assert!(
                    allowed.contains(&word),
                    "mot inattendu « {word} » dans {json}"
                );
            }
        }
    }

    #[test]
    fn power_actions_are_correctly_classified() {
        assert!(ControlCommand::Reboot.is_power_action());
        assert!(ControlCommand::Shutdown.is_power_action());
        assert!(ControlCommand::Sleep.is_power_action());
        assert!(!ControlCommand::Lock.is_power_action());
        assert!(!ControlCommand::RequestStats.is_power_action());
        assert!(!ControlCommand::RequestClipboard.is_power_action());
        assert!(!ControlCommand::SelectDisplay { index: 0 }.is_power_action());
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
        let events = [
            ControlEvent::Hello {
                version: "1.0.0".into(),
                capabilities: Capabilities {
                    power_actions: false,
                    input_injection: true,
                    clipboard: false,
                    video_codec: "H264".into(),
                    width: 1920,
                    height: 1080,
                    display: 0,
                    displays: vec![DisplayInfo {
                        index: 0,
                        width: 1920,
                        height: 1080,
                        primary: true,
                    }],
                    quality: QualityPreset::Balanced,
                },
            },
            ControlEvent::DisplayChanged {
                index: 1,
                width: 2560,
                height: 1440,
            },
            ControlEvent::PointerShape {
                width: 1,
                height: 1,
                hot_x: 0,
                hot_y: 0,
                rgba: "AAAA/w==".into(),
            },
            ControlEvent::Clipboard {
                text: "é\n\"".into(),
                truncated: false,
            },
            ControlEvent::Stats(Stats {
                fps: 60.0,
                cpu_percent: Some(1.5),
                ..Stats::default()
            }),
        ];
        for event in events {
            let json = serde_json::to_string(&event).unwrap();
            assert_eq!(serde_json::from_str::<ControlEvent>(&json).unwrap(), event);
        }
    }

    #[test]
    fn unmeasured_stats_are_null_not_zero() {
        let json = serde_json::to_string(&ControlEvent::Stats(Stats::default())).unwrap();
        assert!(json.contains(r#""cpu_percent":null"#), "{json}");
        assert!(json.contains(r#""rss_mb":null"#), "{json}");
        assert!(json.contains(r#""rtt_ms":null"#), "{json}");
    }
}
