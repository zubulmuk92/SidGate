//! Encodage vidéo matériel.
//!
//! L'image reste en VRAM de la capture jusqu'à l'ASIC d'encodage : seul le
//! train binaire compressé redescend en mémoire centrale, parce qu'il faut bien
//! le mettre sur le réseau.
//!
//! Le backend [`mediafoundation`] passe par Media Foundation plutôt que par
//! NVENC ou AMF en direct : le système route la transformation vers le MFT du
//! constructeur présent (NVIDIA, AMD ou Intel), ce qui donne un seul chemin de
//! code pour les trois familles de GPU, sans dépendance native.

#![cfg_attr(not(windows), allow(dead_code))]

use std::time::Duration;

#[cfg(windows)]
pub mod mediafoundation;

#[cfg(windows)]
pub use mediafoundation::{EncoderTimings, MediaFoundationEncoder as Encoder, Submission};

/// Paramètres d'une session d'encodage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncoderConfig {
    /// Largeur de l'image, en pixels.
    pub width: u32,
    /// Hauteur de l'image, en pixels.
    pub height: u32,
    /// Cadence nominale, en images par seconde.
    pub framerate: u32,
    /// Débit cible, en bits par seconde.
    pub bitrate: u32,
}

impl EncoderConfig {
    /// Met le débit à l'échelle du nombre réel de pixels.
    ///
    /// Les paliers de qualité sont exprimés pour du 1080p ; sur un écran plus
    /// grand ou plus petit, le débit suit la surface plutôt que de rester figé.
    pub fn scale_bitrate_to_resolution(mut self, bitrate_1080p: u32) -> Self {
        const REFERENCE_PIXELS: u64 = 1920 * 1080;
        let pixels = u64::from(self.width) * u64::from(self.height);
        let scaled = u64::from(bitrate_1080p) * pixels / REFERENCE_PIXELS;
        self.bitrate = scaled.clamp(500_000, 100_000_000) as u32;
        self
    }
}

/// Une unité d'accès H.264 prête à être empaquetée en RTP.
#[derive(Debug, Clone)]
pub struct EncodedFrame {
    /// Train binaire au format Annex-B (`00 00 00 01` en préfixe de NALU).
    pub data: bytes::Bytes,
    /// Horodatage de présentation, depuis le début de la session.
    pub timestamp: Duration,
    /// L'unité est-elle une image clé (IDR) ?
    pub keyframe: bool,
}

/// Erreurs d'encodage.
#[derive(Debug, thiserror::Error)]
pub enum EncodeError {
    /// Aucun encodeur matériel compatible n'a été trouvé.
    #[error("aucun encodeur matériel {codec} disponible sur cette machine")]
    NoHardwareEncoder {
        /// Codec recherché.
        codec: &'static str,
    },
    /// L'encodeur a changé de format de sortie en cours de route.
    #[error("le format de sortie a changé et n'a pas pu être renégocié")]
    FormatChange,
    /// Erreur remontée par l'API système.
    #[error("erreur système: {0}")]
    System(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(width: u32, height: u32) -> EncoderConfig {
        EncoderConfig {
            width,
            height,
            framerate: 60,
            bitrate: 0,
        }
    }

    #[test]
    fn bitrate_scales_with_pixel_count() {
        assert_eq!(
            config(1920, 1080).scale_bitrate_to_resolution(8_000_000).bitrate,
            8_000_000
        );
        assert_eq!(
            config(3840, 2160).scale_bitrate_to_resolution(8_000_000).bitrate,
            32_000_000
        );
        assert_eq!(
            config(1280, 720).scale_bitrate_to_resolution(8_000_000).bitrate,
            3_555_555
        );
    }

    #[test]
    fn bitrate_stays_within_sane_bounds() {
        // Un écran minuscule ne doit pas tomber à un débit inexploitable…
        assert_eq!(config(64, 64).scale_bitrate_to_resolution(8_000_000).bitrate, 500_000);
        // …ni un mur d'écrans faire exploser le lien.
        assert_eq!(
            config(15360, 8640).scale_bitrate_to_resolution(50_000_000).bitrate,
            100_000_000
        );
    }

    #[test]
    fn bitrate_scaling_does_not_overflow_on_large_surfaces() {
        let scaled = config(u16::MAX as u32, u16::MAX as u32)
            .scale_bitrate_to_resolution(100_000_000)
            .bitrate;
        assert_eq!(scaled, 100_000_000);
    }
}
