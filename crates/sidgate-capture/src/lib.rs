//! Acquisition du bureau, sans copie vers la mémoire système.
//!
//! Le seul backend disponible à ce jour est [`dxgi`] (Windows Desktop
//! Duplication). Le reste du code ne manipule que [`Capturer`], [`Capture`] et
//! [`CaptureError`], ce qui laisse la place à un backend PipeWire/DMA-BUF sans
//! toucher à l'agent.
//!
//! # Ce que « zéro copie » veut dire ici
//!
//! Aucune image ne traverse jamais la mémoire centrale ni le CPU. Un blit
//! VRAM → VRAM reste en revanche obligatoire : la texture rendue par
//! `AcquireNextFrame` appartient au pilote et doit être relâchée avant
//! l'acquisition suivante, donc la capture la recopie une fois vers une texture
//! qu'elle possède. Le coût est d'environ 0,1 ms sur un GPU moderne.

#![cfg_attr(not(windows), allow(dead_code))]

use std::time::Duration;

#[cfg(windows)]
pub mod desktop;
#[cfg(windows)]
pub mod dxgi;

#[cfg(windows)]
pub use dxgi::DxgiCapturer as Capturer;

/// Géométrie et format de la source capturée.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DesktopInfo {
    /// Largeur en pixels.
    pub width: u32,
    /// Hauteur en pixels.
    pub height: u32,
    /// Index de la sortie vidéo dupliquée.
    pub output_index: u32,
}

/// Résultat d'un cycle d'acquisition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameStatus {
    /// Une nouvelle image est disponible dans la texture de destination.
    Ready {
        /// Nombre d'images présentées depuis la dernière acquisition. Au-delà de
        /// 1, le compositeur a présenté plus vite que la capture ne consomme.
        accumulated: u32,
    },
    /// Délai écoulé sans nouvelle image : le bureau est statique.
    ///
    /// C'est le cas nominal sur un bureau immobile. Rien n'est encodé, rien
    /// n'est émis : ni bande passante, ni batterie côté client.
    Idle,
}

/// Erreurs d'acquisition.
#[derive(Debug, thiserror::Error)]
pub enum CaptureError {
    /// La duplication a été invalidée : changement de résolution, bascule vers
    /// le bureau sécurisé (UAC, Ctrl+Alt+Suppr), passage en plein écran
    /// exclusif, mise à jour du pilote. L'appelant doit recréer le capteur.
    #[error("duplication perdue, recréation nécessaire")]
    Lost,
    /// Aucune sortie vidéo à l'index demandé.
    #[error("sortie vidéo {0} introuvable")]
    OutputNotFound(u32),
    /// Le bureau courant n'est pas accessible au processus.
    ///
    /// Un processus tournant dans la session de l'utilisateur ne peut pas
    /// dupliquer l'écran de verrouillage ni le bureau sécurisé (UAC,
    /// Ctrl+Alt+Suppr) : ces bureaux appartiennent à Winlogon. La capture
    /// redevient possible d'elle-même dès le retour au bureau interactif.
    #[error("bureau inaccessible : session verrouillée ou bureau sécurisé actif")]
    DesktopUnavailable,
    /// Erreur remontée par l'API système.
    #[error("erreur système: {0}")]
    System(String),
}

/// Source d'images du bureau.
///
/// Le trait reste volontairement minimal : tout ce qui touche au GPU est
/// spécifique à la plateforme et sort par les accesseurs du backend.
pub trait FrameSource {
    /// Géométrie courante de la source.
    fn desktop(&self) -> DesktopInfo;

    /// Attend au plus `timeout` qu'une nouvelle image soit présentée.
    ///
    /// Rend la main avec [`FrameStatus::Idle`] si rien n'a changé. L'appel est
    /// bloquant côté pilote, sans attente active : c'est ce qui permet de tenir
    /// une charge CPU nulle sur un bureau immobile.
    fn acquire(&mut self, timeout: Duration) -> Result<FrameStatus, CaptureError>;
}
