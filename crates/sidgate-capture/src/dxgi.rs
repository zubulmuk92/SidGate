//! Backend Windows : DXGI Desktop Duplication.
//!
//! # Invariants mémoire des blocs `unsafe`
//!
//! Tous les appels FFI de ce module respectent les règles suivantes, vérifiées
//! par construction :
//!
//! 1. Les interfaces COM sont détenues par `DxgiCapturer` et libérées par le
//!    `Drop` généré par `windows-rs`. Aucune n'est dupliquée manuellement.
//! 2. `AcquireNextFrame` et `ReleaseFrame` s'appellent strictement par paires.
//!    Une image acquise est relâchée avant tout retour de [`DxgiCapturer::acquire`],
//!    y compris sur les chemins d'erreur : le pilote n'autorise qu'une image en
//!    vol, et en retenir une bloque toute acquisition ultérieure.
//! 3. Les descripteurs passés aux fonctions de création sont entièrement
//!    initialisés avant l'appel, et les pointeurs de sortie pointent vers des
//!    `Option<T>` locaux vivants pendant toute la durée de l'appel.
//! 4. Le capteur n'est ni `Send` ni `Sync` : le device D3D11 et la duplication
//!    restent confinés au thread qui les a créés.

use std::time::Duration;

use windows::core::{Interface, HRESULT};
use windows::Win32::Foundation::{E_ACCESSDENIED, HMODULE};
use windows::Win32::Graphics::Direct3D::{D3D_DRIVER_TYPE_UNKNOWN, D3D_FEATURE_LEVEL_11_0};
use windows::Win32::Graphics::Direct3D11::{
    D3D11CreateDevice, ID3D11Device, ID3D11DeviceContext, ID3D11Multithread, ID3D11Resource,
    ID3D11Texture2D, D3D11_BIND_RENDER_TARGET, D3D11_BIND_SHADER_RESOURCE,
    D3D11_CREATE_DEVICE_BGRA_SUPPORT, D3D11_SDK_VERSION, D3D11_TEXTURE2D_DESC, D3D11_USAGE_DEFAULT,
};
use windows::Win32::Graphics::Dxgi::Common::{DXGI_FORMAT_B8G8R8A8_UNORM, DXGI_SAMPLE_DESC};
use windows::Win32::Graphics::Dxgi::{
    CreateDXGIFactory1, IDXGIAdapter1, IDXGIFactory1, IDXGIOutput1, IDXGIOutputDuplication,
    IDXGIResource, DXGI_ERROR_ACCESS_LOST, DXGI_ERROR_DEVICE_REMOVED, DXGI_ERROR_NOT_FOUND,
    DXGI_ERROR_WAIT_TIMEOUT, DXGI_OUTDUPL_FRAME_INFO,
};

use crate::desktop::DesktopGuard;
use crate::{CaptureError, DesktopInfo, FrameSource, FrameStatus};

/// Position du pointeur telle que rapportée par le compositeur.
///
/// Desktop Duplication ne dessine jamais le curseur dans l'image : il est
/// transmis séparément et rendu par le client. C'est la seule façon de garder
/// un curseur fluide malgré la latence réseau, et cela ne coûte rien au GPU.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PointerState {
    /// Abscisse dans l'espace du bureau capturé.
    pub x: i32,
    /// Ordonnée dans l'espace du bureau capturé.
    pub y: i32,
    /// Le curseur est-il visible ?
    pub visible: bool,
}

/// Capteur DXGI d'une sortie vidéo.
pub struct DxgiCapturer {
    // Premier champ : sa destruction rend le thread a son bureau d'origine, ce
    // qui doit arriver apres la liberation de la duplication qu'il porte.
    // L'ordre de destruction des champs suit l'ordre de declaration.
    device: ID3D11Device,
    context: ID3D11DeviceContext,
    duplication: IDXGIOutputDuplication,
    target: ID3D11Texture2D,
    target_resource: ID3D11Resource,
    info: DesktopInfo,
    pointer: PointerState,
    /// Detenu pour son `Drop` seul, jamais lu. Declare en dernier : le thread
    /// ne revient a son bureau d'origine qu'une fois la duplication et le
    /// device liberes, l'ordre de destruction suivant l'ordre de declaration.
    _desktop: DesktopGuard,
}

impl std::fmt::Debug for DxgiCapturer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DxgiCapturer")
            .field("desktop", &self.info)
            .field("pointer", &self.pointer)
            .finish_non_exhaustive()
    }
}

impl DxgiCapturer {
    /// Ouvre la duplication de la sortie vidéo `output_index`.
    ///
    /// L'index parcourt les sorties de tous les adaptateurs, dans l'ordre
    /// d'énumération DXGI : `0` désigne l'écran principal du premier GPU.
    pub fn new(output_index: u32) -> Result<Self, CaptureError> {
        // Se rattacher au bureau d'entree avant toute chose : la duplication
        // est liee au bureau du thread qui la cree, et ce bureau change a
        // chaque verrouillage ou elevation UAC.
        let desktop = DesktopGuard::attach_to_input_desktop()?;

        let (adapter, output) = find_output(output_index)?;
        let (device, context) = create_device(&adapter)?;

        // Le device est partagé avec l'encodeur, qui peut le solliciter depuis
        // un autre thread lors des transitions d'état.
        if let Ok(multithread) = context.cast::<ID3D11Multithread>() {
            // SAFETY: `multithread` est une vue du contexte détenu par `self`.
            let _previous = unsafe { multithread.SetMultithreadProtected(true) };
        }

        // SAFETY: `device` vient d'être créé et vit plus longtemps que l'appel.
        let duplication = unsafe { output.DuplicateOutput(&device) }.map_err(|e| {
            if e.code() == E_ACCESSDENIED {
                CaptureError::DesktopUnavailable
            } else {
                map_hresult(e)
            }
        })?;

        // SAFETY: `desc` est entièrement écrit par l'appel avant lecture.
        let desc = unsafe { duplication.GetDesc() };
        let info = DesktopInfo {
            width: desc.ModeDesc.Width,
            height: desc.ModeDesc.Height,
            output_index,
        };

        let target = create_target_texture(&device, info.width, info.height)?;
        let target_resource: ID3D11Resource = target.cast().map_err(map_hresult)?;

        tracing::info!(
            width = info.width,
            height = info.height,
            output = output_index,
            "duplication du bureau ouverte"
        );

        Ok(Self {
            device,
            context,
            duplication,
            target,
            target_resource,
            info,
            pointer: PointerState::default(),
            _desktop: desktop,
        })
    }

    /// Device D3D11 partagé avec l'encodeur.
    ///
    /// Capture et encodage doivent vivre sur le même device : c'est ce qui
    /// permet à la texture de rester en VRAM de bout en bout.
    pub fn device(&self) -> &ID3D11Device {
        &self.device
    }

    /// Contexte immédiat associé au device.
    pub fn context(&self) -> &ID3D11DeviceContext {
        &self.context
    }

    /// Texture BGRA contenant la dernière image acquise.
    ///
    /// Valide uniquement après un [`FrameStatus::Ready`]. Elle appartient au
    /// capteur et reste à la même adresse pour toute la durée de vie de
    /// celui-ci : l'encodeur peut en garder une vue.
    pub fn target_texture(&self) -> &ID3D11Texture2D {
        &self.target
    }

    /// Dernière position connue du pointeur.
    pub fn pointer(&self) -> PointerState {
        self.pointer
    }
}

impl FrameSource for DxgiCapturer {
    fn desktop(&self) -> DesktopInfo {
        self.info
    }

    fn acquire(&mut self, timeout: Duration) -> Result<FrameStatus, CaptureError> {
        let timeout_ms = u32::try_from(timeout.as_millis()).unwrap_or(u32::MAX);
        let mut frame_info = DXGI_OUTDUPL_FRAME_INFO::default();
        let mut resource: Option<IDXGIResource> = None;

        // SAFETY: `frame_info` et `resource` vivent jusqu'à la fin de la
        // fonction ; le pilote écrit dans les deux avant de rendre la main.
        let acquired =
            unsafe { self.duplication.AcquireNextFrame(timeout_ms, &mut frame_info, &mut resource) };

        match acquired {
            Ok(()) => {}
            Err(e) if e.code() == DXGI_ERROR_WAIT_TIMEOUT => return Ok(FrameStatus::Idle),
            Err(e) if is_lost(e.code()) => return Err(CaptureError::Lost),
            // Une bascule vers le bureau sécurisé en pleine session se
            // manifeste ici plutôt qu'à l'ouverture.
            Err(e) if e.code() == E_ACCESSDENIED => return Err(CaptureError::Lost),
            Err(e) => return Err(map_hresult(e)),
        }

        // À partir d'ici l'image est détenue : tous les chemins de sortie
        // passent par `release`, sans quoi la prochaine acquisition échouerait.
        let outcome = self.consume(&frame_info, resource.as_ref());
        self.release()?;
        outcome
    }
}

impl DxgiCapturer {
    /// Copie l'image acquise et met à jour l'état du pointeur.
    fn consume(
        &mut self,
        frame_info: &DXGI_OUTDUPL_FRAME_INFO,
        resource: Option<&IDXGIResource>,
    ) -> Result<FrameStatus, CaptureError> {
        if frame_info.LastMouseUpdateTime != 0 {
            let position = frame_info.PointerPosition;
            self.pointer = PointerState {
                x: position.Position.x,
                y: position.Position.y,
                visible: position.Visible.as_bool(),
            };
        }

        // `LastPresentTime == 0` signifie qu'aucun pixel n'a changé : seul le
        // curseur a bougé. Rien à encoder.
        if frame_info.LastPresentTime == 0 {
            return Ok(FrameStatus::Idle);
        }

        let Some(resource) = resource else {
            return Ok(FrameStatus::Idle);
        };
        let source: ID3D11Resource = resource.cast().map_err(map_hresult)?;

        // SAFETY: source et destination ont le même format, la même taille et
        // le même device ; `CopyResource` est une opération GPU pure qui ne
        // touche jamais la mémoire système.
        unsafe { self.context.CopyResource(&self.target_resource, &source) };

        Ok(FrameStatus::Ready {
            accumulated: frame_info.AccumulatedFrames,
        })
    }

    fn release(&self) -> Result<(), CaptureError> {
        // SAFETY: appelé exactement une fois par acquisition réussie.
        match unsafe { self.duplication.ReleaseFrame() } {
            Ok(()) => Ok(()),
            Err(e) if is_lost(e.code()) => Err(CaptureError::Lost),
            Err(e) => Err(map_hresult(e)),
        }
    }
}

/// Localise l'adaptateur et la sortie correspondant à un index global.
fn find_output(output_index: u32) -> Result<(IDXGIAdapter1, IDXGIOutput1), CaptureError> {
    // SAFETY: la fabrique est immédiatement détenue par la variable locale.
    let factory: IDXGIFactory1 = unsafe { CreateDXGIFactory1() }.map_err(map_hresult)?;

    let mut seen = 0u32;
    for adapter_index in 0.. {
        // SAFETY: l'énumération s'arrête sur DXGI_ERROR_NOT_FOUND.
        let adapter = match unsafe { factory.EnumAdapters1(adapter_index) } {
            Ok(adapter) => adapter,
            Err(e) if e.code() == DXGI_ERROR_NOT_FOUND => break,
            Err(e) => return Err(map_hresult(e)),
        };

        for local_index in 0.. {
            // SAFETY: même invariant d'énumération.
            let output = match unsafe { adapter.EnumOutputs(local_index) } {
                Ok(output) => output,
                Err(e) if e.code() == DXGI_ERROR_NOT_FOUND => break,
                Err(e) => return Err(map_hresult(e)),
            };
            if seen == output_index {
                let output1: IDXGIOutput1 = output.cast().map_err(map_hresult)?;
                return Ok((adapter, output1));
            }
            seen += 1;
        }
    }
    Err(CaptureError::OutputNotFound(output_index))
}

/// Crée le device D3D11 sur l'adaptateur qui pilote réellement la sortie.
///
/// Le type de pilote doit être `UNKNOWN` dès lors qu'un adaptateur explicite est
/// fourni, faute de quoi Direct3D refuse la création.
fn create_device(
    adapter: &IDXGIAdapter1,
) -> Result<(ID3D11Device, ID3D11DeviceContext), CaptureError> {
    let mut device = None;
    let mut context = None;
    let levels = [D3D_FEATURE_LEVEL_11_0];

    // SAFETY: `device` et `context` sont des `Option` locaux vivants pendant
    // tout l'appel ; Direct3D y écrit des interfaces déjà référencées.
    unsafe {
        D3D11CreateDevice(
            adapter,
            D3D_DRIVER_TYPE_UNKNOWN,
            HMODULE::default(),
            D3D11_CREATE_DEVICE_BGRA_SUPPORT,
            Some(&levels),
            D3D11_SDK_VERSION,
            Some(&mut device),
            None,
            Some(&mut context),
        )
    }
    .map_err(map_hresult)?;

    match (device, context) {
        (Some(device), Some(context)) => Ok((device, context)),
        _ => Err(CaptureError::System(
            "Direct3D n'a pas renvoyé de device".into(),
        )),
    }
}

/// Alloue la texture que le capteur possède et réutilise à chaque image.
///
/// Elle est allouée une seule fois par session : la boucle de capture ne fait
/// plus aucune allocation GPU ensuite.
fn create_target_texture(
    device: &ID3D11Device,
    width: u32,
    height: u32,
) -> Result<ID3D11Texture2D, CaptureError> {
    let desc = D3D11_TEXTURE2D_DESC {
        Width: width,
        Height: height,
        MipLevels: 1,
        ArraySize: 1,
        Format: DXGI_FORMAT_B8G8R8A8_UNORM,
        SampleDesc: DXGI_SAMPLE_DESC {
            Count: 1,
            Quality: 0,
        },
        Usage: D3D11_USAGE_DEFAULT,
        // `RENDER_TARGET` est exigé par le processeur vidéo qui convertit en
        // NV12 juste avant l'encodage.
        BindFlags: (D3D11_BIND_SHADER_RESOURCE.0 | D3D11_BIND_RENDER_TARGET.0) as u32,
        CPUAccessFlags: 0,
        MiscFlags: 0,
    };

    let mut texture = None;
    // SAFETY: `desc` est entièrement initialisé ; `texture` vit pendant l'appel.
    unsafe { device.CreateTexture2D(&desc, None, Some(&mut texture)) }.map_err(map_hresult)?;
    texture.ok_or_else(|| CaptureError::System("texture de destination non allouée".into()))
}

/// Codes signalant qu'il faut recréer entièrement la duplication.
fn is_lost(code: HRESULT) -> bool {
    code == DXGI_ERROR_ACCESS_LOST || code == DXGI_ERROR_DEVICE_REMOVED
}

fn map_hresult(error: windows::core::Error) -> CaptureError {
    CaptureError::System(format!("{} (0x{:08X})", error.message(), error.code().0))
}
