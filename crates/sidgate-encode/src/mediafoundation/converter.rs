//! Conversion BGRA → NV12 sur l'unité vidéo du GPU.
//!
//! Les encodeurs matériels consomment du NV12, la duplication de bureau produit
//! du BGRA. La conversion passe par `ID3D11VideoProcessor`, c'est-à-dire par le
//! bloc fixe de traitement vidéo du GPU et non par les unités de calcul 3D.
//!
//! À noter honnêtement : certains pilotes émulent une partie de ce bloc en
//! shaders. La charge 3D réellement observée se mesure au banc d'essai, elle ne
//! se déduit pas du choix d'API.
//!
//! # Invariants des blocs `unsafe`
//!
//! 1. Les vues d'entrée et de sortie sont créées une fois et détenues par la
//!    structure ; les textures qu'elles référencent vivent au moins aussi
//!    longtemps, ce qu'assure la possession des interfaces COM correspondantes.
//! 2. `VideoProcessorBlt` reçoit un tableau de flux dont les vues sont
//!    enveloppées dans `ManuallyDrop` : l'API ne prend pas de référence, donc
//!    laisser Rust les libérer à la sortie du bloc provoquerait un double
//!    relâchement.

use std::mem::ManuallyDrop;

use windows::core::Interface;
use windows::Win32::Graphics::Direct3D11::{
    ID3D11Device, ID3D11DeviceContext, ID3D11Resource, ID3D11Texture2D, ID3D11VideoContext,
    ID3D11VideoDevice, ID3D11VideoProcessor, ID3D11VideoProcessorEnumerator,
    ID3D11VideoProcessorInputView, ID3D11VideoProcessorOutputView, D3D11_BIND_RENDER_TARGET,
    D3D11_TEXTURE2D_DESC, D3D11_USAGE_DEFAULT, D3D11_VIDEO_FRAME_FORMAT_PROGRESSIVE,
    D3D11_VIDEO_PROCESSOR_COLOR_SPACE, D3D11_VIDEO_PROCESSOR_CONTENT_DESC,
    D3D11_VIDEO_PROCESSOR_INPUT_VIEW_DESC, D3D11_VIDEO_PROCESSOR_INPUT_VIEW_DESC_0,
    D3D11_VIDEO_PROCESSOR_OUTPUT_VIEW_DESC, D3D11_VIDEO_PROCESSOR_OUTPUT_VIEW_DESC_0,
    D3D11_VIDEO_PROCESSOR_STREAM, D3D11_VIDEO_USAGE_PLAYBACK_NORMAL, D3D11_VPIV_DIMENSION_TEXTURE2D,
    D3D11_VPOV_DIMENSION_TEXTURE2D,
};
use windows::Win32::Graphics::Dxgi::Common::{
    DXGI_FORMAT_NV12, DXGI_RATIONAL, DXGI_SAMPLE_DESC,
};

use crate::EncodeError;

use super::map_error;

/// Espace colorimétrique de l'entrée : RGB, plage complète.
const INPUT_COLOR_SPACE: u32 = 0;
/// Sortie YCbCr : matrice BT.709 (bit 2) et plage studio 16-235 (bits 4-5).
///
/// C'est ce que les navigateurs supposent par défaut pour un flux H.264 ; s'en
/// écarter produit des gris délavés ou des noirs écrasés.
const OUTPUT_COLOR_SPACE: u32 = (1 << 2) | (1 << 4);

/// Convertisseur d'une texture BGRA fixe vers une texture NV12 fixe.
pub struct Nv12Converter {
    video_context: ID3D11VideoContext,
    processor: ID3D11VideoProcessor,
    input_view: ID3D11VideoProcessorInputView,
    output_view: ID3D11VideoProcessorOutputView,
    output: ID3D11Texture2D,
}

impl std::fmt::Debug for Nv12Converter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Nv12Converter").finish_non_exhaustive()
    }
}

impl Nv12Converter {
    /// Prépare la conversion d'une texture source donnée, une fois pour toutes.
    ///
    /// Les vues sont liées aux textures : la source doit rester la même pendant
    /// toute la session, ce qui est le cas puisque la capture réutilise sa
    /// texture de destination.
    pub fn new(
        device: &ID3D11Device,
        context: &ID3D11DeviceContext,
        source: &ID3D11Texture2D,
        width: u32,
        height: u32,
        framerate: u32,
    ) -> Result<Self, EncodeError> {
        let video_device: ID3D11VideoDevice = device.cast().map_err(map_error)?;
        let video_context: ID3D11VideoContext = context.cast().map_err(map_error)?;

        let rate = DXGI_RATIONAL {
            Numerator: framerate.max(1),
            Denominator: 1,
        };
        let content = D3D11_VIDEO_PROCESSOR_CONTENT_DESC {
            InputFrameFormat: D3D11_VIDEO_FRAME_FORMAT_PROGRESSIVE,
            InputFrameRate: rate,
            InputWidth: width,
            InputHeight: height,
            OutputFrameRate: rate,
            OutputWidth: width,
            OutputHeight: height,
            Usage: D3D11_VIDEO_USAGE_PLAYBACK_NORMAL,
        };

        // SAFETY: `content` est entièrement initialisé et n'est pas conservé par
        // l'API au-delà de l'appel.
        let enumerator: ID3D11VideoProcessorEnumerator =
            unsafe { video_device.CreateVideoProcessorEnumerator(&content) }.map_err(map_error)?;
        // SAFETY: `enumerator` est détenu localement pendant l'appel.
        let processor = unsafe { video_device.CreateVideoProcessor(&enumerator, 0) }
            .map_err(map_error)?;

        let output = create_nv12_texture(device, width, height)?;

        let source_resource: ID3D11Resource = source.cast().map_err(map_error)?;
        let output_resource: ID3D11Resource = output.cast().map_err(map_error)?;

        let input_desc = D3D11_VIDEO_PROCESSOR_INPUT_VIEW_DESC {
            FourCC: 0,
            ViewDimension: D3D11_VPIV_DIMENSION_TEXTURE2D,
            Anonymous: D3D11_VIDEO_PROCESSOR_INPUT_VIEW_DESC_0 {
                Texture2D: windows::Win32::Graphics::Direct3D11::D3D11_TEX2D_VPIV {
                    MipSlice: 0,
                    ArraySlice: 0,
                },
            },
        };
        let mut input_view = None;
        // SAFETY: la ressource source est détenue par le capteur pour toute la
        // durée de la session ; `input_view` vit pendant l'appel.
        unsafe {
            video_device.CreateVideoProcessorInputView(
                &source_resource,
                &enumerator,
                &input_desc,
                Some(&mut input_view),
            )
        }
        .map_err(map_error)?;

        let output_desc = D3D11_VIDEO_PROCESSOR_OUTPUT_VIEW_DESC {
            ViewDimension: D3D11_VPOV_DIMENSION_TEXTURE2D,
            Anonymous: D3D11_VIDEO_PROCESSOR_OUTPUT_VIEW_DESC_0 {
                Texture2D: windows::Win32::Graphics::Direct3D11::D3D11_TEX2D_VPOV {
                    MipSlice: 0,
                },
            },
        };
        let mut output_view = None;
        // SAFETY: `output` est détenu par la structure construite ici.
        unsafe {
            video_device.CreateVideoProcessorOutputView(
                &output_resource,
                &enumerator,
                &output_desc,
                Some(&mut output_view),
            )
        }
        .map_err(map_error)?;

        let converter = Self {
            video_context,
            processor,
            input_view: input_view
                .ok_or_else(|| EncodeError::System("vue d'entrée non créée".into()))?,
            output_view: output_view
                .ok_or_else(|| EncodeError::System("vue de sortie non créée".into()))?,
            output,
        };
        converter.configure_color_space();
        Ok(converter)
    }

    /// Texture NV12 alimentée par [`Self::convert`].
    pub fn output(&self) -> &ID3D11Texture2D {
        &self.output
    }

    /// Convertit l'image courante de la texture source vers la texture NV12.
    pub fn convert(&self) -> Result<(), EncodeError> {
        let mut streams = [D3D11_VIDEO_PROCESSOR_STREAM {
            Enable: true.into(),
            OutputIndex: 0,
            InputFrameOrField: 0,
            PastFrames: 0,
            FutureFrames: 0,
            ppPastSurfaces: std::ptr::null_mut(),
            pInputSurface: ManuallyDrop::new(Some(self.input_view.clone())),
            ppFutureSurfaces: std::ptr::null_mut(),
            ppPastSurfacesRight: std::ptr::null_mut(),
            pInputSurfaceRight: ManuallyDrop::new(None),
            ppFutureSurfacesRight: std::ptr::null_mut(),
        }];

        // SAFETY: le descripteur emprunte la vue d'entrée sans en prendre de
        // référence, d'où le `ManuallyDrop` exigé par la signature. Le clone
        // qu'il contient est relâché explicitement juste après l'appel, une
        // seule fois — d'où le passage par une variable locale mutable plutôt
        // qu'un temporaire.
        let result = unsafe {
            self.video_context
                .VideoProcessorBlt(&self.processor, &self.output_view, 0, &streams)
        };
        // SAFETY: libère l'unique référence prise par `input_view.clone()`.
        unsafe { ManuallyDrop::drop(&mut streams[0].pInputSurface) };
        result.map_err(map_error)
    }

    /// Fixe les espaces colorimétriques d'entrée et de sortie.
    ///
    /// Les deux appels ne renvoient rien : un pilote qui ne les honore pas
    /// produit une image aux couleurs décalées, jamais une erreur.
    fn configure_color_space(&self) {
        let input = D3D11_VIDEO_PROCESSOR_COLOR_SPACE {
            _bitfield: INPUT_COLOR_SPACE,
        };
        let output = D3D11_VIDEO_PROCESSOR_COLOR_SPACE {
            _bitfield: OUTPUT_COLOR_SPACE,
        };
        // SAFETY: `self.processor` est détenu par la structure ; les
        // descripteurs sont copiés par l'API.
        unsafe {
            self.video_context
                .VideoProcessorSetStreamColorSpace(&self.processor, 0, &input);
            self.video_context
                .VideoProcessorSetOutputColorSpace(&self.processor, &output);
        }
    }
}

/// Alloue la texture NV12 que l'encodeur consommera.
fn create_nv12_texture(
    device: &ID3D11Device,
    width: u32,
    height: u32,
) -> Result<ID3D11Texture2D, EncodeError> {
    let desc = D3D11_TEXTURE2D_DESC {
        Width: width,
        Height: height,
        MipLevels: 1,
        ArraySize: 1,
        Format: DXGI_FORMAT_NV12,
        SampleDesc: DXGI_SAMPLE_DESC {
            Count: 1,
            Quality: 0,
        },
        Usage: D3D11_USAGE_DEFAULT,
        BindFlags: D3D11_BIND_RENDER_TARGET.0 as u32,
        CPUAccessFlags: 0,
        MiscFlags: 0,
    };
    let mut texture = None;
    // SAFETY: `desc` est entièrement initialisé ; `texture` vit pendant l'appel.
    unsafe { device.CreateTexture2D(&desc, None, Some(&mut texture)) }.map_err(map_error)?;
    texture.ok_or_else(|| EncodeError::System("texture NV12 non allouée".into()))
}
