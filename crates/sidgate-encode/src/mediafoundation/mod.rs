//! Backend Windows : encodeur H.264 matériel via Media Foundation.
//!
//! Media Foundation sélectionne la transformation du constructeur présent
//! (NVENC, AMF ou QuickSync). Le device D3D11 de la capture lui est confié via
//! un `IMFDXGIDeviceManager`, ce qui permet de lui passer directement la texture
//! NV12 produite en VRAM plutôt qu'un tampon en mémoire centrale.
//!
//! # Invariants des blocs `unsafe`
//!
//! 1. `MFStartup` est appelé une seule fois par processus ([`ensure_started`]).
//! 2. Le tableau renvoyé par `MFTEnumEx` est alloué par COM : ses éléments sont
//!    déplacés dans un `Vec` avec `ptr::read` — ce qui en transfère la
//!    propriété — puis le tableau lui-même est libéré par `CoTaskMemFree`.
//!    Aucune interface n'est relâchée deux fois.
//! 3. `MFT_OUTPUT_DATA_BUFFER` contient des `ManuallyDrop` : l'échantillon
//!    produit est extrait par `ManuallyDrop::take`, ce qui en rend la libération
//!    à Rust.
//! 4. Le verrou d'un `IMFMediaBuffer` est systématiquement relâché avant le
//!    retour, y compris sur erreur.
//! 5. L'encodeur n'est ni `Send` ni `Sync` : il partage le device D3D11 du
//!    capteur et reste sur le même thread.

mod converter;

use std::sync::OnceLock;
use std::time::Duration;

use bytes::Bytes;
use windows::core::{Interface, GUID, PWSTR};
use windows::Win32::Graphics::Direct3D11::{ID3D11Device, ID3D11DeviceContext, ID3D11Texture2D};
use windows::Win32::Media::MediaFoundation::*;
use windows::Win32::System::Com::{
    CoInitializeEx, CoTaskMemFree, COINIT_MULTITHREADED,
};
use windows::Win32::System::Variant::VARIANT;

use crate::{EncodeError, EncodedFrame, EncoderConfig};

use converter::Nv12Converter;

/// Nombre de surfaces NV12 en rotation.
///
/// Un encodeur asynchrone peut encore lire une surface pendant que la
/// conversion suivante s'exécute. Trois surfaces suffisent à découpler les deux
/// sans consommer de VRAM notable (environ 10 Mo en 1920x1200).
const SURFACE_COUNT: usize = 3;

/// Issue d'une tentative de soumission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Submission {
    /// L'image a été confiée à l'encodeur.
    Accepted,
    /// L'encodeur est saturé ; l'image a été abandonnée.
    Busy,
}

/// Unité de temps de Media Foundation : 100 nanosecondes.
const HNS_PER_SECOND: u64 = 10_000_000;

/// Encodeur H.264 matériel.
pub struct MediaFoundationEncoder {
    transform: IMFTransform,
    codec_api: Option<ICodecAPI>,
    events: Option<IMFMediaEventGenerator>,
    surfaces: Vec<Surface>,
    next_surface: usize,
    pending_input: u32,
    sequence_header: Vec<u8>,
    config: EncoderConfig,
    frame_duration_hns: u64,
    scratch: Vec<u8>,
    timings: EncoderTimings,
}

/// Décomposition du temps passé dans [`MediaFoundationEncoder::submit`].
///
/// Sert au diagnostic et alimente la télémétrie : savoir si le coût est dans la
/// conversion de format ou dans l'attente de l'ASIC change complètement ce
/// qu'il faut optimiser.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct EncoderTimings {
    /// Temps cumulé dans la conversion BGRA -> NV12.
    pub convert: Duration,
    /// Images refusées faute de place dans l'encodeur.
    pub dropped: u64,
    /// Temps cumulé dans la soumission et le drainage.
    pub process: Duration,
    /// Nombre d'images comptabilisées.
    pub frames: u64,
}

impl std::fmt::Debug for MediaFoundationEncoder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MediaFoundationEncoder")
            .field("config", &self.config)
            .field("async", &self.events.is_some())
            .finish_non_exhaustive()
    }
}

/// Une surface NV12 et l'échantillon Media Foundation qui l'enveloppe.
///
/// L'échantillon est construit une fois : la boucle d'encodage ne fait plus
/// qu'en changer l'horodatage.
struct Surface {
    converter: Nv12Converter,
    sample: IMFSample,
}

impl MediaFoundationEncoder {
    /// Prépare un encodeur pour la texture BGRA `source`.
    ///
    /// Le device doit être celui du capteur : c'est ce partage qui garde
    /// l'image en VRAM.
    pub fn new(
        device: &ID3D11Device,
        context: &ID3D11DeviceContext,
        source: &ID3D11Texture2D,
        config: EncoderConfig,
    ) -> Result<Self, EncodeError> {
        ensure_started()?;

        let manager = create_device_manager(device)?;
        let (transform, activate_name) = select_encoder(&manager, config)?;
        tracing::info!(encoder = %activate_name, "encodeur matériel sélectionné");

        let events: Option<IMFMediaEventGenerator> = transform.cast().ok();
        let codec_api: Option<ICodecAPI> = transform.cast().ok();
        if let Some(codec_api) = &codec_api {
            apply_low_latency_settings(codec_api, config);
        }

        let mut surfaces = Vec::with_capacity(SURFACE_COUNT);
        for _ in 0..SURFACE_COUNT {
            let converter = Nv12Converter::new(
                device,
                context,
                source,
                config.width,
                config.height,
                config.framerate,
            )?;
            let sample = wrap_texture_in_sample(converter.output())?;
            surfaces.push(Surface { converter, sample });
        }

        // SAFETY: messages de cycle de vie sans paramètre.
        unsafe {
            transform.ProcessMessage(MFT_MESSAGE_NOTIFY_BEGIN_STREAMING, 0)?;
            transform.ProcessMessage(MFT_MESSAGE_NOTIFY_START_OF_STREAM, 0)?;
        }

        let sequence_header = read_sequence_header(&transform);
        if sequence_header.is_empty() {
            tracing::debug!("pas d'en-tête de séquence hors bande, il sera émis en flux");
        }

        Ok(Self {
            transform,
            codec_api,
            events,
            surfaces,
            next_surface: 0,
            pending_input: 0,
            sequence_header,
            config,
            frame_duration_hns: HNS_PER_SECOND / u64::from(config.framerate.max(1)),
            scratch: Vec::with_capacity(256 * 1024),
            timings: EncoderTimings::default(),
        })
    }

    /// Convertit l'image courante du capteur et la soumet à l'encodeur.
    ///
    /// Ne bloque jamais : si l'ASIC n'a pas de place, l'image est refusée et
    /// l'appelant la laisse tomber. C'est la politique voulue pour du direct —
    /// une image mise en file d'attente est une image qui arrivera en retard,
    /// et le client préfère toujours l'image suivante à l'image précédente.
    ///
    /// Les unités d'accès déjà produites sont poussées dans `out`.
    pub fn submit(
        &mut self,
        timestamp: Duration,
        out: &mut Vec<EncodedFrame>,
    ) -> Result<Submission, EncodeError> {
        // Récupère d'abord les crédits d'entrée et les sorties en attente.
        self.pump(out, false)?;
        if self.events.is_some() && self.pending_input == 0 {
            self.timings.dropped += 1;
            return Ok(Submission::Busy);
        }

        let index = self.next_surface;
        self.next_surface = (self.next_surface + 1) % self.surfaces.len();

        let mark = std::time::Instant::now();
        self.surfaces[index].converter.convert()?;
        self.timings.convert += mark.elapsed();
        self.timings.frames += 1;

        let time_hns = (timestamp.as_nanos() / 100) as i64;
        // SAFETY: l'échantillon appartient à la surface, détenue par `self`.
        unsafe {
            self.surfaces[index].sample.SetSampleTime(time_hns)?;
            self.surfaces[index]
                .sample
                .SetSampleDuration(self.frame_duration_hns as i64)?;
        }

        if self.events.is_some() {
            self.pending_input -= 1;
        }

        let mark = std::time::Instant::now();
        let sample = self.surfaces[index].sample.clone();
        // SAFETY: `ProcessInput` prend sa propre référence sur l'échantillon.
        unsafe { self.transform.ProcessInput(0, &sample, 0) }.map_err(map_error)?;

        if self.events.is_none() {
            // MFT synchrone : la sortie se draine immédiatement après l'entrée.
            while self.drain_one(out)? {}
        } else {
            self.pump(out, false)?;
        }
        self.timings.process += mark.elapsed();
        Ok(Submission::Accepted)
    }

    /// Renvoie et remet à zéro la décomposition du temps d'encodage.
    pub fn take_timings(&mut self) -> EncoderTimings {
        std::mem::take(&mut self.timings)
    }

    /// Récupère les unités d'accès prêtes, sans bloquer.
    pub fn poll(&mut self, out: &mut Vec<EncodedFrame>) -> Result<(), EncodeError> {
        if self.events.is_some() {
            self.pump(out, false)
        } else {
            while self.drain_one(out)? {}
            Ok(())
        }
    }

    /// Force une image clé sur la prochaine image encodée.
    ///
    /// Appelé sur demande du client après une perte visible, ou à l'arrivée
    /// d'un nouveau destinataire du flux.
    pub fn request_keyframe(&mut self) {
        let Some(codec_api) = &self.codec_api else {
            return;
        };
        // SAFETY: la valeur est copiée par l'appel.
        let result = unsafe {
            codec_api.SetValue(&CODECAPI_AVEncVideoForceKeyFrame, &VARIANT::from(1u32))
        };
        if let Err(e) = result {
            tracing::debug!(error = %e, "image clé forcée non supportée par cet encodeur");
        }
    }

    /// Ajuste le débit cible en cours de session.
    pub fn set_bitrate(&mut self, bitrate: u32) {
        self.config.bitrate = bitrate;
        let Some(codec_api) = &self.codec_api else {
            return;
        };
        // SAFETY: la valeur est copiée par l'appel.
        let result =
            unsafe { codec_api.SetValue(&CODECAPI_AVEncCommonMeanBitRate, &VARIANT::from(bitrate)) };
        match result {
            Ok(()) => tracing::info!(bitrate, "débit cible ajusté"),
            Err(e) => tracing::debug!(error = %e, "débit non ajustable à chaud"),
        }
    }

    /// Configuration courante.
    pub fn config(&self) -> EncoderConfig {
        self.config
    }

    /// Traite les événements de la transformation asynchrone.
    ///
    /// En mode bloquant, l'attente ne porte que tant qu'aucune place d'entrée
    /// n'est disponible ; dès qu'il y en a une, la boucle repasse en lecture
    /// non bloquante et rend la main sur file vide.
    fn pump(&mut self, out: &mut Vec<EncodedFrame>, blocking: bool) -> Result<(), EncodeError> {
        let Some(events) = self.events.clone() else {
            return Ok(());
        };
        loop {
            let flags = if blocking && self.pending_input == 0 {
                MEDIA_EVENT_GENERATOR_GET_EVENT_FLAGS(0)
            } else {
                MF_EVENT_FLAG_NO_WAIT
            };
            // SAFETY: `events` est une vue de la transformation détenue par `self`.
            let event = match unsafe { events.GetEvent(flags) } {
                Ok(event) => event,
                Err(e) if e.code() == MF_E_NO_EVENTS_AVAILABLE => return Ok(()),
                Err(e) => return Err(map_error(e)),
            };
            // SAFETY: l'événement est détenu localement.
            let kind = unsafe { event.GetType() }.map_err(map_error)?;
            if kind == METransformNeedInput.0 as u32 {
                self.pending_input += 1;
            } else if kind == METransformHaveOutput.0 as u32 {
                self.drain_one(out)?;
            }
        }
    }

    /// Extrait une unité d'accès si l'encodeur en a une.
    ///
    /// Renvoie `false` lorsqu'il faut d'abord lui fournir davantage d'entrées.
    fn drain_one(&mut self, out: &mut Vec<EncodedFrame>) -> Result<bool, EncodeError> {
        let mut buffers = [MFT_OUTPUT_DATA_BUFFER {
            dwStreamID: 0,
            pSample: std::mem::ManuallyDrop::new(None),
            dwStatus: 0,
            pEvents: std::mem::ManuallyDrop::new(None),
        }];
        let mut status = 0u32;

        // SAFETY: `buffers` vit pendant tout l'appel ; la transformation y
        // dépose une référence que nous reprenons juste après.
        let result = unsafe { self.transform.ProcessOutput(0, &mut buffers, &mut status) };

        // SAFETY: reprend la propriété des interfaces déposées par l'appel, que
        // celui-ci ait réussi ou non.
        let sample = unsafe { std::mem::ManuallyDrop::take(&mut buffers[0].pSample) };
        // SAFETY: même raison ; la collection d'événements est simplement
        // relâchée, l'encodeur n'en produit pas dans notre configuration.
        drop(unsafe { std::mem::ManuallyDrop::take(&mut buffers[0].pEvents) });

        match result {
            Ok(()) => {}
            Err(e) if e.code() == MF_E_TRANSFORM_NEED_MORE_INPUT => return Ok(false),
            Err(e) if e.code() == MF_E_TRANSFORM_STREAM_CHANGE => {
                self.renegotiate_output()?;
                return Ok(false);
            }
            Err(e) => return Err(map_error(e)),
        }

        let Some(sample) = sample else {
            return Ok(false);
        };
        if let Some(frame) = self.read_sample(&sample)? {
            out.push(frame);
        }
        Ok(true)
    }

    /// Copie le train binaire d'un échantillon vers un tampon réseau.
    ///
    /// C'est le seul transfert VRAM → mémoire centrale du pipeline, et il porte
    /// sur les données déjà compressées : quelques dizaines de kilo-octets par
    /// image au lieu de plusieurs mégaoctets.
    fn read_sample(&mut self, sample: &IMFSample) -> Result<Option<EncodedFrame>, EncodeError> {
        // SAFETY: l'échantillon est détenu par l'appelant pendant tout l'appel.
        let buffer = unsafe { sample.ConvertToContiguousBuffer() }.map_err(map_error)?;

        let mut data = std::ptr::null_mut();
        let mut length = 0u32;
        // SAFETY: `Lock` renvoie un pointeur valide jusqu'à `Unlock`, appelé
        // inconditionnellement ci-dessous.
        unsafe { buffer.Lock(&mut data, None, Some(&mut length)) }.map_err(map_error)?;

        self.scratch.clear();
        if !data.is_null() && length > 0 {
            // SAFETY: `data` pointe sur `length` octets initialisés, valides
            // jusqu'au `Unlock` qui suit immédiatement.
            let slice = unsafe { std::slice::from_raw_parts(data, length as usize) };
            self.scratch.extend_from_slice(slice);
        }
        // SAFETY: contrepartie obligatoire du `Lock` ci-dessus.
        let unlocked = unsafe { buffer.Unlock() };
        unlocked.map_err(map_error)?;

        if self.scratch.is_empty() {
            return Ok(None);
        }

        // SAFETY: lectures d'attributs sur un échantillon détenu par l'appelant.
        let keyframe = unsafe { sample.GetUINT32(&MFSampleExtension_CleanPoint) }.unwrap_or(0) == 1;
        let time_hns = unsafe { sample.GetSampleTime() }.unwrap_or(0).max(0) as u64;

        // Le client peut se raccrocher au flux à tout moment : une image clé
        // doit toujours être précédée de ses paramètres de séquence.
        let mut payload = Vec::with_capacity(self.scratch.len() + self.sequence_header.len());
        if keyframe && !self.sequence_header.is_empty() && !starts_with_parameter_set(&self.scratch)
        {
            payload.extend_from_slice(&self.sequence_header);
        }
        payload.extend_from_slice(&self.scratch);

        Ok(Some(EncodedFrame {
            data: Bytes::from(payload),
            timestamp: Duration::from_nanos(time_hns * 100),
            keyframe,
        }))
    }

    /// Réaccorde le type de sortie après un changement de format imposé par
    /// l'encodeur.
    fn renegotiate_output(&mut self) -> Result<(), EncodeError> {
        // SAFETY: énumération des types proposés par la transformation.
        let media_type = unsafe { self.transform.GetOutputAvailableType(0, 0) }
            .map_err(|_| EncodeError::FormatChange)?;
        // SAFETY: le type vient d'être obtenu de la transformation elle-même.
        unsafe { self.transform.SetOutputType(0, &media_type, 0) }
            .map_err(|_| EncodeError::FormatChange)?;
        self.sequence_header = read_sequence_header(&self.transform);
        tracing::info!("format de sortie renégocié");
        Ok(())
    }
}

impl Drop for MediaFoundationEncoder {
    fn drop(&mut self) {
        // SAFETY: messages de fin de flux sans paramètre, sur une
        // transformation encore détenue par `self`.
        unsafe {
            let _ = self.transform.ProcessMessage(MFT_MESSAGE_COMMAND_FLUSH, 0);
            let _ = self
                .transform
                .ProcessMessage(MFT_MESSAGE_NOTIFY_END_OF_STREAM, 0);
            let _ = self
                .transform
                .ProcessMessage(MFT_MESSAGE_NOTIFY_END_STREAMING, 0);
        }
    }
}

/// Démarre Media Foundation une seule fois par processus.
fn ensure_started() -> Result<(), EncodeError> {
    static STARTED: OnceLock<Result<(), String>> = OnceLock::new();
    STARTED
        .get_or_init(|| {
            // SAFETY: initialisation COM du thread courant ; un mode déjà
            // choisi n'est pas une erreur pour nous.
            let _ = unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) };
            // SAFETY: appelé exactement une fois grâce au `OnceLock`.
            unsafe { MFStartup(MF_VERSION, MFSTARTUP_NOSOCKET) }
                .map_err(|e| format!("MFStartup a échoué: {e}"))
        })
        .clone()
        .map_err(EncodeError::System)
}

/// Crée le gestionnaire qui expose le device D3D11 à Media Foundation.
fn create_device_manager(device: &ID3D11Device) -> Result<IMFDXGIDeviceManager, EncodeError> {
    let mut token = 0u32;
    let mut manager = None;
    // SAFETY: `token` et `manager` vivent pendant l'appel.
    unsafe { MFCreateDXGIDeviceManager(&mut token, &mut manager) }.map_err(map_error)?;
    let manager =
        manager.ok_or_else(|| EncodeError::System("gestionnaire DXGI non créé".into()))?;
    // SAFETY: `device` survit au gestionnaire, qui est détenu par l'encodeur.
    unsafe { manager.ResetDevice(device, token) }.map_err(map_error)?;
    Ok(manager)
}

/// Choisit la première transformation matérielle qui accepte notre configuration.
///
/// `MFT_ENUM_FLAG_SORTANDFILTER` place en tête celle que le système juge la
/// mieux adaptée ; les suivantes servent de repli si la configuration échoue.
fn select_encoder(
    manager: &IMFDXGIDeviceManager,
    config: EncoderConfig,
) -> Result<(IMFTransform, String), EncodeError> {
    let input = MFT_REGISTER_TYPE_INFO {
        guidMajorType: MFMediaType_Video,
        guidSubtype: MFVideoFormat_NV12,
    };
    let output = MFT_REGISTER_TYPE_INFO {
        guidMajorType: MFMediaType_Video,
        guidSubtype: MFVideoFormat_H264,
    };

    let mut last_error = None;
    for activate in enumerate_encoders(&input, &output)? {
        let name = read_friendly_name(&activate);

        // SAFETY: instancie la transformation décrite par l'activation.
        let transform: IMFTransform = match unsafe { activate.ActivateObject() } {
            Ok(transform) => transform,
            Err(e) => {
                last_error = Some(map_error(e));
                continue;
            }
        };

        match configure_encoder(&transform, manager, config) {
            Ok(()) => return Ok((transform, name)),
            Err(e) => {
                tracing::debug!(encoder = %name, error = %e, "encodeur écarté");
                last_error = Some(e);
            }
        }
    }

    Err(last_error.unwrap_or(EncodeError::NoHardwareEncoder { codec: "H.264" }))
}

/// Lit le nom lisible d'une transformation, pour la journalisation.
fn read_friendly_name(activate: &IMFActivate) -> String {
    let mut value = PWSTR::null();
    let mut length = 0u32;
    // SAFETY: `value` et `length` vivent pendant l'appel ; en cas d'échec
    // aucune allocation n'a lieu.
    if unsafe { activate.GetAllocatedString(&MFT_FRIENDLY_NAME_Attribute, &mut value, &mut length) }
        .is_err()
    {
        return "encodeur sans nom".into();
    }
    // SAFETY: chaîne UTF-16 terminée par un zéro, allouée par COM.
    let name = unsafe { value.to_string() }.unwrap_or_default();
    // SAFETY: libère l'allocation faite par `GetAllocatedString`.
    unsafe { CoTaskMemFree(Some(value.as_ptr() as *const _)) };
    name
}

/// Énumère les encodeurs matériels correspondant aux types demandés.
fn enumerate_encoders(
    input: &MFT_REGISTER_TYPE_INFO,
    output: &MFT_REGISTER_TYPE_INFO,
) -> Result<Vec<IMFActivate>, EncodeError> {
    let mut activates: *mut Option<IMFActivate> = std::ptr::null_mut();
    let mut count = 0u32;

    // SAFETY: l'API alloue un tableau COM dont nous prenons la propriété.
    unsafe {
        MFTEnumEx(
            MFT_CATEGORY_VIDEO_ENCODER,
            MFT_ENUM_FLAG_HARDWARE | MFT_ENUM_FLAG_SORTANDFILTER,
            Some(input),
            Some(output),
            &mut activates,
            &mut count,
        )
    }
    .map_err(map_error)?;

    if activates.is_null() || count == 0 {
        if !activates.is_null() {
            // SAFETY: tableau alloué par COM, jamais lu ensuite.
            unsafe { CoTaskMemFree(Some(activates as *const _)) };
        }
        return Err(EncodeError::NoHardwareEncoder { codec: "H.264" });
    }

    let mut result = Vec::with_capacity(count as usize);
    for index in 0..count as usize {
        // SAFETY: `activates` pointe sur `count` entrées initialisées ; `read`
        // en déplace la propriété, si bien que le tableau ne détient plus rien.
        if let Some(activate) = unsafe { std::ptr::read(activates.add(index)) } {
            result.push(activate);
        }
    }
    // SAFETY: toutes les entrées ont été déplacées ; seul le tableau reste.
    unsafe { CoTaskMemFree(Some(activates as *const _)) };

    Ok(result)
}

/// Applique le device partagé puis les types d'entrée et de sortie.
///
/// L'ordre compte : le gestionnaire D3D doit être posé avant les types, et le
/// type de sortie avant celui d'entrée — un encodeur refuse un format d'entrée
/// tant qu'il ignore ce qu'il doit produire.
fn configure_encoder(
    transform: &IMFTransform,
    manager: &IMFDXGIDeviceManager,
    config: EncoderConfig,
) -> Result<(), EncodeError> {
    // SAFETY: lecture des attributs de la transformation détenue par l'appelant.
    if let Ok(attributes) = unsafe { transform.GetAttributes() } {
        // SAFETY: une transformation matérielle est asynchrone et doit être
        // déverrouillée avant tout usage.
        unsafe {
            let is_async = attributes.GetUINT32(&MF_TRANSFORM_ASYNC).unwrap_or(0);
            if is_async == 1 {
                attributes.SetUINT32(&MF_TRANSFORM_ASYNC_UNLOCK, 1)?;
            }
            let _ = attributes.SetUINT32(&MF_LOW_LATENCY, 1);
        }
    }

    // SAFETY: le gestionnaire survit à la transformation, tous deux étant
    // détenus par l'encodeur.
    unsafe {
        transform.ProcessMessage(MFT_MESSAGE_SET_D3D_MANAGER, manager.as_raw() as usize)
    }
    .map_err(map_error)?;

    let output_type = build_output_type(config)?;
    // SAFETY: le type vient d'être construit et vit pendant l'appel.
    unsafe { transform.SetOutputType(0, &output_type, 0) }.map_err(map_error)?;

    let input_type = build_input_type(config)?;
    // SAFETY: idem.
    unsafe { transform.SetInputType(0, &input_type, 0) }.map_err(map_error)?;

    Ok(())
}

/// Type de sortie : H.264 progressif, débit et cadence cibles.
fn build_output_type(config: EncoderConfig) -> Result<IMFMediaType, EncodeError> {
    // SAFETY: création d'un objet Media Foundation vierge.
    let media_type = unsafe { MFCreateMediaType() }.map_err(map_error)?;
    // SAFETY: écritures d'attributs sur un objet détenu localement.
    unsafe {
        media_type.SetGUID(&MF_MT_MAJOR_TYPE, &MFMediaType_Video)?;
        media_type.SetGUID(&MF_MT_SUBTYPE, &MFVideoFormat_H264)?;
        media_type.SetUINT32(&MF_MT_AVG_BITRATE, config.bitrate)?;
        media_type.SetUINT64(&MF_MT_FRAME_SIZE, pack_ratio(config.width, config.height))?;
        media_type.SetUINT64(&MF_MT_FRAME_RATE, pack_ratio(config.framerate, 1))?;
        media_type.SetUINT64(&MF_MT_PIXEL_ASPECT_RATIO, pack_ratio(1, 1))?;
        media_type.SetUINT32(&MF_MT_INTERLACE_MODE, MFVideoInterlace_Progressive.0 as u32)?;
        // Profil High : tous les décodeurs matériels de navigateur le gèrent, et
        // il compresse sensiblement mieux que Baseline à qualité égale.
        media_type.SetUINT32(&MF_MT_MPEG2_PROFILE, eAVEncH264VProfile_High.0 as u32)?;
    }
    Ok(media_type)
}

/// Type d'entrée : NV12, même géométrie et même cadence.
fn build_input_type(config: EncoderConfig) -> Result<IMFMediaType, EncodeError> {
    // SAFETY: création d'un objet Media Foundation vierge.
    let media_type = unsafe { MFCreateMediaType() }.map_err(map_error)?;
    // SAFETY: écritures d'attributs sur un objet détenu localement.
    unsafe {
        media_type.SetGUID(&MF_MT_MAJOR_TYPE, &MFMediaType_Video)?;
        media_type.SetGUID(&MF_MT_SUBTYPE, &MFVideoFormat_NV12)?;
        media_type.SetUINT64(&MF_MT_FRAME_SIZE, pack_ratio(config.width, config.height))?;
        media_type.SetUINT64(&MF_MT_FRAME_RATE, pack_ratio(config.framerate, 1))?;
        media_type.SetUINT64(&MF_MT_PIXEL_ASPECT_RATIO, pack_ratio(1, 1))?;
        media_type.SetUINT32(&MF_MT_INTERLACE_MODE, MFVideoInterlace_Progressive.0 as u32)?;
    }
    Ok(media_type)
}

/// Règle l'encodeur pour la latence plutôt que pour la taille du fichier.
///
/// Chaque propriété est facultative : un encodeur qui n'en connaît pas une
/// renvoie une erreur, qui est journalisée sans interrompre la configuration.
fn apply_low_latency_settings(codec_api: &ICodecAPI, config: EncoderConfig) {
    let settings: [(GUID, VARIANT, &str); 6] = [
        (
            CODECAPI_AVEncCommonRateControlMode,
            VARIANT::from(eAVEncCommonRateControlMode_CBR.0 as u32),
            "débit constant",
        ),
        (
            CODECAPI_AVEncCommonMeanBitRate,
            VARIANT::from(config.bitrate),
            "débit moyen",
        ),
        (
            CODECAPI_AVEncCommonLowLatency,
            VARIANT::from(true),
            "mode faible latence",
        ),
        (
            CODECAPI_AVEncMPVDefaultBPictureCount,
            VARIANT::from(0u32),
            "aucune image B",
        ),
        (
            CODECAPI_AVEncVideoMaxNumRefFrame,
            VARIANT::from(1u32),
            "une seule image de référence",
        ),
        (
            // GOP infini : les images clés ne sont émises que sur demande du
            // client, ce qui évite les pics de débit périodiques.
            CODECAPI_AVEncMPVGOPSize,
            VARIANT::from(0u32),
            "GOP infini",
        ),
    ];

    for (key, value, label) in settings {
        // SAFETY: `key` et `value` sont copiés par l'appel.
        if let Err(e) = unsafe { codec_api.SetValue(&key, &value) } {
            tracing::debug!(setting = label, error = %e, "réglage non supporté");
        }
    }
}

/// Récupère les paramètres de séquence (SPS/PPS) hors bande, s'ils existent.
fn read_sequence_header(transform: &IMFTransform) -> Vec<u8> {
    // SAFETY: lecture du type de sortie courant de la transformation.
    let Ok(media_type) = (unsafe { transform.GetOutputCurrentType(0) }) else {
        return Vec::new();
    };
    // SAFETY: première passe pour connaître la taille du blob.
    let Ok(length) = (unsafe { media_type.GetBlobSize(&MF_MT_MPEG_SEQUENCE_HEADER) }) else {
        return Vec::new();
    };
    if length == 0 {
        return Vec::new();
    }
    let mut buffer = vec![0u8; length as usize];
    let mut written = 0u32;
    // SAFETY: `buffer` a exactement la taille annoncée par l'appel précédent.
    if unsafe {
        media_type.GetBlob(
            &MF_MT_MPEG_SEQUENCE_HEADER,
            &mut buffer,
            Some(&mut written),
        )
    }
    .is_err()
    {
        return Vec::new();
    }
    buffer.truncate(written as usize);
    buffer
}

/// Enveloppe une texture D3D11 dans un échantillon Media Foundation.
///
/// La texture n'est pas copiée : l'échantillon la référence directement, ce qui
/// est tout l'intérêt du gestionnaire DXGI.
fn wrap_texture_in_sample(texture: &ID3D11Texture2D) -> Result<IMFSample, EncodeError> {
    // SAFETY: `texture` est détenue par le convertisseur, lui-même détenu par
    // la surface qui portera cet échantillon.
    let buffer = unsafe {
        MFCreateDXGISurfaceBuffer(&ID3D11Texture2D::IID, texture, 0, false)
    }
    .map_err(map_error)?;

    // Un tampon DXGI naît avec une longueur nulle ; l'encodeur refuserait un
    // échantillon vide.
    // SAFETY: le tampon vient d'être créé et est détenu localement.
    if let Ok(two_d) = buffer.cast::<IMF2DBuffer>() {
        // SAFETY: idem.
        if let Ok(length) = unsafe { two_d.GetContiguousLength() } {
            // SAFETY: idem.
            unsafe { buffer.SetCurrentLength(length) }.map_err(map_error)?;
        }
    }

    // SAFETY: création puis remplissage d'un échantillon détenu localement.
    let sample = unsafe { MFCreateSample() }.map_err(map_error)?;
    // SAFETY: `AddBuffer` prend sa propre référence sur le tampon.
    unsafe { sample.AddBuffer(&buffer) }.map_err(map_error)?;
    Ok(sample)
}

/// Empaquette deux entiers 32 bits dans l'attribut 64 bits attendu par MF.
fn pack_ratio(high: u32, low: u32) -> u64 {
    (u64::from(high) << 32) | u64::from(low)
}

/// Le train binaire commence-t-il déjà par un jeu de paramètres ?
///
/// Format Annex-B : un préfixe `00 00 01` ou `00 00 00 01`, puis un octet dont
/// les cinq bits de poids faible donnent le type de NALU — 7 pour un SPS.
fn starts_with_parameter_set(data: &[u8]) -> bool {
    let payload = if data.starts_with(&[0, 0, 0, 1]) {
        &data[4..]
    } else if data.starts_with(&[0, 0, 1]) {
        &data[3..]
    } else {
        return false;
    };
    matches!(payload.first().map(|b| b & 0x1F), Some(7))
}

pub(crate) fn map_error(error: windows::core::Error) -> EncodeError {
    EncodeError::System(format!("{} (0x{:08X})", error.message(), error.code().0))
}

impl From<windows::core::Error> for EncodeError {
    fn from(error: windows::core::Error) -> Self {
        map_error(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ratio_packing_matches_media_foundation_layout() {
        assert_eq!(pack_ratio(1920, 1080), (1920u64 << 32) | 1080);
        assert_eq!(pack_ratio(60, 1), (60u64 << 32) | 1);
        assert_eq!(pack_ratio(0, 0), 0);
    }

    #[test]
    fn detects_a_leading_sequence_parameter_set() {
        assert!(starts_with_parameter_set(&[0, 0, 0, 1, 0x67, 0x42]));
        assert!(starts_with_parameter_set(&[0, 0, 1, 0x27]));
    }

    #[test]
    fn ignores_slices_and_malformed_prefixes() {
        // NALU de type 5 : image IDR sans paramètres en tête.
        assert!(!starts_with_parameter_set(&[0, 0, 0, 1, 0x65]));
        // NALU de type 1 : image inter.
        assert!(!starts_with_parameter_set(&[0, 0, 1, 0x41]));
        assert!(!starts_with_parameter_set(&[0x67, 0x42]));
        assert!(!starts_with_parameter_set(&[]));
        assert!(!starts_with_parameter_set(&[0, 0, 0, 1]));
    }
}
