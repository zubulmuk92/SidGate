//! Ce que le train binaire dit de l'encodeur qui l'a produit.
//!
//! Deux comportements d'encodeur matériel, constatés sur machine réelle, se
//! lisent dans les unités H.264 qu'il rend, et se corrigent ici.
//!
//! # Le remplissage
//!
//! En débit constant, un encodeur tient sa promesse à la lettre : une image qui
//! se compresse bien est complétée par des unités de *remplissage* — des
//! milliers d'octets à `0xFF` qui ne décrivent rien. Sur un bureau, où presque
//! toutes les images se compressent bien, elles pèsent jusqu'à neuf dixièmes de
//! la sortie. Elles n'ont rien à faire sur le réseau : [`strip_filler`] les
//! retire avant que quoi que ce soit ne les compte ou ne les transporte.
//!
//! # La cadence supposée
//!
//! Le remplissage a une vertu : puisque chaque image est complétée jusqu'à son
//! budget, la taille d'une image *est* ce budget, et le budget vaut le débit
//! divisé par la cadence que l'encodeur croit devoir tenir. Or certains pilotes
//! ignorent la cadence qu'on leur déclare et en supposent une autre — trente
//! images par seconde, mesuré, quand soixante sont demandées. Chaque image
//! reçoit alors le double de sa part, et le flux réel peut atteindre le double
//! du débit choisi dès que l'écran s'anime.
//!
//! [`RateCalibration`] compare le budget observé à celui attendu et en tire le
//! facteur par lequel corriger le débit donné à l'encodeur. Un encodeur qui
//! respecte la cadence déclarée donne un facteur de un ; un encodeur qui ne
//! remplit pas ne révèle rien, et n'est pas corrigé.

/// Type d'unité NAL des données de remplissage (`filler data`).
const NAL_FILLER: u8 = 12;

/// Recopie un train Annex-B dans `out` en retirant les unités de remplissage.
///
/// `out` est vidé au préalable. Renvoie le nombre d'octets retirés. Un tampon
/// qui ne commence pas par un code de départ est recopié tel quel : ce n'est
/// pas à ce filtre de juger un flux qu'il ne sait pas lire.
pub fn strip_filler(input: &[u8], out: &mut Vec<u8>) -> usize {
    out.clear();
    let starts = start_codes(input);
    let Some(&first) = starts.first() else {
        out.extend_from_slice(input);
        return 0;
    };
    // Ce qui précède le premier code de départ n'appartient à aucune unité.
    out.extend_from_slice(&input[..first.begin]);

    let mut removed = 0;
    for (index, code) in starts.iter().enumerate() {
        let end = starts.get(index + 1).map_or(input.len(), |next| next.begin);
        let is_filler = input
            .get(code.payload)
            .is_some_and(|header| header & 0x1F == NAL_FILLER);
        if is_filler {
            removed += end - code.begin;
        } else {
            out.extend_from_slice(&input[code.begin..end]);
        }
    }
    removed
}

/// Emplacement d'un code de départ et de l'unité qu'il introduit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct StartCode {
    /// Premier octet du code de départ, zéro de tête compris.
    begin: usize,
    /// Premier octet de l'unité : son en-tête.
    payload: usize,
}

/// Localise les codes de départ `00 00 01` et `00 00 00 01`.
///
/// La recherche saute de zéro en zéro : le remplissage n'en contient aucun, et
/// c'est lui qui fait l'essentiel du volume.
fn start_codes(input: &[u8]) -> Vec<StartCode> {
    let mut found = Vec::new();
    let mut cursor = 0;
    while let Some(offset) = input[cursor..].iter().position(|byte| *byte == 0) {
        let zero = cursor + offset;
        if input.get(zero + 1) == Some(&0) && input.get(zero + 2) == Some(&1) {
            // Un zéro juste avant fait partie du code : forme à quatre octets.
            // Sauf si ce zéro est l'en-tête de l'unité précédente.
            let free = found
                .last()
                .is_none_or(|last: &StartCode| last.payload + 1 < zero);
            let begin = if zero > 0 && input[zero - 1] == 0 && free {
                zero - 1
            } else {
                zero
            };
            found.push(StartCode {
                begin,
                payload: zero + 3,
            });
            cursor = zero + 3;
        } else {
            cursor = zero + 1;
        }
    }
    found
}

/// Images consécutives observées avant de conclure.
const WINDOW: u32 = 30;
/// Part de remplissage à partir de laquelle une image a visiblement été
/// complétée jusqu'à son budget, en pourcentage de sa taille.
const PADDED_PERCENT: usize = 5;
/// Part des images de la fenêtre qui doivent avoir été complétées pour que
/// leur taille renseigne sur le budget, en pourcentage.
const PADDED_SHARE_PERCENT: u32 = 80;
/// Écart en deçà duquel la cadence supposée est tenue pour la bonne.
const TOLERANCE: f64 = 0.2;

/// Déduit de la taille des images la cadence que l'encodeur suppose.
#[derive(Debug, Clone, PartialEq)]
pub struct RateCalibration {
    framerate: u32,
    /// Débit actuellement donné à l'encodeur, en bits par seconde.
    encoder_bitrate: u32,
    seen: u32,
    padded: u32,
    padded_bits: u64,
    /// Facteur à appliquer au débit voulu ; `None` tant que rien n'est conclu.
    factor: Option<f64>,
}

impl RateCalibration {
    /// Nouvelle observation, pour un encodeur réglé à `encoder_bitrate` et
    /// auquel on a déclaré `framerate` images par seconde.
    pub fn new(framerate: u32, encoder_bitrate: u32) -> Self {
        Self {
            framerate: framerate.max(1),
            encoder_bitrate,
            seen: 0,
            padded: 0,
            padded_bits: 0,
            factor: None,
        }
    }

    /// Facteur par lequel multiplier le débit voulu avant de le donner à
    /// l'encodeur. Vaut un tant que rien n'a été mesuré.
    pub fn factor(&self) -> f64 {
        self.factor.unwrap_or(1.0)
    }

    /// Le débit donné à l'encodeur vient de changer : les tailles observées
    /// jusque-là décrivaient l'ancien budget.
    pub fn restart(&mut self, encoder_bitrate: u32) {
        self.encoder_bitrate = encoder_bitrate;
        self.seen = 0;
        self.padded = 0;
        self.padded_bits = 0;
    }

    /// Observe une image rendue par l'encodeur.
    ///
    /// `total` est sa taille remplissage compris, `filler` la part de
    /// remplissage. Renvoie le facteur de correction la première fois qu'il est
    /// établi et qu'il s'écarte de un ; `None` le reste du temps.
    pub fn observe(&mut self, total: usize, filler: usize, keyframe: bool) -> Option<f64> {
        // Une image clé dépasse son budget par nature : elle ne dit rien de lui.
        if self.factor.is_some() || keyframe || total == 0 {
            return None;
        }
        self.seen += 1;
        if filler * 100 >= total * PADDED_PERCENT {
            self.padded += 1;
            self.padded_bits += total as u64 * 8;
        }
        if self.seen < WINDOW {
            return None;
        }

        let conclusive = self.padded * 100 >= self.seen * PADDED_SHARE_PERCENT;
        let average_bits = self.padded_bits.checked_div(u64::from(self.padded));
        self.seen = 0;
        self.padded = 0;
        self.padded_bits = 0;
        // Trop peu d'images complétées : l'encodeur ne remplit pas, ou l'écran
        // est trop animé pour que le budget se lise. On regarde la suite.
        let average_bits = average_bits.filter(|bits| conclusive && *bits > 0)?;

        let assumed_framerate = f64::from(self.encoder_bitrate) / average_bits as f64;
        let factor = (assumed_framerate / f64::from(self.framerate)).clamp(0.25, 4.0);
        if (factor - 1.0).abs() <= TOLERANCE {
            self.factor = Some(1.0);
            return None;
        }
        self.factor = Some(factor);
        Some(factor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SHORT: [u8; 3] = [0, 0, 1];
    const LONG: [u8; 4] = [0, 0, 0, 1];

    /// Assemble un train Annex-B à partir de ses unités.
    fn stream(units: &[(&[u8], u8, usize)]) -> Vec<u8> {
        let mut out = Vec::new();
        for (code, header, length) in units {
            out.extend_from_slice(code);
            out.push(*header);
            let fill = if header & 0x1F == NAL_FILLER {
                0xFF
            } else {
                0x42
            };
            out.extend(std::iter::repeat_n(fill, *length));
        }
        out
    }

    fn stripped(input: &[u8]) -> (Vec<u8>, usize) {
        let mut out = vec![0xAA; 7];
        let removed = strip_filler(input, &mut out);
        (out, removed)
    }

    #[test]
    fn filler_is_removed_and_everything_else_kept_in_order() {
        // Délimiteur, tranche, remplissage : ce que rend l'encodeur pour une
        // image qui se compresse bien.
        let input = stream(&[(&LONG, 0x09, 1), (&LONG, 0x41, 50), (&SHORT, 0x0C, 4000)]);
        let expected = stream(&[(&LONG, 0x09, 1), (&LONG, 0x41, 50)]);
        let (out, removed) = stripped(&input);
        assert_eq!(out, expected);
        assert_eq!(removed, 3 + 1 + 4000);
    }

    #[test]
    fn filler_in_the_middle_does_not_swallow_what_follows() {
        let input = stream(&[(&LONG, 0x67, 10), (&LONG, 0x0C, 500), (&LONG, 0x65, 80)]);
        let expected = stream(&[(&LONG, 0x67, 10), (&LONG, 0x65, 80)]);
        let (out, removed) = stripped(&input);
        assert_eq!(out, expected);
        assert_eq!(removed, 4 + 1 + 500);
    }

    #[test]
    fn a_stream_without_filler_is_copied_unchanged() {
        let input = stream(&[(&LONG, 0x67, 10), (&SHORT, 0x68, 4), (&SHORT, 0x65, 300)]);
        let (out, removed) = stripped(&input);
        assert_eq!(out, input);
        assert_eq!(removed, 0);
    }

    #[test]
    fn a_frame_made_only_of_filler_becomes_empty() {
        let input = stream(&[(&LONG, 0x0C, 100)]);
        let (out, removed) = stripped(&input);
        assert!(out.is_empty());
        assert_eq!(removed, input.len());
    }

    #[test]
    fn the_filler_type_is_read_from_the_low_five_bits() {
        // Bits de priorité à un : c'est toujours du remplissage.
        let input = stream(&[(&LONG, 0x41, 5), (&LONG, 0x6C, 64)]);
        assert_eq!(stripped(&input).0, stream(&[(&LONG, 0x41, 5)]));
        // Type 28, dont l'octet ressemble au 12 sans en être un.
        let input = stream(&[(&LONG, 0x1C, 5)]);
        assert_eq!(stripped(&input).1, 0);
    }

    #[test]
    fn data_that_is_not_annex_b_passes_through() {
        let input = [0x42u8, 0x00, 0x17, 0x00, 0x00];
        let (out, removed) = stripped(&input);
        assert_eq!(out, input);
        assert_eq!(removed, 0);
        assert_eq!(stripped(&[]).0, Vec::<u8>::new());
    }

    #[test]
    fn truncated_start_codes_do_not_read_out_of_bounds() {
        for input in [&[0u8][..], &[0, 0], &[0, 0, 1], &[0, 0, 0, 1], &[1, 0, 0]] {
            let (out, removed) = stripped(input);
            assert_eq!(out, input, "{input:?}");
            assert_eq!(removed, 0);
        }
    }

    #[test]
    fn a_trailing_zero_of_one_unit_is_not_taken_for_the_next_start_code() {
        // Tranche terminée par un zéro, suivie d'un code court : le zéro est
        // rattaché au code suivant, ce qui laisse les deux unités intactes une
        // fois recollées.
        let mut input = stream(&[(&LONG, 0x41, 3)]);
        input.push(0);
        input.extend(stream(&[(&SHORT, 0x41, 3)]));
        let (out, removed) = stripped(&input);
        assert_eq!(out, input);
        assert_eq!(removed, 0);
    }

    /// Fait défiler `count` images complétées jusqu'au budget d'un encodeur
    /// qui suppose `assumed` images par seconde.
    fn feed(
        calibration: &mut RateCalibration,
        bitrate: u32,
        assumed: u32,
        count: u32,
    ) -> Option<f64> {
        let budget = (bitrate / assumed / 8) as usize;
        (0..count)
            .filter_map(|_| calibration.observe(budget, budget * 9 / 10, false))
            .last()
    }

    #[test]
    fn an_encoder_assuming_half_the_rate_is_given_half_the_bitrate() {
        // Mesuré sur un encodeur AMD : 60 i/s déclarées, budget calculé sur 30.
        let mut calibration = RateCalibration::new(60, 8_000_000);
        let factor = feed(&mut calibration, 8_000_000, 30, WINDOW).expect("écart à corriger");
        assert!((factor - 0.5).abs() < 0.01, "{factor}");
        assert!((calibration.factor() - 0.5).abs() < 0.01);
    }

    #[test]
    fn an_encoder_honouring_the_declared_rate_is_left_alone() {
        let mut calibration = RateCalibration::new(60, 8_000_000);
        assert_eq!(feed(&mut calibration, 8_000_000, 60, WINDOW * 3), None);
        assert_eq!(calibration.factor(), 1.0);
    }

    #[test]
    fn an_encoder_that_does_not_pad_reveals_nothing() {
        let mut calibration = RateCalibration::new(60, 8_000_000);
        for _ in 0..WINDOW * 4 {
            assert_eq!(calibration.observe(4_000, 0, false), None);
        }
        assert_eq!(calibration.factor(), 1.0);
    }

    #[test]
    fn nothing_is_concluded_before_a_full_window() {
        let mut calibration = RateCalibration::new(60, 8_000_000);
        assert_eq!(feed(&mut calibration, 8_000_000, 30, WINDOW - 1), None);
        assert_eq!(calibration.factor(), 1.0);
    }

    #[test]
    fn keyframes_are_not_counted() {
        let mut calibration = RateCalibration::new(60, 8_000_000);
        for _ in 0..WINDOW * 2 {
            assert_eq!(calibration.observe(200_000, 0, true), None);
        }
        // Les images ordinaires qui suivent sont jugées sur une fenêtre neuve.
        assert!(feed(&mut calibration, 8_000_000, 30, WINDOW).is_some());
    }

    #[test]
    fn a_busy_screen_postpones_the_verdict_instead_of_skewing_it() {
        // La moitié des images dépasse le budget, sans remplissage : la
        // fenêtre n'est pas concluante, et la suivante l'est.
        let mut calibration = RateCalibration::new(60, 8_000_000);
        let budget = 8_000_000 / 30 / 8;
        for index in 0..WINDOW {
            let filler = if index % 2 == 0 { budget * 9 / 10 } else { 0 };
            assert_eq!(calibration.observe(budget, filler, false), None);
        }
        assert_eq!(calibration.factor(), 1.0);
        assert!(feed(&mut calibration, 8_000_000, 30, WINDOW).is_some());
    }

    #[test]
    fn the_factor_is_established_once() {
        let mut calibration = RateCalibration::new(60, 8_000_000);
        assert!(feed(&mut calibration, 8_000_000, 30, WINDOW).is_some());
        // Débit corrigé donné à l'encodeur ; les images qui suivent ont la
        // taille voulue et ne doivent rien déclencher de plus.
        calibration.restart(4_000_000);
        assert_eq!(feed(&mut calibration, 4_000_000, 30, WINDOW * 3), None);
        assert!((calibration.factor() - 0.5).abs() < 0.01);
    }

    #[test]
    fn an_absurd_reading_is_bounded() {
        let mut calibration = RateCalibration::new(60, 8_000_000);
        // Budget cent fois trop petit : cadence supposée invraisemblable.
        let factor = feed(&mut calibration, 8_000_000, 6_000, WINDOW).unwrap();
        assert_eq!(factor, 4.0);
        let mut calibration = RateCalibration::new(240, 8_000_000);
        let factor = feed(&mut calibration, 8_000_000, 1, WINDOW).unwrap();
        assert_eq!(factor, 0.25);
    }
}
