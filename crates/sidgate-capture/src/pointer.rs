//! Forme du curseur, convertie en une image que tout client sait dessiner.
//!
//! Le compositeur livre le curseur sous trois formats hérités de GDI, dont deux
//! ne sont pas des images au sens courant : ils décrivent une *opération* sur
//! les pixels du bureau — remplacer, laisser, ou inverser. Le client, lui, ne
//! sait que superposer une image avec transparence. La conversion a lieu ici,
//! une fois par changement de forme, et ne manipule que quelques kilo-octets.
//!
//! # L'inversion
//!
//! Le curseur de saisie de texte est le cas d'école : il ne possède aucune
//! couleur propre, il inverse ce qu'il recouvre pour rester lisible sur tout
//! fond. Sans accès aux pixels du bureau — qui ne quittent jamais la VRAM —
//! l'inversion ne peut pas être reproduite. Elle est rendue par ce qui s'en
//! approche le plus : un trait blanc cerné de noir, lisible lui aussi sur fond
//! clair comme sur fond sombre.

/// Plus grand côté accepté pour une forme de curseur.
///
/// Les curseurs système font 32 pixels, 64 ou 96 sur un écran à forte densité.
/// Au-delà, la forme vient d'une application fantaisiste ou d'un pilote
/// défaillant, et le curseur précédent est conservé.
pub const MAX_POINTER_SIDE: u32 = 256;

const OPAQUE_BLACK: [u8; 4] = [0, 0, 0, 255];
const OPAQUE_WHITE: [u8; 4] = [255, 255, 255, 255];
const TRANSPARENT: [u8; 4] = [0, 0, 0, 0];

/// Format d'origine d'une forme de curseur.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShapeKind {
    /// Deux masques d'un bit par pixel, l'un au-dessus de l'autre.
    Monochrome,
    /// Image 32 bits avec canal alpha.
    Color,
    /// Image 32 bits dont le canal alpha est un masque d'inversion.
    MaskedColor,
}

/// Image d'un curseur, prête à être superposée.
#[derive(Clone, PartialEq, Eq)]
pub struct PointerShape {
    /// Largeur, en pixels.
    pub width: u32,
    /// Hauteur, en pixels.
    pub height: u32,
    /// Abscisse du point chaud dans l'image.
    pub hot_x: u32,
    /// Ordonnée du point chaud dans l'image.
    pub hot_y: u32,
    /// Pixels RGBA non prémultipliés, ligne par ligne.
    pub rgba: Vec<u8>,
}

impl std::fmt::Debug for PointerShape {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Les pixels n'apprennent rien dans un journal.
        f.debug_struct("PointerShape")
            .field("width", &self.width)
            .field("height", &self.height)
            .field("hot_x", &self.hot_x)
            .field("hot_y", &self.hot_y)
            .finish_non_exhaustive()
    }
}

impl PointerShape {
    /// Convertit une forme telle que le compositeur la livre.
    ///
    /// `height` est la hauteur du tampon, pas celle du curseur : pour une forme
    /// monochrome, les deux masques y sont empilés. Renvoie `None` si les
    /// dimensions annoncées ne tiennent pas dans `data` ou sortent des bornes —
    /// le tampon vient d'un pilote, et un pilote se trompe aussi.
    pub fn convert(
        kind: ShapeKind,
        width: u32,
        height: u32,
        pitch: u32,
        hot: (i32, i32),
        data: &[u8],
    ) -> Option<Self> {
        let rows = match kind {
            ShapeKind::Monochrome => height / 2,
            ShapeKind::Color | ShapeKind::MaskedColor => height,
        };
        if width == 0 || rows == 0 || width > MAX_POINTER_SIDE || rows > MAX_POINTER_SIDE {
            return None;
        }

        let (w, h, pitch) = (width as usize, rows as usize, pitch as usize);
        let needed = match kind {
            ShapeKind::Monochrome => (pitch >= w.div_ceil(8)).then(|| pitch * h * 2),
            ShapeKind::Color | ShapeKind::MaskedColor => (pitch >= w * 4).then(|| pitch * h),
        }?;
        if data.len() < needed {
            return None;
        }

        let mut rgba = vec![0u8; w * h * 4];
        let mut inverted = vec![false; w * h];

        for y in 0..h {
            for x in 0..w {
                let pixel = match kind {
                    ShapeKind::Monochrome => {
                        let bit = 0x80u8 >> (x % 8);
                        let and = data[y * pitch + x / 8] & bit != 0;
                        let xor = data[(y + h) * pitch + x / 8] & bit != 0;
                        match (and, xor) {
                            (false, false) => OPAQUE_BLACK,
                            (false, true) => OPAQUE_WHITE,
                            (true, false) => TRANSPARENT,
                            (true, true) => {
                                inverted[y * w + x] = true;
                                OPAQUE_WHITE
                            }
                        }
                    }
                    ShapeKind::Color => {
                        let o = y * pitch + x * 4;
                        [data[o + 2], data[o + 1], data[o], data[o + 3]]
                    }
                    ShapeKind::MaskedColor => {
                        let o = y * pitch + x * 4;
                        let (b, g, r, mask) = (data[o], data[o + 1], data[o + 2], data[o + 3]);
                        if mask == 0 {
                            // Masque nul : la couleur remplace le bureau.
                            [r, g, b, 255]
                        } else if (r, g, b) == (0, 0, 0) {
                            // Inverser par du noir ne change rien : transparent.
                            TRANSPARENT
                        } else {
                            inverted[y * w + x] = true;
                            OPAQUE_WHITE
                        }
                    }
                };
                rgba[(y * w + x) * 4..][..4].copy_from_slice(&pixel);
            }
        }

        outline_inverted(&mut rgba, &inverted, w, h);

        Some(Self {
            width,
            height: rows,
            hot_x: hot.0.clamp(0, width as i32 - 1) as u32,
            hot_y: hot.1.clamp(0, rows as i32 - 1) as u32,
            rgba,
        })
    }

    /// L'image ne contient-elle aucun pixel visible ?
    ///
    /// Certaines applications masquent le curseur en lui donnant une forme
    /// entièrement transparente plutôt qu'en le déclarant invisible.
    pub fn is_blank(&self) -> bool {
        self.rgba.chunks_exact(4).all(|pixel| pixel[3] == 0)
    }
}

/// Cerne de noir les pixels issus d'une inversion.
///
/// Seuls les pixels transparents voisins sont noircis : le contour ne recouvre
/// jamais une partie colorée du curseur.
fn outline_inverted(rgba: &mut [u8], inverted: &[bool], w: usize, h: usize) {
    for y in 0..h {
        for x in 0..w {
            if inverted[y * w + x] || rgba[(y * w + x) * 4 + 3] != 0 {
                continue;
            }
            let touches = (x > 0 && inverted[y * w + x - 1])
                || (x + 1 < w && inverted[y * w + x + 1])
                || (y > 0 && inverted[(y - 1) * w + x])
                || (y + 1 < h && inverted[(y + 1) * w + x]);
            if touches {
                rgba[(y * w + x) * 4..][..4].copy_from_slice(&OPAQUE_BLACK);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pixel(shape: &PointerShape, x: u32, y: u32) -> [u8; 4] {
        let o = ((y * shape.width + x) * 4) as usize;
        shape.rgba[o..o + 4].try_into().unwrap()
    }

    #[test]
    fn color_shapes_are_reordered_from_bgra_to_rgba() {
        // Deux pixels : bleu opaque, rouge à moitié transparent.
        let data = [255, 0, 0, 255, 0, 0, 255, 128];
        let shape = PointerShape::convert(ShapeKind::Color, 2, 1, 8, (1, 0), &data).unwrap();
        assert_eq!(pixel(&shape, 0, 0), [0, 0, 255, 255]);
        assert_eq!(pixel(&shape, 1, 0), [255, 0, 0, 128]);
        assert_eq!((shape.hot_x, shape.hot_y), (1, 0));
    }

    #[test]
    fn row_padding_is_skipped() {
        // Un pas de 12 octets pour 2 pixels : les 4 derniers de chaque ligne
        // sont du remplissage et ne doivent pas se retrouver dans l'image.
        let mut data = vec![0xEEu8; 24];
        data[0..4].copy_from_slice(&[1, 2, 3, 255]);
        data[12..16].copy_from_slice(&[4, 5, 6, 255]);
        let shape = PointerShape::convert(ShapeKind::Color, 2, 2, 12, (0, 0), &data).unwrap();
        assert_eq!(pixel(&shape, 0, 0), [3, 2, 1, 255]);
        assert_eq!(pixel(&shape, 0, 1), [6, 5, 4, 255]);
    }

    #[test]
    fn monochrome_masks_map_to_the_four_operations() {
        // Une ligne de 8 pixels. Masque ET puis masque OU exclusif :
        //   ET  = 0011 1100
        //   OUX = 0101 0100
        // soit : noir, blanc, transparent, inversé, transparent, inversé, noir, noir.
        let data = [0b0011_1100, 0b0101_0100];
        let shape = PointerShape::convert(ShapeKind::Monochrome, 8, 2, 1, (0, 0), &data).unwrap();
        assert_eq!(
            shape.height, 1,
            "la hauteur du tampon compte les deux masques"
        );
        assert_eq!(pixel(&shape, 0, 0), OPAQUE_BLACK); // ET 0, OUX 0
        assert_eq!(pixel(&shape, 1, 0), OPAQUE_WHITE); // ET 0, OUX 1
        assert_eq!(pixel(&shape, 3, 0), OPAQUE_WHITE); // ET 1, OUX 1 : inversé
        assert_eq!(pixel(&shape, 5, 0), OPAQUE_WHITE); // ET 1, OUX 1 : inversé
        assert_eq!(pixel(&shape, 6, 0), OPAQUE_BLACK); // ET 0, OUX 0
    }

    #[test]
    fn inverted_pixels_get_a_dark_outline() {
        // Une barre verticale inversée au centre d'un carré 3x3 transparent :
        // exactement le curseur de saisie de texte.
        let and = [0b1110_0000u8; 3];
        let xor = [0b0100_0000u8; 3];
        let data: Vec<u8> = and.iter().chain(xor.iter()).copied().collect();
        let shape = PointerShape::convert(ShapeKind::Monochrome, 3, 6, 1, (1, 1), &data).unwrap();
        for y in 0..3 {
            assert_eq!(pixel(&shape, 1, y), OPAQUE_WHITE, "le trait");
            assert_eq!(pixel(&shape, 0, y), OPAQUE_BLACK, "son contour gauche");
            assert_eq!(pixel(&shape, 2, y), OPAQUE_BLACK, "son contour droit");
        }
        assert!(!shape.is_blank());
    }

    #[test]
    fn masked_color_distinguishes_replace_transparent_and_invert() {
        let data = [
            10, 20, 30, 0, // masque nul : couleur opaque
            0, 0, 0, 255, // inversion par du noir : transparent
            255, 255, 255, 255, // inversion réelle
        ];
        let shape = PointerShape::convert(ShapeKind::MaskedColor, 3, 1, 12, (0, 0), &data).unwrap();
        assert_eq!(pixel(&shape, 0, 0), [30, 20, 10, 255]);
        // Transparent à l'origine, mais voisin d'un pixel inversé : cerné.
        assert_eq!(pixel(&shape, 1, 0), OPAQUE_BLACK);
        assert_eq!(pixel(&shape, 2, 0), OPAQUE_WHITE);
    }

    #[test]
    fn the_outline_never_covers_the_cursor_itself() {
        let data = [
            10, 20, 30, 0, // couleur opaque, voisine du pixel inversé
            255, 255, 255, 255,
        ];
        let shape = PointerShape::convert(ShapeKind::MaskedColor, 2, 1, 8, (0, 0), &data).unwrap();
        assert_eq!(pixel(&shape, 0, 0), [30, 20, 10, 255]);
    }

    #[test]
    fn buffers_shorter_than_announced_are_rejected() {
        assert!(PointerShape::convert(ShapeKind::Color, 2, 2, 8, (0, 0), &[0; 15]).is_none());
        assert!(PointerShape::convert(ShapeKind::Monochrome, 8, 2, 1, (0, 0), &[0; 1]).is_none());
        // Un pas plus court qu'une ligne ferait lire au-delà de chaque ligne.
        assert!(PointerShape::convert(ShapeKind::Color, 2, 1, 4, (0, 0), &[0; 8]).is_none());
        assert!(PointerShape::convert(ShapeKind::Monochrome, 9, 2, 1, (0, 0), &[0; 4]).is_none());
    }

    #[test]
    fn absurd_dimensions_are_rejected() {
        assert!(PointerShape::convert(ShapeKind::Color, 0, 1, 0, (0, 0), &[]).is_none());
        assert!(PointerShape::convert(ShapeKind::Monochrome, 8, 1, 1, (0, 0), &[0; 2]).is_none());
        let side = MAX_POINTER_SIDE + 1;
        let data = vec![0u8; (side * side * 4) as usize];
        assert!(
            PointerShape::convert(ShapeKind::Color, side, side, side * 4, (0, 0), &data).is_none()
        );
    }

    #[test]
    fn the_hot_spot_is_clamped_inside_the_image() {
        let data = [0u8; 16];
        let shape = PointerShape::convert(ShapeKind::Color, 2, 2, 8, (9, -3), &data).unwrap();
        assert_eq!((shape.hot_x, shape.hot_y), (1, 0));
    }

    #[test]
    fn a_fully_transparent_shape_is_blank() {
        let shape = PointerShape::convert(ShapeKind::Color, 2, 2, 8, (0, 0), &[0u8; 16]).unwrap();
        assert!(shape.is_blank());
    }
}
