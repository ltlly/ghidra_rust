//! Image utility functions.
//!
//! Port of `generic.util.image.ImageUtils` from Ghidra's Framework/Gui.

/// RGBA pixel color.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rgba {
    pub r: u8,
    pub g: u8,
    pub b: u8,
    pub a: u8,
}

impl Rgba {
    pub const TRANSPARENT: Self = Self { r: 0, g: 0, b: 0, a: 0 };
    pub const BLACK: Self = Self { r: 0, g: 0, b: 0, a: 255 };
    pub const WHITE: Self = Self { r: 255, g: 255, b: 255, a: 255 };
    pub const RED: Self = Self { r: 255, g: 0, b: 0, a: 255 };
    pub const GREEN: Self = Self { r: 0, g: 255, b: 0, a: 255 };
    pub const BLUE: Self = Self { r: 0, g: 0, b: 255, a: 255 };

    pub fn new(r: u8, g: u8, b: u8, a: u8) -> Self {
        Self { r, g, b, a }
    }

    /// Create from a 32-bit ARGB packed value.
    pub fn from_argb(argb: u32) -> Self {
        Self {
            r: ((argb >> 16) & 0xFF) as u8,
            g: ((argb >> 8) & 0xFF) as u8,
            b: (argb & 0xFF) as u8,
            a: ((argb >> 24) & 0xFF) as u8,
        }
    }

    /// Convert to a 32-bit ARGB packed value.
    pub fn to_argb(self) -> u32 {
        ((self.a as u32) << 24)
            | ((self.r as u32) << 16)
            | ((self.g as u32) << 8)
            | (self.b as u32)
    }
}

/// Simple in-memory ARGB image buffer.
///
/// Port of Ghidra's `ImageUtils` convenience methods for
/// pixel-level image manipulation.
#[derive(Debug, Clone)]
pub struct ImageBuffer {
    width: u32,
    height: u32,
    pixels: Vec<Rgba>,
}

impl ImageBuffer {
    /// Create a new blank (transparent) image.
    pub fn new(width: u32, height: u32) -> Self {
        Self {
            width,
            height,
            pixels: vec![Rgba::TRANSPARENT; (width * height) as usize],
        }
    }

    /// Create an image filled with a single color.
    pub fn filled(width: u32, height: u32, color: Rgba) -> Self {
        Self {
            width,
            height,
            pixels: vec![color; (width * height) as usize],
        }
    }

    /// Image width in pixels.
    pub fn width(&self) -> u32 {
        self.width
    }

    /// Image height in pixels.
    pub fn height(&self) -> u32 {
        self.height
    }

    /// Get a pixel at (x, y).  Returns `None` if out of bounds.
    pub fn get_pixel(&self, x: u32, y: u32) -> Option<Rgba> {
        if x < self.width && y < self.height {
            Some(self.pixels[(y * self.width + x) as usize])
        } else {
            None
        }
    }

    /// Set a pixel at (x, y).
    pub fn set_pixel(&mut self, x: u32, y: u32, color: Rgba) {
        if x < self.width && y < self.height {
            self.pixels[(y * self.width + x) as usize] = color;
        }
    }

    /// Get raw pixel data as a slice.
    pub fn pixels(&self) -> &[Rgba] {
        &self.pixels
    }

    /// Get raw pixel data as a mutable slice.
    pub fn pixels_mut(&mut self) -> &mut [Rgba] {
        &mut self.pixels
    }

    /// Convert to raw ARGB u32 buffer.
    pub fn to_argb_vec(&self) -> Vec<u32> {
        self.pixels.iter().map(|p| p.to_argb()).collect()
    }

    /// Create from a raw ARGB u32 buffer.
    pub fn from_argb_slice(width: u32, height: u32, data: &[u32]) -> Self {
        let pixels = data.iter().map(|&v| Rgba::from_argb(v)).collect();
        Self { width, height, pixels }
    }

    /// Scale the image by the given factor using nearest-neighbor interpolation.
    pub fn scale_nearest(&self, factor: f64) -> Self {
        let new_w = (self.width as f64 * factor).max(1.0) as u32;
        let new_h = (self.height as f64 * factor).max(1.0) as u32;
        let mut out = ImageBuffer::new(new_w, new_h);
        for y in 0..new_h {
            for x in 0..new_w {
                let src_x = ((x as f64 / factor) as u32).min(self.width - 1);
                let src_y = ((y as f64 / factor) as u32).min(self.height - 1);
                if let Some(px) = self.get_pixel(src_x, src_y) {
                    out.set_pixel(x, y, px);
                }
            }
        }
        out
    }

    /// Create a sub-image (crop).
    pub fn sub_image(&self, x: u32, y: u32, w: u32, h: u32) -> Self {
        let mut out = ImageBuffer::new(w, h);
        for dy in 0..h {
            for dx in 0..w {
                if let Some(px) = self.get_pixel(x + dx, y + dy) {
                    out.set_pixel(dx, dy, px);
                }
            }
        }
        out
    }
}

/// Convert a hex color string (e.g. "#FF0000" or "FF0000") to an RGBA color.
pub fn hex_to_rgba(hex: &str) -> Option<Rgba> {
    let hex = hex.trim_start_matches('#');
    if hex.len() == 6 {
        let r = u8::from_str_radix(&hex[0..2], 16).ok()?;
        let g = u8::from_str_radix(&hex[2..4], 16).ok()?;
        let b = u8::from_str_radix(&hex[4..6], 16).ok()?;
        Some(Rgba::new(r, g, b, 255))
    } else if hex.len() == 8 {
        let r = u8::from_str_radix(&hex[0..2], 16).ok()?;
        let g = u8::from_str_radix(&hex[2..4], 16).ok()?;
        let b = u8::from_str_radix(&hex[4..6], 16).ok()?;
        let a = u8::from_str_radix(&hex[6..8], 16).ok()?;
        Some(Rgba::new(r, g, b, a))
    } else {
        None
    }
}

/// Convert RGBA to a hex color string.
pub fn rgba_to_hex(color: Rgba) -> String {
    format!("#{:02X}{:02X}{:02X}{:02X}", color.r, color.g, color.b, color.a)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rgba_construction() {
        let c = Rgba::new(10, 20, 30, 255);
        assert_eq!(c.r, 10);
        assert_eq!(c.a, 255);
    }

    #[test]
    fn rgba_argb_roundtrip() {
        let c = Rgba::new(0xAA, 0xBB, 0xCC, 0xDD);
        let packed = c.to_argb();
        let back = Rgba::from_argb(packed);
        assert_eq!(c, back);
    }

    #[test]
    fn image_buffer_basic() {
        let mut img = ImageBuffer::new(4, 4);
        img.set_pixel(2, 3, Rgba::RED);
        assert_eq!(img.get_pixel(2, 3), Some(Rgba::RED));
        assert_eq!(img.get_pixel(0, 0), Some(Rgba::TRANSPARENT));
        assert_eq!(img.get_pixel(5, 5), None);
    }

    #[test]
    fn image_scale_nearest() {
        let mut img = ImageBuffer::new(2, 2);
        img.set_pixel(0, 0, Rgba::RED);
        img.set_pixel(1, 1, Rgba::BLUE);
        let scaled = img.scale_nearest(2.0);
        assert_eq!(scaled.width(), 4);
        assert_eq!(scaled.height(), 4);
        assert_eq!(scaled.get_pixel(0, 0), Some(Rgba::RED));
        assert_eq!(scaled.get_pixel(1, 0), Some(Rgba::RED));
        assert_eq!(scaled.get_pixel(3, 3), Some(Rgba::BLUE));
    }

    #[test]
    fn image_sub_image() {
        let mut img = ImageBuffer::new(4, 4);
        img.set_pixel(1, 1, Rgba::GREEN);
        img.set_pixel(2, 2, Rgba::BLUE);
        let sub = img.sub_image(1, 1, 2, 2);
        assert_eq!(sub.width(), 2);
        assert_eq!(sub.get_pixel(0, 0), Some(Rgba::GREEN));
        assert_eq!(sub.get_pixel(1, 1), Some(Rgba::BLUE));
    }

    #[test]
    fn argb_vec_roundtrip() {
        let mut img = ImageBuffer::new(2, 1);
        img.set_pixel(0, 0, Rgba::new(1, 2, 3, 4));
        img.set_pixel(1, 0, Rgba::new(5, 6, 7, 8));
        let vec = img.to_argb_vec();
        let back = ImageBuffer::from_argb_slice(2, 1, &vec);
        assert_eq!(back.get_pixel(0, 0), Some(Rgba::new(1, 2, 3, 4)));
        assert_eq!(back.get_pixel(1, 0), Some(Rgba::new(5, 6, 7, 8)));
    }

    #[test]
    fn hex_to_rgba_valid() {
        assert_eq!(hex_to_rgba("#FF0000"), Some(Rgba::new(255, 0, 0, 255)));
        assert_eq!(hex_to_rgba("00FF00"), Some(Rgba::new(0, 255, 0, 255)));
        assert_eq!(hex_to_rgba("#0000FF80"), Some(Rgba::new(0, 0, 255, 128)));
    }

    #[test]
    fn hex_to_rgba_invalid() {
        assert_eq!(hex_to_rgba("xyz"), None);
        assert_eq!(hex_to_rgba(""), None);
    }

    #[test]
    fn rgba_to_hex_format() {
        assert_eq!(rgba_to_hex(Rgba::new(255, 0, 0, 255)), "#FF0000FF");
        assert_eq!(rgba_to_hex(Rgba::new(0, 128, 64, 32)), "#00804020");
    }

    #[test]
    fn filled_image() {
        let img = ImageBuffer::filled(3, 3, Rgba::WHITE);
        for y in 0..3 {
            for x in 0..3 {
                assert_eq!(img.get_pixel(x, y), Some(Rgba::WHITE));
            }
        }
    }
}
