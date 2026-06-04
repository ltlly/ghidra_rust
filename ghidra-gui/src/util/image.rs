//! Image utility functions.
//!
//! Port of Ghidra's `generic.util.image.ImageUtils`.

/// An RGBA pixel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RgbaPixel {
    /// Red channel.
    pub r: u8,
    /// Green channel.
    pub g: u8,
    /// Blue channel.
    pub b: u8,
    /// Alpha channel.
    pub a: u8,
}

impl RgbaPixel {
    /// Create a new RGBA pixel.
    pub const fn new(r: u8, g: u8, b: u8, a: u8) -> Self {
        Self { r, g, b, a }
    }

    /// Create an opaque RGB pixel.
    pub const fn rgb(r: u8, g: u8, b: u8) -> Self {
        Self { r, g, b, a: 255 }
    }

    /// Fully transparent pixel.
    pub const TRANSPARENT: RgbaPixel = RgbaPixel::new(0, 0, 0, 0);

    /// Convert to a packed ARGB integer (0xAARRGGBB).
    pub fn to_argb(&self) -> u32 {
        ((self.a as u32) << 24) | ((self.r as u32) << 16) | ((self.g as u32) << 8) | (self.b as u32)
    }

    /// Create from a packed ARGB integer.
    pub fn from_argb(argb: u32) -> Self {
        Self {
            a: ((argb >> 24) & 0xFF) as u8,
            r: ((argb >> 16) & 0xFF) as u8,
            g: ((argb >> 8) & 0xFF) as u8,
            b: (argb & 0xFF) as u8,
        }
    }

    /// Blend this pixel with another using alpha compositing (over).
    pub fn blend_over(&self, bg: RgbaPixel) -> RgbaPixel {
        let sa = self.a as f64 / 255.0;
        let da = bg.a as f64 / 255.0;
        let out_a = sa + da * (1.0 - sa);
        if out_a < 1e-6 {
            return RgbaPixel::TRANSPARENT;
        }
        let r = (self.r as f64 * sa + bg.r as f64 * da * (1.0 - sa)) / out_a;
        let g = (self.g as f64 * sa + bg.g as f64 * da * (1.0 - sa)) / out_a;
        let b = (self.b as f64 * sa + bg.b as f64 * da * (1.0 - sa)) / out_a;
        RgbaPixel::new(r as u8, g as u8, b as u8, (out_a * 255.0) as u8)
    }
}

impl std::fmt::Display for RgbaPixel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "#{:02X}{:02X}{:02X}{:02X}", self.r, self.g, self.b, self.a)
    }
}

/// An image buffer with RGBA pixel data.
#[derive(Debug, Clone)]
pub struct ImageBuffer {
    /// Width in pixels.
    pub width: usize,
    /// Height in pixels.
    pub height: usize,
    /// Pixel data in row-major order (RGBA, 4 bytes per pixel).
    pub pixels: Vec<RgbaPixel>,
}

impl ImageBuffer {
    /// Create a new image buffer filled with the given pixel.
    pub fn new(width: usize, height: usize, fill: RgbaPixel) -> Self {
        Self {
            width,
            height,
            pixels: vec![fill; width * height],
        }
    }

    /// Create a new transparent image buffer.
    pub fn transparent(width: usize, height: usize) -> Self {
        Self::new(width, height, RgbaPixel::TRANSPARENT)
    }

    /// Get the pixel at the given coordinates.
    pub fn get_pixel(&self, x: usize, y: usize) -> Option<RgbaPixel> {
        if x < self.width && y < self.height {
            Some(self.pixels[y * self.width + x])
        } else {
            None
        }
    }

    /// Set the pixel at the given coordinates.
    pub fn set_pixel(&mut self, x: usize, y: usize, pixel: RgbaPixel) {
        if x < self.width && y < self.height {
            self.pixels[y * self.width + x] = pixel;
        }
    }

    /// Fill a rectangular region with a solid color.
    pub fn fill_rect(&mut self, x: usize, y: usize, w: usize, h: usize, color: RgbaPixel) {
        for dy in 0..h {
            for dx in 0..w {
                self.set_pixel(x + dx, y + dy, color);
            }
        }
    }

    /// Get the total number of pixels.
    pub fn pixel_count(&self) -> usize {
        self.width * self.height
    }

    /// Check whether the image is entirely transparent.
    pub fn is_fully_transparent(&self) -> bool {
        self.pixels.iter().all(|p| p.a == 0)
    }

    /// Apply a grayscale filter to the image in-place.
    pub fn apply_grayscale(&mut self) {
        for pixel in &mut self.pixels {
            let gray = (0.299 * pixel.r as f64 + 0.587 * pixel.g as f64 + 0.114 * pixel.b as f64) as u8;
            pixel.r = gray;
            pixel.g = gray;
            pixel.b = gray;
        }
    }

    /// Create a disabled (grayed-out) version of this image.
    pub fn to_disabled(&self) -> Self {
        let mut result = self.clone();
        result.apply_grayscale();
        for pixel in &mut result.pixels {
            pixel.a = (pixel.a as f64 * 0.5) as u8;
        }
        result
    }

    /// Scale the image by the given factors using nearest-neighbor interpolation.
    pub fn scale_nearest(&self, scale_x: f64, scale_y: f64) -> Self {
        let new_w = (self.width as f64 * scale_x).round() as usize;
        let new_h = (self.height as f64 * scale_y).round() as usize;
        let mut result = ImageBuffer::transparent(new_w, new_h);

        for y in 0..new_h {
            let src_y = (y as f64 / scale_y).min((self.height - 1) as f64) as usize;
            for x in 0..new_w {
                let src_x = (x as f64 / scale_x).min((self.width - 1) as f64) as usize;
                if let Some(pixel) = self.get_pixel(src_x, src_y) {
                    result.set_pixel(x, y, pixel);
                }
            }
        }
        result
    }
}

/// Image utility functions matching Ghidra's `ImageUtils`.
pub struct ImageUtils;

impl ImageUtils {
    /// Create a disabled (grayed-out and semi-transparent) version of the given image data.
    ///
    /// This is a direct port of `ImageUtils.createDisabledImage()`.
    pub fn create_disabled_image(image: &ImageBuffer) -> ImageBuffer {
        image.to_disabled()
    }

    /// Convert an image to grayscale in-place.
    pub fn to_grayscale(image: &mut ImageBuffer) {
        image.apply_grayscale();
    }

    /// Scale an image by the given factors using nearest-neighbor.
    pub fn scale(image: &ImageBuffer, scale_x: f64, scale_y: f64) -> ImageBuffer {
        image.scale_nearest(scale_x, scale_y)
    }

    /// Check if an image has any non-transparent content.
    pub fn has_content(image: &ImageBuffer) -> bool {
        !image.is_fully_transparent()
    }

    /// Merge two images by alpha-compositing `overlay` on top of `base`.
    pub fn overlay(base: &ImageBuffer, overlay: &ImageBuffer) -> ImageBuffer {
        let w = base.width.max(overlay.width);
        let h = base.height.max(overlay.height);
        let mut result = base.clone();
        if result.width < w || result.height < h {
            let mut expanded = ImageBuffer::transparent(w, h);
            for y in 0..base.height {
                for x in 0..base.width {
                    if let Some(p) = base.get_pixel(x, y) {
                        expanded.set_pixel(x, y, p);
                    }
                }
            }
            result = expanded;
        }
        for y in 0..overlay.height {
            for x in 0..overlay.width {
                if let Some(ov) = overlay.get_pixel(x, y) {
                    let bg = result.get_pixel(x, y).unwrap_or(RgbaPixel::TRANSPARENT);
                    result.set_pixel(x, y, ov.blend_over(bg));
                }
            }
        }
        result
    }

    /// Convert a hex color string ("#RRGGBB" or "#RRGGBBAA") to an RgbaPixel.
    pub fn from_hex(hex: &str) -> Option<RgbaPixel> {
        let hex = hex.trim_start_matches('#');
        match hex.len() {
            6 => {
                let r = u8::from_str_radix(&hex[0..2], 16).ok()?;
                let g = u8::from_str_radix(&hex[2..4], 16).ok()?;
                let b = u8::from_str_radix(&hex[4..6], 16).ok()?;
                Some(RgbaPixel::rgb(r, g, b))
            }
            8 => {
                let r = u8::from_str_radix(&hex[0..2], 16).ok()?;
                let g = u8::from_str_radix(&hex[2..4], 16).ok()?;
                let b = u8::from_str_radix(&hex[4..6], 16).ok()?;
                let a = u8::from_str_radix(&hex[6..8], 16).ok()?;
                Some(RgbaPixel::new(r, g, b, a))
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rgba_pixel_argb_roundtrip() {
        let p = RgbaPixel::new(0x12, 0x34, 0x56, 0x78);
        let argb = p.to_argb();
        let p2 = RgbaPixel::from_argb(argb);
        assert_eq!(p, p2);
    }

    #[test]
    fn rgba_pixel_display() {
        let p = RgbaPixel::rgb(255, 128, 0);
        assert_eq!(p.to_string(), "#FF8000FF");
    }

    #[test]
    fn rgba_pixel_blend_over_opaque() {
        let fg = RgbaPixel::rgb(255, 0, 0);
        let bg = RgbaPixel::rgb(0, 0, 255);
        let result = fg.blend_over(bg);
        assert_eq!(result.r, 255);
        assert_eq!(result.b, 0);
    }

    #[test]
    fn image_buffer_basic() {
        let mut img = ImageBuffer::new(4, 4, RgbaPixel::rgb(255, 255, 255));
        assert_eq!(img.pixel_count(), 16);
        img.set_pixel(1, 1, RgbaPixel::rgb(0, 0, 0));
        assert_eq!(img.get_pixel(1, 1), Some(RgbaPixel::rgb(0, 0, 0)));
        assert_eq!(img.get_pixel(0, 0), Some(RgbaPixel::rgb(255, 255, 255)));
    }

    #[test]
    fn image_buffer_out_of_bounds() {
        let img = ImageBuffer::new(2, 2, RgbaPixel::TRANSPARENT);
        assert_eq!(img.get_pixel(5, 5), None);
    }

    #[test]
    fn image_buffer_fill_rect() {
        let mut img = ImageBuffer::transparent(10, 10);
        img.fill_rect(2, 2, 3, 3, RgbaPixel::rgb(255, 0, 0));
        assert_eq!(img.get_pixel(2, 2), Some(RgbaPixel::rgb(255, 0, 0)));
        assert_eq!(img.get_pixel(0, 0), Some(RgbaPixel::TRANSPARENT));
    }

    #[test]
    fn image_buffer_grayscale() {
        let mut img = ImageBuffer::new(1, 1, RgbaPixel::rgb(255, 0, 0));
        img.apply_grayscale();
        let p = img.get_pixel(0, 0).unwrap();
        assert_eq!(p.r, p.g);
        assert_eq!(p.g, p.b);
    }

    #[test]
    fn image_buffer_disabled() {
        let img = ImageBuffer::new(1, 1, RgbaPixel::rgb(255, 255, 255));
        let disabled = img.to_disabled();
        let p = disabled.get_pixel(0, 0).unwrap();
        assert!(p.a < 255);
    }

    #[test]
    fn image_buffer_scale_nearest() {
        let mut img = ImageBuffer::transparent(2, 2);
        img.set_pixel(0, 0, RgbaPixel::rgb(255, 0, 0));
        img.set_pixel(1, 1, RgbaPixel::rgb(0, 255, 0));
        let scaled = img.scale_nearest(2.0, 2.0);
        assert_eq!(scaled.width, 4);
        assert_eq!(scaled.height, 4);
        assert_eq!(scaled.get_pixel(0, 0), Some(RgbaPixel::rgb(255, 0, 0)));
    }

    #[test]
    fn image_utils_overlay() {
        let base = ImageBuffer::new(4, 4, RgbaPixel::rgb(0, 0, 255));
        let mut over = ImageBuffer::transparent(4, 4);
        over.set_pixel(0, 0, RgbaPixel::rgb(255, 0, 0));
        let result = ImageUtils::overlay(&base, &over);
        assert_eq!(result.get_pixel(0, 0), Some(RgbaPixel::rgb(255, 0, 0)));
    }

    #[test]
    fn image_utils_from_hex() {
        let p = ImageUtils::from_hex("#FF8000").unwrap();
        assert_eq!(p, RgbaPixel::rgb(255, 128, 0));

        let p2 = ImageUtils::from_hex("#FF800080").unwrap();
        assert_eq!(p2.a, 0x80);
    }

    #[test]
    fn image_utils_has_content() {
        let empty = ImageBuffer::transparent(4, 4);
        assert!(!ImageUtils::has_content(&empty));
        let mut filled = ImageBuffer::transparent(4, 4);
        filled.set_pixel(0, 0, RgbaPixel::rgb(1, 1, 1));
        assert!(ImageUtils::has_content(&filled));
    }
}
