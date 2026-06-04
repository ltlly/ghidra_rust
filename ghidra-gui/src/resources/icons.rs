//! Concrete icon types ported from Ghidra's `resources.icons` package.
//!
//! Includes: `ColorIcon`, `EmptyIcon`, `ScaledImageIcon`, `TranslateIcon`,
//! `RotateIcon`, `ReflectedIcon`, `DerivedImageIcon`, `OvalColorIcon`,
//! and `DisabledImageIcon`.

use crate::util::image::{ImageBuffer, RgbaPixel};

// ============================================================================
// ColorIcon -- renders a solid color rectangle
// ============================================================================

/// An icon that displays a solid color.
#[derive(Debug, Clone)]
pub struct ColorIcon {
    /// The color to display.
    pub color: RgbaPixel,
    /// Width in pixels.
    pub width: u32,
    /// Height in pixels.
    pub height: u32,
    /// Optional border color.
    pub border_color: Option<RgbaPixel>,
}

impl ColorIcon {
    /// Create a new color icon.
    pub fn new(color: RgbaPixel, width: u32, height: u32) -> Self {
        Self {
            color,
            width,
            height,
            border_color: Some(RgbaPixel::rgb(0, 0, 0)),
        }
    }

    /// Create without a border.
    pub fn no_border(color: RgbaPixel, width: u32, height: u32) -> Self {
        Self {
            color,
            width,
            height,
            border_color: None,
        }
    }

    /// Render the icon to an ImageBuffer.
    pub fn render(&self) -> ImageBuffer {
        let mut img = ImageBuffer::new(self.width as usize, self.height as usize, self.color);
        if let Some(border) = self.border_color {
            // Draw border
            for x in 0..self.width {
                img.set_pixel(x as usize, 0, border);
                img.set_pixel(x as usize, (self.height - 1) as usize, border);
            }
            for y in 0..self.height {
                img.set_pixel(0, y as usize, border);
                img.set_pixel((self.width - 1) as usize, y as usize, border);
            }
        }
        img
    }
}

/// 3D-style color icon with a bevel effect.
#[derive(Debug, Clone)]
pub struct ColorIcon3D {
    /// The color to display.
    pub color: RgbaPixel,
    /// Width in pixels.
    pub width: u32,
    /// Height in pixels.
    pub height: u32,
}

impl ColorIcon3D {
    /// Create a new 3D color icon.
    pub fn new(color: RgbaPixel, width: u32, height: u32) -> Self {
        Self { color, width, height }
    }

    /// Render the icon to an ImageBuffer with a bevel effect.
    pub fn render(&self) -> ImageBuffer {
        let mut img = ImageBuffer::new(self.width as usize, self.height as usize, self.color);
        let highlight = RgbaPixel::rgb(255, 255, 255);
        let shadow = RgbaPixel::rgb(128, 128, 128);
        // Top/left highlight
        for x in 0..self.width {
            img.set_pixel(x as usize, 0, highlight);
        }
        for y in 0..self.height {
            img.set_pixel(0, y as usize, highlight);
        }
        // Bottom/right shadow
        for x in 0..self.width {
            img.set_pixel(x as usize, (self.height - 1) as usize, shadow);
        }
        for y in 0..self.height {
            img.set_pixel((self.width - 1) as usize, y as usize, shadow);
        }
        img
    }
}

// ============================================================================
// EmptyIcon -- a transparent icon placeholder
// ============================================================================

/// An icon that renders as empty/transparent space.
#[derive(Debug, Clone, Copy)]
pub struct EmptyIcon {
    /// Width in pixels.
    pub width: u32,
    /// Height in pixels.
    pub height: u32,
}

impl EmptyIcon {
    /// Create a new empty icon.
    pub fn new(width: u32, height: u32) -> Self {
        Self { width, height }
    }

    /// Render the icon to an ImageBuffer (all transparent).
    pub fn render(&self) -> ImageBuffer {
        ImageBuffer::transparent(self.width as usize, self.height as usize)
    }
}

// ============================================================================
// ScaledImageIcon -- an icon scaled to a specific size
// ============================================================================

/// An icon that wraps another image and scales it.
#[derive(Debug, Clone)]
pub struct ScaledImageIcon {
    /// The source image.
    pub source: ImageBuffer,
    /// Target width.
    pub target_width: u32,
    /// Target height.
    pub target_height: u32,
}

impl ScaledImageIcon {
    /// Create a new scaled image icon.
    pub fn new(source: ImageBuffer, target_width: u32, target_height: u32) -> Self {
        Self {
            source,
            target_width,
            target_height,
        }
    }

    /// Render the scaled icon.
    pub fn render(&self) -> ImageBuffer {
        let sx = self.target_width as f64 / self.source.width.max(1) as f64;
        let sy = self.target_height as f64 / self.source.height.max(1) as f64;
        self.source.scale_nearest(sx, sy)
    }
}

// ============================================================================
// TranslateIcon -- an icon shifted by an offset
// ============================================================================

/// An icon that renders its source image at an offset.
#[derive(Debug, Clone)]
pub struct TranslateIcon {
    /// The source image.
    pub source: ImageBuffer,
    /// Canvas width.
    pub canvas_width: usize,
    /// Canvas height.
    pub canvas_height: usize,
    /// X offset.
    pub offset_x: i32,
    /// Y offset.
    pub offset_y: i32,
}

impl TranslateIcon {
    /// Create a new translate icon.
    pub fn new(source: ImageBuffer, canvas_width: usize, canvas_height: usize, offset_x: i32, offset_y: i32) -> Self {
        Self {
            source,
            canvas_width,
            canvas_height,
            offset_x,
            offset_y,
        }
    }

    /// Render the translated icon.
    pub fn render(&self) -> ImageBuffer {
        let mut canvas = ImageBuffer::transparent(self.canvas_width, self.canvas_height);
        for sy in 0..self.source.height {
            for sx in 0..self.source.width {
                let dx = sx as i32 + self.offset_x;
                let dy = sy as i32 + self.offset_y;
                if dx >= 0 && dy >= 0 && (dx as usize) < self.canvas_width && (dy as usize) < self.canvas_height {
                    if let Some(pixel) = self.source.get_pixel(sx, sy) {
                        canvas.set_pixel(dx as usize, dy as usize, pixel);
                    }
                }
            }
        }
        canvas
    }
}

// ============================================================================
// RotateIcon -- a rotated version of a source icon
// ============================================================================

/// Rotation angles (90-degree increments).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RotationAngle {
    /// 0 degrees.
    Deg0,
    /// 90 degrees clockwise.
    Deg90,
    /// 180 degrees.
    Deg180,
    /// 270 degrees clockwise (90 counter-clockwise).
    Deg270,
}

/// An icon that rotates its source image by 90-degree increments.
#[derive(Debug, Clone)]
pub struct RotateIcon {
    /// The source image.
    pub source: ImageBuffer,
    /// Rotation angle.
    pub angle: RotationAngle,
}

impl RotateIcon {
    /// Create a new rotate icon.
    pub fn new(source: ImageBuffer, angle: RotationAngle) -> Self {
        Self { source, angle }
    }

    /// Render the rotated icon.
    pub fn render(&self) -> ImageBuffer {
        match self.angle {
            RotationAngle::Deg0 => self.source.clone(),
            RotationAngle::Deg90 => {
                let mut result = ImageBuffer::transparent(self.source.height, self.source.width);
                for y in 0..self.source.height {
                    for x in 0..self.source.width {
                        if let Some(p) = self.source.get_pixel(x, y) {
                            result.set_pixel(self.source.height - 1 - y, x, p);
                        }
                    }
                }
                result
            }
            RotationAngle::Deg180 => {
                let mut result = ImageBuffer::transparent(self.source.width, self.source.height);
                for y in 0..self.source.height {
                    for x in 0..self.source.width {
                        if let Some(p) = self.source.get_pixel(x, y) {
                            result.set_pixel(self.source.width - 1 - x, self.source.height - 1 - y, p);
                        }
                    }
                }
                result
            }
            RotationAngle::Deg270 => {
                let mut result = ImageBuffer::transparent(self.source.height, self.source.width);
                for y in 0..self.source.height {
                    for x in 0..self.source.width {
                        if let Some(p) = self.source.get_pixel(x, y) {
                            result.set_pixel(y, self.source.width - 1 - x, p);
                        }
                    }
                }
                result
            }
        }
    }
}

// ============================================================================
// ReflectedIcon -- a vertically mirrored source icon
// ============================================================================

/// An icon that displays a vertically flipped version of its source.
#[derive(Debug, Clone)]
pub struct ReflectedIcon {
    /// The source image.
    pub source: ImageBuffer,
}

impl ReflectedIcon {
    /// Create a new reflected icon.
    pub fn new(source: ImageBuffer) -> Self {
        Self { source }
    }

    /// Render the reflected (vertically flipped) icon.
    pub fn render(&self) -> ImageBuffer {
        let mut result = ImageBuffer::transparent(self.source.width, self.source.height);
        for y in 0..self.source.height {
            for x in 0..self.source.width {
                if let Some(p) = self.source.get_pixel(x, y) {
                    result.set_pixel(x, self.source.height - 1 - y, p);
                }
            }
        }
        result
    }
}

// ============================================================================
// OvalColorIcon -- renders an oval with a solid color
// ============================================================================

/// An icon that renders an oval shape filled with a solid color.
#[derive(Debug, Clone)]
pub struct OvalColorIcon {
    /// Fill color.
    pub color: RgbaPixel,
    /// Width in pixels.
    pub width: u32,
    /// Height in pixels.
    pub height: u32,
}

impl OvalColorIcon {
    /// Create a new oval color icon.
    pub fn new(color: RgbaPixel, width: u32, height: u32) -> Self {
        Self { color, width, height }
    }

    /// Render the oval icon.
    pub fn render(&self) -> ImageBuffer {
        let mut img = ImageBuffer::transparent(self.width as usize, self.height as usize);
        let cx = self.width as f64 / 2.0;
        let cy = self.height as f64 / 2.0;
        let rx = cx;
        let ry = cy;

        for y in 0..self.height {
            for x in 0..self.width {
                let dx = (x as f64 + 0.5 - cx) / rx;
                let dy = (y as f64 + 0.5 - cy) / ry;
                if dx * dx + dy * dy <= 1.0 {
                    img.set_pixel(x as usize, y as usize, self.color);
                }
            }
        }
        img
    }
}

// ============================================================================
// DisabledImageIcon -- a grayed-out, semi-transparent version of a source
// ============================================================================

/// An icon that renders a disabled (grayed out) version of its source.
#[derive(Debug, Clone)]
pub struct DisabledImageIcon {
    /// The source image.
    pub source: ImageBuffer,
}

impl DisabledImageIcon {
    /// Create a new disabled image icon.
    pub fn new(source: ImageBuffer) -> Self {
        Self { source }
    }

    /// Render the disabled icon.
    pub fn render(&self) -> ImageBuffer {
        self.source.to_disabled()
    }
}

// ============================================================================
// DerivedImageIcon -- an icon that is lazily derived from a source
// ============================================================================

/// An icon derived from a source by applying a transformation function.
///
/// The transformation is applied once during rendering and the result is cached.
#[derive(Debug, Clone)]
pub struct DerivedImageIcon {
    /// The source image.
    pub source: ImageBuffer,
    /// Description.
    pub description: String,
}

impl DerivedImageIcon {
    /// Create a new derived image icon.
    pub fn new(source: ImageBuffer, description: impl Into<String>) -> Self {
        Self {
            source,
            description: description.into(),
        }
    }

    /// Render the derived icon (currently just returns a clone of the source).
    pub fn render(&self) -> ImageBuffer {
        self.source.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn color_icon_render() {
        let icon = ColorIcon::new(RgbaPixel::rgb(255, 0, 0), 8, 8);
        let img = icon.render();
        assert_eq!(img.width, 8);
        assert_eq!(img.height, 8);
        // Interior should be red
        assert_eq!(img.get_pixel(4, 4), Some(RgbaPixel::rgb(255, 0, 0)));
        // Border should be black
        assert_eq!(img.get_pixel(0, 0), Some(RgbaPixel::rgb(0, 0, 0)));
    }

    #[test]
    fn color_icon_3d_render() {
        let icon = ColorIcon3D::new(RgbaPixel::rgb(0, 0, 255), 6, 6);
        let img = icon.render();
        // Top-left corner should be highlight (white)
        assert_eq!(img.get_pixel(0, 0), Some(RgbaPixel::rgb(255, 255, 255)));
        // Bottom-right corner should be shadow
        assert_eq!(img.get_pixel(5, 5), Some(RgbaPixel::rgb(128, 128, 128)));
    }

    #[test]
    fn empty_icon_render() {
        let icon = EmptyIcon::new(16, 16);
        let img = icon.render();
        assert!(img.is_fully_transparent());
    }

    #[test]
    fn scaled_image_icon() {
        let source = ImageBuffer::new(4, 4, RgbaPixel::rgb(255, 0, 0));
        let icon = ScaledImageIcon::new(source, 8, 8);
        let img = icon.render();
        assert_eq!(img.width, 8);
        assert_eq!(img.height, 8);
    }

    #[test]
    fn translate_icon() {
        let mut source = ImageBuffer::transparent(4, 4);
        source.set_pixel(0, 0, RgbaPixel::rgb(255, 0, 0));
        let icon = TranslateIcon::new(source, 8, 8, 2, 2);
        let img = icon.render();
        assert_eq!(img.get_pixel(2, 2), Some(RgbaPixel::rgb(255, 0, 0)));
        assert_eq!(img.get_pixel(0, 0), Some(RgbaPixel::TRANSPARENT));
    }

    #[test]
    fn rotate_icon_90() {
        let mut source = ImageBuffer::transparent(2, 2);
        source.set_pixel(0, 0, RgbaPixel::rgb(255, 0, 0));
        let icon = RotateIcon::new(source, RotationAngle::Deg90);
        let img = icon.render();
        assert_eq!(img.width, 2);
        assert_eq!(img.height, 2);
        // (0,0) -> (1,0) after 90 CW rotation
        assert_eq!(img.get_pixel(1, 0), Some(RgbaPixel::rgb(255, 0, 0)));
    }

    #[test]
    fn reflected_icon() {
        let mut source = ImageBuffer::transparent(4, 4);
        source.set_pixel(0, 0, RgbaPixel::rgb(255, 0, 0));
        let icon = ReflectedIcon::new(source);
        let img = icon.render();
        // (0,0) -> (0,3) after vertical flip
        assert_eq!(img.get_pixel(0, 3), Some(RgbaPixel::rgb(255, 0, 0)));
    }

    #[test]
    fn oval_color_icon_render() {
        let icon = OvalColorIcon::new(RgbaPixel::rgb(0, 255, 0), 10, 10);
        let img = icon.render();
        // Center should be filled
        assert_eq!(img.get_pixel(5, 5), Some(RgbaPixel::rgb(0, 255, 0)));
        // Corner should be transparent
        assert_eq!(img.get_pixel(0, 0), Some(RgbaPixel::TRANSPARENT));
    }

    #[test]
    fn disabled_image_icon() {
        let source = ImageBuffer::new(4, 4, RgbaPixel::rgb(255, 255, 255));
        let icon = DisabledImageIcon::new(source);
        let img = icon.render();
        let p = img.get_pixel(0, 0).unwrap();
        assert!(p.a < 255);
    }

    #[test]
    fn derived_image_icon() {
        let source = ImageBuffer::new(2, 2, RgbaPixel::rgb(0, 0, 255));
        let icon = DerivedImageIcon::new(source, "test icon");
        let img = icon.render();
        assert_eq!(img.width, 2);
        assert_eq!(icon.description, "test icon");
    }
}
