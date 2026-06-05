//! Additional icon types ported from Ghidra's `resources.icons` package.
//!
//! Includes: `BytesImageIcon`, `CenterTranslateIcon`, `FileBasedIcon`,
//! `IconWrapper`, `ImageIconWrapper`, `LazyImageIcon`, `OvalBackgroundColorIcon`,
//! `ScaledImageIconWrapper`, `UnresolvedIcon`, `UrlImageIcon`,
//! `DisabledImageIconWrapper`.

use crate::util::image::{ImageBuffer, RgbaPixel};
use super::Icon;

// ============================================================================
// BytesImageIcon -- icon from raw RGBA bytes
// ============================================================================

/// An icon created from raw RGBA byte data.
///
/// Port of Ghidra's `resources.icons.BytesImageIcon`.
#[derive(Debug, Clone)]
pub struct BytesImageIcon {
    /// Raw RGBA pixel data.
    pub data: Vec<u8>,
    /// Width in pixels.
    pub width: u32,
    /// Height in pixels.
    pub height: u32,
    /// Optional description.
    pub description: Option<String>,
}

impl BytesImageIcon {
    /// Create a new icon from raw RGBA bytes.
    pub fn new(data: Vec<u8>, width: u32, height: u32) -> Self {
        Self { data, width, height, description: None }
    }

    /// Set the description.
    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = Some(desc.into());
        self
    }

    /// Render the icon to an ImageBuffer.
    pub fn render(&self) -> ImageBuffer {
        let mut img = ImageBuffer::transparent(self.width as usize, self.height as usize);
        for y in 0..self.height {
            for x in 0..self.width {
                let idx = ((y * self.width + x) * 4) as usize;
                if idx + 3 < self.data.len() {
                    let r = self.data[idx];
                    let g = self.data[idx + 1];
                    let b = self.data[idx + 2];
                    let a = self.data[idx + 3];
                    img.set_pixel(x as usize, y as usize, RgbaPixel::new(r, g, b, a));
                }
            }
        }
        img
    }

    /// Get the icon dimensions.
    pub fn dimensions(&self) -> (u32, u32) {
        (self.width, self.height)
    }
}

// ============================================================================
// CenterTranslateIcon -- centers source on a canvas
// ============================================================================

/// An icon that centers its source image on a larger canvas.
///
/// Port of Ghidra's `resources.icons.CenterTranslateIcon`.
#[derive(Debug, Clone)]
pub struct CenterTranslateIcon {
    /// The source image to center.
    pub source: ImageBuffer,
    /// Canvas width.
    pub canvas_width: usize,
    /// Canvas height.
    pub canvas_height: usize,
}

impl CenterTranslateIcon {
    /// Create a new centering translate icon.
    pub fn new(source: ImageBuffer, canvas_width: usize, canvas_height: usize) -> Self {
        Self { source, canvas_width, canvas_height }
    }

    /// Render the icon with the source centered on the canvas.
    pub fn render(&self) -> ImageBuffer {
        let offset_x = (self.canvas_width as i32 - self.source.width as i32) / 2;
        let offset_y = (self.canvas_height as i32 - self.source.height as i32) / 2;
        let mut canvas = ImageBuffer::transparent(self.canvas_width, self.canvas_height);
        for sy in 0..self.source.height {
            for sx in 0..self.source.width {
                let dx = sx as i32 + offset_x;
                let dy = sy as i32 + offset_y;
                if dx >= 0 && dy >= 0
                    && (dx as usize) < self.canvas_width
                    && (dy as usize) < self.canvas_height
                {
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
// FileBasedIcon -- icon loaded from a file path
// ============================================================================

/// An icon backed by a file on disk.
///
/// Port of Ghidra's `resources.icons.FileBasedIcon`.
#[derive(Debug, Clone)]
pub struct FileBasedIcon {
    /// Path to the icon file.
    pub file_path: String,
    /// Cached image data (if loaded).
    cached_image: Option<ImageBuffer>,
}

impl FileBasedIcon {
    /// Create a new file-based icon.
    pub fn new(file_path: impl Into<String>) -> Self {
        Self { file_path: file_path.into(), cached_image: None }
    }

    /// Get the file path.
    pub fn path(&self) -> &str {
        &self.file_path
    }

    /// Check if the image has been loaded.
    pub fn is_loaded(&self) -> bool {
        self.cached_image.is_some()
    }

    /// Set the cached image.
    pub fn set_cached_image(&mut self, image: ImageBuffer) {
        self.cached_image = Some(image);
    }

    /// Get the cached image, if any.
    pub fn cached_image(&self) -> Option<&ImageBuffer> {
        self.cached_image.as_ref()
    }

    /// Render returns cached image or a placeholder.
    pub fn render(&self) -> ImageBuffer {
        if let Some(ref img) = self.cached_image {
            img.clone()
        } else {
            // Placeholder: gray 16x16
            ImageBuffer::new(16, 16, RgbaPixel::rgb(192, 192, 192))
        }
    }
}

// ============================================================================
// IconWrapper -- wraps an Icon with metadata
// ============================================================================

/// A wrapper around an `Icon` that adds metadata.
///
/// Port of Ghidra's `resources.icons.IconWrapper`.
#[derive(Debug, Clone)]
pub struct IconWrapper {
    /// The wrapped icon.
    pub inner: Icon,
    /// Tooltip text.
    pub tooltip: Option<String>,
    /// Whether this icon is enabled.
    pub enabled: bool,
}

impl IconWrapper {
    /// Create a new icon wrapper.
    pub fn new(inner: Icon) -> Self {
        Self { inner, tooltip: None, enabled: true }
    }

    /// Set tooltip text.
    pub fn with_tooltip(mut self, tooltip: impl Into<String>) -> Self {
        self.tooltip = Some(tooltip.into());
        self
    }

    /// Set enabled state.
    pub fn with_enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }

    /// Get the wrapped icon path.
    pub fn path(&self) -> &str {
        self.inner.path()
    }
}

// ============================================================================
// ImageIconWrapper -- wraps an ImageBuffer as an icon
// ============================================================================

/// An icon wrapper backed by an `ImageBuffer`.
///
/// Port of Ghidra's `resources.icons.ImageIconWrapper`.
#[derive(Debug, Clone)]
pub struct ImageIconWrapper {
    /// The image data.
    image: ImageBuffer,
    /// Description.
    pub description: String,
}

impl ImageIconWrapper {
    /// Create a new image icon wrapper.
    pub fn new(image: ImageBuffer, description: impl Into<String>) -> Self {
        Self { image, description: description.into() }
    }

    /// Get the width.
    pub fn width(&self) -> usize {
        self.image.width
    }

    /// Get the height.
    pub fn height(&self) -> usize {
        self.image.height
    }

    /// Render the icon.
    pub fn render(&self) -> ImageBuffer {
        self.image.clone()
    }
}

// ============================================================================
// LazyImageIcon -- lazily loaded image icon
// ============================================================================

/// An icon that lazily loads its image data.
///
/// Port of Ghidra's `resources.icons.LazyImageIcon`.
#[derive(Debug, Clone)]
pub struct LazyImageIcon {
    /// The path to load from.
    path: String,
    /// Cached image (if loaded).
    image: Option<ImageBuffer>,
}

impl LazyImageIcon {
    /// Create a new lazy image icon.
    pub fn new(path: impl Into<String>) -> Self {
        Self { path: path.into(), image: None }
    }

    /// Get the path.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Check if the image is loaded.
    pub fn is_loaded(&self) -> bool {
        self.image.is_some()
    }

    /// Set the image (simulates loading).
    pub fn load(&mut self, image: ImageBuffer) {
        self.image = Some(image);
    }

    /// Render the icon.
    pub fn render(&self) -> ImageBuffer {
        if let Some(ref img) = self.image {
            img.clone()
        } else {
            // Placeholder
            ImageBuffer::new(16, 16, RgbaPixel::rgb(200, 200, 200))
        }
    }
}

// ============================================================================
// OvalBackgroundColorIcon -- oval with background and foreground colors
// ============================================================================

/// An icon rendering an oval with a background color behind the foreground.
///
/// Port of Ghidra's `resources.icons.OvalBackgroundColorIcon`.
#[derive(Debug, Clone)]
pub struct OvalBackgroundColorIcon {
    /// Foreground (oval) color.
    pub foreground: RgbaPixel,
    /// Background (canvas) color.
    pub background: RgbaPixel,
    /// Width in pixels.
    pub width: u32,
    /// Height in pixels.
    pub height: u32,
}

impl OvalBackgroundColorIcon {
    /// Create a new oval background color icon.
    pub fn new(foreground: RgbaPixel, background: RgbaPixel, width: u32, height: u32) -> Self {
        Self { foreground, background, width, height }
    }

    /// Render the icon.
    pub fn render(&self) -> ImageBuffer {
        let mut img = ImageBuffer::new(self.width as usize, self.height as usize, self.background);
        let cx = self.width as f64 / 2.0;
        let cy = self.height as f64 / 2.0;
        let rx = cx;
        let ry = cy;
        for y in 0..self.height {
            for x in 0..self.width {
                let dx = (x as f64 + 0.5 - cx) / rx;
                let dy = (y as f64 + 0.5 - cy) / ry;
                if dx * dx + dy * dy <= 1.0 {
                    img.set_pixel(x as usize, y as usize, self.foreground);
                }
            }
        }
        img
    }
}

// ============================================================================
// ScaledImageIconWrapper -- wraps an existing icon and scales it
// ============================================================================

/// A wrapper that scales an existing icon to a new size.
///
/// Port of Ghidra's `resources.icons.ScaledImageIconWrapper`.
#[derive(Debug, Clone)]
pub struct ScaledImageIconWrapper {
    /// The source image.
    pub source: ImageBuffer,
    /// Target width.
    pub target_width: u32,
    /// Target height.
    pub target_height: u32,
}

impl ScaledImageIconWrapper {
    /// Create a new scaled image icon wrapper.
    pub fn new(source: ImageBuffer, target_width: u32, target_height: u32) -> Self {
        Self { source, target_width, target_height }
    }

    /// Render the scaled icon.
    pub fn render(&self) -> ImageBuffer {
        let sx = self.target_width as f64 / self.source.width.max(1) as f64;
        let sy = self.target_height as f64 / self.source.height.max(1) as f64;
        self.source.scale_nearest(sx, sy)
    }
}

// ============================================================================
// UnresolvedIcon -- a placeholder for icons that could not be loaded
// ============================================================================

/// An icon shown when the actual icon could not be resolved.
///
/// Port of Ghidra's `resources.icons.UnresolvedIcon`.
#[derive(Debug, Clone)]
pub struct UnresolvedIcon {
    /// The path that failed to resolve.
    pub missing_path: String,
    /// Width in pixels.
    pub width: u32,
    /// Height in pixels.
    pub height: u32,
}

impl UnresolvedIcon {
    /// Create a new unresolved icon.
    pub fn new(missing_path: impl Into<String>) -> Self {
        Self { missing_path: missing_path.into(), width: 16, height: 16 }
    }

    /// Create with specific size.
    pub fn with_size(mut self, width: u32, height: u32) -> Self {
        self.width = width;
        self.height = height;
        self
    }

    /// Render the unresolved icon as a red X pattern.
    pub fn render(&self) -> ImageBuffer {
        let mut img = ImageBuffer::new(self.width as usize, self.height as usize, RgbaPixel::rgb(255, 200, 200));
        let red = RgbaPixel::rgb(255, 0, 0);
        let size = self.width.min(self.height) as i32;
        for i in 0..size {
            // Diagonal lines forming an X
            if (i as usize) < img.width && (i as usize) < img.height {
                img.set_pixel(i as usize, i as usize, red);
                img.set_pixel((size - 1 - i) as usize, i as usize, red);
            }
        }
        img
    }
}

// ============================================================================
// UrlImageIcon -- icon loaded from a URL
// ============================================================================

/// An icon backed by a URL.
///
/// Port of Ghidra's `resources.icons.UrlImageIcon`.
#[derive(Debug, Clone)]
pub struct UrlImageIcon {
    /// The URL of the icon.
    pub url: String,
    /// Description.
    pub description: Option<String>,
    /// Cached image (if loaded).
    cached_image: Option<ImageBuffer>,
}

impl UrlImageIcon {
    /// Create a new URL image icon.
    pub fn new(url: impl Into<String>) -> Self {
        Self { url: url.into(), description: None, cached_image: None }
    }

    /// Set the description.
    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = Some(desc.into());
        self
    }

    /// Get the URL.
    pub fn url(&self) -> &str {
        &self.url
    }

    /// Check if the image has been loaded.
    pub fn is_loaded(&self) -> bool {
        self.cached_image.is_some()
    }

    /// Set the cached image.
    pub fn set_cached_image(&mut self, image: ImageBuffer) {
        self.cached_image = Some(image);
    }

    /// Render the icon.
    pub fn render(&self) -> ImageBuffer {
        if let Some(ref img) = self.cached_image {
            img.clone()
        } else {
            ImageBuffer::new(16, 16, RgbaPixel::rgb(200, 200, 200))
        }
    }
}

// ============================================================================
// DisabledImageIconWrapper -- wraps an icon to produce a disabled version
// ============================================================================

/// A wrapper that creates a disabled (grayed out) version of any icon.
///
/// Port of Ghidra's `resources.icons.DisabledImageIconWrapper`.
#[derive(Debug, Clone)]
pub struct DisabledImageIconWrapper {
    /// The source image.
    pub source: ImageBuffer,
}

impl DisabledImageIconWrapper {
    /// Create a new disabled image icon wrapper.
    pub fn new(source: ImageBuffer) -> Self {
        Self { source }
    }

    /// Render the disabled icon.
    pub fn render(&self) -> ImageBuffer {
        self.source.to_disabled()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes_image_icon_basic() {
        let data = vec![255u8, 0, 0, 255, 0, 255, 0, 255]; // 2 pixels
        let icon = BytesImageIcon::new(data, 2, 1);
        let img = icon.render();
        assert_eq!(img.width, 2);
        assert_eq!(img.height, 1);
        assert_eq!(img.get_pixel(0, 0), Some(RgbaPixel::new(255, 0, 0, 255)));
        assert_eq!(img.get_pixel(1, 0), Some(RgbaPixel::new(0, 255, 0, 255)));
    }

    #[test]
    fn bytes_image_icon_dimensions() {
        let icon = BytesImageIcon::new(vec![0u8; 16], 2, 2);
        assert_eq!(icon.dimensions(), (2, 2));
    }

    #[test]
    fn center_translate_icon() {
        let source = ImageBuffer::new(2, 2, RgbaPixel::rgb(255, 0, 0));
        let icon = CenterTranslateIcon::new(source, 4, 4);
        let img = icon.render();
        assert_eq!(img.width, 4);
        assert_eq!(img.height, 4);
        // Source should be centered at offset (1, 1)
        assert_eq!(img.get_pixel(1, 1), Some(RgbaPixel::rgb(255, 0, 0)));
        assert_eq!(img.get_pixel(0, 0), Some(RgbaPixel::TRANSPARENT));
    }

    #[test]
    fn file_based_icon_basic() {
        let icon = FileBasedIcon::new("/tmp/test.png");
        assert_eq!(icon.path(), "/tmp/test.png");
        assert!(!icon.is_loaded());
        let img = icon.render(); // placeholder
        assert_eq!(img.width, 16);
    }

    #[test]
    fn file_based_icon_loaded() {
        let mut icon = FileBasedIcon::new("/tmp/test.png");
        icon.set_cached_image(ImageBuffer::new(8, 8, RgbaPixel::rgb(0, 255, 0)));
        assert!(icon.is_loaded());
        let img = icon.render();
        assert_eq!(img.width, 8);
    }

    #[test]
    fn icon_wrapper_basic() {
        let inner = Icon::new("test.png");
        let wrapper = IconWrapper::new(inner).with_tooltip("A test icon").with_enabled(true);
        assert_eq!(wrapper.path(), "test.png");
        assert_eq!(wrapper.tooltip.as_deref(), Some("A test icon"));
        assert!(wrapper.enabled);
    }

    #[test]
    fn image_icon_wrapper() {
        let img = ImageBuffer::new(4, 4, RgbaPixel::rgb(0, 0, 255));
        let wrapper = ImageIconWrapper::new(img, "Blue icon");
        assert_eq!(wrapper.width(), 4);
        assert_eq!(wrapper.height(), 4);
        let rendered = wrapper.render();
        assert_eq!(rendered.width, 4);
    }

    #[test]
    fn lazy_image_icon() {
        let mut icon = LazyImageIcon::new("lazy.png");
        assert!(!icon.is_loaded());
        icon.load(ImageBuffer::new(8, 8, RgbaPixel::rgb(128, 128, 128)));
        assert!(icon.is_loaded());
        let img = icon.render();
        assert_eq!(img.width, 8);
    }

    #[test]
    fn oval_background_color_icon() {
        let icon = OvalBackgroundColorIcon::new(
            RgbaPixel::rgb(255, 0, 0),
            RgbaPixel::rgb(0, 0, 0),
            10, 10,
        );
        let img = icon.render();
        // Center should be foreground
        assert_eq!(img.get_pixel(5, 5), Some(RgbaPixel::rgb(255, 0, 0)));
        // Corner should be background
        assert_eq!(img.get_pixel(0, 0), Some(RgbaPixel::rgb(0, 0, 0)));
    }

    #[test]
    fn scaled_image_icon_wrapper() {
        let source = ImageBuffer::new(4, 4, RgbaPixel::rgb(255, 255, 0));
        let wrapper = ScaledImageIconWrapper::new(source, 8, 8);
        let img = wrapper.render();
        assert_eq!(img.width, 8);
        assert_eq!(img.height, 8);
    }

    #[test]
    fn unresolved_icon() {
        let icon = UnresolvedIcon::new("missing/icon.png").with_size(16, 16);
        assert_eq!(icon.missing_path, "missing/icon.png");
        let img = icon.render();
        assert_eq!(img.width, 16);
        assert_eq!(img.height, 16);
    }

    #[test]
    fn url_image_icon() {
        let mut icon = UrlImageIcon::new("https://example.com/icon.png")
            .with_description("Remote icon");
        assert_eq!(icon.url(), "https://example.com/icon.png");
        assert!(!icon.is_loaded());
        let _ = icon.render(); // placeholder
        icon.set_cached_image(ImageBuffer::new(8, 8, RgbaPixel::rgb(0, 128, 255)));
        assert!(icon.is_loaded());
    }

    #[test]
    fn disabled_image_icon_wrapper() {
        let source = ImageBuffer::new(4, 4, RgbaPixel::rgb(255, 255, 255));
        let wrapper = DisabledImageIconWrapper::new(source);
        let img = wrapper.render();
        let p = img.get_pixel(0, 0).unwrap();
        assert!(p.a < 255);
    }
}
