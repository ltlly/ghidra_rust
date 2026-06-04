//! Resource and media data types ported from Ghidra.
//!
//! Covers:
//! - `Resource` trait/interface
//! - `BitmapResource` trait/interface
//! - `IconResource` trait/interface
//! - `GIFResource` trait/interface
//! - `PngResource` trait/interface
//! - `Playable` trait/interface
//! - `DataImage` trait/interface
//! - `ScorePlayer` trait/interface
//! - `AudioPlayer` trait/interface
//! - Resource data types: `BitmapResourceDataType`, `IconResourceDataType`,
//!   `IconMaskResourceDataType`, `DialogResourceDataType`, `MenuResourceDataType`
//! - Color data types: `RGB16ColorDataType`, `RGB32ColorDataType`, `AbstractColorDataType`
//! - Media data types: `AIFFDataType`, `AUDataType`, `WAVEDataType`, `MIDIDataType`,
//!   `JPEGDataType`, `PngDataType`, `GifDataType`

use serde::{Deserialize, Serialize};
use std::fmt;

use super::types::DataType;
use super::CategoryPath;

// ============================================================================
// Resource traits
// ============================================================================

/// A resource in a program. Port of Ghidra's `Resource` interface.
pub trait Resource: fmt::Debug {
    /// Get the name of this resource.
    fn get_name(&self) -> &str;
    /// Get the path of this resource.
    fn get_path(&self) -> &str;
    /// Get the size of this resource in bytes.
    fn get_data_size(&self) -> usize;
}

/// A bitmap resource. Port of Ghidra's `BitmapResource` interface.
pub trait BitmapResource: Resource {
    /// Get the width in pixels.
    fn get_width(&self) -> usize;
    /// Get the height in pixels.
    fn get_height(&self) -> usize;
    /// Get bits per pixel.
    fn get_bits_per_pixel(&self) -> usize;
}

/// An icon resource. Port of Ghidra's `IconResource` interface.
pub trait IconResource: BitmapResource {
    /// Get the icon width.
    fn get_icon_width(&self) -> usize;
    /// Get the icon height.
    fn get_icon_height(&self) -> usize;
}

/// A GIF resource. Port of Ghidra's `GIFResource` interface.
pub trait GIFResource: BitmapResource {
    /// Get the number of frames.
    fn get_frame_count(&self) -> usize;
    /// Get the delay between frames in milliseconds.
    fn get_frame_delay(&self) -> usize;
}

/// A PNG resource. Port of Ghidra's `PngResource` interface.
pub trait PngResource: BitmapResource {
    /// Check if the image has an alpha channel.
    fn has_alpha(&self) -> bool;
}

/// Content that can be played (audio/video). Port of Ghidra's `Playable` interface.
pub trait Playable: fmt::Debug {
    /// Returns true if this content can be played.
    fn is_playable(&self) -> bool;
}

/// An image representation of data. Port of Ghidra's `DataImage` interface.
pub trait DataImage: fmt::Debug {
    /// Get the width of the image.
    fn get_width(&self) -> usize;
    /// Get the height of the image.
    fn get_height(&self) -> usize;
}

/// Can play scores (MIDI). Port of Ghidra's `ScorePlayer` interface.
pub trait ScorePlayer: Playable {
    /// Get the score data.
    fn get_score_data(&self) -> &[u8];
}

/// Audio playback. Port of Ghidra's `AudioPlayer` interface.
pub trait AudioPlayer: Playable {
    /// Get the sample rate.
    fn get_sample_rate(&self) -> u32;
    /// Get the number of channels.
    fn get_channels(&self) -> usize;
    /// Get the duration in seconds.
    fn get_duration_secs(&self) -> f64;
}

// ============================================================================
// Resource data types
// ============================================================================

macro_rules! define_resource_type {
    ($(#[$meta:meta])* $vis:vis struct $name:ident { display: $disp:expr, desc: $desc:expr, size: $sz:expr }) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Serialize, Deserialize)]
        $vis struct $name {
            pub category_path: CategoryPath,
            pub resource_size: usize,
        }

        impl $name {
            pub fn new(resource_size: usize) -> Self {
                Self { category_path: CategoryPath::from_path_string("/builtin/resource"), resource_size }
            }
            pub fn with_category_path(mut self, path: CategoryPath) -> Self {
                self.category_path = path; self
            }
        }

        impl DataType for $name {
            fn as_any(&self) -> &dyn std::any::Any { self }
            fn name(&self) -> &str { $disp }
            fn description(&self) -> &str { $desc }
            fn get_size(&self) -> usize { self.resource_size }
            fn get_alignment(&self) -> usize { 1 }
            fn clone_type(&self) -> Box<dyn DataType> { Box::new(self.clone()) }
            fn is_equivalent(&self, other: &dyn DataType) -> bool { self.name() == other.name() }
            fn get_category_path(&self) -> &CategoryPath { &self.category_path }
            fn set_category_path(&mut self, path: CategoryPath) { self.category_path = path; }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{} ({} bytes)", $disp, self.resource_size)
            }
        }
    };
}

define_resource_type! {
    /// Bitmap resource data type. Port of Ghidra's `BitmapResourceDataType`.
    pub struct BitmapResourceDataType {
        display: "bitmap",
        desc: "Bitmap Resource",
        size: 0
    }
}

define_resource_type! {
    /// Icon resource data type. Port of Ghidra's `IconResourceDataType`.
    pub struct IconResourceDataType {
        display: "icon",
        desc: "Icon Resource",
        size: 0
    }
}

define_resource_type! {
    /// Icon mask resource data type. Port of Ghidra's `IconMaskResourceDataType`.
    pub struct IconMaskResourceDataType {
        display: "icon_mask",
        desc: "Icon Mask Resource",
        size: 0
    }
}

define_resource_type! {
    /// Dialog resource data type. Port of Ghidra's `DialogResourceDataType`.
    pub struct DialogResourceDataType {
        display: "dialog",
        desc: "Dialog Resource",
        size: 0
    }
}

define_resource_type! {
    /// Menu resource data type. Port of Ghidra's `MenuResourceDataType`.
    pub struct MenuResourceDataType {
        display: "menu",
        desc: "Menu Resource",
        size: 0
    }
}

// ============================================================================
// Color data types
// ============================================================================

/// Abstract color data type. Port of Ghidra's `AbstractColorDataType`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AbstractColorDataType {
    pub name: String,
    pub description: String,
    pub size: usize,
    pub category_path: CategoryPath,
}

impl AbstractColorDataType {
    pub fn new(name: impl Into<String>, size: usize) -> Self {
        Self {
            name: name.into(), description: "Color data type".into(), size,
            category_path: CategoryPath::from_path_string("/builtin"),
        }
    }
    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = desc.into(); self
    }
    pub fn with_category_path(mut self, path: CategoryPath) -> Self {
        self.category_path = path; self
    }
}

impl DataType for AbstractColorDataType {
    fn as_any(&self) -> &dyn std::any::Any { self }
    fn name(&self) -> &str { &self.name }
    fn description(&self) -> &str { &self.description }
    fn get_size(&self) -> usize { self.size }
    fn get_alignment(&self) -> usize { self.size.max(1) }
    fn clone_type(&self) -> Box<dyn DataType> { Box::new(self.clone()) }
    fn is_equivalent(&self, other: &dyn DataType) -> bool {
        self.name == other.name() && self.size == other.get_size()
    }
    fn get_category_path(&self) -> &CategoryPath { &self.category_path }
    fn set_category_path(&mut self, path: CategoryPath) { self.category_path = path; }
}

impl fmt::Display for AbstractColorDataType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({} bytes)", self.name, self.size)
    }
}

/// 16-bit RGB color data type. Port of Ghidra's `RGB16ColorDataType`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RGB16ColorDataType {
    pub category_path: CategoryPath,
}

impl RGB16ColorDataType {
    pub fn new() -> Self {
        Self { category_path: CategoryPath::from_path_string("/builtin") }
    }
}

impl Default for RGB16ColorDataType { fn default() -> Self { Self::new() } }

impl DataType for RGB16ColorDataType {
    fn as_any(&self) -> &dyn std::any::Any { self }
    fn name(&self) -> &str { "rgb16" }
    fn description(&self) -> &str { "16-bit RGB color" }
    fn get_size(&self) -> usize { 2 }
    fn get_alignment(&self) -> usize { 2 }
    fn clone_type(&self) -> Box<dyn DataType> { Box::new(self.clone()) }
    fn is_equivalent(&self, other: &dyn DataType) -> bool { other.name() == "rgb16" }
    fn get_category_path(&self) -> &CategoryPath { &self.category_path }
    fn set_category_path(&mut self, path: CategoryPath) { self.category_path = path; }
}

impl fmt::Display for RGB16ColorDataType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "rgb16 (2 bytes)") }
}

/// 32-bit RGB color data type. Port of Ghidra's `RGB32ColorDataType`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RGB32ColorDataType {
    pub category_path: CategoryPath,
}

impl RGB32ColorDataType {
    pub fn new() -> Self {
        Self { category_path: CategoryPath::from_path_string("/builtin") }
    }
}

impl Default for RGB32ColorDataType { fn default() -> Self { Self::new() } }

impl DataType for RGB32ColorDataType {
    fn as_any(&self) -> &dyn std::any::Any { self }
    fn name(&self) -> &str { "rgb32" }
    fn description(&self) -> &str { "32-bit RGB color (with alpha)" }
    fn get_size(&self) -> usize { 4 }
    fn get_alignment(&self) -> usize { 4 }
    fn clone_type(&self) -> Box<dyn DataType> { Box::new(self.clone()) }
    fn is_equivalent(&self, other: &dyn DataType) -> bool { other.name() == "rgb32" }
    fn get_category_path(&self) -> &CategoryPath { &self.category_path }
    fn set_category_path(&mut self, path: CategoryPath) { self.category_path = path; }
}

impl fmt::Display for RGB32ColorDataType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "rgb32 (4 bytes)") }
}

// ============================================================================
// Media data types
// ============================================================================

macro_rules! define_media_type {
    ($(#[$meta:meta])* $vis:vis struct $name:ident { display: $disp:expr, desc: $desc:expr, mnemonic: $mnem:expr }) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Serialize, Deserialize)]
        $vis struct $name {
            pub category_path: CategoryPath,
            pub data_size: usize,
        }

        impl $name {
            pub fn new(data_size: usize) -> Self {
                Self { category_path: CategoryPath::from_path_string("/builtin/media"), data_size }
            }
            pub fn with_category_path(mut self, path: CategoryPath) -> Self {
                self.category_path = path; self
            }
        }

        impl DataType for $name {
            fn as_any(&self) -> &dyn std::any::Any { self }
            fn name(&self) -> &str { $disp }
            fn description(&self) -> &str { $desc }
            fn get_size(&self) -> usize { self.data_size }
            fn get_alignment(&self) -> usize { 1 }
            fn clone_type(&self) -> Box<dyn DataType> { Box::new(self.clone()) }
            fn is_equivalent(&self, other: &dyn DataType) -> bool { self.name() == other.name() }
            fn get_category_path(&self) -> &CategoryPath { &self.category_path }
            fn set_category_path(&mut self, path: CategoryPath) { self.category_path = path; }
            fn mnemonic(&self) -> String { $mnem.into() }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{} ({} bytes)", $disp, self.data_size)
            }
        }
    };
}

define_media_type! {
    /// AIFF audio data type. Port of Ghidra's `AIFFDataType`.
    pub struct AIFFDataType {
        display: "aiff",
        desc: "AIFF Audio File",
        mnemonic: "aiff"
    }
}

define_media_type! {
    /// AU audio data type. Port of Ghidra's `AUDataType`.
    pub struct AUDataType {
        display: "au",
        desc: "AU Audio File",
        mnemonic: "au"
    }
}

define_media_type! {
    /// WAVE audio data type. Port of Ghidra's `WAVEDataType`.
    pub struct WAVEDataType {
        display: "wave",
        desc: "WAVE Audio File",
        mnemonic: "wav"
    }
}

define_media_type! {
    /// MIDI data type. Port of Ghidra's `MIDIDataType`.
    pub struct MIDIDataType {
        display: "midi",
        desc: "MIDI Musical Data",
        mnemonic: "midi"
    }
}

define_media_type! {
    /// JPEG image data type. Port of Ghidra's `JPEGDataType`.
    pub struct JPEGDataType {
        display: "jpeg",
        desc: "JPEG Image",
        mnemonic: "jpg"
    }
}

define_media_type! {
    /// PNG image data type. Port of Ghidra's `PngDataType`.
    pub struct PngDataType {
        display: "png",
        desc: "PNG Image",
        mnemonic: "png"
    }
}

define_media_type! {
    /// GIF image data type. Port of Ghidra's `GifDataType`.
    pub struct GifDataType {
        display: "gif",
        desc: "GIF Image",
        mnemonic: "gif"
    }
}

// ============================================================================
// Time data types
// ============================================================================

/// File time data type (Windows FILETIME). Port of Ghidra's `FileTimeDataType`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileTimeDataType {
    pub category_path: CategoryPath,
}

impl FileTimeDataType {
    pub fn new() -> Self {
        Self { category_path: CategoryPath::from_path_string("/builtin") }
    }
}

impl Default for FileTimeDataType { fn default() -> Self { Self::new() } }

impl DataType for FileTimeDataType {
    fn as_any(&self) -> &dyn std::any::Any { self }
    fn name(&self) -> &str { "filetime" }
    fn description(&self) -> &str { "Windows FILETIME (64-bit, 100-nanosecond intervals since 1601)" }
    fn get_size(&self) -> usize { 8 }
    fn get_alignment(&self) -> usize { 8 }
    fn clone_type(&self) -> Box<dyn DataType> { Box::new(self.clone()) }
    fn is_equivalent(&self, other: &dyn DataType) -> bool { other.name() == "filetime" }
    fn get_category_path(&self) -> &CategoryPath { &self.category_path }
    fn set_category_path(&mut self, path: CategoryPath) { self.category_path = path; }
}

impl fmt::Display for FileTimeDataType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "filetime (8 bytes)") }
}

/// Macintosh timestamp data type. Port of Ghidra's `MacintoshTimeStampDataType`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MacintoshTimeStampDataType {
    pub category_path: CategoryPath,
}

impl MacintoshTimeStampDataType {
    pub fn new() -> Self {
        Self { category_path: CategoryPath::from_path_string("/builtin") }
    }
}

impl Default for MacintoshTimeStampDataType { fn default() -> Self { Self::new() } }

impl DataType for MacintoshTimeStampDataType {
    fn as_any(&self) -> &dyn std::any::Any { self }
    fn name(&self) -> &str { "mac_time" }
    fn description(&self) -> &str { "Macintosh timestamp (seconds since 1904)" }
    fn get_size(&self) -> usize { 4 }
    fn get_alignment(&self) -> usize { 4 }
    fn clone_type(&self) -> Box<dyn DataType> { Box::new(self.clone()) }
    fn is_equivalent(&self, other: &dyn DataType) -> bool { other.name() == "mac_time" }
    fn get_category_path(&self) -> &CategoryPath { &self.category_path }
    fn set_category_path(&mut self, path: CategoryPath) { self.category_path = path; }
}

impl fmt::Display for MacintoshTimeStampDataType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "mac_time (4 bytes)") }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resource_types() {
        let bmp = BitmapResourceDataType::new(1024);
        assert_eq!(bmp.name(), "bitmap");
        assert_eq!(bmp.get_size(), 1024);

        let icon = IconResourceDataType::new(512);
        assert_eq!(icon.name(), "icon");
        assert_eq!(icon.get_size(), 512);

        let dlg = DialogResourceDataType::new(2048);
        assert_eq!(dlg.name(), "dialog");
    }

    #[test]
    fn test_color_types() {
        let rgb16 = RGB16ColorDataType::new();
        assert_eq!(rgb16.name(), "rgb16");
        assert_eq!(rgb16.get_size(), 2);

        let rgb32 = RGB32ColorDataType::new();
        assert_eq!(rgb32.name(), "rgb32");
        assert_eq!(rgb32.get_size(), 4);

        let custom = AbstractColorDataType::new("custom_color", 3);
        assert_eq!(custom.get_size(), 3);
    }

    #[test]
    fn test_media_types() {
        let aiff = AIFFDataType::new(4096);
        assert_eq!(aiff.name(), "aiff");
        assert_eq!(aiff.get_size(), 4096);
        assert_eq!(aiff.mnemonic(), "aiff");

        let wav = WAVEDataType::new(8192);
        assert_eq!(wav.name(), "wave");
        assert_eq!(wav.mnemonic(), "wav");

        let jpeg = JPEGDataType::new(2048);
        assert_eq!(jpeg.name(), "jpeg");

        let png = PngDataType::new(1024);
        assert_eq!(png.name(), "png");

        let gif = GifDataType::new(512);
        assert_eq!(gif.name(), "gif");

        let midi = MIDIDataType::new(256);
        assert_eq!(midi.name(), "midi");

        let au = AUDataType::new(4096);
        assert_eq!(au.name(), "au");
    }

    #[test]
    fn test_time_types() {
        let ft = FileTimeDataType::new();
        assert_eq!(ft.name(), "filetime");
        assert_eq!(ft.get_size(), 8);

        let mac = MacintoshTimeStampDataType::new();
        assert_eq!(mac.name(), "mac_time");
        assert_eq!(mac.get_size(), 4);
    }

    #[test]
    fn test_resource_display() {
        let bmp = BitmapResourceDataType::new(1024);
        assert_eq!(format!("{}", bmp), "bitmap (1024 bytes)");
    }
}
