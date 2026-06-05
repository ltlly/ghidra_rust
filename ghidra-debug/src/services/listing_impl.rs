//! Listing service implementation for the debugger.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.debug.service` package.
//! Provides a service for managing the listing view in a debugging session,
//! including current position tracking, blended background colors for
//! multiple trace sources, and memory auto-read behavior.

use serde::{Deserialize, Serialize};

/// The auto-read memory specification for the listing.
///
/// When the debugger steps, the listing may automatically read memory
/// from the trace at the current location. This controls that behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AutoReadMemorySpec {
    /// Never auto-read memory from the trace.
    Never,
    /// Auto-read on demand when navigating to an address.
    OnDemand,
    /// Auto-read whenever the snapshot changes.
    OnSnapshotChange,
    /// Always keep memory synchronized.
    Always,
}

impl Default for AutoReadMemorySpec {
    fn default() -> Self {
        Self::OnDemand
    }
}

/// A blended listing background color entry.
///
/// In the debugger listing, memory from multiple sources (the original
/// program and one or more traces) may be overlaid. Each source gets
/// a distinct background color blending.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlendedColorEntry {
    /// The source identifier (e.g., trace key, program URL).
    pub source: String,
    /// The red component (0-255).
    pub r: u8,
    /// The green component (0-255).
    pub g: u8,
    /// The blue component (0-255).
    pub b: u8,
    /// The alpha/opacity (0-255, where 255 is fully opaque).
    pub a: u8,
    /// The blend weight (0.0 - 1.0).
    pub weight: f64,
}

impl BlendedColorEntry {
    /// Create a new blended color entry.
    pub fn new(source: impl Into<String>, r: u8, g: u8, b: u8) -> Self {
        Self {
            source: source.into(),
            r,
            g,
            b,
            a: 255,
            weight: 0.5,
        }
    }

    /// Set the alpha.
    pub fn with_alpha(mut self, a: u8) -> Self {
        self.a = a;
        self
    }

    /// Set the blend weight.
    pub fn with_weight(mut self, weight: f64) -> Self {
        self.weight = weight.clamp(0.0, 1.0);
        self
    }

    /// Get the color as a packed RGBA u32.
    pub fn to_rgba(&self) -> u32 {
        ((self.r as u32) << 24) | ((self.g as u32) << 16) | ((self.b as u32) << 8) | (self.a as u32)
    }
}

/// A listing location in the debugger.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DebuggerListingLocation {
    /// The address in the listing.
    pub address: u64,
    /// The address space name.
    pub space: String,
    /// The snap (if viewing a trace).
    pub snap: Option<i64>,
    /// The thread key (if applicable).
    pub thread_key: Option<i64>,
}

impl DebuggerListingLocation {
    /// Create a new listing location.
    pub fn new(address: u64, space: impl Into<String>) -> Self {
        Self {
            address,
            space: space.into(),
            snap: None,
            thread_key: None,
        }
    }

    /// Set the snap.
    pub fn with_snap(mut self, snap: i64) -> Self {
        self.snap = Some(snap);
        self
    }

    /// Set the thread.
    pub fn with_thread(mut self, thread_key: i64) -> Self {
        self.thread_key = Some(thread_key);
        self
    }
}

/// Multi-source blended listing background color model.
///
/// Maintains a set of color entries for blending multiple trace sources
/// in the listing panel.
#[derive(Debug, Default)]
pub struct MultiBlendedListingColorModel {
    entries: Vec<BlendedColorEntry>,
}

impl MultiBlendedListingColorModel {
    /// Create a new empty color model.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a color entry.
    pub fn add(&mut self, entry: BlendedColorEntry) {
        self.entries.push(entry);
    }

    /// Remove a color entry by source.
    pub fn remove(&mut self, source: &str) {
        self.entries.retain(|e| e.source != source);
    }

    /// Get all entries.
    pub fn entries(&self) -> &[BlendedColorEntry] {
        &self.entries
    }

    /// Get the entry for a specific source.
    pub fn get(&self, source: &str) -> Option<&BlendedColorEntry> {
        self.entries.iter().find(|e| e.source == source)
    }

    /// Compute the blended color for the given entries.
    ///
    /// Returns an RGBA value by weighted-averaging all entries.
    pub fn compute_blended(&self) -> u32 {
        if self.entries.is_empty() {
            return 0x00000000; // transparent
        }
        let total_weight: f64 = self.entries.iter().map(|e| e.weight).sum();
        if total_weight == 0.0 {
            return 0x00000000;
        }
        let mut r = 0.0_f64;
        let mut g = 0.0_f64;
        let mut b = 0.0_f64;
        for entry in &self.entries {
            let w = entry.weight / total_weight;
            r += entry.r as f64 * w;
            g += entry.g as f64 * w;
            b += entry.b as f64 * w;
        }
        ((r as u32) << 24) | ((g as u32) << 16) | ((b as u32) << 8) | 0xFF
    }

    /// Clear all entries.
    pub fn clear(&mut self) {
        self.entries.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auto_read_memory_spec_default() {
        assert_eq!(AutoReadMemorySpec::default(), AutoReadMemorySpec::OnDemand);
    }

    #[test]
    fn test_blended_color_entry() {
        let entry = BlendedColorEntry::new("trace1", 255, 0, 0)
            .with_alpha(128)
            .with_weight(0.7);
        assert_eq!(entry.r, 255);
        assert_eq!(entry.a, 128);
        assert!((entry.weight - 0.7).abs() < f64::EPSILON);
    }

    #[test]
    fn test_blended_color_to_rgba() {
        let entry = BlendedColorEntry::new("test", 0xFF, 0x80, 0x40);
        let rgba = entry.to_rgba();
        assert_eq!((rgba >> 24) & 0xFF, 0xFF);
        assert_eq!((rgba >> 16) & 0xFF, 0x80);
        assert_eq!((rgba >> 8) & 0xFF, 0x40);
    }

    #[test]
    fn test_multi_blended_model() {
        let mut model = MultiBlendedListingColorModel::new();
        model.add(BlendedColorEntry::new("prog", 255, 0, 0).with_weight(0.5));
        model.add(BlendedColorEntry::new("trace", 0, 0, 255).with_weight(0.5));
        assert_eq!(model.entries().len(), 2);
        assert!(model.get("prog").is_some());

        model.remove("prog");
        assert_eq!(model.entries().len(), 1);
    }

    #[test]
    fn test_blended_color_computation() {
        let mut model = MultiBlendedListingColorModel::new();
        model.add(BlendedColorEntry::new("a", 255, 0, 0).with_weight(1.0));
        let blended = model.compute_blended();
        assert_eq!((blended >> 24) & 0xFF, 255);
    }

    #[test]
    fn test_blended_empty() {
        let model = MultiBlendedListingColorModel::new();
        assert_eq!(model.compute_blended(), 0x00000000);
    }

    #[test]
    fn test_listing_location() {
        let loc = DebuggerListingLocation::new(0x400000, "ram")
            .with_snap(5)
            .with_thread(1);
        assert_eq!(loc.address, 0x400000);
        assert_eq!(loc.snap, Some(5));
        assert_eq!(loc.thread_key, Some(1));
    }

    #[test]
    fn test_blended_weight_clamp() {
        let entry = BlendedColorEntry::new("x", 0, 0, 0).with_weight(2.0);
        assert!((entry.weight - 1.0).abs() < f64::EPSILON);
    }
}
