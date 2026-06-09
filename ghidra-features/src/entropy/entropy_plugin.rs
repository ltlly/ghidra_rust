//! Entropy analysis plugin -- ported from Ghidra's
//! `ghidra.app.plugin.core.overview.entropy.EntropyOverviewColorService`
//! and `EntropyOverviewOptionsManager`.
//!
//! The [`EntropyPlugin`] manages an [`EntropyCalculator`] (from the parent
//! module) together with configurable options (chunk size, palette, knot
//! visibility) and exposes an address-to-color mapping suitable for
//! overview-bar rendering.
//!
//! # Example
//!
//! ```
//! use ghidra_features::entropy::plugin::EntropyPlugin;
//!
//! let mut plugin = EntropyPlugin::new();
//! plugin.set_chunk_size(512);
//!
//! // Feed program data
//! let data: Vec<u8> = (0..2048).map(|i| (i % 256) as u8).collect();
//! plugin.compute_from_bytes(&data, 0x400000);
//!
//! // Query entropy at a specific address
//! assert!(plugin.entropy_at(0x400000).is_some());
//! ```

use super::EntropyCalculator;

// ---------------------------------------------------------------------------
// EntropyOptions
// ---------------------------------------------------------------------------

/// Configurable options for the entropy plugin.
///
/// Mirrors `EntropyOverviewOptionsManager` from the Java codebase.
#[derive(Debug, Clone)]
pub struct EntropyOptions {
    /// Chunk size in bytes for entropy computation.
    pub chunk_size: usize,
    /// Number of configurable knot highlight slots.
    pub knot_slots: usize,
}

impl Default for EntropyOptions {
    fn default() -> Self {
        Self {
            chunk_size: 1024,
            knot_slots: 5,
        }
    }
}

// ---------------------------------------------------------------------------
// EntropyPlugin
// ---------------------------------------------------------------------------

/// Central entropy analysis plugin.
///
/// Manages an [`EntropyCalculator`], plugin options, and provides
/// address-to-quantized-entropy mapping for rendering.
///
/// Ported from `EntropyOverviewColorService` and
/// `EntropyOverviewOptionsManager`.
#[derive(Debug)]
pub struct EntropyPlugin {
    /// Plugin options.
    options: EntropyOptions,
    /// The entropy calculator (set after `compute_*` is called).
    calculator: Option<EntropyCalculator>,
    /// Base address of the analyzed region.
    base_address: u64,
    /// Whether the plugin is currently enabled.
    enabled: bool,
}

impl EntropyPlugin {
    /// Create a new entropy plugin with default options.
    pub fn new() -> Self {
        Self {
            options: EntropyOptions::default(),
            calculator: None,
            base_address: 0,
            enabled: true,
        }
    }

    /// Create a new entropy plugin with the given options.
    pub fn with_options(options: EntropyOptions) -> Self {
        Self {
            options,
            calculator: None,
            base_address: 0,
            enabled: true,
        }
    }

    // ------------------------------------------------------------------
    // Options
    // ------------------------------------------------------------------

    /// Get the current chunk size.
    pub fn chunk_size(&self) -> usize {
        self.options.chunk_size
    }

    /// Set the chunk size.  This invalidates any cached computation.
    pub fn set_chunk_size(&mut self, size: usize) {
        self.options.chunk_size = size;
        self.calculator = None;
    }

    /// Get the plugin options.
    pub fn options(&self) -> &EntropyOptions {
        &self.options
    }

    /// Get a mutable reference to the plugin options.
    pub fn options_mut(&mut self) -> &mut EntropyOptions {
        &mut self.options
    }

    // ------------------------------------------------------------------
    // State
    // ------------------------------------------------------------------

    /// Whether the plugin is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Enable or disable the plugin.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    /// Return the base address of the currently loaded data.
    pub fn base_address(&self) -> u64 {
        self.base_address
    }

    /// Return a reference to the underlying calculator, if available.
    pub fn calculator(&self) -> Option<&EntropyCalculator> {
        self.calculator.as_ref()
    }

    // ------------------------------------------------------------------
    // Computation
    // ------------------------------------------------------------------

    /// Compute entropy over a contiguous byte buffer.
    ///
    /// `base_address` is the virtual address corresponding to byte 0
    /// of `data`, used to translate addresses into chunk indices.
    pub fn compute_from_bytes(&mut self, data: &[u8], base_address: u64) {
        self.base_address = base_address;
        self.calculator = Some(EntropyCalculator::from_bytes(data, self.options.chunk_size));
    }

    /// Compute entropy from sparse `(offset, byte)` pairs.
    ///
    /// Mirrors the Java `MemoryAccessException` path where only some
    /// bytes of a memory block are readable.
    pub fn compute_from_sparse<I>(&mut self, iter: I, block_size: usize, base_address: u64)
    where
        I: IntoIterator<Item = (usize, u8)>,
    {
        self.base_address = base_address;
        self.calculator = Some(EntropyCalculator::from_sparse(
            iter,
            block_size,
            self.options.chunk_size,
        ));
    }

    /// Discard any cached computation.
    pub fn clear(&mut self) {
        self.calculator = None;
    }

    // ------------------------------------------------------------------
    // Query
    // ------------------------------------------------------------------

    /// Return the quantised entropy value at a virtual address.
    ///
    /// Returns `None` if no data has been computed or the address is
    /// out of range.
    pub fn entropy_at(&self, address: u64) -> Option<i32> {
        let calc = self.calculator.as_ref()?;
        if address < self.base_address {
            return None;
        }
        let offset = (address - self.base_address) as usize;
        let val = calc.value_at_offset(offset);
        if val < 0 {
            None
        } else {
            Some(val)
        }
    }

    /// Return the raw entropy slice (per-chunk quantised values).
    pub fn entropy_slice(&self) -> Option<&[i32]> {
        self.calculator.as_ref().map(|c| c.as_slice())
    }

    /// Return the number of chunks, or 0 if no computation has been run.
    pub fn num_chunks(&self) -> usize {
        self.calculator.as_ref().map_or(0, |c| c.num_chunks())
    }

    /// Return a summary string for the entropy at the given address.
    ///
    /// Format: `"Entropy: <value>/255"`.
    pub fn tooltip_at(&self, address: u64) -> String {
        match self.entropy_at(address) {
            Some(val) => format!("Entropy: {}/255", val),
            None => "No entropy data".to_string(),
        }
    }

    // ------------------------------------------------------------------
    // Actions
    // ------------------------------------------------------------------

    /// Return the list of available user-facing actions.
    ///
    /// In the Java codebase these include "Show Legend" and similar
    /// overview-bar context menu entries.  Here we return action
    /// descriptors that a UI layer can bind.
    pub fn available_actions(&self) -> Vec<EntropyAction> {
        vec![EntropyAction::ShowLegend]
    }
}

impl Default for EntropyPlugin {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// EntropyAction
// ---------------------------------------------------------------------------

/// User-facing actions exposed by the entropy plugin.
///
/// Corresponds to `DockingActionIf` instances created in
/// `EntropyOverviewColorService.getActions()`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EntropyAction {
    /// Show the entropy color legend dialog.
    ShowLegend,
}

impl EntropyAction {
    /// Return the human-readable label for this action.
    pub fn label(&self) -> &'static str {
        match self {
            Self::ShowLegend => "Show Legend",
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plugin_default_options() {
        let plugin = EntropyPlugin::new();
        assert_eq!(plugin.chunk_size(), 1024);
        assert!(plugin.is_enabled());
        assert!(plugin.calculator().is_none());
        assert_eq!(plugin.num_chunks(), 0);
    }

    #[test]
    fn test_plugin_set_chunk_size() {
        let mut plugin = EntropyPlugin::new();
        plugin.set_chunk_size(256);
        assert_eq!(plugin.chunk_size(), 256);
    }

    #[test]
    fn test_plugin_compute_and_query() {
        let mut plugin = EntropyPlugin::new();
        plugin.set_chunk_size(256);

        // 256 bytes, all unique -> max entropy
        let data: Vec<u8> = (0..=255).collect();
        plugin.compute_from_bytes(&data, 0x1000);

        assert_eq!(plugin.num_chunks(), 1);
        assert_eq!(plugin.base_address(), 0x1000);

        let val = plugin.entropy_at(0x1000).unwrap();
        assert_eq!(val, 255);
    }

    #[test]
    fn test_plugin_out_of_range_address() {
        let mut plugin = EntropyPlugin::new();
        plugin.set_chunk_size(256);

        let data = vec![0u8; 256];
        plugin.compute_from_bytes(&data, 0x1000);

        // Address before base
        assert!(plugin.entropy_at(0x0FFF).is_none());
        // Address way beyond data
        assert!(plugin.entropy_at(0x9999).is_none());
    }

    #[test]
    fn test_plugin_zero_entropy() {
        let mut plugin = EntropyPlugin::new();
        plugin.set_chunk_size(128);

        let data = vec![0xAAu8; 256];
        plugin.compute_from_bytes(&data, 0);

        let val = plugin.entropy_at(0).unwrap();
        assert_eq!(val, 0);
    }

    #[test]
    fn test_plugin_sparse_computation() {
        let mut plugin = EntropyPlugin::new();
        plugin.set_chunk_size(10);

        // Provide all bytes -> complete chunk, zero entropy
        let iter: Vec<(usize, u8)> = (0..10).map(|i| (i, 0xAA)).collect();
        plugin.compute_from_sparse(iter, 10, 0);

        assert_eq!(plugin.num_chunks(), 1);
        assert_eq!(plugin.entropy_at(0).unwrap(), 0);
    }

    #[test]
    fn test_plugin_sparse_undefined() {
        let mut plugin = EntropyPlugin::new();
        plugin.set_chunk_size(10);

        // Only 1 byte out of 10 -> undefined chunk
        let iter = vec![(5usize, 0x42u8)];
        plugin.compute_from_sparse(iter, 10, 0);

        assert_eq!(plugin.num_chunks(), 1);
        // Missing bytes -> None
        assert!(plugin.entropy_at(0).is_none());
    }

    #[test]
    fn test_plugin_clear() {
        let mut plugin = EntropyPlugin::new();
        let data = vec![0u8; 256];
        plugin.compute_from_bytes(&data, 0);
        assert!(plugin.calculator().is_some());

        plugin.clear();
        assert!(plugin.calculator().is_none());
        assert_eq!(plugin.num_chunks(), 0);
    }

    #[test]
    fn test_plugin_enable_disable() {
        let mut plugin = EntropyPlugin::new();
        assert!(plugin.is_enabled());

        plugin.set_enabled(false);
        assert!(!plugin.is_enabled());

        plugin.set_enabled(true);
        assert!(plugin.is_enabled());
    }

    #[test]
    fn test_plugin_tooltip() {
        let mut plugin = EntropyPlugin::new();
        plugin.set_chunk_size(256);

        // No data yet
        assert_eq!(plugin.tooltip_at(0), "No entropy data");

        let data = vec![0u8; 256];
        plugin.compute_from_bytes(&data, 0);
        let tip = plugin.tooltip_at(0);
        assert!(tip.contains("Entropy"));
        assert!(tip.contains("0/255"));
    }

    #[test]
    fn test_plugin_entropy_slice() {
        let mut plugin = EntropyPlugin::new();
        plugin.set_chunk_size(128);

        assert!(plugin.entropy_slice().is_none());

        let data = vec![0u8; 256];
        plugin.compute_from_bytes(&data, 0);

        let slice = plugin.entropy_slice().unwrap();
        assert_eq!(slice.len(), 2);
        assert_eq!(slice[0], 0);
        assert_eq!(slice[1], 0);
    }

    #[test]
    fn test_plugin_actions() {
        let plugin = EntropyPlugin::new();
        let actions = plugin.available_actions();
        assert_eq!(actions.len(), 1);
        assert_eq!(actions[0], EntropyAction::ShowLegend);
        assert_eq!(actions[0].label(), "Show Legend");
    }

    #[test]
    fn test_plugin_with_custom_options() {
        let opts = EntropyOptions {
            chunk_size: 512,
            knot_slots: 3,
        };
        let plugin = EntropyPlugin::with_options(opts);
        assert_eq!(plugin.chunk_size(), 512);
        assert_eq!(plugin.options().knot_slots, 3);
    }

    #[test]
    fn test_plugin_change_chunk_size_invalidates() {
        let mut plugin = EntropyPlugin::new();
        plugin.set_chunk_size(256);

        let data = vec![0u8; 256];
        plugin.compute_from_bytes(&data, 0);
        assert!(plugin.calculator().is_some());

        // Changing chunk size clears the calculator
        plugin.set_chunk_size(512);
        assert!(plugin.calculator().is_none());
    }

    #[test]
    fn test_plugin_multiple_chunks() {
        let mut plugin = EntropyPlugin::new();
        plugin.set_chunk_size(128);

        let data: Vec<u8> = (0..512).map(|i| (i % 256) as u8).collect();
        plugin.compute_from_bytes(&data, 0x2000);

        assert_eq!(plugin.num_chunks(), 4);
        // Each 128-byte chunk has 128 distinct values -> entropy ~224
        for i in 0..4 {
            let addr = 0x2000 + (i as u64) * 128;
            let val = plugin.entropy_at(addr).unwrap();
            assert!(val > 200, "Expected high entropy at chunk {}, got {}", i, val);
        }
    }
}
