//! Module map proposal implementation.
//!
//! Ported from Ghidra's `DefaultModuleMapProposal` in
//! `ghidra.app.plugin.core.debug.service.modules`.
//!
//! Provides the default module mapping proposal that matches trace modules
//! to static program modules by comparing memory block ranges.

use serde::{Deserialize, Serialize};

use crate::model::Lifespan;

/// Quantization block bits for aligning address ranges.
///
/// Ported from Ghidra's `DefaultModuleMapProposal.BLOCK_BITS`.
pub const BLOCK_BITS: u32 = 12;

/// Quantization block size (4 KiB).
pub const BLOCK_SIZE: u64 = 1 << BLOCK_BITS;

/// Quantization block mask for aligning addresses down.
pub const BLOCK_MASK: u64 = !((1u64 << BLOCK_BITS) - 1);

/// Quantize an address range to block boundaries.
///
/// Ported from Ghidra's `DefaultModuleMapProposal.quantize()`.
pub fn quantize_range(min_addr: u64, max_addr: u64) -> (u64, u64) {
    let aligned_min = min_addr & BLOCK_MASK;
    let aligned_max = max_addr | (!BLOCK_MASK);
    (aligned_min, aligned_max)
}

/// A module mapping entry that pairs a trace module with a static program.
///
/// Ported from Ghidra's `DefaultModuleMapEntry`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleMapEntry {
    /// The trace module name.
    pub module_name: String,
    /// The trace module base address.
    pub trace_base: u64,
    /// The static program base address.
    pub static_base: u64,
    /// The module image size.
    pub image_size: u64,
    /// The lifespan for this mapping.
    pub lifespan: Lifespan,
    /// Whether the block should be included in size computations.
    pub include_in_computation: bool,
}

impl ModuleMapEntry {
    /// Create a new module map entry.
    pub fn new(
        module_name: impl Into<String>,
        trace_base: u64,
        static_base: u64,
        image_size: u64,
    ) -> Self {
        Self {
            module_name: module_name.into(),
            trace_base,
            static_base,
            image_size,
            lifespan: Lifespan::ALL,
            include_in_computation: true,
        }
    }

    /// Set the lifespan.
    pub fn with_lifespan(mut self, lifespan: Lifespan) -> Self {
        self.lifespan = lifespan;
        self
    }

    /// Compute the "image size" of a program.
    ///
    /// This is the maximum loaded address minus the image base.
    /// Ported from Ghidra's `DefaultModuleMapEntry.computeImageSize()`.
    pub fn compute_image_size(base: u64, blocks: &[(u64, u64)]) -> u64 {
        let mut max_addr = base;
        for &(_block_start, block_end) in blocks {
            if block_end > max_addr {
                max_addr = block_end;
            }
        }
        max_addr.saturating_sub(base)
    }

    /// Check if a block should be included in size computations.
    ///
    /// Ported from Ghidra's `DefaultModuleMapEntry.includeBlock()`.
    pub fn should_include_block(
        block_start: u64,
        _block_end: u64,
        image_base: u64,
        is_loaded: bool,
        is_mapped: bool,
        is_artificial: bool,
    ) -> bool {
        // Block must be in the same space as image base (simplified: same region)
        if block_start < image_base {
            return false;
        }
        if !is_loaded {
            return false;
        }
        if is_mapped {
            return false;
        }
        if is_artificial {
            return false;
        }
        true
    }
}

/// The result of computing a module map proposal.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleMapProposalResult {
    /// The proposed entries.
    pub entries: Vec<ModuleMapEntry>,
    /// The module name.
    pub module_name: String,
    /// The program name being mapped to.
    pub program_name: String,
}

impl ModuleMapProposalResult {
    /// Create a new proposal result.
    pub fn new(
        module_name: impl Into<String>,
        program_name: impl Into<String>,
    ) -> Self {
        Self {
            entries: Vec::new(),
            module_name: module_name.into(),
            program_name: program_name.into(),
        }
    }

    /// Add an entry to the proposal.
    pub fn add_entry(&mut self, entry: ModuleMapEntry) {
        self.entries.push(entry);
    }

    /// Get the number of proposed entries.
    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    /// Check if the proposal is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_module_map_proposal_re_export() {
        let p = ModuleMapProposal::new("libc", "libc");
        assert_eq!(p.module_name, "libc");
    }

    #[test]
    fn test_quantize_range() {
        let (min, max) = quantize_range(0x1234, 0x5678);
        assert_eq!(min, 0x1000);
        assert_eq!(max, 0x5FFF);
    }

    #[test]
    fn test_quantize_range_aligned() {
        let (min, max) = quantize_range(0x1000, 0x1FFF);
        assert_eq!(min, 0x1000);
        assert_eq!(max, 0x1FFF);
    }

    #[test]
    fn test_block_constants() {
        assert_eq!(BLOCK_BITS, 12);
        assert_eq!(BLOCK_SIZE, 4096);
        assert_eq!(BLOCK_MASK, 0xFFFF_FFFF_FFFF_F000);
    }

    #[test]
    fn test_module_map_entry_new() {
        let entry = ModuleMapEntry::new("libc.so", 0x7F0000, 0x400000, 0x10000);
        assert_eq!(entry.module_name, "libc.so");
        assert_eq!(entry.trace_base, 0x7F0000);
        assert_eq!(entry.static_base, 0x400000);
        assert_eq!(entry.image_size, 0x10000);
    }

    #[test]
    fn test_module_map_entry_with_lifespan() {
        let entry = ModuleMapEntry::new("test", 0, 0, 100)
            .with_lifespan(Lifespan::at(5));
        assert_eq!(entry.lifespan, Lifespan::at(5));
    }

    #[test]
    fn test_compute_image_size() {
        let blocks = vec![
            (0x400000, 0x400FFF),
            (0x401000, 0x401FFF),
        ];
        let size = ModuleMapEntry::compute_image_size(0x400000, &blocks);
        // max_addr is 0x401FFF, so size = 0x401FFF - 0x400000 = 0x1FFF
        assert_eq!(size, 0x1FFF);
    }

    #[test]
    fn test_compute_image_size_empty() {
        let size = ModuleMapEntry::compute_image_size(0x400000, &[]);
        assert_eq!(size, 0);
    }

    #[test]
    fn test_should_include_block() {
        assert!(ModuleMapEntry::should_include_block(
            0x401000, 0x401FFF, 0x400000, true, false, false
        ));
        assert!(!ModuleMapEntry::should_include_block(
            0x300000, 0x300FFF, 0x400000, true, false, false
        ));
        assert!(!ModuleMapEntry::should_include_block(
            0x401000, 0x401FFF, 0x400000, false, false, false
        ));
        assert!(!ModuleMapEntry::should_include_block(
            0x401000, 0x401FFF, 0x400000, true, true, false
        ));
        assert!(!ModuleMapEntry::should_include_block(
            0x401000, 0x401FFF, 0x400000, true, false, true
        ));
    }

    #[test]
    fn test_proposal_result() {
        let mut result = ModuleMapProposalResult::new("test_module", "test_program");
        assert!(result.is_empty());
        assert_eq!(result.entry_count(), 0);

        result.add_entry(ModuleMapEntry::new("entry1", 0, 0, 100));
        assert!(!result.is_empty());
        assert_eq!(result.entry_count(), 1);
    }
}
