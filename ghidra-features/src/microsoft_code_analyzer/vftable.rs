//! Virtual function table (vftable) analysis for MSVC binaries.
//!
//! Ported from Ghidra's `VfTableModel` and `CreateVfTableBackgroundCmd`.
//!
//! A vftable in MSVC has a layout like:
//!
//! ```text
//! ┌──────────────────────┐
//! │ [meta] pointer ──────┼──► RTTI4 (CompleteObjectLocator)
//! ├──────────────────────┤
//! │ vfptr[0] ────────────┼──► virtual function 0
//! │ vfptr[1] ────────────┼──► virtual function 1
//! │ ...                  │
//! │ vfptr[N]             │
//! │ [RTTI4 at meta addr] │  (placed before the vtable in memory)
//! └──────────────────────┘
//! ```

use serde::{Deserialize, Serialize};

use super::rtti::{read_ptr, read_u32, CompleteObjectLocator};

// ---------------------------------------------------------------------------
// VfTable
// ---------------------------------------------------------------------------

/// A parsed virtual function table.
///
/// Represents the contents of a vftable in an MSVC binary, including the
/// associated RTTI4 `CompleteObjectLocator` and the list of virtual function
/// pointers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VfTable {
    /// The address of the vftable in the binary (first function pointer).
    pub address: u64,
    /// The meta-pointer address (the pointer to the `CompleteObjectLocator`,
    /// located just *before* the first function pointer).
    pub meta_pointer_address: u64,
    /// The RTTI4 structure associated with this vftable.
    pub rtti4: Option<CompleteObjectLocator>,
    /// Virtual function pointers in order.
    pub function_pointers: Vec<u64>,
    /// Number of known function entries (may be approximate).
    pub entry_count: usize,
    /// Whether the vtable uses 64-bit pointers.
    pub is_64bit: bool,
}

impl VfTable {
    /// Attempt to parse a vftable from a byte buffer.
    ///
    /// * `data` -- byte buffer starting at the vtable's meta-pointer address.
    /// * `base_address` -- the address of the first byte in `data`.
    /// * `ptr_size` -- 4 or 8.
    /// * `max_entries` -- upper bound on the number of virtual function pointers to read.
    pub fn parse(
        data: &[u8],
        base_address: u64,
        ptr_size: usize,
        max_entries: usize,
    ) -> Option<Self> {
        let entry_size = ptr_size;

        // The meta pointer (pointer to RTTI4) is located at `base_address`.
        // The vtable function pointers start at `base_address + ptr_size`.
        // We need at least ptr_size (meta pointer) + entry_size (one function pointer).
        if data.len() < ptr_size + entry_size {
            return None;
        }

        let _meta_ptr = read_ptr(data, 0, ptr_size);
        let vf_start = ptr_size;
        let remaining = data.len() - vf_start;
        let count = (remaining / entry_size).min(max_entries);

        let mut function_pointers = Vec::with_capacity(count);
        for i in 0..count {
            let off = vf_start + i * entry_size;
            let ptr = read_ptr(data, off, ptr_size);
            function_pointers.push(ptr);
        }

        Some(Self {
            address: base_address + ptr_size as u64,
            meta_pointer_address: base_address,
            rtti4: None,
            function_pointers,
            entry_count: count,
            is_64bit: ptr_size == 8,
        })
    }

    /// Try to resolve and attach the RTTI4 structure by reading from the
    /// provided data at the meta pointer location.
    pub fn resolve_rtti4(&mut self, full_data: &[u8], full_base: u64, ptr_size: usize) {
        let meta_abs = self.meta_pointer_address;
        if meta_abs < full_base {
            return;
        }
        let rel = (meta_abs - full_base) as usize;
        if rel + ptr_size > full_data.len() {
            return;
        }
        let rtti4_addr = read_ptr(full_data, rel, ptr_size);
        if rtti4_addr == 0 || rtti4_addr < full_base {
            return;
        }
        let rtti4_rel = (rtti4_addr - full_base) as usize;
        let rtti4_end = rtti4_rel + CompleteObjectLocator::SIZE_32;
        if rtti4_end > full_data.len() {
            return;
        }
        self.rtti4 = CompleteObjectLocator::parse(&full_data[rtti4_rel..rtti4_end], rtti4_addr, ptr_size);
    }

    /// Get a function pointer by index.
    pub fn get_function_pointer(&self, index: usize) -> Option<u64> {
        self.function_pointers.get(index).copied()
    }

    /// The label name for this vtable, based on its RTTI4 -> RTTI0 class name.
    pub fn label_name(&self) -> String {
        if let Some(ref rtti4) = self.rtti4 {
            format!("vftable_col_{:x}", rtti4.address)
        } else {
            format!("vftable_{:x}", self.address)
        }
    }
}

// ---------------------------------------------------------------------------
// Scan for vtable candidates
// ---------------------------------------------------------------------------

/// Scan a binary for vftable candidates.
///
/// A vftable candidate is identified by looking for a sequence of valid
/// code pointers preceded by a pointer to a valid `CompleteObjectLocator`
/// (RTTI4 signature = 0 or 1).
///
/// Returns a list of `(address, vftable)` tuples.
pub fn scan_for_vftables(
    data: &[u8],
    base_address: u64,
    ptr_size: usize,
    max_entries: usize,
) -> Vec<(u64, VfTable)> {
    let mut results = Vec::new();
    let step = ptr_size;
    let max_scan = data.len().saturating_sub(ptr_size + CompleteObjectLocator::SIZE_32);

    // We scan for potential meta-pointers: pointer-sized values that point
    // into the data range and are followed by at least one non-zero function
    // pointer. The meta pointer must be aligned and point to a valid
    // CompleteObjectLocator.
    let mut offset = 0;
    while offset <= max_scan {
        let meta_ptr = read_ptr(data, offset, ptr_size);

        // Skip zero pointers (uninitialized memory).
        if meta_ptr == 0 {
            offset += step;
            continue;
        }

        // The meta pointer should point into the data range, be properly
        // aligned, and be at a different location than the vtable itself.
        let vtable_addr = base_address + offset as u64;
        if meta_ptr >= base_address
            && meta_ptr != vtable_addr
            && (meta_ptr - base_address) as usize % step == 0
        {
            let col_rel = (meta_ptr - base_address) as usize;
            if col_rel + CompleteObjectLocator::SIZE_32 <= data.len() {
                let sig = read_u32(data, col_rel);
                if sig <= 1 {
                    // Verify the RTTI chain is at least partially valid:
                    // the COL must reference valid RTTI0 and RTTI3 addresses.
                    if let Some(col) = CompleteObjectLocator::parse(
                        &data[col_rel..col_rel + CompleteObjectLocator::SIZE_32],
                        meta_ptr,
                        ptr_size,
                    ) {
                        // Require both RTTI references to be non-zero and in range
                        if col.rtti0_address != 0
                            && col.rtti3_address != 0
                            && col.rtti0_address >= base_address
                            && col.rtti3_address >= base_address
                        {
                            if let Some(vf) = VfTable::parse(
                                &data[offset..],
                                vtable_addr,
                                ptr_size,
                                max_entries,
                            ) {
                                if vf.function_pointers.iter().any(|&p| p != 0) {
                                    results.push((vtable_addr, vf));
                                }
                            }
                        }
                    }
                }
            }
        }
        offset += step;
    }

    results
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vftable_parse_basic() {
        let ptr_size = 4;
        let base = 0x5000u64;

        // Layout: [meta ptr] [vf0] [vf1] [vf2]
        let mut data = vec![0u8; 16];
        // meta pointer to 0x2000 (would point to RTTI4)
        data[0..4].copy_from_slice(&0x2000u32.to_le_bytes());
        // 3 virtual function pointers
        data[4..8].copy_from_slice(&0x6000u32.to_le_bytes());
        data[8..12].copy_from_slice(&0x6010u32.to_le_bytes());
        data[12..16].copy_from_slice(&0x6020u32.to_le_bytes());

        let vf = VfTable::parse(&data, base, ptr_size, 100).unwrap();
        assert_eq!(vf.address, base + 4); // first function pointer addr
        assert_eq!(vf.function_pointers.len(), 3);
        assert_eq!(vf.function_pointers[0], 0x6000);
        assert_eq!(vf.function_pointers[1], 0x6010);
        assert_eq!(vf.function_pointers[2], 0x6020);
        assert!(!vf.is_64bit);
    }

    #[test]
    fn test_vftable_parse_64bit() {
        let ptr_size = 8;
        let base = 0x14000_0000u64;

        // Layout: [meta ptr (8)] [vf0 (8)] [vf1 (8)]
        let mut data = vec![0u8; 24];
        // meta pointer
        data[0..8].copy_from_slice(&0x14000_2000u64.to_le_bytes());
        // function pointers
        data[8..16].copy_from_slice(&0x14000_6000u64.to_le_bytes());
        data[16..24].copy_from_slice(&0x14000_6010u64.to_le_bytes());

        let vf = VfTable::parse(&data, base, ptr_size, 100).unwrap();
        assert_eq!(vf.address, base + 8);
        assert_eq!(vf.function_pointers.len(), 2);
        assert_eq!(vf.function_pointers[0], 0x14000_6000);
        assert!(vf.is_64bit);
    }

    #[test]
    fn test_vftable_label_name() {
        let mut vf = VfTable {
            address: 0x4000,
            meta_pointer_address: 0x3FFC,
            rtti4: None,
            function_pointers: vec![0x1000],
            entry_count: 1,
            is_64bit: false,
        };
        assert_eq!(vf.label_name(), "vftable_4000");

        vf.rtti4 = Some(CompleteObjectLocator {
            signature: 0,
            vb_table_offset: 0,
            constructor_disp_offset: 0,
            rtti0_address: 0,
            rtti3_address: 0,
            address: 0x1234,
            is_relative: false,
        });
        assert_eq!(vf.label_name(), "vftable_col_1234");
    }

    #[test]
    fn test_vftable_empty_data() {
        let data = [0u8; 2];
        assert!(VfTable::parse(&data, 0, 4, 10).is_none());
    }

    #[test]
    fn test_scan_for_vftables_basic() {
        // Create a small binary with one COL at 0x100 and a vftable at 0x200
        let base = 0u64;
        let mut data = vec![0u8; 0x400];

        // COL at 0x100: signature=0, vbOff=0, ctorDisp=0, pRtti0=0x300, pRtti3=0x350
        data[0x100..0x104].copy_from_slice(&0u32.to_le_bytes());
        data[0x104..0x108].copy_from_slice(&0u32.to_le_bytes());
        data[0x108..0x10C].copy_from_slice(&0u32.to_le_bytes());
        data[0x10C..0x110].copy_from_slice(&0x300u32.to_le_bytes()); // pRtti0
        data[0x110..0x114].copy_from_slice(&0x350u32.to_le_bytes()); // pRtti3

        // Meta pointer at 0x200 -> points to 0x100 (the COL)
        data[0x200..0x204].copy_from_slice(&0x100u32.to_le_bytes());
        // Function pointers at 0x204, 0x208, 0x20C
        data[0x204..0x208].copy_from_slice(&0x3000u32.to_le_bytes());
        data[0x208..0x20C].copy_from_slice(&0x3010u32.to_le_bytes());
        data[0x20C..0x210].copy_from_slice(&0x3020u32.to_le_bytes());

        let results = scan_for_vftables(&data, base, 4, 100);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, 0x200);
    }

    #[test]
    fn test_get_function_pointer() {
        let vf = VfTable {
            address: 0x4000,
            meta_pointer_address: 0x3FFC,
            rtti4: None,
            function_pointers: vec![0x1000, 0x2000, 0x3000],
            entry_count: 3,
            is_64bit: false,
        };
        assert_eq!(vf.get_function_pointer(0), Some(0x1000));
        assert_eq!(vf.get_function_pointer(2), Some(0x3000));
        assert_eq!(vf.get_function_pointer(5), None);
    }
}
