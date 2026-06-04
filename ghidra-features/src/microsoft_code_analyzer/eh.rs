//! MSVC Exception Handling (SEH / C++ EH) data structures.
//!
//! Ported from Ghidra's `ghidra.app.cmd.data.exceptionhandling` package.
//!
//! These structures describe the SEH3/SEH4 exception handling frame layout used
//! by MSVC-compiled binaries, including FuncInfo, UnwindMapEntry, TryBlockMapEntry,
//! HandlerType (CatchHandler), IPToStateMapEntry, and ESTypeList.
//!
//! # EH Magic Numbers
//!
//! ```text
//! 0x19930520 = version 1
//! 0x19930521 = version 2
//! 0x19930522 = version 3
//! ```

use serde::{Deserialize, Serialize};

use super::rtti::{read_i32, read_u32};

// ---------------------------------------------------------------------------
// EH magic number constants
// ---------------------------------------------------------------------------

/// EH FuncInfo magic number for version 1 (SEH3, x86).
pub const EH_MAGIC_NUMBER_V1: u32 = 0x19930520;
/// EH FuncInfo magic number for version 2 (SEH3, updated).
pub const EH_MAGIC_NUMBER_V2: u32 = 0x19930521;
/// EH FuncInfo magic number for version 3 (SEH4).
pub const EH_MAGIC_NUMBER_V3: u32 = 0x19930522;

// ---------------------------------------------------------------------------
// UnwindMapEntry
// ---------------------------------------------------------------------------

/// An entry in the unwind action map.
///
/// ```c
/// struct UnwindMapEntry {
///     int    toState;  // state to transition to
///     void*  action;   // address of unwind action (dtor or cleanup code)
/// };
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnwindMapEntry {
    /// State to transition to upon unwind.
    pub to_state: i32,
    /// Address of the cleanup action function.
    pub action_address: u64,
    /// The address where this entry lives.
    pub address: u64,
}

impl UnwindMapEntry {
    /// Size in bytes for 32-bit targets (int + pointer = 8 bytes).
    pub const SIZE_32: usize = 8;
    /// Size in bytes for 64-bit targets (int + IBO32 = 8 bytes).
    pub const SIZE_64: usize = 8;

    /// Parse an UnwindMapEntry from a byte buffer.
    pub fn parse(data: &[u8], address: u64, ptr_size: usize) -> Option<Self> {
        if data.len() < 8 {
            return None;
        }
        let to_state = read_i32(data, 0);
        let action_address = if ptr_size == 4 {
            read_u32(data, 4) as u64
        } else {
            // 64-bit: image base offset
            address.wrapping_add(4).wrapping_add(read_i32(data, 4) as i64 as u64)
        };
        Some(Self {
            to_state,
            action_address,
            address,
        })
    }
}

// ---------------------------------------------------------------------------
// HandlerType (Catch Handler)
// ---------------------------------------------------------------------------

/// A single catch handler in a try block.
///
/// ```c
/// struct HandlerType {
///     unsigned long   adjectives;       // modifier flags
///     TypeDescriptor* pTypeDescriptor;   // type of caught exception
///     int             catchObjOffset;    // offset to catch object in frame
///     void*           handlerAddress;    // address of catch handler code
///     unsigned long   functionFrame;     // frame offset for function-level catch
/// };
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandlerType {
    /// Adjective / modifier flags (see [`CatchHandlerModifier`]).
    pub adjectives: u32,
    /// Address of the TypeDescriptor (RTTI 0) for the caught exception type.
    /// 0 if this is a catch-all handler.
    pub type_descriptor_address: u64,
    /// Frame offset for the catch object variable.
    pub catch_object_offset: i32,
    /// Address of the handler code.
    pub handler_address: u64,
    /// Frame pointer offset for the function-level catch frame.
    pub function_frame: u32,
    /// The address where this entry lives.
    pub address: u64,
}

impl HandlerType {
    /// Size in bytes for 32-bit targets.
    pub const SIZE_32: usize = 20;

    /// Parse a HandlerType from a byte buffer.
    pub fn parse(data: &[u8], address: u64, ptr_size: usize) -> Option<Self> {
        if data.len() < 4 {
            return None;
        }
        let adjectives = read_u32(data, 0);

        let (type_descriptor_address, td_len) = if ptr_size == 4 && data.len() >= 8 {
            (read_u32(data, 4) as u64, 4usize)
        } else if ptr_size == 8 && data.len() >= 8 {
            (address.wrapping_add(4).wrapping_add(read_i32(data, 4) as i64 as u64), 4)
        } else {
            return None;
        };

        let offset_after_td = 4 + td_len;
        if data.len() < offset_after_td + 8 {
            return None;
        }
        let catch_object_offset = read_i32(data, offset_after_td);

        let handler_address = if ptr_size == 4 && data.len() >= offset_after_td + 8 {
            read_u32(data, offset_after_td + 4) as u64
        } else if ptr_size == 8 && data.len() >= offset_after_td + 8 {
            address
                .wrapping_add((offset_after_td + 4) as u64)
                .wrapping_add(read_i32(data, offset_after_td + 4) as i64 as u64)
        } else {
            0
        };

        let func_frame_offset = offset_after_td + 8;
        let function_frame = if data.len() >= func_frame_offset + 4 {
            read_u32(data, func_frame_offset)
        } else {
            0
        };

        Some(Self {
            adjectives,
            type_descriptor_address,
            catch_object_offset,
            handler_address,
            function_frame,
            address,
        })
    }

    /// Whether this is a catch-all handler (no type specifier).
    pub fn is_catch_all(&self) -> bool {
        self.type_descriptor_address == 0
    }

    /// Whether this handler is decorated with `const`.
    pub fn is_const(&self) -> bool {
        self.adjectives & CatchHandlerModifier::CONST.bits() != 0
    }

    /// Whether this handler is decorated with `volatile`.
    pub fn is_volatile(&self) -> bool {
        self.adjectives & CatchHandlerModifier::VOLATILE.bits() != 0
    }

    /// Whether this handler uses a reference (&) catch.
    pub fn is_reference(&self) -> bool {
        self.adjectives & CatchHandlerModifier::REFERENCE.bits() != 0
    }
}

/// Bit flags for the `adjectives` field in [`HandlerType`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CatchHandlerModifier(u32);

impl CatchHandlerModifier {
    /// No modifiers.
    pub const NO_MODIFIERS: Self = Self(0x00);
    /// The handler catches a `const` exception.
    pub const CONST: Self = Self(0x01);
    /// The handler catches a `volatile` exception.
    pub const VOLATILE: Self = Self(0x02);
    /// The handler catches by reference.
    pub const REFERENCE: Self = Self(0x08);
    /// The handler catches any exception (catch-all / ellipsis).
    pub const ELLIPSIS: Self = Self(0x10);

    /// Returns the raw adjectives value.
    pub fn bits(&self) -> u32 {
        self.0
    }
}

// ---------------------------------------------------------------------------
// TryBlockMapEntry
// ---------------------------------------------------------------------------

/// A try-block entry in the try-block map.
///
/// ```c
/// struct TryBlockMapEntry {
///     int            tryLow;       // lowest state index of the try block
///     int            tryHigh;      // highest state index of the try block
///     int            catchHigh;    // highest state index of any associated catch
///     int            nCatches;     // number of catch handlers
///     HandlerType*   pHandlerArray; // pointer to array of HandlerType entries
/// };
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TryBlockMapEntry {
    /// Lowest state index of the try block (inclusive).
    pub try_low: i32,
    /// Highest state index of the try block (inclusive).
    pub try_high: i32,
    /// Highest state index of any associated catch handler.
    pub catch_high: i32,
    /// Number of catch handlers.
    pub num_catches: i32,
    /// Address of the handler array.
    pub handler_array_address: u64,
    /// The address where this entry lives.
    pub address: u64,
}

impl TryBlockMapEntry {
    /// Size in bytes for 32-bit targets (4 ints + pointer = 20 bytes).
    pub const SIZE_32: usize = 20;

    /// Parse a TryBlockMapEntry from a byte buffer.
    pub fn parse(data: &[u8], address: u64, ptr_size: usize) -> Option<Self> {
        if data.len() < 16 {
            return None;
        }
        let try_low = read_i32(data, 0);
        let try_high = read_i32(data, 4);
        let catch_high = read_i32(data, 8);
        let num_catches = read_i32(data, 12);

        let handler_array_address = if ptr_size == 4 && data.len() >= 20 {
            read_u32(data, 16) as u64
        } else if ptr_size == 8 && data.len() >= 20 {
            address
                .wrapping_add(16)
                .wrapping_add(read_i32(data, 16) as i64 as u64)
        } else {
            0
        };

        Some(Self {
            try_low,
            try_high,
            catch_high,
            num_catches,
            handler_array_address,
            address,
        })
    }

    /// Check if `state` falls within this try block.
    pub fn contains_state(&self, state: i32) -> bool {
        state >= self.try_low && state <= self.try_high
    }
}

// ---------------------------------------------------------------------------
// IPToStateMapEntry
// ---------------------------------------------------------------------------

/// Maps an instruction pointer (EIP/RIP) to a state number.
///
/// ```c
/// struct IPToStateMapEntry {
///     void* ip;       // instruction pointer (function-relative)
///     int   state;    // state number at this instruction
/// };
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IPToStateMapEntry {
    /// Instruction pointer address.
    pub ip: u64,
    /// State number at this instruction.
    pub state: i32,
    /// The address where this entry lives.
    pub address: u64,
}

impl IPToStateMapEntry {
    /// Size in bytes for 32-bit targets (pointer + int = 8 bytes).
    pub const SIZE_32: usize = 8;

    /// Parse from a byte buffer.
    pub fn parse(data: &[u8], address: u64, ptr_size: usize) -> Option<Self> {
        if data.len() < 8 {
            return None;
        }
        let ip = if ptr_size == 4 {
            read_u32(data, 0) as u64
        } else {
            address.wrapping_add(read_i32(data, 0) as i64 as u64)
        };
        let state = read_i32(data, 4);
        Some(Self { ip, state, address })
    }
}

// ---------------------------------------------------------------------------
// ESTypeList
// ---------------------------------------------------------------------------

/// The exception specification type list.
///
/// ```c
/// struct ESTypeList {
///     int           nCount;          // number of type entries
///     HandlerType** pTypeArray;      // pointer to array of HandlerType pointers
/// };
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ESTypeList {
    /// Number of exception specification types.
    pub count: i32,
    /// Address of the handler type array.
    pub type_array_address: u64,
    /// The address where this entry lives.
    pub address: u64,
}

impl ESTypeList {
    /// Size in bytes for 32-bit targets (int + pointer = 8 bytes).
    pub const SIZE_32: usize = 8;

    /// Parse from a byte buffer.
    pub fn parse(data: &[u8], address: u64, ptr_size: usize) -> Option<Self> {
        if data.len() < 8 {
            return None;
        }
        let count = read_i32(data, 0);
        let type_array_address = if ptr_size == 4 {
            read_u32(data, 4) as u64
        } else {
            address.wrapping_add(4).wrapping_add(read_i32(data, 4) as i64 as u64)
        };
        Some(Self {
            count,
            type_array_address,
            address,
        })
    }
}

// ---------------------------------------------------------------------------
// FuncInfo -- the top-level exception-handling descriptor for a function
// ---------------------------------------------------------------------------

/// Top-level function-level EH descriptor.
///
/// Contains the magic number, unwind map, try-block map, and IP-to-state map.
///
/// ```c
/// struct FuncInfo {
///     unsigned long       magicNumber;
///     int                 maxState;
///     UnwindMapEntry*     pUnwindMap;
///     int                 nTryBlocks;
///     TryBlockMapEntry*   pTryBlockMap;
///     int                 nIPMapEntries;
///     IPToStateMapEntry*  pIPToStateMap;
///     // ... additional v2/v3 fields
/// };
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuncInfo {
    /// The magic number identifying the EH version.
    pub magic_number: u32,
    /// Maximum state number.
    pub max_state: i32,
    /// Address of the unwind map.
    pub unwind_map_address: u64,
    /// Number of try blocks.
    pub try_block_count: i32,
    /// Address of the try-block map.
    pub try_block_map_address: u64,
    /// Number of IP-to-state map entries.
    pub ip_to_state_count: i32,
    /// Address of the IP-to-state map.
    pub ip_to_state_map_address: u64,
    /// Whether this is a v2+ FuncInfo (has ESTypeList).
    pub has_es_type_list: bool,
    /// Address of the ESTypeList (v2+).
    pub es_type_list_address: Option<u64>,
    /// Whether this function uses SEH4 (image-relative pointers).
    pub is_relative: bool,
    /// The address where this FuncInfo lives.
    pub address: u64,
}

impl FuncInfo {
    /// Minimum size for a v1 FuncInfo in 32-bit mode (1 dword + 3 * (int+ptr) = 28 bytes).
    pub const MIN_SIZE_32: usize = 28;

    /// Parse a FuncInfo from a byte buffer.
    pub fn parse(data: &[u8], address: u64, ptr_size: usize) -> Option<Self> {
        if data.len() < 4 {
            return None;
        }
        let magic_number = read_u32(data, 0);
        if !matches!(magic_number, EH_MAGIC_NUMBER_V1 | EH_MAGIC_NUMBER_V2 | EH_MAGIC_NUMBER_V3) {
            return None;
        }

        if data.len() < 28 {
            return None;
        }

        let is_relative = magic_number == EH_MAGIC_NUMBER_V3;
        let max_state = read_i32(data, 4);

        let unwind_map_address = read_ptr_or_ibo(data, 8, address, ptr_size, is_relative);
        let try_block_count = read_i32(data, 12);
        let try_block_map_address = read_ptr_or_ibo(data, 16, address, ptr_size, is_relative);
        let ip_to_state_count = read_i32(data, 20);
        let ip_to_state_map_address = read_ptr_or_ibo(data, 24, address, ptr_size, is_relative);

        // v2/v3 may have additional ESTypeList fields
        let (has_es_type_list, es_type_list_address) = if magic_number >= EH_MAGIC_NUMBER_V2 {
            let estype_offset = if is_relative { 28 } else { 28 };
            if data.len() >= estype_offset + 8 {
                let es_count = read_i32(data, estype_offset);
                if es_count >= 0 && data.len() >= estype_offset + 8 {
                    let addr = read_ptr_or_ibo(data, estype_offset + 4, address, ptr_size, is_relative);
                    (es_count > 0, Some(addr))
                } else {
                    (false, None)
                }
            } else {
                (false, None)
            }
        } else {
            (false, None)
        };

        Some(Self {
            magic_number,
            max_state,
            unwind_map_address,
            try_block_count,
            try_block_map_address,
            ip_to_state_count,
            ip_to_state_map_address,
            has_es_type_list,
            es_type_list_address,
            is_relative,
            address,
        })
    }

    /// Returns the EH version (1, 2, or 3).
    pub fn version(&self) -> u32 {
        match self.magic_number {
            EH_MAGIC_NUMBER_V1 => 1,
            EH_MAGIC_NUMBER_V2 => 2,
            EH_MAGIC_NUMBER_V3 => 3,
            _ => 0,
        }
    }

    /// Whether this FuncInfo uses SEH4 (image-relative pointers).
    pub fn is_seh4(&self) -> bool {
        self.magic_number == EH_MAGIC_NUMBER_V3
    }

    /// Whether this FuncInfo is SEH3.
    pub fn is_seh3(&self) -> bool {
        self.magic_number == EH_MAGIC_NUMBER_V1 || self.magic_number == EH_MAGIC_NUMBER_V2
    }
}

/// Read either a direct pointer or an image-base-offset (IBO32) from the buffer.
fn read_ptr_or_ibo(data: &[u8], offset: usize, base: u64, ptr_size: usize, is_relative: bool) -> u64 {
    if offset + 4 > data.len() {
        return 0;
    }
    let raw = read_i32(data, offset) as i64;
    if is_relative || ptr_size == 8 {
        // Image-relative offset
        base.wrapping_add(offset as u64).wrapping_add(raw as u64)
    } else {
        // Absolute pointer (32-bit)
        raw as u64
    }
}

// ---------------------------------------------------------------------------
// EHFullFrame -- parsed representation of all EH structures for a function
// ---------------------------------------------------------------------------

/// Fully-parsed EH data for a single function, including all subordinate structures.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EHFrame {
    /// The FuncInfo descriptor.
    pub func_info: FuncInfo,
    /// Unwind map entries.
    pub unwind_map: Vec<UnwindMapEntry>,
    /// Try-block entries and their catch handlers.
    pub try_blocks: Vec<TryBlockWithHandlers>,
    /// IP-to-state mappings.
    pub ip_to_state_map: Vec<IPToStateMapEntry>,
}

/// A TryBlockMapEntry together with its parsed catch handlers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TryBlockWithHandlers {
    /// The try-block descriptor.
    pub try_block: TryBlockMapEntry,
    /// Catch handlers associated with this try block.
    pub handlers: Vec<HandlerType>,
}

// ---------------------------------------------------------------------------
// EH Analyzer
// ---------------------------------------------------------------------------

/// Analyzer for Microsoft SEH / C++ exception handling data.
///
/// Scans for `FuncInfo` signatures in the binary and creates labels for
/// the associated unwind/try-block/handler structures.
#[derive(Debug)]
pub struct EHAnalyzer {
    /// The pointer size (4 or 8).
    pub ptr_size: usize,
}

impl Default for EHAnalyzer {
    fn default() -> Self {
        Self { ptr_size: 4 }
    }
}

impl EHAnalyzer {
    /// Create a new EH analyzer.
    pub fn new(ptr_size: usize) -> Self {
        Self { ptr_size }
    }

    /// Scan a byte buffer for a valid FuncInfo magic number and attempt to parse.
    ///
    /// Returns the parsed FuncInfo if the magic number matches and the buffer is
    /// large enough.
    pub fn try_parse_func_info(&self, data: &[u8], address: u64) -> Option<FuncInfo> {
        FuncInfo::parse(data, address, self.ptr_size)
    }

    /// Scan a byte buffer for EH magic numbers.
    ///
    /// Returns offsets into `data` where valid magic numbers were found.
    pub fn scan_for_func_info_signatures(&self, data: &[u8]) -> Vec<usize> {
        let mut offsets = Vec::new();
        if data.len() < 4 {
            return offsets;
        }
        for i in 0..=(data.len() - 4) {
            let val = read_u32(data, i);
            if matches!(val, EH_MAGIC_NUMBER_V1 | EH_MAGIC_NUMBER_V2 | EH_MAGIC_NUMBER_V3) {
                offsets.push(i);
            }
        }
        offsets
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_func_info_parse_v1() {
        let mut data = [0u8; 28];
        data[0..4].copy_from_slice(&EH_MAGIC_NUMBER_V1.to_le_bytes());
        data[4..8].copy_from_slice(&5i32.to_le_bytes());  // maxState
        data[8..12].copy_from_slice(&0x2000u32.to_le_bytes()); // pUnwindMap
        data[12..16].copy_from_slice(&2i32.to_le_bytes()); // nTryBlocks
        data[16..20].copy_from_slice(&0x3000u32.to_le_bytes()); // pTryBlockMap
        data[20..24].copy_from_slice(&10i32.to_le_bytes()); // nIPMapEntries
        data[24..28].copy_from_slice(&0x4000u32.to_le_bytes()); // pIPToStateMap

        let fi = FuncInfo::parse(&data, 0x5000, 4).unwrap();
        assert_eq!(fi.magic_number, EH_MAGIC_NUMBER_V1);
        assert_eq!(fi.max_state, 5);
        assert_eq!(fi.try_block_count, 2);
        assert_eq!(fi.ip_to_state_count, 10);
        assert_eq!(fi.version(), 1);
        assert!(!fi.is_seh4());
        assert!(fi.is_seh3());
    }

    #[test]
    fn test_func_info_parse_v3_seh4() {
        let base = 0x14000_0000u64;
        let mut data = [0u8; 32];
        data[0..4].copy_from_slice(&EH_MAGIC_NUMBER_V3.to_le_bytes());
        data[4..8].copy_from_slice(&3i32.to_le_bytes()); // maxState

        // IBO32 for unwind map at base+8+0x100 = absolute base+0x108
        let unwind_offset: i32 = 0x100;
        data[8..12].copy_from_slice(&unwind_offset.to_le_bytes());
        data[12..16].copy_from_slice(&1i32.to_le_bytes()); // nTryBlocks

        let try_block_offset: i32 = 0x200;
        data[16..20].copy_from_slice(&try_block_offset.to_le_bytes());
        data[20..24].copy_from_slice(&5i32.to_le_bytes()); // nIPMapEntries

        let ip_map_offset: i32 = 0x300;
        data[24..28].copy_from_slice(&ip_map_offset.to_le_bytes());

        let fi = FuncInfo::parse(&data, base, 8).unwrap();
        assert_eq!(fi.version(), 3);
        assert!(fi.is_seh4());
        assert_eq!(fi.unwind_map_address, base + 8 + 0x100);
        assert_eq!(fi.try_block_map_address, base + 16 + 0x200);
        assert_eq!(fi.ip_to_state_map_address, base + 24 + 0x300);
    }

    #[test]
    fn test_func_info_invalid_magic() {
        let mut data = [0u8; 28];
        data[0..4].copy_from_slice(&0xDEADBEEFu32.to_le_bytes());
        assert!(FuncInfo::parse(&data, 0, 4).is_none());
    }

    #[test]
    fn test_unwind_map_entry_parse() {
        let mut data = [0u8; 8];
        data[0..4].copy_from_slice(&2i32.to_le_bytes()); // toState
        data[4..8].copy_from_slice(&0x6000u32.to_le_bytes()); // action

        let entry = UnwindMapEntry::parse(&data, 0x7000, 4).unwrap();
        assert_eq!(entry.to_state, 2);
        assert_eq!(entry.action_address, 0x6000);
    }

    #[test]
    fn test_try_block_map_entry_parse() {
        let mut data = [0u8; 20];
        data[0..4].copy_from_slice(&1i32.to_le_bytes());   // tryLow
        data[4..8].copy_from_slice(&5i32.to_le_bytes());    // tryHigh
        data[8..12].copy_from_slice(&10i32.to_le_bytes());  // catchHigh
        data[12..16].copy_from_slice(&2i32.to_le_bytes());  // nCatches
        data[16..20].copy_from_slice(&0x8000u32.to_le_bytes()); // pHandlerArray

        let entry = TryBlockMapEntry::parse(&data, 0x9000, 4).unwrap();
        assert_eq!(entry.try_low, 1);
        assert_eq!(entry.try_high, 5);
        assert_eq!(entry.catch_high, 10);
        assert_eq!(entry.num_catches, 2);
        assert!(entry.contains_state(3));
        assert!(!entry.contains_state(0));
        assert!(!entry.contains_state(6));
    }

    #[test]
    fn test_handler_type_parse() {
        let mut data = [0u8; 20];
        data[0..4].copy_from_slice(&0x08u32.to_le_bytes());  // adjectives (REFERENCE)
        data[4..8].copy_from_slice(&0xA000u32.to_le_bytes()); // pTypeDescriptor
        data[8..12].copy_from_slice(&(-4i32).to_le_bytes());  // catchObjOffset
        data[12..16].copy_from_slice(&0xB000u32.to_le_bytes()); // handlerAddress
        data[16..20].copy_from_slice(&0u32.to_le_bytes());    // functionFrame

        let handler = HandlerType::parse(&data, 0xC000, 4).unwrap();
        assert_eq!(handler.type_descriptor_address, 0xA000);
        assert_eq!(handler.catch_object_offset, -4);
        assert_eq!(handler.handler_address, 0xB000);
        assert!(handler.is_reference());
        assert!(!handler.is_catch_all());
    }

    #[test]
    fn test_handler_type_catch_all() {
        let mut data = [0u8; 20];
        data[0..4].copy_from_slice(&0u32.to_le_bytes()); // adjectives = 0
        data[4..8].copy_from_slice(&0u32.to_le_bytes()); // pTypeDescriptor = 0 (catch-all)
        data[8..12].copy_from_slice(&0i32.to_le_bytes());
        data[12..16].copy_from_slice(&0xD000u32.to_le_bytes()); // handlerAddress
        data[16..20].copy_from_slice(&0u32.to_le_bytes());

        let handler = HandlerType::parse(&data, 0, 4).unwrap();
        assert!(handler.is_catch_all());
    }

    #[test]
    fn test_ip_to_state_entry_parse() {
        let mut data = [0u8; 8];
        data[0..4].copy_from_slice(&0xE000u32.to_le_bytes()); // ip
        data[4..8].copy_from_slice(&3i32.to_le_bytes());      // state

        let entry = IPToStateMapEntry::parse(&data, 0xF000, 4).unwrap();
        assert_eq!(entry.ip, 0xE000);
        assert_eq!(entry.state, 3);
    }

    #[test]
    fn test_es_type_list_parse() {
        let mut data = [0u8; 8];
        data[0..4].copy_from_slice(&3i32.to_le_bytes());       // nCount
        data[4..8].copy_from_slice(&0xF000u32.to_le_bytes());  // pTypeArray

        let es = ESTypeList::parse(&data, 0, 4).unwrap();
        assert_eq!(es.count, 3);
        assert_eq!(es.type_array_address, 0xF000);
    }

    #[test]
    fn test_eh_analyzer_scan_for_signatures() {
        let analyzer = EHAnalyzer::new(4);
        let mut data = vec![0u8; 12];
        data[0..4].copy_from_slice(&EH_MAGIC_NUMBER_V1.to_le_bytes());
        data[8..12].copy_from_slice(&EH_MAGIC_NUMBER_V3.to_le_bytes());

        let offsets = analyzer.scan_for_func_info_signatures(&data);
        assert_eq!(offsets, vec![0, 8]);
    }

    #[test]
    fn test_eh_analyzer_scan_no_match() {
        let analyzer = EHAnalyzer::new(4);
        let data = vec![0u8; 64];
        let offsets = analyzer.scan_for_func_info_signatures(&data);
        assert!(offsets.is_empty());
    }
}
