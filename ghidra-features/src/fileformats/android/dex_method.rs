//! Android DEX method structures.
//!
//! Ported from Ghidra's `ghidra.file.formats.android.dex.format`
//! `MethodIDItem` and `EncodedMethod` packages.
//!
//! Covers the `method_id_item` (8 bytes) and `encoded_method`
//! (variable-length, ULEB128-encoded) on-disk structures.

// ═══════════════════════════════════════════════════════════════════════════════════
// MethodIDItem
// ═══════════════════════════════════════════════════════════════════════════════════

/// Represents a `method_id_item` structure (8 bytes).
///
/// Each method referenced in the DEX file has an entry in the `method_ids`
/// table.  The entry identifies the declaring class, the prototype (return
/// type and parameter types), and the method name.
#[derive(Debug, Clone)]
pub struct MethodIDItem {
    /// File offset of this item (set during parsing).
    pub file_offset: u64,
    /// Index into `type_ids` for the declaring class.
    pub class_index: u16,
    /// Index into `proto_ids` for the method prototype.
    pub proto_index: u16,
    /// Index into `string_ids` for the method name.
    pub name_index: u32,
}

impl MethodIDItem {
    /// Size of the on-disk structure (8 bytes).
    pub const SIZE: usize = 8;

    /// Parse a `method_id_item` from a byte slice.
    pub fn parse(data: &[u8]) -> Result<Self, String> {
        Self::parse_at(data, 0)
    }

    /// Parse a `method_id_item` from a byte slice, recording the file offset.
    pub fn parse_at(data: &[u8], file_offset: usize) -> Result<Self, String> {
        if data.len() < Self::SIZE {
            return Err("Data too short for MethodIDItem".to_string());
        }

        let class_index = u16::from_le_bytes(data[0..2].try_into().unwrap());
        let proto_index = u16::from_le_bytes(data[2..4].try_into().unwrap());
        let name_index = u32::from_le_bytes(data[4..8].try_into().unwrap());

        Ok(MethodIDItem {
            file_offset: file_offset as u64,
            class_index,
            proto_index,
            name_index,
        })
    }

    /// Parse all `method_id_item` entries from a DEX file.
    ///
    /// `count` is the number of entries (from the DEX header).
    /// `offset` is the byte offset of the `method_ids` table.
    pub fn parse_all(data: &[u8], offset: u32, count: u32) -> Result<Vec<Self>, String> {
        let start = offset as usize;
        let table_size = count as usize * Self::SIZE;
        if start + table_size > data.len() {
            return Err("MethodIDItem table extends beyond data".to_string());
        }

        let mut result = Vec::with_capacity(count as usize);
        for i in 0..count as usize {
            let entry_start = start + i * Self::SIZE;
            let item = Self::parse_at(&data[entry_start..], entry_start)?;
            result.push(item);
        }
        Ok(result)
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════
// EncodedMethod
// ═══════════════════════════════════════════════════════════════════════════════════

/// Represents an `encoded_method` structure.
///
/// Methods within a `class_data_item` are stored as ULEB128-encoded
/// triples of (method_idx_diff, access_flags, code_off).  The
/// `method_idx_diff` is a delta from the previous method index.
#[derive(Debug, Clone)]
pub struct EncodedMethod {
    /// File offset where this encoded method starts.
    pub file_offset: u64,
    /// Delta-encoded index into `method_ids` (add to previous index).
    pub method_index_diff: u32,
    /// Absolute method index (resolved during parsing).
    pub method_index: u32,
    /// Access flags (ACC_PUBLIC, ACC_STATIC, etc.).
    pub access_flags: u32,
    /// Offset to the `code_item`, or 0 for native/abstract methods.
    pub code_offset: u32,
    /// Length of the `method_idx_diff` ULEB128 encoding (bytes).
    pub method_index_diff_length: u32,
    /// Length of the `access_flags` ULEB128 encoding (bytes).
    pub access_flags_length: u32,
    /// Length of the `code_off` ULEB128 encoding (bytes).
    pub code_offset_length: u32,
}

impl EncodedMethod {
    /// Parse a single `encoded_method` from raw bytes.
    pub fn parse(data: &[u8]) -> Result<Self, String> {
        Self::parse_at(data, 0)
    }

    /// Parse a single `encoded_method`, recording the file offset.
    pub fn parse_at(data: &[u8], file_offset: usize) -> Result<Self, String> {
        let mut pos = 0;

        let (method_index_diff, new_pos, diff_len) = read_uleb128_with_len(data, pos)?;
        pos = new_pos;

        let (access_flags, new_pos, flags_len) = read_uleb128_with_len(data, pos)?;
        pos = new_pos;

        let (code_offset, new_pos, code_len) = read_uleb128_with_len(data, pos)?;
        pos = new_pos;

        let _ = pos;

        Ok(EncodedMethod {
            file_offset: file_offset as u64,
            method_index_diff,
            method_index: 0, // resolved later
            access_flags,
            code_offset,
            method_index_diff_length: diff_len,
            access_flags_length: flags_len,
            code_offset_length: code_len,
        })
    }

    /// Parse all `encoded_method` entries from a list.
    ///
    /// `count` is the number of entries.
    /// `data` is the raw bytes starting at the first entry.
    ///
    /// Returns the parsed methods and the number of bytes consumed.
    pub fn parse_all(data: &[u8], count: u32) -> Result<(Vec<Self>, usize), String> {
        let mut result = Vec::with_capacity(count as usize);
        let mut pos = 0;
        let mut last_method_index: u32 = 0;

        for _ in 0..count {
            let mut method = Self::parse_at(&data[pos..], pos)?;
            last_method_index = last_method_index.wrapping_add(method.method_index_diff);
            method.method_index = last_method_index;
            // Advance past the three ULEB128 values we consumed
            pos += method.method_index_diff_length as usize
                + method.access_flags_length as usize
                + method.code_offset_length as usize;
            result.push(method);
        }

        Ok((result, pos))
    }

    /// Returns true if this method has a code item.
    pub fn has_code(&self) -> bool {
        self.code_offset != 0
    }

    /// Returns true if this method is public.
    pub fn is_public(&self) -> bool {
        self.access_flags & 0x0001 != 0
    }

    /// Returns true if this method is private.
    pub fn is_private(&self) -> bool {
        self.access_flags & 0x0002 != 0
    }

    /// Returns true if this method is protected.
    pub fn is_protected(&self) -> bool {
        self.access_flags & 0x0004 != 0
    }

    /// Returns true if this method is static.
    pub fn is_static(&self) -> bool {
        self.access_flags & 0x0008 != 0
    }

    /// Returns true if this method is final.
    pub fn is_final(&self) -> bool {
        self.access_flags & 0x0010 != 0
    }

    /// Returns true if this method is synchronized.
    pub fn is_synchronized(&self) -> bool {
        self.access_flags & 0x0020 != 0
    }

    /// Returns true if this method is a bridge method.
    pub fn is_bridge(&self) -> bool {
        self.access_flags & 0x0040 != 0
    }

    /// Returns true if this method has variable arguments.
    pub fn is_varargs(&self) -> bool {
        self.access_flags & 0x0080 != 0
    }

    /// Returns true if this method is native.
    pub fn is_native(&self) -> bool {
        self.access_flags & 0x0100 != 0
    }

    /// Returns true if this method is abstract.
    pub fn is_abstract(&self) -> bool {
        self.access_flags & 0x0400 != 0
    }

    /// Returns true if this method is synthetic.
    pub fn is_synthetic(&self) -> bool {
        self.access_flags & 0x1000 != 0
    }

    /// Returns true if this method is a constructor.
    pub fn is_constructor(&self) -> bool {
        self.access_flags & 0x10000 != 0
    }

    /// Returns true if this method is declared synchronized.
    pub fn is_declared_synchronized(&self) -> bool {
        self.access_flags & 0x20000 != 0
    }

    /// Returns a human-readable list of modifier names for this method.
    pub fn modifier_names(&self) -> Vec<&'static str> {
        let mut names = Vec::new();
        if self.is_public() { names.push("public"); }
        if self.is_private() { names.push("private"); }
        if self.is_protected() { names.push("protected"); }
        if self.is_static() { names.push("static"); }
        if self.is_final() { names.push("final"); }
        if self.is_synchronized() { names.push("synchronized"); }
        if self.is_bridge() { names.push("bridge"); }
        if self.is_varargs() { names.push("varargs"); }
        if self.is_native() { names.push("native"); }
        if self.is_abstract() { names.push("abstract"); }
        if self.is_synthetic() { names.push("synthetic"); }
        if self.is_constructor() { names.push("constructor"); }
        if self.is_declared_synchronized() { names.push("declared_synchronized"); }
        names
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════
// CodeItem
// ═══════════════════════════════════════════════════════════════════════════════════

/// Represents a `code_item` structure.
///
/// The `code_item` contains the bytecode for a single method, along
/// with register counts, try/catch handlers, and debug info offsets.
#[derive(Debug, Clone)]
pub struct CodeItem {
    /// Number of registers used by this method.
    pub registers_size: u16,
    /// Number of words of incoming arguments.
    pub ins_size: u16,
    /// Number of words of outgoing argument space.
    pub outs_size: u16,
    /// Number of `try_item` entries.
    pub tries_size: u16,
    /// File offset to the debug info, or 0.
    pub debug_info_offset: u32,
    /// Number of 16-bit code units.
    pub insns_size: u32,
    /// Raw bytecode (insns_size * 2 bytes).
    pub insns: Vec<u8>,
}

impl CodeItem {
    /// Minimum size of the `code_item` header (16 bytes).
    pub const HEADER_SIZE: usize = 16;

    /// Parse a `code_item` from raw bytes.
    pub fn parse(data: &[u8]) -> Result<Self, String> {
        if data.len() < Self::HEADER_SIZE {
            return Err("Data too short for CodeItem".to_string());
        }

        let registers_size = u16::from_le_bytes(data[0..2].try_into().unwrap());
        let ins_size = u16::from_le_bytes(data[2..4].try_into().unwrap());
        let outs_size = u16::from_le_bytes(data[4..6].try_into().unwrap());
        let tries_size = u16::from_le_bytes(data[6..8].try_into().unwrap());
        let debug_info_offset = u32::from_le_bytes(data[8..12].try_into().unwrap());
        let insns_size = u32::from_le_bytes(data[12..16].try_into().unwrap());

        let insns_byte_count = insns_size as usize * 2; // code units are 16-bit
        let insns_end = Self::HEADER_SIZE + insns_byte_count;
        if data.len() < insns_end {
            return Err("Data too short for CodeItem insns".to_string());
        }

        let insns = data[Self::HEADER_SIZE..insns_end].to_vec();

        Ok(CodeItem {
            registers_size,
            ins_size,
            outs_size,
            tries_size,
            debug_info_offset,
            insns_size,
            insns,
        })
    }

    /// Returns the number of local registers (registers - ins).
    pub fn locals_count(&self) -> u16 {
        self.registers_size.saturating_sub(self.ins_size)
    }

    /// Returns true if this method has try/catch blocks.
    pub fn has_tries(&self) -> bool {
        self.tries_size > 0
    }

    /// Returns true if debug info is present.
    pub fn has_debug_info(&self) -> bool {
        self.debug_info_offset != 0
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════
// ULEB128 reader with length tracking
// ═══════════════════════════════════════════════════════════════════════════════════

/// Read an unsigned LEB128 value from `data` starting at `pos`.
///
/// Returns `(value, new_position, byte_length)`.
fn read_uleb128_with_len(data: &[u8], mut pos: usize) -> Result<(u32, usize, u32), String> {
    let mut result: u32 = 0;
    let mut shift = 0;
    let start_pos = pos;

    loop {
        if pos >= data.len() {
            return Err("ULEB128: unexpected end of data".to_string());
        }
        let byte = data[pos];
        pos += 1;
        result |= ((byte & 0x7F) as u32) << shift;
        if byte & 0x80 == 0 {
            return Ok((result, pos, (pos - start_pos) as u32));
        }
        shift += 7;
        if shift >= 32 {
            return Err("ULEB128: too many bytes for u32".to_string());
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_method_id_item_parse() {
        let mut data = vec![0u8; MethodIDItem::SIZE];
        data[0..2].copy_from_slice(&3u16.to_le_bytes()); // class_index
        data[2..4].copy_from_slice(&7u16.to_le_bytes()); // proto_index
        data[4..8].copy_from_slice(&42u32.to_le_bytes()); // name_index

        let item = MethodIDItem::parse(&data).unwrap();
        assert_eq!(item.class_index, 3);
        assert_eq!(item.proto_index, 7);
        assert_eq!(item.name_index, 42);
    }

    #[test]
    fn test_method_id_item_parse_all() {
        // Build two method_id_items
        let mut data = vec![0u8; MethodIDItem::SIZE * 2];
        // First
        data[0..2].copy_from_slice(&0u16.to_le_bytes());
        data[2..4].copy_from_slice(&0u16.to_le_bytes());
        data[4..8].copy_from_slice(&0u32.to_le_bytes());
        // Second
        data[8..10].copy_from_slice(&1u16.to_le_bytes());
        data[10..12].copy_from_slice(&1u16.to_le_bytes());
        data[12..16].copy_from_slice(&5u32.to_le_bytes());

        let items = MethodIDItem::parse_all(&data, 0, 2).unwrap();
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].class_index, 0);
        assert_eq!(items[1].class_index, 1);
        assert_eq!(items[1].name_index, 5);
    }

    #[test]
    fn test_encoded_method_parse() {
        // Build an encoded method:
        //   method_idx_diff = 0 (1 byte ULEB128)
        //   access_flags = ACC_PUBLIC | ACC_STATIC = 0x09 (1 byte)
        //   code_offset = 0x200 (2 bytes ULEB128)
        let data = vec![0x00, 0x09, 0x80, 0x04];
        let method = EncodedMethod::parse_at(&data, 0x100).unwrap();
        assert_eq!(method.file_offset, 0x100);
        assert_eq!(method.method_index_diff, 0);
        assert_eq!(method.access_flags, 0x09);
        assert_eq!(method.code_offset, 0x200);
        assert!(method.has_code());
        assert!(method.is_public());
        assert!(method.is_static());
        assert!(!method.is_native());
    }

    #[test]
    fn test_encoded_method_parse_all() {
        // Two methods with delta encoding:
        //   Method 0: idx_diff=0, flags=0x01, code_off=0x100
        //   Method 1: idx_diff=2, flags=0x09, code_off=0x200
        let data = vec![
            0x00, 0x01, 0x80, 0x02, // method 0: diff=0, flags=1, code=0x100
            0x02, 0x09, 0x80, 0x04, // method 1: diff=2, flags=9, code=0x200
        ];
        let (methods, consumed) = EncodedMethod::parse_all(&data, 2).unwrap();
        assert_eq!(methods.len(), 2);
        assert_eq!(consumed, 8);
        assert_eq!(methods[0].method_index, 0);
        assert_eq!(methods[1].method_index, 2);
    }

    #[test]
    fn test_encoded_method_modifiers() {
        let method = EncodedMethod {
            file_offset: 0,
            method_index_diff: 0,
            method_index: 0,
            access_flags: 0x0001 | 0x0008 | 0x10000, // PUBLIC | STATIC | CONSTRUCTOR
            code_offset: 0,
            method_index_diff_length: 1,
            access_flags_length: 1,
            code_offset_length: 1,
        };
        let mods = method.modifier_names();
        assert!(mods.contains(&"public"));
        assert!(mods.contains(&"static"));
        assert!(mods.contains(&"constructor"));
        assert!(!mods.contains(&"native"));
    }

    #[test]
    fn test_code_item_parse() {
        let mut data = vec![0u8; CodeItem::HEADER_SIZE + 4];
        data[0..2].copy_from_slice(&4u16.to_le_bytes()); // registers_size
        data[2..4].copy_from_slice(&2u16.to_le_bytes()); // ins_size
        data[4..6].copy_from_slice(&1u16.to_le_bytes()); // outs_size
        data[6..8].copy_from_slice(&0u16.to_le_bytes()); // tries_size
        data[8..12].copy_from_slice(&0u32.to_le_bytes()); // debug_info_off
        data[12..16].copy_from_slice(&2u32.to_le_bytes()); // insns_size (2 code units)
        // 4 bytes of bytecode
        data[16] = 0x0E;
        data[17] = 0x00;
        data[18] = 0x0F;
        data[19] = 0x01;

        let code = CodeItem::parse(&data).unwrap();
        assert_eq!(code.registers_size, 4);
        assert_eq!(code.ins_size, 2);
        assert_eq!(code.locals_count(), 2);
        assert!(!code.has_tries());
        assert!(!code.has_debug_info());
        assert_eq!(code.insns.len(), 4);
    }

    #[test]
    fn test_method_id_truncated() {
        let data = vec![0u8; 4];
        assert!(MethodIDItem::parse(&data).is_err());
    }

    #[test]
    fn test_code_item_truncated() {
        let data = vec![0u8; 8];
        assert!(CodeItem::parse(&data).is_err());
    }
}
