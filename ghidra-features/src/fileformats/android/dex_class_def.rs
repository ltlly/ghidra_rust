//! Android DEX class definition structures.
//!
//! Ported from Ghidra's `ghidra.file.formats.android.dex.format.ClassDefItem`
//! and `ClassDataItem` packages.
//!
//! Covers the `class_def_item` (32 bytes) and `class_data_item`
//! (variable-length, ULEB128-encoded) on-disk structures.

use crate::fileformats::android::dex_format::DexHeader;

// ═══════════════════════════════════════════════════════════════════════════════════
// ClassDefItem
// ═══════════════════════════════════════════════════════════════════════════════════

/// Represents a `class_def_item` structure (32 bytes).
///
/// Each class defined in a DEX file has one entry in the `class_defs` table.
/// The entry identifies the class, its superclass, interfaces, source file,
/// and points to annotations and class data.
#[derive(Debug, Clone)]
pub struct ClassDefItem {
    /// Index into `type_ids` for this class.
    pub class_index: u32,
    /// Access flags (ACC_PUBLIC, ACC_FINAL, etc.).
    pub access_flags: u32,
    /// Index into `type_ids` for the superclass, or `NO_INDEX` (0xFFFFFFFF).
    pub superclass_index: u32,
    /// Offset to the `type_list` for implemented interfaces, or 0.
    pub interfaces_offset: u32,
    /// Index into `string_ids` for the source file name, or `NO_INDEX`.
    pub source_file_index: u32,
    /// Offset to the `annotations_directory_item`, or 0.
    /// NOTE: For CDEX files, this value is relative to `data_off` in `DexHeader`.
    pub annotations_offset: u32,
    /// Offset to the `class_data_item`, or 0.
    pub class_data_offset: u32,
    /// Offset to the `encoded_array_item` for static field initializers, or 0.
    pub static_values_offset: u32,
}

/// Sentinel value for "no index".
pub const NO_INDEX: u32 = 0xFFFFFFFF;

impl ClassDefItem {
    /// Size of the on-disk structure (32 bytes).
    pub const SIZE: usize = 32;

    /// Parse a `class_def_item` from a byte slice.
    pub fn parse(data: &[u8]) -> Result<Self, String> {
        if data.len() < Self::SIZE {
            return Err("Data too short for ClassDefItem".to_string());
        }

        let class_index = u32::from_le_bytes(data[0..4].try_into().unwrap());
        let access_flags = u32::from_le_bytes(data[4..8].try_into().unwrap());
        let superclass_index = u32::from_le_bytes(data[8..12].try_into().unwrap());
        let interfaces_offset = u32::from_le_bytes(data[12..16].try_into().unwrap());
        let source_file_index = u32::from_le_bytes(data[16..20].try_into().unwrap());
        let annotations_offset = u32::from_le_bytes(data[20..24].try_into().unwrap());
        let class_data_offset = u32::from_le_bytes(data[24..28].try_into().unwrap());
        let static_values_offset = u32::from_le_bytes(data[28..32].try_into().unwrap());

        Ok(ClassDefItem {
            class_index,
            access_flags,
            superclass_index,
            interfaces_offset,
            source_file_index,
            annotations_offset,
            class_data_offset,
            static_values_offset,
        })
    }

    /// Returns true if the superclass index is set (not `NO_INDEX`).
    pub fn has_superclass(&self) -> bool {
        self.superclass_index != NO_INDEX
    }

    /// Returns true if this class has an interfaces list.
    pub fn has_interfaces(&self) -> bool {
        self.interfaces_offset != 0
    }

    /// Returns true if a source file name is specified.
    pub fn has_source_file(&self) -> bool {
        self.source_file_index != NO_INDEX
    }

    /// Returns true if annotations are present.
    pub fn has_annotations(&self) -> bool {
        self.annotations_offset != 0
    }

    /// Returns true if class data is present.
    pub fn has_class_data(&self) -> bool {
        self.class_data_offset != 0
    }

    /// Returns true if static value initializers are present.
    pub fn has_static_values(&self) -> bool {
        self.static_values_offset != 0
    }

    /// Returns true if this class is public.
    pub fn is_public(&self) -> bool {
        self.access_flags & 0x0001 != 0
    }

    /// Returns true if this class is final.
    pub fn is_final(&self) -> bool {
        self.access_flags & 0x0010 != 0
    }

    /// Returns true if this class is an interface.
    pub fn is_interface(&self) -> bool {
        self.access_flags & 0x0200 != 0
    }

    /// Returns true if this class is abstract.
    pub fn is_abstract(&self) -> bool {
        self.access_flags & 0x0400 != 0
    }

    /// Returns true if this class is synthetic.
    pub fn is_synthetic(&self) -> bool {
        self.access_flags & 0x1000 != 0
    }

    /// Returns true if this class is an annotation type.
    pub fn is_annotation(&self) -> bool {
        self.access_flags & 0x2000 != 0
    }

    /// Returns true if this class is an enum.
    pub fn is_enum(&self) -> bool {
        self.access_flags & 0x4000 != 0
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════
// ClassDataItem
// ═══════════════════════════════════════════════════════════════════════════════════

/// An encoded field within a `class_data_item`.
#[derive(Debug, Clone)]
pub struct EncodedClassField {
    /// Delta-encoded index into `field_ids`.
    pub field_idx_diff: u32,
    /// Access flags for this field.
    pub access_flags: u32,
}

/// An encoded method within a `class_data_item`.
#[derive(Debug, Clone)]
pub struct EncodedClassMethod {
    /// Delta-encoded index into `method_ids`.
    pub method_idx_diff: u32,
    /// Access flags for this method.
    pub access_flags: u32,
    /// Offset to the `code_item`, or 0 for native/abstract methods.
    pub code_offset: u32,
}

impl EncodedClassMethod {
    /// Returns true if this method has a code item.
    pub fn has_code(&self) -> bool {
        self.code_offset != 0
    }

    /// Returns true if this method is static.
    pub fn is_static(&self) -> bool {
        self.access_flags & 0x0008 != 0
    }

    /// Returns true if this method is a constructor (`<init>` or `<clinit>`).
    pub fn is_constructor(&self) -> bool {
        self.access_flags & 0x10000 != 0
    }
}

/// A parsed `class_data_item`.
///
/// The `class_data_item` is a variable-length, ULEB128-encoded structure
/// that lists the static fields, instance fields, direct methods, and
/// virtual methods belonging to a class.
#[derive(Debug, Clone)]
pub struct ClassDataItem {
    /// Static fields of this class.
    pub static_fields: Vec<EncodedClassField>,
    /// Instance fields of this class.
    pub instance_fields: Vec<EncodedClassField>,
    /// Direct methods (static, private, constructors).
    pub direct_methods: Vec<EncodedClassMethod>,
    /// Virtual methods (overridable).
    pub virtual_methods: Vec<EncodedClassMethod>,
}

impl ClassDataItem {
    /// Parse a `class_data_item` from raw bytes.
    pub fn parse(data: &[u8], offset: usize) -> Result<Self, String> {
        if offset >= data.len() {
            return Err("ClassDataItem offset out of range".to_string());
        }

        let input = &data[offset..];
        let mut pos = 0;

        // Read counts
        let (static_fields_size, new_pos) = read_uleb128(input, pos)?;
        pos = new_pos;
        let (instance_fields_size, new_pos) = read_uleb128(input, pos)?;
        pos = new_pos;
        let (direct_methods_size, new_pos) = read_uleb128(input, pos)?;
        pos = new_pos;
        let (virtual_methods_size, new_pos) = read_uleb128(input, pos)?;
        pos = new_pos;

        // Parse static fields
        let mut static_fields = Vec::with_capacity(static_fields_size as usize);
        for _ in 0..static_fields_size {
            let (field_idx_diff, new_pos) = read_uleb128(input, pos)?;
            pos = new_pos;
            let (access_flags, new_pos) = read_uleb128(input, pos)?;
            pos = new_pos;
            static_fields.push(EncodedClassField {
                field_idx_diff,
                access_flags,
            });
        }

        // Parse instance fields
        let mut instance_fields = Vec::with_capacity(instance_fields_size as usize);
        for _ in 0..instance_fields_size {
            let (field_idx_diff, new_pos) = read_uleb128(input, pos)?;
            pos = new_pos;
            let (access_flags, new_pos) = read_uleb128(input, pos)?;
            pos = new_pos;
            instance_fields.push(EncodedClassField {
                field_idx_diff,
                access_flags,
            });
        }

        // Parse direct methods
        let mut direct_methods = Vec::with_capacity(direct_methods_size as usize);
        for _ in 0..direct_methods_size {
            let (method_idx_diff, new_pos) = read_uleb128(input, pos)?;
            pos = new_pos;
            let (access_flags, new_pos) = read_uleb128(input, pos)?;
            pos = new_pos;
            let (code_offset, new_pos) = read_uleb128(input, pos)?;
            pos = new_pos;
            direct_methods.push(EncodedClassMethod {
                method_idx_diff,
                access_flags,
                code_offset,
            });
        }

        // Parse virtual methods
        let mut virtual_methods = Vec::with_capacity(virtual_methods_size as usize);
        for _ in 0..virtual_methods_size {
            let (method_idx_diff, new_pos) = read_uleb128(input, pos)?;
            pos = new_pos;
            let (access_flags, new_pos) = read_uleb128(input, pos)?;
            pos = new_pos;
            let (code_offset, new_pos) = read_uleb128(input, pos)?;
            pos = new_pos;
            virtual_methods.push(EncodedClassMethod {
                method_idx_diff,
                access_flags,
                code_offset,
            });
        }

        Ok(ClassDataItem {
            static_fields,
            instance_fields,
            direct_methods,
            virtual_methods,
        })
    }

    /// Total number of fields (static + instance).
    pub fn total_fields(&self) -> usize {
        self.static_fields.len() + self.instance_fields.len()
    }

    /// Total number of methods (direct + virtual).
    pub fn total_methods(&self) -> usize {
        self.direct_methods.len() + self.virtual_methods.len()
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════
// ULEB128 reader
// ═══════════════════════════════════════════════════════════════════════════════════

/// Read an unsigned LEB128 value from `data` starting at `pos`.
///
/// Returns `(value, new_position)` or an error if the encoding is
/// invalid or the data is exhausted.
fn read_uleb128(data: &[u8], mut pos: usize) -> Result<(u32, usize), String> {
    let mut result: u32 = 0;
    let mut shift = 0;

    loop {
        if pos >= data.len() {
            return Err("ULEB128: unexpected end of data".to_string());
        }
        let byte = data[pos];
        pos += 1;
        result |= ((byte & 0x7F) as u32) << shift;
        if byte & 0x80 == 0 {
            return Ok((result, pos));
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
    fn test_class_def_item_parse() {
        let mut data = vec![0u8; ClassDefItem::SIZE];
        data[0..4].copy_from_slice(&5u32.to_le_bytes()); // class_index
        data[4..8].copy_from_slice(&0x0001u32.to_le_bytes()); // access_flags = ACC_PUBLIC
        data[8..12].copy_from_slice(&NO_INDEX.to_le_bytes()); // superclass = NO_INDEX
        data[12..16].copy_from_slice(&0u32.to_le_bytes()); // interfaces_offset
        data[16..20].copy_from_slice(&NO_INDEX.to_le_bytes()); // source_file
        data[20..24].copy_from_slice(&0u32.to_le_bytes()); // annotations
        data[24..28].copy_from_slice(&0x8000u32.to_le_bytes()); // class_data_offset
        data[28..32].copy_from_slice(&0u32.to_le_bytes()); // static_values

        let item = ClassDefItem::parse(&data).unwrap();
        assert_eq!(item.class_index, 5);
        assert!(item.is_public());
        assert!(!item.has_superclass());
        assert!(item.has_class_data());
        assert!(!item.has_annotations());
    }

    #[test]
    fn test_class_def_access_flags() {
        let item = ClassDefItem {
            class_index: 0,
            access_flags: 0x0200 | 0x0400, // ACC_INTERFACE | ACC_ABSTRACT
            superclass_index: 0,
            interfaces_offset: 0,
            source_file_index: 0,
            annotations_offset: 0,
            class_data_offset: 0,
            static_values_offset: 0,
        };
        assert!(item.is_interface());
        assert!(item.is_abstract());
        assert!(!item.is_final());
        assert!(!item.is_enum());
    }

    #[test]
    fn test_class_data_item_parse() {
        // Build a minimal class_data_item with:
        //   1 static field, 0 instance fields, 1 direct method, 0 virtual methods
        let mut data = Vec::new();
        // static_fields_size = 1 (ULEB128)
        data.push(0x01);
        // instance_fields_size = 0
        data.push(0x00);
        // direct_methods_size = 1
        data.push(0x01);
        // virtual_methods_size = 0
        data.push(0x00);
        // static field: field_idx_diff=0, access_flags=ACC_PUBLIC (0x01)
        data.push(0x00); // field_idx_diff
        data.push(0x01); // access_flags
        // direct method: method_idx_diff=0, access_flags=ACC_PUBLIC, code_offset=0x100
        data.push(0x00); // method_idx_diff
        data.push(0x01); // access_flags
        data.push(0x80); // code_offset ULEB128: 0x100 = 128 + 0x80 ...
        data.push(0x02); // ... second byte of ULEB128 for 0x100

        let item = ClassDataItem::parse(&data, 0).unwrap();
        assert_eq!(item.static_fields.len(), 1);
        assert_eq!(item.instance_fields.len(), 0);
        assert_eq!(item.direct_methods.len(), 1);
        assert_eq!(item.virtual_methods.len(), 0);
        assert_eq!(item.total_fields(), 1);
        assert_eq!(item.total_methods(), 1);

        assert_eq!(item.static_fields[0].access_flags, 0x01);
        assert_eq!(item.direct_methods[0].code_offset, 0x100);
        assert!(item.direct_methods[0].has_code());
    }

    #[test]
    fn test_class_def_truncated() {
        let data = vec![0u8; 10];
        assert!(ClassDefItem::parse(&data).is_err());
    }

    #[test]
    fn test_read_uleb128() {
        // 0x00 -> 0
        assert_eq!(read_uleb128(&[0x00], 0).unwrap(), (0, 1));
        // 0x7F -> 127
        assert_eq!(read_uleb128(&[0x7F], 0).unwrap(), (127, 1));
        // 0x80 0x01 -> 128
        assert_eq!(read_uleb128(&[0x80, 0x01], 0).unwrap(), (128, 2));
        // 0xE5 0x8E 0x26 -> 624485
        assert_eq!(
            read_uleb128(&[0xE5, 0x8E, 0x26], 0).unwrap(),
            (624485, 3)
        );
    }

    #[test]
    fn test_read_uleb128_truncated() {
        assert!(read_uleb128(&[0x80], 0).is_err());
    }
}
