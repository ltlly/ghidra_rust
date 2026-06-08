//! YAFFS2 (Yet Another Flash File System 2) parser.
//!
//! Ported from Ghidra's `ghidra.file.formats.yaffs2` package.
//!
//! References:
//! - <https://yaffs.net/documents/yaffs-direct-user-guide>


// ═══════════════════════════════════════════════════════════════════════════════════
// Constants
// ═══════════════════════════════════════════════════════════════════════════════════

/// YAFFS2 object header magic (SPARE area marker).
pub const YAFFS_OBJECT_HEADER_MAGIC: u32 = 0x00000000; // no fixed magic; identified by tags

/// YAFFS2 tags ECC size.
pub const YAFFS_TAGS_SIZE: usize = 20;

/// YAFFS2 object types.
pub const YAFFS_OBJECT_TYPE_UNKNOWN: u32 = 0;
pub const YAFFS_OBJECT_TYPE_FILE: u32 = 1;
pub const YAFFS_OBJECT_TYPE_SYMLINK: u32 = 2;
pub const YAFFS_OBJECT_TYPE_DIRECTORY: u32 = 3;
pub const YAFFS_OBJECT_TYPE_HARDLINK: u32 = 4;
pub const YAFFS_OBJECT_TYPE_SPECIAL: u32 = 5;

/// Maximum YAFFS object name length.
pub const YAFFS_MAX_NAME_LENGTH: usize = 256;

/// YAFFS2 header name offset within object header.
pub const YAFFS_HEADER_NAME_OFFSET: usize = 26;

// ═══════════════════════════════════════════════════════════════════════════════════
// YAFFS2 Tags (spare area)
// ═══════════════════════════════════════════════════════════════════════════════════

/// YAFFS2 tags from the spare area.
#[derive(Debug, Clone, Copy)]
pub struct YaffsTags {
    /// Chunk ID (within the object).
    pub chunk_id: u32,
    /// Object ID.
    pub object_id: u32,
    /// Number of bytes used in this chunk.
    pub n_bytes: u32,
    /// Sequence number (ordering).
    pub seq_number: u32,
    /// ECC for the data.
    pub ecc: u32,
    /// ECC for the tags.
    pub tags_ecc: u32,
    /// Is this chunk deleted?
    pub is_deleted: bool,
}

impl YaffsTags {
    /// Parse YAFFS2 tags from raw spare bytes.
    pub fn parse(data: &[u8]) -> Result<Self, String> {
        if data.len() < YAFFS_TAGS_SIZE {
            return Err("Not enough data for YAFFS2 tags".to_string());
        }

        // YAFFS2 tags are packed across 8 bytes with ECC interleaved
        let chunk_id = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) & 0x0FFFFFFF;
        let object_id = u32::from_le_bytes([data[4], data[5], data[6], data[7]]) & 0x0FFFFFFF;
        let n_bytes = u32::from_le_bytes([data[8], data[9], data[10], data[11]]) & 0x0000FFFF;
        let seq_number = u32::from_le_bytes([data[8], data[9], data[10], data[11]]) >> 16;
        let is_deleted = (data[8] & 0x80) != 0;

        Ok(YaffsTags {
            chunk_id,
            object_id,
            n_bytes,
            seq_number,
            ecc: 0,
            tags_ecc: 0,
            is_deleted,
        })
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════
// YAFFS2 Object Header
// ═══════════════════════════════════════════════════════════════════════════════════

/// Parsed YAFFS2 object header (from the first chunk of an object).
#[derive(Debug, Clone)]
pub struct YaffsObjectHeader {
    /// Object type.
    pub object_type: u32,
    /// Parent object ID.
    pub parent_id: u32,
    /// Object name.
    pub name: String,
    /// File mode (Unix permissions).
    pub mode: u32,
    /// User ID.
    pub uid: u32,
    /// Group ID.
    pub gid: u32,
    /// File size (for regular files).
    pub file_size: u64,
    /// Modification time.
    pub mtime: u64,
    /// Creation time.
    pub ctime: u64,
    /// Access time.
    pub atime: u64,
    /// Equivalent ID (for hard links).
    pub equiv_id: u32,
    /// Alias (for symlinks).
    pub alias: String,
}

impl YaffsObjectHeader {
    /// Whether this object is a directory.
    pub fn is_directory(&self) -> bool {
        self.object_type == YAFFS_OBJECT_TYPE_DIRECTORY
    }

    /// Whether this object is a regular file.
    pub fn is_file(&self) -> bool {
        self.object_type == YAFFS_OBJECT_TYPE_FILE
    }

    /// Whether this object is a symlink.
    pub fn is_symlink(&self) -> bool {
        self.object_type == YAFFS_OBJECT_TYPE_SYMLINK
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_object_types() {
        assert_eq!(YAFFS_OBJECT_TYPE_UNKNOWN, 0);
        assert_eq!(YAFFS_OBJECT_TYPE_FILE, 1);
        assert_eq!(YAFFS_OBJECT_TYPE_SYMLINK, 2);
        assert_eq!(YAFFS_OBJECT_TYPE_DIRECTORY, 3);
        assert_eq!(YAFFS_OBJECT_TYPE_HARDLINK, 4);
        assert_eq!(YAFFS_OBJECT_TYPE_SPECIAL, 5);
    }

    #[test]
    fn test_tags_parse() {
        let mut data = vec![0u8; YAFFS_TAGS_SIZE];
        // chunk_id = 1 (in low 28 bits)
        data[0..4].copy_from_slice(&1u32.to_le_bytes());
        // object_id = 5
        data[4..8].copy_from_slice(&5u32.to_le_bytes());
        // n_bytes = 100
        data[8..12].copy_from_slice(&100u32.to_le_bytes());

        let tags = YaffsTags::parse(&data).unwrap();
        assert_eq!(tags.chunk_id, 1);
        assert_eq!(tags.object_id, 5);
    }

    #[test]
    fn test_max_name_length() {
        assert_eq!(YAFFS_MAX_NAME_LENGTH, 256);
    }
}
