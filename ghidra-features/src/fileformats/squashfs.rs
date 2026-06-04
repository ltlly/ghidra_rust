//! SquashFS filesystem parser.
//!
//! Ported from Ghidra's `ghidra.file.formats.squashfs` package.
//!
//! References:
//! - SquashFS Documentation: <https://github.com/plougher/squashfs-tools>
//! - Linux kernel fs/squashfs/

use nom::{
    bytes::complete::take,
    number::complete::{le_u16, le_u32, le_u64, le_u8},
    IResult,
};
use std::fmt;

// ═══════════════════════════════════════════════════════════════════════════════════
// Constants
// ═══════════════════════════════════════════════════════════════════════════════════

/// SquashFS magic: `"sqsh"`.
pub const SQUASHFS_MAGIC: u32 = 0x73717368;

/// Inode types.
pub const SQUASHFS_INODE_TYPE_BASIC_DIR: u16 = 1;
pub const SQUASHFS_INODE_TYPE_BASIC_FILE: u16 = 2;
pub const SQUASHFS_INODE_TYPE_BASIC_SYMLINK: u16 = 3;
pub const SQUASHFS_INODE_TYPE_BASIC_BLKDEV: u16 = 4;
pub const SQUASHFS_INODE_TYPE_BASIC_CHRDEV: u16 = 5;
pub const SQUASHFS_INODE_TYPE_BASIC_FIFO: u16 = 6;
pub const SQUASHFS_INODE_TYPE_BASIC_SOCKET: u16 = 7;
pub const SQUASHFS_INODE_TYPE_EXT_DIR: u16 = 8;
pub const SQUASHFS_INODE_TYPE_EXT_FILE: u16 = 9;
pub const SQUASHFS_INODE_TYPE_EXT_SYMLINK: u16 = 10;
pub const SQUASHFS_INODE_TYPE_EXT_BLKDEV: u16 = 11;
pub const SQUASHFS_INODE_TYPE_EXT_CHRDEV: u16 = 12;
pub const SQUASHFS_INODE_TYPE_EXT_FIFO: u16 = 13;
pub const SQUASHFS_INODE_TYPE_EXT_SOCKET: u16 = 14;

/// No fragments marker.
pub const SQUASHFS_INODE_NO_FRAGMENTS: u32 = 0xFFFFFFFF;

/// Block size mask: if set, block is not compressed.
pub const SQUASHFS_DATABLOCK_COMPRESSED_MASK: u32 = 1 << 24;

// Superblock flags.
/// Inodes are uncompressed.
pub const SQUASHFS_FLAG_UNCOMPRESSED_INODES: u32 = 1 << 0;
/// Data blocks are uncompressed.
pub const SQUASHFS_FLAG_UNCOMPRESSED_DATA: u32 = 1 << 1;
/// Fragments are uncompressed.
pub const SQUASHFS_FLAG_UNCOMPRESSED_FRAGMENTS: u32 = 1 << 3;
/// No fragment blocks; files are padded to block size.
pub const SQUASHFS_FLAG_NO_FRAGMENTS: u32 = 1 << 4;
/// Always use fragments.
pub const SQUASHFS_FLAG_ALWAYS_FRAGMENTS: u32 = 1 << 5;
/// Deduplicate files.
pub const SQUASHFS_FLAG_DUPLICATES: u32 = 1 << 6;
/// Exportable filesystem (NFS).
pub const SQUASHFS_FLAG_EXPORTABLE: u32 = 1 << 7;
/// Xattrs are uncompressed.
pub const SQUASHFS_FLAG_UNCOMPRESSED_XATTRS: u32 = 1 << 8;
/// No xattrs.
pub const SQUASHFS_FLAG_NO_XATTRS: u32 = 1 << 9;
/// Compression options section present.
pub const SQUASHFS_FLAG_COMPRESSOR_OPTIONS: u32 = 1 << 10;

/// Compression types.
pub const SQUASHFS_COMP_ZLIB: u16 = 1;
pub const SQUASHFS_COMP_LZMA: u16 = 2;
pub const SQUASHFS_COMP_LZO: u16 = 3;
pub const SQUASHFS_COMP_XZ: u16 = 4;
pub const SQUASHFS_COMP_LZ4: u16 = 5;
pub const SQUASHFS_COMP_ZSTD: u16 = 6;

// ═══════════════════════════════════════════════════════════════════════════════════
// Super Block
// ═══════════════════════════════════════════════════════════════════════════════════

/// SquashFS super block (96 bytes).
#[derive(Debug, Clone)]
pub struct SquashSuperBlock {
    /// Magic: `0x73717368` ("sqsh").
    pub magic: u32,
    /// Number of inodes.
    pub inode_count: u32,
    /// Last modification time (Unix timestamp).
    pub mod_time: u32,
    /// Block size (always power of 2, typically 131072).
    pub block_size: u32,
    /// Number of fragments.
    pub total_fragments: u32,
    /// Compression type.
    pub compression_type: u16,
    /// Block log (log2 of block_size).
    pub block_log: u16,
    /// Flags.
    pub flags: u16,
    /// Number of inode ids.
    pub no_ids: u16,
    /// First inode number.
    pub first_inode: u16,
    /// Root inode reference (inode_number << 16 | block_offset).
    pub root_inode: u32,
    /// Total number of bytes used by inodes.
    pub bytes_used: u64,
    /// Start of the id table.
    pub id_table_start: u64,
    /// Start of the xattr id table.
    pub xattr_id_table_start: u64,
    /// Start of the inode table.
    pub inode_table_start: u64,
    /// Start of the directory table.
    pub directory_table_start: u64,
    /// Start of the fragment table.
    pub fragment_table_start: u64,
    /// Start of the lookup table.
    pub lookup_table_start: u64,
}

impl SquashSuperBlock {
    /// Parse a SquashFS super block from little-endian bytes.
    pub fn parse(data: &[u8]) -> IResult<&[u8], Self> {
        let (i, magic) = le_u32(data)?;
        let (i, inode_count) = le_u32(i)?;
        let (i, mod_time) = le_u32(i)?;
        let (i, block_size) = le_u32(i)?;
        let (i, total_fragments) = le_u32(i)?;
        let (i, compression_type) = le_u16(i)?;
        let (i, block_log) = le_u16(i)?;
        let (i, flags) = le_u16(i)?;
        let (i, no_ids) = le_u16(i)?;
        let (i, first_inode) = le_u16(i)?;
        let (i, root_inode) = le_u32(i)?;
        let (i, bytes_used) = le_u64(i)?;
        let (i, id_table_start) = le_u64(i)?;
        let (i, xattr_id_table_start) = le_u64(i)?;
        let (i, inode_table_start) = le_u64(i)?;
        let (i, directory_table_start) = le_u64(i)?;
        let (i, fragment_table_start) = le_u64(i)?;
        let (i, lookup_table_start) = le_u64(i)?;

        Ok((
            i,
            SquashSuperBlock {
                magic,
                inode_count,
                mod_time,
                block_size,
                total_fragments,
                compression_type,
                block_log,
                flags,
                no_ids,
                first_inode,
                root_inode,
                bytes_used,
                id_table_start,
                xattr_id_table_start,
                inode_table_start,
                directory_table_start,
                fragment_table_start,
                lookup_table_start,
            },
        ))
    }

    /// Whether the magic is valid.
    pub fn is_valid(&self) -> bool {
        self.magic == SQUASHFS_MAGIC
    }

    /// Whether inodes are stored uncompressed.
    pub fn uncompressed_inodes(&self) -> bool {
        self.flags & SQUASHFS_FLAG_UNCOMPRESSED_INODES as u16 != 0
    }

    /// Whether data blocks are stored uncompressed.
    pub fn uncompressed_data(&self) -> bool {
        self.flags & SQUASHFS_FLAG_UNCOMPRESSED_DATA as u16 != 0
    }

    /// Whether fragments are not used.
    pub fn no_fragments(&self) -> bool {
        self.flags & SQUASHFS_FLAG_NO_FRAGMENTS as u16 != 0
    }

    /// Whether the filesystem is exportable (NFS).
    pub fn exportable(&self) -> bool {
        self.flags & SQUASHFS_FLAG_EXPORTABLE as u16 != 0
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════
// Common Inode Header
// ═══════════════════════════════════════════════════════════════════════════════════

/// Common inode header (16 bytes) shared by all inode types.
#[derive(Debug, Clone, Copy)]
pub struct SquashInodeHeader {
    /// Inode type.
    pub inode_type: u16,
    /// File permissions.
    pub permissions: u16,
    /// Owner user ID (index into id table).
    pub user_id: u16,
    /// Owner group ID (index into id table).
    pub group_id: u16,
    /// Last modification time (seconds since epoch).
    pub mtime: u32,
    /// Inode number.
    pub inode_number: u32,
}

impl SquashInodeHeader {
    pub fn parse(data: &[u8]) -> IResult<&[u8], Self> {
        let (i, inode_type) = le_u16(data)?;
        let (i, permissions) = le_u16(i)?;
        let (i, user_id) = le_u16(i)?;
        let (i, group_id) = le_u16(i)?;
        let (i, mtime) = le_u32(i)?;
        let (i, inode_number) = le_u32(i)?;

        Ok((
            i,
            SquashInodeHeader {
                inode_type,
                permissions,
                user_id,
                group_id,
                mtime,
                inode_number,
            },
        ))
    }

    /// Whether this inode is a directory type.
    pub fn is_dir(&self) -> bool {
        self.inode_type == SQUASHFS_INODE_TYPE_BASIC_DIR
            || self.inode_type == SQUASHFS_INODE_TYPE_EXT_DIR
    }

    /// Whether this inode is a file type.
    pub fn is_file(&self) -> bool {
        self.inode_type == SQUASHFS_INODE_TYPE_BASIC_FILE
            || self.inode_type == SQUASHFS_INODE_TYPE_EXT_FILE
    }

    /// Whether this inode is a symlink type.
    pub fn is_symlink(&self) -> bool {
        self.inode_type == SQUASHFS_INODE_TYPE_BASIC_SYMLINK
            || self.inode_type == SQUASHFS_INODE_TYPE_EXT_SYMLINK
    }
}

/// Basic directory inode (additional fields after common header).
#[derive(Debug, Clone, Copy)]
pub struct SquashBasicDirInode {
    /// Block number of the start of the directory table.
    pub start_block: u32,
    /// Number of hard links.
    pub nlink: u32,
    /// Size of directory data including headers.
    pub file_size: u16,
    /// Block offset within the start block.
    pub offset: u16,
    /// Parent inode number.
    pub parent_inode: u32,
}

impl SquashBasicDirInode {
    pub fn parse(data: &[u8]) -> IResult<&[u8], Self> {
        let (i, start_block) = le_u32(data)?;
        let (i, nlink) = le_u32(i)?;
        let (i, file_size) = le_u16(i)?;
        let (i, offset) = le_u16(i)?;
        let (i, parent_inode) = le_u32(i)?;

        Ok((
            i,
            SquashBasicDirInode {
                start_block,
                nlink,
                file_size,
                offset,
                parent_inode,
            },
        ))
    }
}

/// Basic file inode (additional fields after common header).
#[derive(Debug, Clone, Copy)]
pub struct SquashBasicFileInode {
    /// Block number of the start of the data blocks.
    pub blocks_start: u32,
    /// Fragment block index.
    pub fragment: u32,
    /// Offset within the fragment block.
    pub offset: u32,
    /// File size.
    pub file_size: u32,
    /// Block sizes array (offsets into data blocks).
    pub block_list: Vec<u32>,
}

/// A parsed directory entry within a SquashFS directory.
#[derive(Debug, Clone)]
pub struct SquashDirEntry {
    /// Offset into the inode table.
    pub inode_number: u16,
    /// Offset of this entry within the directory data.
    pub offset: i16,
    /// Type of the inode (same as inode_type).
    pub inode_type: u16,
    /// Size of the name (one less than actual size).
    pub name_size: u16,
    /// File name.
    pub name: String,
}

impl SquashDirEntry {
    pub fn parse(data: &[u8]) -> IResult<&[u8], Self> {
        let (i, inode_number) = le_u16(data)?;
        let (i, offset) = le_u16(i)?; // Note: this is actually i16
        let offset = offset as i16;
        let (i, inode_type) = le_u16(i)?;
        let (i, name_size) = le_u16(i)?;
        let (i, name_bytes) = take((name_size + 1) as usize)(i)?;
        let name = String::from_utf8_lossy(name_bytes).to_string();

        Ok((
            i,
            SquashDirEntry {
                inode_number,
                offset,
                inode_type,
                name_size,
                name,
            },
        ))
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_magic() {
        assert_eq!(SQUASHFS_MAGIC, 0x73717368);
    }

    #[test]
    fn test_compression_types() {
        assert_eq!(SQUASHFS_COMP_ZLIB, 1);
        assert_eq!(SQUASHFS_COMP_LZMA, 2);
        assert_eq!(SQUASHFS_COMP_LZO, 3);
        assert_eq!(SQUASHFS_COMP_XZ, 4);
        assert_eq!(SQUASHFS_COMP_LZ4, 5);
        assert_eq!(SQUASHFS_COMP_ZSTD, 6);
    }

    #[test]
    fn test_inode_header_parse() {
        let mut data = vec![0u8; 16];
        data[0..2].copy_from_slice(&SQUASHFS_INODE_TYPE_BASIC_DIR.to_le_bytes());
        data[2..4].copy_from_slice(&0o0755u16.to_le_bytes()); // permissions
        data[4..6].copy_from_slice(&0u16.to_le_bytes()); // uid
        data[6..8].copy_from_slice(&0u16.to_le_bytes()); // gid
        data[8..12].copy_from_slice(&1234567890u32.to_le_bytes()); // mtime
        data[12..16].copy_from_slice(&1u32.to_le_bytes()); // inode_number

        let (_, hdr) = SquashInodeHeader::parse(&data).unwrap();
        assert!(hdr.is_dir());
        assert!(!hdr.is_file());
        assert!(!hdr.is_symlink());
        assert_eq!(hdr.permissions, 0o755);
        assert_eq!(hdr.inode_number, 1);
    }

    #[test]
    fn test_inode_types() {
        assert_eq!(SQUASHFS_INODE_TYPE_BASIC_DIR, 1);
        assert_eq!(SQUASHFS_INODE_TYPE_BASIC_FILE, 2);
        assert_eq!(SQUASHFS_INODE_TYPE_BASIC_SYMLINK, 3);
        assert_eq!(SQUASHFS_INODE_TYPE_EXT_DIR, 8);
        assert_eq!(SQUASHFS_INODE_TYPE_EXT_FILE, 9);
    }

    #[test]
    fn test_flags() {
        assert_eq!(SQUASHFS_FLAG_UNCOMPRESSED_INODES, 1);
        assert_eq!(SQUASHFS_FLAG_UNCOMPRESSED_DATA, 2);
        assert_eq!(SQUASHFS_DATABLOCK_COMPRESSED_MASK, 1 << 24);
    }

    #[test]
    fn test_basic_dir_inode_parse() {
        let mut data = vec![0u8; 16];
        data[0..4].copy_from_slice(&64u32.to_le_bytes()); // start_block
        data[4..8].copy_from_slice(&1u32.to_le_bytes()); // nlink
        data[8..10].copy_from_slice(&48u16.to_le_bytes()); // file_size
        data[10..12].copy_from_slice(&0u16.to_le_bytes()); // offset
        data[12..16].copy_from_slice(&2u32.to_le_bytes()); // parent_inode

        let (_, dir) = SquashBasicDirInode::parse(&data).unwrap();
        assert_eq!(dir.start_block, 64);
        assert_eq!(dir.nlink, 1);
        assert_eq!(dir.file_size, 48);
        assert_eq!(dir.parent_inode, 2);
    }
}
