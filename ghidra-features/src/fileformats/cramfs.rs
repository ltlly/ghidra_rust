//! CramFS (Compressed ROM File System) parser.
//!
//! Ported from Ghidra's `ghidra.file.formats.cramfs` package.
//!
//! References:
//! - Linux kernel Documentation/filesystems/cramfs.txt
//! - <https://en.wikipedia.org/wiki/Cramfs>

use nom::{
    bytes::complete::take,
    number::complete::{le_u16, le_u32},
    IResult,
};

// ═══════════════════════════════════════════════════════════════════════════════════
// Constants
// ═══════════════════════════════════════════════════════════════════════════════════

/// CramFS magic: `"Compressed ROMFS"`.
pub const CRAMFS_MAGIC: &[u8; 4] = b"\x45\x3D\xCD\x28";

/// CramFS magic as a u32 (little-endian).
pub const CRAMFS_MAGIC_U32: u32 = 0x28CD3D45;

/// CramFS signature string.
pub const CRAMFS_SIGNATURE: &[u8] = b"Compressed ROMFS";

/// Maximum path component length.
pub const CRAMFS_MAXPATHLEN: usize = 256;

/// CramFS inode file types (Unix mode_t encoding, top 4 bits of mode).
pub const CRAMFS_INODE_FMT_FIFO: u8 = 0o01;
pub const CRAMFS_INODE_FMT_CHRDEV: u8 = 0o02;
pub const CRAMFS_INODE_FMT_DIR: u8 = 0o04;
pub const CRAMFS_INODE_FMT_BLKDEV: u8 = 0o06;
pub const CRAMFS_INODE_FMT_REGULAR: u8 = 0o10;
pub const CRAMFS_INODE_FMT_SYMLINK: u8 = 0o12;
pub const CRAMFS_INODE_FMT_SOCKET: u8 = 0o14;
pub const CRAMFS_INODE_FMT_UNKNOWN: u8 = 0;

/// Flag: data in inode is zero-filled.
pub const CRAMFS_FLAG_SPARSE: u32 = 1;
/// Flag: data in inode is stored as block pointers.
pub const CRAMFS_FLAG_PTRLEN: u32 = 2;
/// Flag: symlink target path is stored directly.
pub const CRAMFS_FLAG_WRONGCRC: u32 = 4;
// Note: FLAG_FSID_VERSION_2 = 8 (v2 only)

// ═══════════════════════════════════════════════════════════════════════════════════
// CramFS Super Block
// ═══════════════════════════════════════════════════════════════════════════════════

/// CramFS super block (header).
#[derive(Debug, Clone)]
pub struct CramFsSuperBlock {
    /// Magic number.
    pub magic: u32,
    /// Size of the filesystem in bytes.
    pub size: u32,
    /// Flags.
    pub flags: u32,
    /// Future use.
    pub future: u32,
    /// Signature: `"Compressed ROMFS"`.
    pub signature: [u8; 16],
    /// CRC32 checksum of the filesystem.
    pub fsid_crc: u32,
    /// CRC32 of the super block.
    pub fsid_edition: u32,
    /// Number of root directory entries (v2).
    pub fsid_blocks: u32,
    /// Number of files (v2).
    pub fsid_files: u32,
    /// Name of the volume.
    pub name: [u8; 16],
}

impl CramFsSuperBlock {
    /// Super block size (64 bytes).
    pub const SIZE: usize = 64;

    /// Parse a CramFS super block from little-endian bytes.
    pub fn parse(data: &[u8]) -> IResult<&[u8], Self> {
        let (i, magic) = le_u32(data)?;
        let (i, size) = le_u32(i)?;
        let (i, flags) = le_u32(i)?;
        let (i, future) = le_u32(i)?;

        let (i, sig_bytes) = take(16usize)(i)?;
        let mut signature = [0u8; 16];
        signature.copy_from_slice(sig_bytes);

        let (i, fsid_crc) = le_u32(i)?;
        let (i, fsid_edition) = le_u32(i)?;
        let (i, fsid_blocks) = le_u32(i)?;
        let (i, fsid_files) = le_u32(i)?;

        let (i, name_bytes) = take(16usize)(i)?;
        let mut name = [0u8; 16];
        name.copy_from_slice(name_bytes);

        Ok((
            i,
            CramFsSuperBlock {
                magic,
                size,
                flags,
                future,
                signature,
                fsid_crc,
                fsid_edition,
                fsid_blocks,
                fsid_files,
                name,
            },
        ))
    }

    /// Whether the magic and signature are valid.
    pub fn is_valid(&self) -> bool {
        self.magic == CRAMFS_MAGIC_U32 && &self.signature[..16] == CRAMFS_SIGNATURE
    }

    /// Whether the filesystem is v2 (has FLAG_FSID_VERSION_2).
    pub fn is_v2(&self) -> bool {
        self.flags & 8 != 0
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════
// CramFS Inode
// ═══════════════════════════════════════════════════════════════════════════════════

/// CramFS inode header.
#[derive(Debug, Clone)]
pub struct CramFsInode {
    /// Inode mode (permissions + type).
    pub mode: u16,
    /// Owner UID.
    pub uid: u16,
    /// Size of the file data.
    pub size: u32,
    /// Owner group ID (lower 8 bits).
    pub gid: u8,
    /// Name length (5 bits) + offset (27 bits).
    pub name_len_offset: u32,
}

impl CramFsInode {
    /// Inode header size (12 bytes).
    pub const SIZE: usize = 12;

    /// Parse a CramFS inode from little-endian bytes.
    pub fn parse(data: &[u8]) -> IResult<&[u8], Self> {
        let (i, mode) = le_u16(data)?;
        let (i, uid) = le_u16(i)?;
        let (i, size_gid) = le_u32(i)?;
        let size = size_gid & 0x00FFFFFF;
        let gid = ((size_gid >> 24) & 0xFF) as u8;
        let (i, name_len_offset) = le_u32(i)?;

        Ok((
            i,
            CramFsInode {
                mode,
                uid,
                size,
                gid,
                name_len_offset,
            },
        ))
    }

    /// File type (top 4 bits of mode).
    pub fn file_type(&self) -> u8 {
        ((self.mode >> 12) & 0xF) as u8
    }

    /// Whether this is a directory.
    pub fn is_directory(&self) -> bool {
        self.file_type() == CRAMFS_INODE_FMT_DIR
    }

    /// Whether this is a regular file.
    pub fn is_regular(&self) -> bool {
        self.file_type() == CRAMFS_INODE_FMT_REGULAR
    }

    /// Whether this is a symlink.
    pub fn is_symlink(&self) -> bool {
        self.file_type() == CRAMFS_INODE_FMT_SYMLINK
    }

    /// Name length (5 bits).
    pub fn name_len(&self) -> u32 {
        (self.name_len_offset >> 26) & 0x3F
    }

    /// Offset (27 bits).
    pub fn offset(&self) -> u32 {
        self.name_len_offset & 0x07FFFFFF
    }

    /// Permission bits.
    pub fn permissions(&self) -> u16 {
        self.mode & 0xFFF
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_superblock_parse() {
        let mut data = vec![0u8; CramFsSuperBlock::SIZE];
        data[0..4].copy_from_slice(&CRAMFS_MAGIC_U32.to_le_bytes());
        data[4..8].copy_from_slice(&1024u32.to_le_bytes()); // size
        data[8..12].copy_from_slice(&0u32.to_le_bytes()); // flags
        data[12..16].copy_from_slice(&0u32.to_le_bytes()); // future
        data[16..32].copy_from_slice(CRAMFS_SIGNATURE);

        let (_, sb) = CramFsSuperBlock::parse(&data).unwrap();
        assert!(sb.is_valid());
        assert_eq!(sb.size, 1024);
    }

    #[test]
    fn test_inode_parse() {
        // mode=040755 (directory), uid=0, size_gid=0|gid=0, name_len_offset
        let mut data = vec![0u8; CramFsInode::SIZE];
        data[0..2].copy_from_slice(&0o040755u16.to_le_bytes());
        data[2..4].copy_from_slice(&0u16.to_le_bytes());
        // size=0, gid=0
        data[4..8].copy_from_slice(&0u32.to_le_bytes());
        // name_len=4 (4 << 26), offset=0
        data[8..12].copy_from_slice(&(4u32 << 26).to_le_bytes());

        let (_, inode) = CramFsInode::parse(&data).unwrap();
        assert!(inode.is_directory());
        assert!(!inode.is_regular());
        assert_eq!(inode.name_len(), 4);
        assert_eq!(inode.permissions(), 0o755);
    }

    #[test]
    fn test_inode_regular() {
        let mut data = vec![0u8; CramFsInode::SIZE];
        data[0..2].copy_from_slice(&0o100644u16.to_le_bytes());
        let (_, inode) = CramFsInode::parse(&data).unwrap();
        assert!(inode.is_regular());
        assert!(!inode.is_directory());
    }

    #[test]
    fn test_constants() {
        assert_eq!(CramFsSuperBlock::SIZE, 64);
        assert_eq!(CramFsInode::SIZE, 12);
    }
}
