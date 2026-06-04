//! Ext4 (Fourth Extended File System) parser.
//!
//! Ported from Ghidra's `ghidra.file.formats.ext4` package.
//!
//! References:
//! - Linux kernel fs/ext4/ext4.h
//! - <https://ext4.wiki.kernel.org/index.php/Ext4_Disk_Layout>

use nom::{bytes::complete::take, number::complete::{le_u16, le_u32, le_u64, le_u8}, IResult};
use std::fmt;

// ═══════════════════════════════════════════════════════════════════════════════════
// Constants
// ═══════════════════════════════════════════════════════════════════════════════════

/// Ext4 superblock magic: `0xEF53`.
pub const EXT4_SUPER_MAGIC: u16 = 0xEF53;

/// Superblock offset within the partition.
pub const EXT4_SUPER_OFFSET: usize = 1024;

/// Superblock size.
pub const EXT4_SUPER_SIZE: usize = 1024; // not the full block, just the fields

/// Extent header magic: `0xF30A`.
pub const EXT4_EXTENT_HEADER_MAGIC: u16 = 0xF30A;

/// Extended attributes magic: `0xEA020000`.
pub const EXT4_XATTR_MAGIC: u32 = 0xEA020000;

// Directory file types.
pub const EXT4_FT_UNKNOWN: u8 = 0;
pub const EXT4_FT_REG_FILE: u8 = 1;
pub const EXT4_FT_DIR: u8 = 2;
pub const EXT4_FT_CHRDEV: u8 = 3;
pub const EXT4_FT_BLKDEV: u8 = 4;
pub const EXT4_FT_FIFO: u8 = 5;
pub const EXT4_FT_SOCK: u8 = 6;
pub const EXT4_FT_SYMLINK: u8 = 7;

// Special inode numbers.
pub const EXT4_ROOT_INO: u32 = 2;
pub const EXT4_JOURNAL_INO: u32 = 8;
pub const EXT4_BAD_INO: u32 = 1;
pub const EXT4_UNDEL_DIR_INO: u32 = 6;
pub const EXT4_BOOT_LOADER_INO: u32 = 5;
pub const EXT4_RESIZE_INO: u32 = 7;

// Feature flags (feature_compat).
pub const EXT4_FEATURE_COMPAT_DIR_PREALLOC: u32 = 0x0001;
pub const EXT4_FEATURE_COMPAT_IMAGIC_INODES: u32 = 0x0002;
pub const EXT4_FEATURE_COMPAT_HAS_JOURNAL: u32 = 0x0004;
pub const EXT4_FEATURE_COMPAT_EXT_ATTR: u32 = 0x0008;
pub const EXT4_FEATURE_COMPAT_RESIZE_INODE: u32 = 0x0010;
pub const EXT4_FEATURE_COMPAT_DIR_INDEX: u32 = 0x0020;

// Feature flags (feature_incompat).
pub const EXT4_FEATURE_INCOMPAT_COMPRESSION: u32 = 0x0001;
pub const EXT4_FEATURE_INCOMPAT_FILETYPE: u32 = 0x0002;
pub const EXT4_FEATURE_INCOMPAT_RECOVER: u32 = 0x0004;
pub const EXT4_FEATURE_INCOMPAT_JOURNAL_DEV: u32 = 0x0008;
pub const EXT4_FEATURE_INCOMPAT_META_BG: u32 = 0x0010;
pub const EXT4_FEATURE_INCOMPAT_EXTENTS: u32 = 0x0040;
pub const EXT4_FEATURE_INCOMPAT_64BIT: u32 = 0x0080;
pub const EXT4_FEATURE_INCOMPAT_MMP: u32 = 0x0100;
pub const EXT4_FEATURE_INCOMPAT_FLEX_BG: u32 = 0x0200;
pub const EXT4_FEATURE_INCOMPAT_INLINE_DATA: u32 = 0x8000;

// Feature flags (feature_ro_compat).
pub const EXT4_FEATURE_RO_COMPAT_SPARSE_SUPER: u32 = 0x0001;
pub const EXT4_FEATURE_RO_COMPAT_LARGE_FILE: u32 = 0x0002;
pub const EXT4_FEATURE_RO_COMPAT_BTREE_DIR: u32 = 0x0004;
pub const EXT4_FEATURE_RO_COMPAT_HUGE_FILE: u32 = 0x0008;
pub const EXT4_FEATURE_RO_COMPAT_GDT_CSUM: u32 = 0x0010;
pub const EXT4_FEATURE_RO_COMPAT_DIR_NLINK: u32 = 0x0020;
pub const EXT4_FEATURE_RO_COMPAT_EXTRA_ISIZE: u32 = 0x0040;
pub const EXT4_FEATURE_RO_COMPAT_QUOTA: u32 = 0x0100;
pub const EXT4_FEATURE_RO_COMPAT_BIGALLOC: u32 = 0x0200;
pub const EXT4_FEATURE_RO_COMPAT_METADATA_CSUM: u32 = 0x0400;

// ═══════════════════════════════════════════════════════════════════════════════════
// Ext4 Superblock
// ═══════════════════════════════════════════════════════════════════════════════════

/// Ext4 superblock structure.
#[derive(Debug, Clone)]
pub struct Ext4SuperBlock {
    pub s_inodes_count: u32,
    pub s_blocks_count_lo: u32,
    pub s_r_blocks_count_lo: u32,
    pub s_free_blocks_count_lo: u32,
    pub s_free_inodes_count: u32,
    pub s_first_data_block: u32,
    pub s_log_block_size: u32,
    pub s_log_cluster_size: u32,
    pub s_blocks_per_group: u32,
    pub s_clusters_per_group: u32,
    pub s_inodes_per_group: u32,
    pub s_mtime: u32,
    pub s_wtime: u32,
    pub s_mnt_count: u16,
    pub s_max_mnt_count: u16,
    pub s_magic: u16,
    pub s_state: u16,
    pub s_errors: u16,
    pub s_minor_rev_level: u16,
    pub s_lastcheck: u32,
    pub s_checkinterval: u32,
    pub s_creator_os: u32,
    pub s_rev_level: u32,
    pub s_def_resuid: u16,
    pub s_def_resgid: u16,
    // Extended fields (s_rev_level >= 1)
    pub s_first_ino: u32,
    pub s_inode_size: u16,
    pub s_block_group_nr: u16,
    pub s_feature_compat: u32,
    pub s_feature_incompat: u32,
    pub s_feature_ro_compat: u32,
    pub s_uuid: [u8; 16],
    pub s_volume_name: [u8; 16],
    pub s_last_mounted: [u8; 64],
    pub s_algorithm_usage_bitmap: u32,
    // Performance hints
    pub s_prealloc_blocks: u8,
    pub s_prealloc_dir_blocks: u8,
    pub s_reserved_gdt_blocks: u16,
    // Journaling support
    pub s_journal_uuid: [u8; 16],
    pub s_journal_inum: u32,
    pub s_journal_dev: u32,
    pub s_last_orphan: u32,
    pub s_hash_seed: [u32; 4],
    pub s_def_hash_version: u8,
    pub s_jnl_backup_type: u8,
    pub s_desc_size: u16,
    pub s_default_mount_opts: u32,
    pub s_first_meta_bg: u32,
    pub s_mkfs_time: u32,
    // 64-bit support
    pub s_blocks_count_hi: u32,
    pub s_r_blocks_count_hi: u32,
    pub s_free_blocks_count_hi: u32,
    pub s_min_extra_isize: u16,
    pub s_want_extra_isize: u16,
    pub s_flags: u32,
    pub s_raid_stride: u16,
    pub s_mmp_interval: u16,
    pub s_mmp_block: u64,
    pub s_raid_stripe_width: u32,
    pub s_log_groups_per_flex: u8,
    pub s_checksum_type: u8,
    pub s_reserved_pad: u16,
    pub s_kbytes_written: u64,
    pub s_checksum: u32,
}

impl Ext4SuperBlock {
    /// Parse the superblock from little-endian bytes.
    pub fn parse(data: &[u8]) -> IResult<&[u8], Self> {
        let i = data;
        let (i, s_inodes_count) = le_u32(i)?;
        let (i, s_blocks_count_lo) = le_u32(i)?;
        let (i, s_r_blocks_count_lo) = le_u32(i)?;
        let (i, s_free_blocks_count_lo) = le_u32(i)?;
        let (i, s_free_inodes_count) = le_u32(i)?;
        let (i, s_first_data_block) = le_u32(i)?;
        let (i, s_log_block_size) = le_u32(i)?;
        let (i, s_log_cluster_size) = le_u32(i)?;
        let (i, s_blocks_per_group) = le_u32(i)?;
        let (i, s_clusters_per_group) = le_u32(i)?;
        let (i, s_inodes_per_group) = le_u32(i)?;
        let (i, s_mtime) = le_u32(i)?;
        let (i, s_wtime) = le_u32(i)?;
        let (i, s_mnt_count) = le_u16(i)?;
        let (i, s_max_mnt_count) = le_u16(i)?;
        let (i, s_magic) = le_u16(i)?;
        let (i, s_state) = le_u16(i)?;
        let (i, s_errors) = le_u16(i)?;
        let (i, s_minor_rev_level) = le_u16(i)?;
        let (i, s_lastcheck) = le_u32(i)?;
        let (i, s_checkinterval) = le_u32(i)?;
        let (i, s_creator_os) = le_u32(i)?;
        let (i, s_rev_level) = le_u32(i)?;
        let (i, s_def_resuid) = le_u16(i)?;
        let (i, s_def_resgid) = le_u16(i)?;

        // Extended fields
        let (i, s_first_ino) = le_u32(i)?;
        let (i, s_inode_size) = le_u16(i)?;
        let (i, s_block_group_nr) = le_u16(i)?;
        let (i, s_feature_compat) = le_u32(i)?;
        let (i, s_feature_incompat) = le_u32(i)?;
        let (i, s_feature_ro_compat) = le_u32(i)?;

        let (i, uuid_bytes) = take(16usize)(i)?;
        let mut s_uuid = [0u8; 16];
        s_uuid.copy_from_slice(uuid_bytes);

        let (i, vol_bytes) = take(16usize)(i)?;
        let mut s_volume_name = [0u8; 16];
        s_volume_name.copy_from_slice(vol_bytes);

        let (i, mount_bytes) = take(64usize)(i)?;
        let mut s_last_mounted = [0u8; 64];
        s_last_mounted.copy_from_slice(mount_bytes);

        let (i, s_algorithm_usage_bitmap) = le_u32(i)?;

        // Performance hints
        let (i, s_prealloc_blocks) = le_u8(i)?;
        let (i, s_prealloc_dir_blocks) = le_u8(i)?;
        let (i, s_reserved_gdt_blocks) = le_u16(i)?;

        // Journaling
        let (i, journal_bytes) = take(16usize)(i)?;
        let mut s_journal_uuid = [0u8; 16];
        s_journal_uuid.copy_from_slice(journal_bytes);

        let (i, s_journal_inum) = le_u32(i)?;
        let (i, s_journal_dev) = le_u32(i)?;
        let (i, s_last_orphan) = le_u32(i)?;

        let (i, h0) = le_u32(i)?;
        let (i, h1) = le_u32(i)?;
        let (i, h2) = le_u32(i)?;
        let (i, h3) = le_u32(i)?;
        let s_hash_seed = [h0, h1, h2, h3];

        let (i, s_def_hash_version) = le_u8(i)?;
        let (i, s_jnl_backup_type) = le_u8(i)?;
        let (i, s_desc_size) = le_u16(i)?;
        let (i, s_default_mount_opts) = le_u32(i)?;
        let (i, s_first_meta_bg) = le_u32(i)?;
        let (i, s_mkfs_time) = le_u32(i)?;

        // Skip jnl_blocks (17 ints = 68 bytes)
        let (i, _) = take(68usize)(i)?;

        // 64-bit support
        let (i, s_blocks_count_hi) = le_u32(i)?;
        let (i, s_r_blocks_count_hi) = le_u32(i)?;
        let (i, s_free_blocks_count_hi) = le_u32(i)?;
        let (i, s_min_extra_isize) = le_u16(i)?;
        let (i, s_want_extra_isize) = le_u16(i)?;
        let (i, s_flags) = le_u32(i)?;
        let (i, s_raid_stride) = le_u16(i)?;
        let (i, s_mmp_interval) = le_u16(i)?;
        let (i, s_mmp_block) = le_u64(i)?;
        let (i, s_raid_stripe_width) = le_u32(i)?;
        let (i, s_log_groups_per_flex) = le_u8(i)?;
        let (i, s_checksum_type) = le_u8(i)?;
        let (i, s_reserved_pad) = le_u16(i)?;
        let (i, s_kbytes_written) = le_u64(i)?;

        // Skip snapshot fields (20 bytes) + error fields (32 bytes) + first_error_time etc.
        let (i, _) = take(52usize)(i)?;

        let (i, s_checksum) = le_u32(i)?;

        Ok((
            i,
            Ext4SuperBlock {
                s_inodes_count,
                s_blocks_count_lo,
                s_r_blocks_count_lo,
                s_free_blocks_count_lo,
                s_free_inodes_count,
                s_first_data_block,
                s_log_block_size,
                s_log_cluster_size,
                s_blocks_per_group,
                s_clusters_per_group,
                s_inodes_per_group,
                s_mtime,
                s_wtime,
                s_mnt_count,
                s_max_mnt_count,
                s_magic,
                s_state,
                s_errors,
                s_minor_rev_level,
                s_lastcheck,
                s_checkinterval,
                s_creator_os,
                s_rev_level,
                s_def_resuid,
                s_def_resgid,
                s_first_ino,
                s_inode_size,
                s_block_group_nr,
                s_feature_compat,
                s_feature_incompat,
                s_feature_ro_compat,
                s_uuid,
                s_volume_name,
                s_last_mounted,
                s_algorithm_usage_bitmap,
                s_prealloc_blocks,
                s_prealloc_dir_blocks,
                s_reserved_gdt_blocks,
                s_journal_uuid,
                s_journal_inum,
                s_journal_dev,
                s_last_orphan,
                s_hash_seed,
                s_def_hash_version,
                s_jnl_backup_type,
                s_desc_size,
                s_default_mount_opts,
                s_first_meta_bg,
                s_mkfs_time,
                s_blocks_count_hi,
                s_r_blocks_count_hi,
                s_free_blocks_count_hi,
                s_min_extra_isize,
                s_want_extra_isize,
                s_flags,
                s_raid_stride,
                s_mmp_interval,
                s_mmp_block,
                s_raid_stripe_width,
                s_log_groups_per_flex,
                s_checksum_type,
                s_reserved_pad,
                s_kbytes_written,
                s_checksum,
            },
        ))
    }

    /// Whether the magic is valid (0xEF53).
    pub fn is_valid(&self) -> bool {
        self.magic() == EXT4_SUPER_MAGIC
    }

    /// Convenience: magic field.
    pub fn magic(&self) -> u16 {
        self.s_magic
    }

    /// Block size in bytes: 1024 << s_log_block_size.
    pub fn block_size(&self) -> u32 {
        1024u32 << self.s_log_block_size
    }

    /// Volume name as a string (trimmed).
    pub fn volume_name_str(&self) -> String {
        let end = self.s_volume_name.iter().position(|&b| b == 0).unwrap_or(16);
        String::from_utf8_lossy(&self.s_volume_name[..end]).to_string()
    }

    /// UUID as a hex string.
    pub fn uuid_str(&self) -> String {
        format!(
            "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            self.s_uuid[0], self.s_uuid[1], self.s_uuid[2], self.s_uuid[3],
            self.s_uuid[4], self.s_uuid[5],
            self.s_uuid[6], self.s_uuid[7],
            self.s_uuid[8], self.s_uuid[9],
            self.s_uuid[10], self.s_uuid[11], self.s_uuid[12], self.s_uuid[13], self.s_uuid[14], self.s_uuid[15]
        )
    }

    /// Total blocks count (64-bit).
    pub fn blocks_count(&self) -> u64 {
        ((self.s_blocks_count_hi as u64) << 32) | (self.s_blocks_count_lo as u64)
    }

    /// Whether EXTENTS feature is enabled.
    pub fn has_extents(&self) -> bool {
        self.s_feature_incompat & EXT4_FEATURE_INCOMPAT_EXTENTS != 0
    }

    /// Whether 64-bit feature is enabled.
    pub fn has_64bit(&self) -> bool {
        self.s_feature_incompat & EXT4_FEATURE_INCOMPAT_64BIT != 0
    }

    /// Whether inline data feature is enabled.
    pub fn has_inline_data(&self) -> bool {
        self.s_feature_incompat & EXT4_FEATURE_INCOMPAT_INLINE_DATA != 0
    }

    /// Whether a journal is present.
    pub fn has_journal(&self) -> bool {
        self.s_feature_compat & EXT4_FEATURE_COMPAT_HAS_JOURNAL != 0
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════
// Ext4 Inode
// ═══════════════════════════════════════════════════════════════════════════════════

/// Ext4 inode structure (128 bytes base).
#[derive(Debug, Clone)]
pub struct Ext4Inode {
    pub i_mode: u16,
    pub i_uid: u16,
    pub i_size_lo: u32,
    pub i_atime: u32,
    pub i_ctime: u32,
    pub i_mtime: u32,
    pub i_dtime: u32,
    pub i_gid: u16,
    pub i_links_count: u16,
    pub i_blocks_lo: u32,
    pub i_flags: u32,
    pub i_osd1: u32,
    pub i_block: [u8; 60],
    pub i_generation: u32,
    pub i_file_acl_lo: u32,
    pub i_size_high: u32,
    pub i_obso_faddr: u32,
    pub i_osd2: [u8; 12],
    // Extended fields
    pub i_extra_isize: u16,
    pub i_checksum_hi: u16,
    pub i_ctime_extra: u32,
    pub i_mtime_extra: u32,
    pub i_atime_extra: u32,
    pub i_crtime: u32,
    pub i_crtime_extra: u32,
    pub i_version_hi: u32,
    pub i_projid: u32,
}

impl Ext4Inode {
    /// Parse an Ext4 inode from little-endian bytes.
    pub fn parse(data: &[u8]) -> IResult<&[u8], Self> {
        let i = data;
        let (i, i_mode) = le_u16(i)?;
        let (i, i_uid) = le_u16(i)?;
        let (i, i_size_lo) = le_u32(i)?;
        let (i, i_atime) = le_u32(i)?;
        let (i, i_ctime) = le_u32(i)?;
        let (i, i_mtime) = le_u32(i)?;
        let (i, i_dtime) = le_u32(i)?;
        let (i, i_gid) = le_u16(i)?;
        let (i, i_links_count) = le_u16(i)?;
        let (i, i_blocks_lo) = le_u32(i)?;
        let (i, i_flags) = le_u32(i)?;
        let (i, i_osd1) = le_u32(i)?;

        let (i, block_bytes) = take(60usize)(i)?;
        let mut i_block = [0u8; 60];
        i_block.copy_from_slice(block_bytes);

        let (i, i_generation) = le_u32(i)?;
        let (i, i_file_acl_lo) = le_u32(i)?;
        let (i, i_size_high) = le_u32(i)?;
        let (i, i_obso_faddr) = le_u32(i)?;

        let (i, osd2_bytes) = take(12usize)(i)?;
        let mut i_osd2 = [0u8; 12];
        i_osd2.copy_from_slice(osd2_bytes);

        let (i, i_extra_isize) = le_u16(i)?;
        let (i, i_checksum_hi) = le_u16(i)?;
        let (i, i_ctime_extra) = le_u32(i)?;
        let (i, i_mtime_extra) = le_u32(i)?;
        let (i, i_atime_extra) = le_u32(i)?;
        let (i, i_crtime) = le_u32(i)?;
        let (i, i_crtime_extra) = le_u32(i)?;
        let (i, i_version_hi) = le_u32(i)?;
        let (i, i_projid) = le_u32(i)?;

        Ok((
            i,
            Ext4Inode {
                i_mode,
                i_uid,
                i_size_lo,
                i_atime,
                i_ctime,
                i_mtime,
                i_dtime,
                i_gid,
                i_links_count,
                i_blocks_lo,
                i_flags,
                i_osd1,
                i_block,
                i_generation,
                i_file_acl_lo,
                i_size_high,
                i_obso_faddr,
                i_osd2,
                i_extra_isize,
                i_checksum_hi,
                i_ctime_extra,
                i_mtime_extra,
                i_atime_extra,
                i_crtime,
                i_crtime_extra,
                i_version_hi,
                i_projid,
            },
        ))
    }

    /// Whether this is a regular file.
    pub fn is_regular(&self) -> bool {
        (self.i_mode & 0xF000) == 0x8000
    }

    /// Whether this is a directory.
    pub fn is_directory(&self) -> bool {
        (self.i_mode & 0xF000) == 0x4000
    }

    /// Whether this is a symlink.
    pub fn is_symlink(&self) -> bool {
        (self.i_mode & 0xF000) == 0xA000
    }

    /// Whether extents are used (EXTENTS flag).
    pub fn uses_extents(&self) -> bool {
        self.i_flags & 0x00080000 != 0
    }

    /// 64-bit file size.
    pub fn size(&self) -> u64 {
        ((self.i_size_high as u64) << 32) | (self.i_size_lo as u64)
    }

    /// Permission bits.
    pub fn permissions(&self) -> u16 {
        self.i_mode & 0xFFF
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════
// Ext4 Group Descriptor
// ═══════════════════════════════════════════════════════════════════════════════════

/// Ext4 block group descriptor (32 bytes, expandable to 64 bytes with 64-bit feature).
#[derive(Debug, Clone)]
pub struct Ext4GroupDescriptor {
    pub bg_block_bitmap_lo: u32,
    pub bg_inode_bitmap_lo: u32,
    pub bg_inode_table_lo: u32,
    pub bg_free_blocks_count_lo: u16,
    pub bg_free_inodes_count_lo: u16,
    pub bg_used_dirs_count_lo: u16,
    pub bg_flags: u16,
    pub bg_exclude_bitmap_lo: u32,
    pub bg_block_bitmap_csum_lo: u16,
    pub bg_inode_bitmap_csum_lo: u16,
    pub bg_itable_unused_lo: u16,
    pub bg_checksum: u16,
    // 64-bit fields
    pub bg_block_bitmap_hi: u32,
    pub bg_inode_bitmap_hi: u32,
    pub bg_inode_table_hi: u32,
    pub bg_free_blocks_count_hi: u16,
    pub bg_free_inodes_count_hi: u16,
    pub bg_used_dirs_count_hi: u16,
    pub bg_itable_unused_hi: u16,
    pub bg_exclude_bitmap_hi: u32,
    pub bg_block_bitmap_csum_hi: u16,
    pub bg_inode_bitmap_csum_hi: u16,
    pub bg_reserved: u32,
}

impl Ext4GroupDescriptor {
    /// Parse a 64-byte group descriptor.
    pub fn parse(data: &[u8]) -> IResult<&[u8], Self> {
        let i = data;
        let (i, bg_block_bitmap_lo) = le_u32(i)?;
        let (i, bg_inode_bitmap_lo) = le_u32(i)?;
        let (i, bg_inode_table_lo) = le_u32(i)?;
        let (i, bg_free_blocks_count_lo) = le_u16(i)?;
        let (i, bg_free_inodes_count_lo) = le_u16(i)?;
        let (i, bg_used_dirs_count_lo) = le_u16(i)?;
        let (i, bg_flags) = le_u16(i)?;
        let (i, bg_exclude_bitmap_lo) = le_u32(i)?;
        let (i, bg_block_bitmap_csum_lo) = le_u16(i)?;
        let (i, bg_inode_bitmap_csum_lo) = le_u16(i)?;
        let (i, bg_itable_unused_lo) = le_u16(i)?;
        let (i, bg_checksum) = le_u16(i)?;
        let (i, bg_block_bitmap_hi) = le_u32(i)?;
        let (i, bg_inode_bitmap_hi) = le_u32(i)?;
        let (i, bg_inode_table_hi) = le_u32(i)?;
        let (i, bg_free_blocks_count_hi) = le_u16(i)?;
        let (i, bg_free_inodes_count_hi) = le_u16(i)?;
        let (i, bg_used_dirs_count_hi) = le_u16(i)?;
        let (i, bg_itable_unused_hi) = le_u16(i)?;
        let (i, bg_exclude_bitmap_hi) = le_u32(i)?;
        let (i, bg_block_bitmap_csum_hi) = le_u16(i)?;
        let (i, bg_inode_bitmap_csum_hi) = le_u16(i)?;
        let (i, bg_reserved) = le_u32(i)?;

        Ok((
            i,
            Ext4GroupDescriptor {
                bg_block_bitmap_lo,
                bg_inode_bitmap_lo,
                bg_inode_table_lo,
                bg_free_blocks_count_lo,
                bg_free_inodes_count_lo,
                bg_used_dirs_count_lo,
                bg_flags,
                bg_exclude_bitmap_lo,
                bg_block_bitmap_csum_lo,
                bg_inode_bitmap_csum_lo,
                bg_itable_unused_lo,
                bg_checksum,
                bg_block_bitmap_hi,
                bg_inode_bitmap_hi,
                bg_inode_table_hi,
                bg_free_blocks_count_hi,
                bg_free_inodes_count_hi,
                bg_used_dirs_count_hi,
                bg_itable_unused_hi,
                bg_exclude_bitmap_hi,
                bg_block_bitmap_csum_hi,
                bg_inode_bitmap_csum_hi,
                bg_reserved,
            },
        ))
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════
// Ext4 Extent Structures
// ═══════════════════════════════════════════════════════════════════════════════════

/// Extent header (12 bytes, at the start of i_block for extent-based inodes).
#[derive(Debug, Clone, Copy)]
pub struct Ext4ExtentHeader {
    /// Magic: 0xF30A.
    pub eh_magic: u16,
    /// Number of valid entries following the header.
    pub eh_entries: u16,
    /// Maximum number of entries that could follow the header.
    pub eh_max: u16,
    /// Depth of this extent node in the extent tree (0 = leaf).
    pub eh_depth: u16,
    /// Generation of the tree.
    pub eh_generation: u32,
}

impl Ext4ExtentHeader {
    pub const SIZE: usize = 12;

    pub fn parse(data: &[u8]) -> IResult<&[u8], Self> {
        let (i, eh_magic) = le_u16(data)?;
        let (i, eh_entries) = le_u16(i)?;
        let (i, eh_max) = le_u16(i)?;
        let (i, eh_depth) = le_u16(i)?;
        let (i, eh_generation) = le_u32(i)?;

        Ok((
            i,
            Ext4ExtentHeader {
                eh_magic,
                eh_entries,
                eh_max,
                eh_depth,
                eh_generation,
            },
        ))
    }

    pub fn is_valid(&self) -> bool {
        self.eh_magic == EXT4_EXTENT_HEADER_MAGIC
    }
}

/// Extent (12 bytes, leaf node).
#[derive(Debug, Clone, Copy)]
pub struct Ext4Extent {
    /// First file block number that this extent covers.
    pub ee_block: u32,
    /// Number of blocks covered by this extent.
    pub ee_len: u16,
    /// High 16 bits of the physical block number.
    pub ee_start_hi: u16,
    /// Low 32 bits of the physical block number.
    pub ee_start_lo: u32,
}

impl Ext4Extent {
    pub const SIZE: usize = 12;

    pub fn parse(data: &[u8]) -> IResult<&[u8], Self> {
        let (i, ee_block) = le_u32(data)?;
        let (i, ee_len) = le_u16(i)?;
        let (i, ee_start_hi) = le_u16(i)?;
        let (i, ee_start_lo) = le_u32(i)?;

        Ok((
            i,
            Ext4Extent {
                ee_block,
                ee_len,
                ee_start_hi,
                ee_start_lo,
            },
        ))
    }

    /// Physical block number (48-bit).
    pub fn physical_block(&self) -> u64 {
        ((self.ee_start_hi as u64) << 32) | (self.ee_start_lo as u64)
    }
}

/// Extent index (12 bytes, internal node).
#[derive(Debug, Clone, Copy)]
pub struct Ext4ExtentIdx {
    /// This index node covers file blocks from this block number onward.
    pub ei_block: u32,
    /// Low 32 bits of the physical block of the child node.
    pub ei_leaf_lo: u32,
    /// High 16 bits of the physical block of the child node.
    pub ei_leaf_hi: u16,
    /// Unused.
    pub ei_unused: u16,
}

impl Ext4ExtentIdx {
    pub const SIZE: usize = 12;

    pub fn parse(data: &[u8]) -> IResult<&[u8], Self> {
        let (i, ei_block) = le_u32(data)?;
        let (i, ei_leaf_lo) = le_u32(i)?;
        let (i, ei_leaf_hi) = le_u16(i)?;
        let (i, ei_unused) = le_u16(i)?;

        Ok((
            i,
            Ext4ExtentIdx {
                ei_block,
                ei_leaf_lo,
                ei_leaf_hi,
                ei_unused,
            },
        ))
    }

    /// Physical block of the child node (48-bit).
    pub fn child_block(&self) -> u64 {
        ((self.ei_leaf_hi as u64) << 32) | (self.ei_leaf_lo as u64)
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constants() {
        assert_eq!(EXT4_SUPER_MAGIC, 0xEF53);
        assert_eq!(EXT4_EXTENT_HEADER_MAGIC, 0xF30A);
        assert_eq!(EXT4_XATTR_MAGIC, 0xEA020000);
    }

    #[test]
    fn test_file_types() {
        assert_eq!(EXT4_FT_REG_FILE, 1);
        assert_eq!(EXT4_FT_DIR, 2);
        assert_eq!(EXT4_FT_SYMLINK, 7);
    }

    #[test]
    fn test_special_inodes() {
        assert_eq!(EXT4_ROOT_INO, 2);
        assert_eq!(EXT4_JOURNAL_INO, 8);
    }

    #[test]
    fn test_extent_header_parse() {
        let mut data = vec![0u8; Ext4ExtentHeader::SIZE];
        data[0..2].copy_from_slice(&EXT4_EXTENT_HEADER_MAGIC.to_le_bytes());
        data[2..4].copy_from_slice(&4u16.to_le_bytes()); // entries
        data[4..6].copy_from_slice(&4u16.to_le_bytes()); // max
        data[6..8].copy_from_slice(&0u16.to_le_bytes()); // depth
        data[8..12].copy_from_slice(&1u32.to_le_bytes()); // generation

        let (_, hdr) = Ext4ExtentHeader::parse(&data).unwrap();
        assert!(hdr.is_valid());
        assert_eq!(hdr.eh_entries, 4);
        assert_eq!(hdr.eh_depth, 0); // leaf node
    }

    #[test]
    fn test_extent_parse() {
        let mut data = vec![0u8; Ext4Extent::SIZE];
        data[0..4].copy_from_slice(&100u32.to_le_bytes()); // ee_block
        data[4..6].copy_from_slice(&10u16.to_le_bytes()); // ee_len
        data[6..8].copy_from_slice(&0u16.to_le_bytes()); // ee_start_hi
        data[8..12].copy_from_slice(&1000u32.to_le_bytes()); // ee_start_lo

        let (_, ext) = Ext4Extent::parse(&data).unwrap();
        assert_eq!(ext.ee_block, 100);
        assert_eq!(ext.ee_len, 10);
        assert_eq!(ext.physical_block(), 1000);
    }

    #[test]
    fn test_extent_idx_parse() {
        let mut data = vec![0u8; Ext4ExtentIdx::SIZE];
        data[0..4].copy_from_slice(&50u32.to_le_bytes());
        data[4..8].copy_from_slice(&2000u32.to_le_bytes());
        data[8..10].copy_from_slice(&0u16.to_le_bytes());
        data[10..12].copy_from_slice(&0u16.to_le_bytes());

        let (_, idx) = Ext4ExtentIdx::parse(&data).unwrap();
        assert_eq!(idx.ei_block, 50);
        assert_eq!(idx.child_block(), 2000);
    }

    #[test]
    fn test_inode_parse() {
        let mut data = vec![0u8; 0xA0]; // minimal inode
        data[0..2].copy_from_slice(&0x8000u16.to_le_bytes()); // i_mode: regular file
        data[2..4].copy_from_slice(&1000u16.to_le_bytes()); // i_uid
        data[4..8].copy_from_slice(&12345u32.to_le_bytes()); // i_size_lo

        let (_, inode) = Ext4Inode::parse(&data).unwrap();
        assert!(inode.is_regular());
        assert!(!inode.is_directory());
        assert_eq!(inode.i_uid, 1000);
        assert_eq!(inode.size(), 12345);
        assert_eq!(inode.permissions(), 0);
    }

    #[test]
    fn test_inode_directory() {
        let mut data = vec![0u8; 0xA0];
        data[0..2].copy_from_slice(&0x4000u16.to_le_bytes()); // i_mode: directory
        let (_, inode) = Ext4Inode::parse(&data).unwrap();
        assert!(inode.is_directory());
        assert!(!inode.is_regular());
    }

    #[test]
    fn test_feature_flags() {
        assert_eq!(EXT4_FEATURE_INCOMPAT_EXTENTS, 0x0040);
        assert_eq!(EXT4_FEATURE_INCOMPAT_64BIT, 0x0080);
        assert_eq!(EXT4_FEATURE_COMPAT_HAS_JOURNAL, 0x0004);
    }
}
