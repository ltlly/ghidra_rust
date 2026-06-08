//! COFF archive constants ported from Ghidra's
//! `ghidra.app.util.bin.format.coff.archive.CoffArchiveConstants`.

/// The magic string that identifies a COFF archive file.
pub const MAGIC: &str = "!<arch>\n";

/// Length of the magic string in bytes.
pub const MAGIC_LEN: usize = 8;

/// The magic bytes.
pub const MAGIC_BYTES: &[u8; MAGIC_LEN] = b"!<arch>\n";

/// Minimum size of an archive member header.
pub const CAMH_MIN_SIZE: u64 = 60;

/// Offset of the name field within a member header.
pub const CAMH_NAME_OFF: usize = 0;
/// Length of the name field.
pub const CAMH_NAME_LEN: usize = 16;

/// Offset of the date field.
pub const CAMH_DATE_OFF: usize = 16;
/// Length of the date field.
pub const CAMH_DATE_LEN: usize = 12;

/// Offset of the user ID field.
pub const CAMH_USERID_OFF: usize = 28;
/// Length of the user ID field.
pub const CAMH_USERID_LEN: usize = 6;

/// Offset of the group ID field.
pub const CAMH_GROUPID_OFF: usize = 34;
/// Length of the group ID field.
pub const CAMH_GROUPID_LEN: usize = 6;

/// Offset of the mode field.
pub const CAMH_MODE_OFF: usize = 40;
/// Length of the mode field.
pub const CAMH_MODE_LEN: usize = 8;

/// Offset of the size field.
pub const CAMH_SIZE_OFF: usize = 48;
/// Length of the size field.
pub const CAMH_SIZE_LEN: usize = 10;

/// Offset of the end-of-header magic.
pub const CAMH_EOH_OFF: usize = 58;
/// Length of the end-of-header magic.
pub const CAMH_EOH_LEN: usize = 2;
/// The expected end-of-header magic bytes (backtick + newline).
pub const CAMH_EOH_MAGIC: &[u8; 2] = b"`\n";

/// Offset of the payload (immediately after header).
pub const CAMH_PAYLOAD_OFF: u64 = 60;

/// Special name for linker members.
pub const SLASH: &str = "/";
/// Special name for the long names member.
pub const SLASH_SLASH: &str = "//";
