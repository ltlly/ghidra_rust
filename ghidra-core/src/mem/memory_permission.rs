//! Memory permission model.
//!
//! This module implements the `MemoryPermission` concept from Ghidra's
//! `ghidra.program.model.mem` package. In the Java codebase, permissions are
//! expressed as bitmask flags (`FLAG_READ`, `FLAG_WRITE`, `FLAG_EXECUTE`, etc.)
//! in `MemoryConstants`. This Rust module provides a richer enum-based
//! representation while remaining interoperable with the raw flag bits.
//!
//! # Relationship to Ghidra
//!
//! Ghidra does not have a standalone `MemoryPermission.java` enum. Instead,
//! `MemoryBlock` stores permission flags as individual bits in a `byte` field,
//! and `Memory` provides per-block read/write/execute checks. This Rust module
//! adds a first-class [`MemoryPermission`] enum that can be converted to/from
//! the raw `FLAG_*` bitmasks and used for ergonomic permission checks.

use std::fmt;

use super::{FLAG_EXECUTE, FLAG_READ, FLAG_WRITE};

// ============================================================================
// MemoryPermission enum
// ============================================================================

/// A set of memory access permissions for a memory block.
///
/// This enum provides a structured representation of the permission flags
/// that Ghidra stores as raw bitmask values. Each variant represents a
/// distinct combination of read, write, and execute permissions.
///
/// # Examples
///
/// ```
/// use ghidra_core::mem::memory_permission::MemoryPermission;
///
/// let perm = MemoryPermission::RWX;
/// assert!(perm.is_readable());
/// assert!(perm.is_writable());
/// assert!(perm.is_executable());
///
/// let perm = MemoryPermission::R;
/// assert!(perm.is_readable());
/// assert!(!perm.is_writable());
/// assert!(!perm.is_executable());
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MemoryPermission {
    /// No access permitted.
    NONE,
    /// Read-only access.
    R,
    /// Read and write access.
    RW,
    /// Read and execute access.
    RX,
    /// Read, write, and execute access.
    RWX,
    /// Execute-only access.
    X,
    /// Write-only access.
    W,
    /// Write and execute access.
    WX,
}

impl MemoryPermission {
    /// Returns `true` if this permission includes read access.
    ///
    /// # Examples
    ///
    /// ```
    /// use ghidra_core::mem::memory_permission::MemoryPermission;
    ///
    /// assert!(MemoryPermission::R.is_readable());
    /// assert!(MemoryPermission::RWX.is_readable());
    /// assert!(!MemoryPermission::X.is_readable());
    /// assert!(!MemoryPermission::NONE.is_readable());
    /// ```
    pub fn is_readable(&self) -> bool {
        matches!(
            self,
            MemoryPermission::R
                | MemoryPermission::RW
                | MemoryPermission::RX
                | MemoryPermission::RWX
        )
    }

    /// Returns `true` if this permission includes write access.
    ///
    /// # Examples
    ///
    /// ```
    /// use ghidra_core::mem::memory_permission::MemoryPermission;
    ///
    /// assert!(MemoryPermission::RW.is_writable());
    /// assert!(MemoryPermission::RWX.is_writable());
    /// assert!(!MemoryPermission::R.is_writable());
    /// assert!(!MemoryPermission::NONE.is_writable());
    /// ```
    pub fn is_writable(&self) -> bool {
        matches!(
            self,
            MemoryPermission::W
                | MemoryPermission::RW
                | MemoryPermission::WX
                | MemoryPermission::RWX
        )
    }

    /// Returns `true` if this permission includes execute access.
    ///
    /// # Examples
    ///
    /// ```
    /// use ghidra_core::mem::memory_permission::MemoryPermission;
    ///
    /// assert!(MemoryPermission::X.is_executable());
    /// assert!(MemoryPermission::RWX.is_executable());
    /// assert!(!MemoryPermission::R.is_executable());
    /// assert!(!MemoryPermission::NONE.is_executable());
    /// ```
    pub fn is_executable(&self) -> bool {
        matches!(
            self,
            MemoryPermission::X
                | MemoryPermission::RX
                | MemoryPermission::WX
                | MemoryPermission::RWX
        )
    }

    /// Converts this permission to the raw flag bitmask used by the memory
    /// model. The returned `u8` value is the bitwise-OR of `FLAG_READ`,
    /// `FLAG_WRITE`, and `FLAG_EXECUTE` as appropriate.
    ///
    /// # Examples
    ///
    /// ```
    /// use ghidra_core::mem::memory_permission::MemoryPermission;
    /// use ghidra_core::mem::{FLAG_READ, FLAG_WRITE, FLAG_EXECUTE};
    ///
    /// assert_eq!(MemoryPermission::RWX.to_flags(), FLAG_READ | FLAG_WRITE | FLAG_EXECUTE);
    /// assert_eq!(MemoryPermission::R.to_flags(), FLAG_READ);
    /// assert_eq!(MemoryPermission::NONE.to_flags(), 0);
    /// ```
    pub fn to_flags(&self) -> u8 {
        let mut flags = 0u8;
        if self.is_readable() {
            flags |= FLAG_READ;
        }
        if self.is_writable() {
            flags |= FLAG_WRITE;
        }
        if self.is_executable() {
            flags |= FLAG_EXECUTE;
        }
        flags
    }

    /// Creates a `MemoryPermission` from raw flag bitmask values.
    ///
    /// Examines the `FLAG_READ`, `FLAG_WRITE`, and `FLAG_EXECUTE` bits in the
    /// given flags value and returns the corresponding enum variant.
    ///
    /// # Examples
    ///
    /// ```
    /// use ghidra_core::mem::memory_permission::MemoryPermission;
    /// use ghidra_core::mem::{FLAG_READ, FLAG_WRITE, FLAG_EXECUTE};
    ///
    /// let perm = MemoryPermission::from_flags(FLAG_READ | FLAG_WRITE | FLAG_EXECUTE);
    /// assert_eq!(perm, MemoryPermission::RWX);
    ///
    /// let perm = MemoryPermission::from_flags(FLAG_READ);
    /// assert_eq!(perm, MemoryPermission::R);
    /// ```
    pub fn from_flags(flags: u8) -> Self {
        let r = (flags & FLAG_READ) != 0;
        let w = (flags & FLAG_WRITE) != 0;
        let x = (flags & FLAG_EXECUTE) != 0;
        match (r, w, x) {
            (false, false, false) => MemoryPermission::NONE,
            (true, false, false) => MemoryPermission::R,
            (false, true, false) => MemoryPermission::W,
            (false, false, true) => MemoryPermission::X,
            (true, true, false) => MemoryPermission::RW,
            (true, false, true) => MemoryPermission::RX,
            (false, true, true) => MemoryPermission::WX,
            (true, true, true) => MemoryPermission::RWX,
        }
    }

    /// Returns a compact string representation of the permissions (e.g. `"rwx"`).
    ///
    /// This is the same format used by `MemoryBlock::permissions_string()` in
    /// the memory model.
    ///
    /// # Examples
    ///
    /// ```
    /// use ghidra_core::mem::memory_permission::MemoryPermission;
    ///
    /// assert_eq!(MemoryPermission::RWX.as_str(), "rwx");
    /// assert_eq!(MemoryPermission::R.as_str(), "r--");
    /// assert_eq!(MemoryPermission::NONE.as_str(), "---");
    /// ```
    pub fn as_str(&self) -> &'static str {
        match self {
            MemoryPermission::NONE => "---",
            MemoryPermission::R => "r--",
            MemoryPermission::W => "-w-",
            MemoryPermission::X => "--x",
            MemoryPermission::RW => "rw-",
            MemoryPermission::RX => "r-x",
            MemoryPermission::WX => "-wx",
            MemoryPermission::RWX => "rwx",
        }
    }

    /// Creates a new permission by adding write access to this permission.
    ///
    /// # Examples
    ///
    /// ```
    /// use ghidra_core::mem::memory_permission::MemoryPermission;
    ///
    /// assert_eq!(MemoryPermission::R.with_write(), MemoryPermission::RW);
    /// assert_eq!(MemoryPermission::RX.with_write(), MemoryPermission::RWX);
    /// assert_eq!(MemoryPermission::RWX.with_write(), MemoryPermission::RWX);
    /// ```
    pub fn with_write(&self) -> Self {
        match self {
            MemoryPermission::NONE => MemoryPermission::W,
            MemoryPermission::R => MemoryPermission::RW,
            MemoryPermission::W => MemoryPermission::W,
            MemoryPermission::X => MemoryPermission::WX,
            MemoryPermission::RW => MemoryPermission::RW,
            MemoryPermission::RX => MemoryPermission::RWX,
            MemoryPermission::WX => MemoryPermission::WX,
            MemoryPermission::RWX => MemoryPermission::RWX,
        }
    }

    /// Creates a new permission by adding execute access to this permission.
    ///
    /// # Examples
    ///
    /// ```
    /// use ghidra_core::mem::memory_permission::MemoryPermission;
    ///
    /// assert_eq!(MemoryPermission::R.with_execute(), MemoryPermission::RX);
    /// assert_eq!(MemoryPermission::RW.with_execute(), MemoryPermission::RWX);
    /// assert_eq!(MemoryPermission::RWX.with_execute(), MemoryPermission::RWX);
    /// ```
    pub fn with_execute(&self) -> Self {
        match self {
            MemoryPermission::NONE => MemoryPermission::X,
            MemoryPermission::R => MemoryPermission::RX,
            MemoryPermission::W => MemoryPermission::WX,
            MemoryPermission::X => MemoryPermission::X,
            MemoryPermission::RW => MemoryPermission::RWX,
            MemoryPermission::RX => MemoryPermission::RX,
            MemoryPermission::WX => MemoryPermission::WX,
            MemoryPermission::RWX => MemoryPermission::RWX,
        }
    }

    /// Creates a new permission by adding read access to this permission.
    ///
    /// # Examples
    ///
    /// ```
    /// use ghidra_core::mem::memory_permission::MemoryPermission;
    ///
    /// assert_eq!(MemoryPermission::W.with_read(), MemoryPermission::RW);
    /// assert_eq!(MemoryPermission::X.with_read(), MemoryPermission::RX);
    /// assert_eq!(MemoryPermission::NONE.with_read(), MemoryPermission::R);
    /// ```
    pub fn with_read(&self) -> Self {
        match self {
            MemoryPermission::NONE => MemoryPermission::R,
            MemoryPermission::R => MemoryPermission::R,
            MemoryPermission::W => MemoryPermission::RW,
            MemoryPermission::X => MemoryPermission::RX,
            MemoryPermission::RW => MemoryPermission::RW,
            MemoryPermission::RX => MemoryPermission::RX,
            MemoryPermission::WX => MemoryPermission::RWX,
            MemoryPermission::RWX => MemoryPermission::RWX,
        }
    }

    /// Returns the union of two permissions (the most permissive combination).
    ///
    /// # Examples
    ///
    /// ```
    /// use ghidra_core::mem::memory_permission::MemoryPermission;
    ///
    /// assert_eq!(MemoryPermission::R.union(MemoryPermission::X), MemoryPermission::RX);
    /// assert_eq!(MemoryPermission::RW.union(MemoryPermission::X), MemoryPermission::RWX);
    /// ```
    pub fn union(&self, other: Self) -> Self {
        let flags = self.to_flags() | other.to_flags();
        Self::from_flags(flags)
    }

    /// Returns the intersection of two permissions (the most restrictive combination).
    ///
    /// # Examples
    ///
    /// ```
    /// use ghidra_core::mem::memory_permission::MemoryPermission;
    ///
    /// assert_eq!(MemoryPermission::RWX.intersection(MemoryPermission::RX), MemoryPermission::RX);
    /// assert_eq!(MemoryPermission::R.intersection(MemoryPermission::W), MemoryPermission::NONE);
    /// ```
    pub fn intersection(&self, other: Self) -> Self {
        let flags = self.to_flags() & other.to_flags();
        Self::from_flags(flags)
    }
}

impl fmt::Display for MemoryPermission {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl From<u8> for MemoryPermission {
    /// Creates a `MemoryPermission` from a raw flag bitmask.
    ///
    /// This is equivalent to [`MemoryPermission::from_flags`].
    fn from(flags: u8) -> Self {
        Self::from_flags(flags)
    }
}

impl From<MemoryPermission> for u8 {
    /// Converts a `MemoryPermission` to its raw flag bitmask.
    ///
    /// This is equivalent to calling [`MemoryPermission::to_flags`].
    fn from(perm: MemoryPermission) -> u8 {
        perm.to_flags()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_none_permissions() {
        let perm = MemoryPermission::NONE;
        assert!(!perm.is_readable());
        assert!(!perm.is_writable());
        assert!(!perm.is_executable());
        assert_eq!(perm.to_flags(), 0);
        assert_eq!(perm.as_str(), "---");
    }

    #[test]
    fn test_read_only() {
        let perm = MemoryPermission::R;
        assert!(perm.is_readable());
        assert!(!perm.is_writable());
        assert!(!perm.is_executable());
        assert_eq!(perm.to_flags(), FLAG_READ);
        assert_eq!(perm.as_str(), "r--");
    }

    #[test]
    fn test_write_only() {
        let perm = MemoryPermission::W;
        assert!(!perm.is_readable());
        assert!(perm.is_writable());
        assert!(!perm.is_executable());
        assert_eq!(perm.to_flags(), FLAG_WRITE);
        assert_eq!(perm.as_str(), "-w-");
    }

    #[test]
    fn test_execute_only() {
        let perm = MemoryPermission::X;
        assert!(!perm.is_readable());
        assert!(!perm.is_writable());
        assert!(perm.is_executable());
        assert_eq!(perm.to_flags(), FLAG_EXECUTE);
        assert_eq!(perm.as_str(), "--x");
    }

    #[test]
    fn test_rw() {
        let perm = MemoryPermission::RW;
        assert!(perm.is_readable());
        assert!(perm.is_writable());
        assert!(!perm.is_executable());
        assert_eq!(perm.to_flags(), FLAG_READ | FLAG_WRITE);
        assert_eq!(perm.as_str(), "rw-");
    }

    #[test]
    fn test_rx() {
        let perm = MemoryPermission::RX;
        assert!(perm.is_readable());
        assert!(!perm.is_writable());
        assert!(perm.is_executable());
        assert_eq!(perm.to_flags(), FLAG_READ | FLAG_EXECUTE);
        assert_eq!(perm.as_str(), "r-x");
    }

    #[test]
    fn test_wx() {
        let perm = MemoryPermission::WX;
        assert!(!perm.is_readable());
        assert!(perm.is_writable());
        assert!(perm.is_executable());
        assert_eq!(perm.to_flags(), FLAG_WRITE | FLAG_EXECUTE);
        assert_eq!(perm.as_str(), "-wx");
    }

    #[test]
    fn test_rwx() {
        let perm = MemoryPermission::RWX;
        assert!(perm.is_readable());
        assert!(perm.is_writable());
        assert!(perm.is_executable());
        assert_eq!(perm.to_flags(), FLAG_READ | FLAG_WRITE | FLAG_EXECUTE);
        assert_eq!(perm.as_str(), "rwx");
    }

    #[test]
    fn test_from_flags_roundtrip() {
        for flags in 0u8..=7 {
            let perm = MemoryPermission::from_flags(flags);
            assert_eq!(perm.to_flags(), flags);
        }
    }

    #[test]
    fn test_from_flags_extra_bits_ignored() {
        // The volatile and artificial flags (0x8, 0x10) should be ignored
        let perm = MemoryPermission::from_flags(FLAG_READ | 0x8);
        assert_eq!(perm, MemoryPermission::R);
    }

    #[test]
    fn test_display() {
        assert_eq!(format!("{}", MemoryPermission::RWX), "rwx");
        assert_eq!(format!("{}", MemoryPermission::NONE), "---");
        assert_eq!(format!("{}", MemoryPermission::R), "r--");
    }

    #[test]
    fn test_from_u8() {
        let perm: MemoryPermission = (FLAG_READ | FLAG_WRITE).into();
        assert_eq!(perm, MemoryPermission::RW);
    }

    #[test]
    fn test_into_u8() {
        let flags: u8 = MemoryPermission::RWX.into();
        assert_eq!(flags, FLAG_READ | FLAG_WRITE | FLAG_EXECUTE);
    }

    #[test]
    fn test_with_write() {
        assert_eq!(MemoryPermission::R.with_write(), MemoryPermission::RW);
        assert_eq!(MemoryPermission::RX.with_write(), MemoryPermission::RWX);
        assert_eq!(MemoryPermission::RWX.with_write(), MemoryPermission::RWX);
        assert_eq!(MemoryPermission::NONE.with_write(), MemoryPermission::W);
    }

    #[test]
    fn test_with_execute() {
        assert_eq!(MemoryPermission::R.with_execute(), MemoryPermission::RX);
        assert_eq!(MemoryPermission::RW.with_execute(), MemoryPermission::RWX);
        assert_eq!(MemoryPermission::RWX.with_execute(), MemoryPermission::RWX);
        assert_eq!(MemoryPermission::NONE.with_execute(), MemoryPermission::X);
    }

    #[test]
    fn test_with_read() {
        assert_eq!(MemoryPermission::W.with_read(), MemoryPermission::RW);
        assert_eq!(MemoryPermission::X.with_read(), MemoryPermission::RX);
        assert_eq!(MemoryPermission::NONE.with_read(), MemoryPermission::R);
        assert_eq!(MemoryPermission::RWX.with_read(), MemoryPermission::RWX);
    }

    #[test]
    fn test_union() {
        assert_eq!(
            MemoryPermission::R.union(MemoryPermission::X),
            MemoryPermission::RX
        );
        assert_eq!(
            MemoryPermission::RW.union(MemoryPermission::X),
            MemoryPermission::RWX
        );
        assert_eq!(
            MemoryPermission::NONE.union(MemoryPermission::NONE),
            MemoryPermission::NONE
        );
        assert_eq!(
            MemoryPermission::RWX.union(MemoryPermission::R),
            MemoryPermission::RWX
        );
    }

    #[test]
    fn test_intersection() {
        assert_eq!(
            MemoryPermission::RWX.intersection(MemoryPermission::RX),
            MemoryPermission::RX
        );
        assert_eq!(
            MemoryPermission::R.intersection(MemoryPermission::W),
            MemoryPermission::NONE
        );
        assert_eq!(
            MemoryPermission::RWX.intersection(MemoryPermission::RWX),
            MemoryPermission::RWX
        );
        assert_eq!(
            MemoryPermission::NONE.intersection(MemoryPermission::R),
            MemoryPermission::NONE
        );
    }

    #[test]
    fn test_copy_clone() {
        let perm = MemoryPermission::RWX;
        let cloned = perm;
        assert_eq!(perm, cloned);
    }
}
