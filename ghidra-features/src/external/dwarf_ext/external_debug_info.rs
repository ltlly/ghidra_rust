//! ExternalDebugInfo -- metadata for locating external DWARF debug files.
//!
//! Ported from `ghidra.app.util.bin.format.dwarf.external.ExternalDebugInfo`.
//!
//! Holds the information extracted from an ELF binary's `.gnu_debuglink`
//! section and/or `.note.gnu.build-id` section, which is used to locate
//! the corresponding external debug file.

use super::ObjectType;

/// Metadata needed to find an ELF/DWARF external debug file.
///
/// Retrieved from an ELF binary's `.gnu_debuglink` section (which provides
/// a filename and CRC) and/or `.note.gnu.build-id` section (which provides
/// a hash that is converted to a filename).
///
/// # Examples
///
/// ```rust
/// use ghidra_features::external::dwarf_ext::{ExternalDebugInfo, ObjectType};
///
/// // From a debuglink section
/// let info = ExternalDebugInfo::for_debug_link("libfoo.debug", 0xABCD1234u32);
/// assert!(info.has_debug_link());
/// assert_eq!(info.filename(), Some("libfoo.debug"));
/// assert_eq!(info.crc(), 0xABCD1234);
///
/// // From a build-id section
/// let info = ExternalDebugInfo::for_build_id("6addc39dc19c1b45f9ba70baf7fd81ea6508ea7f");
/// assert!(info.has_build_id());
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalDebugInfo {
    /// Filename from the `.gnu_debuglink` section, or `None`.
    filename: Option<String>,
    /// CRC32 from the `.gnu_debuglink` section. Only meaningful when `filename` is `Some`.
    crc: u32,
    /// Build-id hash digest from the `.note.gnu.build-id` section, or `None`.
    build_id: Option<String>,
    /// The type of object this metadata refers to.
    object_type: ObjectType,
    /// Additional information (used by `ObjectType::Source`).
    extra: Option<String>,
}

impl ExternalDebugInfo {
    /// Creates a new `ExternalDebugInfo` instance.
    ///
    /// # Arguments
    ///
    /// * `filename` - Filename of the external debug file, or `None`.
    /// * `crc` - CRC32 of the external debug file, or `0` if no filename.
    /// * `build_id` - Build-id hash string, or `None`.
    /// * `object_type` - The type of debug object.
    /// * `extra` - Additional information (used by `ObjectType::Source`).
    pub fn new(
        filename: Option<String>,
        crc: u32,
        build_id: Option<String>,
        object_type: ObjectType,
        extra: Option<String>,
    ) -> Self {
        Self {
            filename,
            crc,
            build_id,
            object_type,
            extra,
        }
    }

    /// Creates an `ExternalDebugInfo` from a build-id value only.
    pub fn for_build_id(build_id: impl Into<String>) -> Self {
        Self {
            filename: None,
            crc: 0,
            build_id: Some(build_id.into()),
            object_type: ObjectType::DebugInfo,
            extra: None,
        }
    }

    /// Creates an `ExternalDebugInfo` from debuglink values only.
    pub fn for_debug_link(
        filename: impl Into<String>,
        crc: u32,
    ) -> Self {
        Self {
            filename: Some(filename.into()),
            crc,
            build_id: None,
            object_type: ObjectType::DebugInfo,
            extra: None,
        }
    }

    /// Returns `true` if a debuglink filename is available.
    pub fn has_debug_link(&self) -> bool {
        self.filename
            .as_ref()
            .map(|f| !f.is_empty())
            .unwrap_or(false)
    }

    /// Returns the filename of the external debug file, or `None`.
    pub fn filename(&self) -> Option<&str> {
        self.filename.as_deref()
    }

    /// Returns the CRC32 of the external debug file.
    ///
    /// Only meaningful when [`has_debug_link()`](Self::has_debug_link) returns `true`.
    pub fn crc(&self) -> u32 {
        self.crc
    }

    /// Returns the build-id hash string, or `None`.
    pub fn build_id(&self) -> Option<&str> {
        self.build_id.as_deref()
    }

    /// Returns `true` if a build-id is available.
    pub fn has_build_id(&self) -> bool {
        self.build_id
            .as_ref()
            .map(|b| !b.is_empty())
            .unwrap_or(false)
    }

    /// Returns the object type.
    pub fn object_type(&self) -> ObjectType {
        self.object_type
    }

    /// Returns the extra information string, or `None`.
    pub fn extra(&self) -> Option<&str> {
        self.extra.as_deref()
    }

    /// Creates a new `ExternalDebugInfo` with a different object type and extra info.
    pub fn with_type(&self, new_object_type: ObjectType, new_extra: Option<String>) -> Self {
        Self {
            filename: self.filename.clone(),
            crc: self.crc,
            build_id: self.build_id.clone(),
            object_type: new_object_type,
            extra: new_extra,
        }
    }
}

impl std::fmt::Display for ExternalDebugInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "ExternalDebugInfo [filename={:?}, crc={:#010x}, hash={:?}, objectType={}, extra={:?}]",
            self.filename, self.crc, self.build_id, self.object_type, self.extra
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_for_debug_link() {
        let info = ExternalDebugInfo::for_debug_link("libfoo.debug", 0xABCD1234);
        assert!(info.has_debug_link());
        assert_eq!(info.filename(), Some("libfoo.debug"));
        assert_eq!(info.crc(), 0xABCD1234);
        assert!(!info.has_build_id());
        assert_eq!(info.object_type(), ObjectType::DebugInfo);
    }

    #[test]
    fn test_for_build_id() {
        let info = ExternalDebugInfo::for_build_id("6addc39dc19c1b45f9ba70baf7fd81ea6508ea7f");
        assert!(!info.has_debug_link());
        assert!(info.has_build_id());
        assert_eq!(
            info.build_id(),
            Some("6addc39dc19c1b45f9ba70baf7fd81ea6508ea7f")
        );
    }

    #[test]
    fn test_new_full() {
        let info = ExternalDebugInfo::new(
            Some("test.debug".into()),
            42,
            Some("abc123".into()),
            ObjectType::Executable,
            Some("extra".into()),
        );
        assert_eq!(info.object_type(), ObjectType::Executable);
        assert_eq!(info.extra(), Some("extra"));
    }

    #[test]
    fn test_with_type() {
        let info = ExternalDebugInfo::for_build_id("abc");
        let source_info = info.with_type(ObjectType::Source, Some("stdio.h".into()));
        assert_eq!(source_info.object_type(), ObjectType::Source);
        assert_eq!(source_info.extra(), Some("stdio.h"));
        assert_eq!(source_info.build_id(), Some("abc"));
    }

    #[test]
    fn test_has_debug_link_empty() {
        let info = ExternalDebugInfo::new(
            Some("".into()),
            0,
            None,
            ObjectType::DebugInfo,
            None,
        );
        assert!(!info.has_debug_link());
    }

    #[test]
    fn test_display() {
        let info = ExternalDebugInfo::for_debug_link("test.debug", 0x12345678);
        let s = info.to_string();
        assert!(s.contains("test.debug"));
        assert!(s.contains("12345678"));
    }
}
