//! Additional data type tree node types.
//!
//! Ported from `ghidra.app.plugin.core.datamgr.tree` Java classes:
//!
//! - [`BuiltInArchiveNode`] -- tree node for the built-in (Ghidra-provided) data type archive
//! - [`ProgramArchiveNode`] -- tree node for the program's internal data type archive
//! - [`ProjectArchiveNode`] -- tree node for a project-level data type archive
//! - [`InvalidArchiveNode`] -- placeholder tree node for archives that failed to load
//! - [`DtBackgroundIcon`] -- icon descriptor for archive/category tree nodes
//! - [`CenterVerticalIcon`] -- vertically-centered icon wrapper
//! - [`ArchiveRootNodeListener`] -- listener for archive root node events

use serde::{Deserialize, Serialize};

use super::archive::ArchiveKind;

// ---------------------------------------------------------------------------
// ArchiveRootNodeListener
// ---------------------------------------------------------------------------

/// Listener for changes to the archive root node (children added/removed,
/// archive loaded/unloaded).
///
/// Ported from `ghidra.app.plugin.core.datamgr.tree.ArchiveRootNodeListener`.
pub trait ArchiveRootNodeListener: Send + Sync {
    /// Called when an archive node is added under the root.
    fn on_archive_added(&self, archive_name: &str);

    /// Called when an archive node is removed from the root.
    fn on_archive_removed(&self, archive_name: &str);

    /// Called when an archive has been reloaded (e.g., from disk).
    fn on_archive_reloaded(&self, archive_name: &str);
}

// ---------------------------------------------------------------------------
// BuiltInArchiveNode
// ---------------------------------------------------------------------------

/// Tree node representing the Ghidra built-in data type archive.
///
/// This archive contains standard types provided by Ghidra (e.g., C
/// primitive types, standard library typedefs).  It is always present
/// and cannot be removed by the user.
///
/// Ported from `ghidra.app.plugin.core.datamgr.tree.BuiltInArchiveNode`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuiltInArchiveNode {
    /// Display name for this node (typically "BuiltInTypes").
    pub name: String,
    /// Whether this node is expanded in the tree.
    pub expanded: bool,
    /// Whether the built-in archive is read-only (always true in practice).
    pub read_only: bool,
}

impl BuiltInArchiveNode {
    /// Create a new built-in archive tree node.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            expanded: false,
            read_only: true,
        }
    }

    /// The kind of archive this node represents.
    pub fn archive_kind(&self) -> ArchiveKind {
        ArchiveKind::BuiltIn
    }

    /// Whether the user can modify types in this archive.
    pub fn is_read_only(&self) -> bool {
        self.read_only
    }

    /// The display name of this node.
    pub fn display_name(&self) -> &str {
        &self.name
    }
}

impl std::fmt::Display for BuiltInArchiveNode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name)
    }
}

// ---------------------------------------------------------------------------
// ProgramArchiveNode
// ---------------------------------------------------------------------------

/// Tree node representing the program's internal data type archive.
///
/// Every open program has exactly one program data type archive that
/// stores all types associated with that program (including types the
/// user has added or modified).
///
/// Ported from `ghidra.app.plugin.core.datamgr.tree.ProgramArchiveNode`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgramArchiveNode {
    /// The name of the program (e.g., "my_program.exe").
    pub program_name: String,
    /// Display name for this tree node.
    pub name: String,
    /// Whether this node is expanded.
    pub expanded: bool,
}

impl ProgramArchiveNode {
    /// Create a new program archive tree node.
    pub fn new(program_name: impl Into<String>) -> Self {
        let pname = program_name.into();
        Self {
            name: format!("[{}]", pname),
            program_name: pname,
            expanded: false,
        }
    }

    /// The kind of archive this node represents.
    pub fn archive_kind(&self) -> ArchiveKind {
        ArchiveKind::Program
    }

    /// The name of the program whose types this node represents.
    pub fn program_name(&self) -> &str {
        &self.program_name
    }

    /// The display name of this node.
    pub fn display_name(&self) -> &str {
        &self.name
    }
}

impl std::fmt::Display for ProgramArchiveNode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name)
    }
}

// ---------------------------------------------------------------------------
// ProjectArchiveNode
// ---------------------------------------------------------------------------

/// Tree node representing a project-level data type archive.
///
/// Project archives are stored within the Ghidra project and can be
/// shared across multiple programs.  They are backed by the project
/// database rather than an external file.
///
/// Ported from `ghidra.app.plugin.core.datamgr.tree.ProjectArchiveNode`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectArchiveNode {
    /// The archive name.
    pub name: String,
    /// Whether the archive is currently open.
    pub open: bool,
    /// Whether the archive is currently locked for editing.
    pub locked: bool,
    /// Whether this node is expanded in the tree.
    pub expanded: bool,
}

impl ProjectArchiveNode {
    /// Create a new project archive tree node.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            open: false,
            locked: false,
            expanded: false,
        }
    }

    /// The kind of archive this node represents.
    pub fn archive_kind(&self) -> ArchiveKind {
        ArchiveKind::Project
    }

    /// Whether the archive is currently open.
    pub fn is_open(&self) -> bool {
        self.open
    }

    /// Set whether the archive is open.
    pub fn set_open(&mut self, open: bool) {
        self.open = open;
    }

    /// Whether the archive is locked for editing.
    pub fn is_locked(&self) -> bool {
        self.locked
    }

    /// Set whether the archive is locked.
    pub fn set_locked(&mut self, locked: bool) {
        self.locked = locked;
    }

    /// The display name of this node.
    pub fn display_name(&self) -> &str {
        &self.name
    }
}

impl std::fmt::Display for ProjectArchiveNode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name)
    }
}

// ---------------------------------------------------------------------------
// InvalidArchiveNode
// ---------------------------------------------------------------------------

/// Placeholder tree node for an archive that failed to load.
///
/// When an archive file is corrupted, missing, or otherwise
/// unreadable, this node appears in the tree to indicate the
/// problem to the user.  The user can attempt to relink or
/// remove the entry.
///
/// Ported from `ghidra.app.plugin.core.datamgr.tree.InvalidArchiveNode`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvalidArchiveNode {
    /// The original name of the archive that failed to load.
    pub name: String,
    /// The path that was attempted (if known).
    pub path: Option<String>,
    /// The error message from the failed load attempt.
    pub error_message: String,
}

impl InvalidArchiveNode {
    /// Create a new invalid archive tree node.
    pub fn new(
        name: impl Into<String>,
        path: Option<String>,
        error_message: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            path,
            error_message: error_message.into(),
        }
    }

    /// The kind of archive this node represents (always `Invalid`).
    pub fn archive_kind(&self) -> ArchiveKind {
        ArchiveKind::Invalid
    }

    /// The display name of this node.
    pub fn display_name(&self) -> String {
        format!("{} [Invalid]", self.name)
    }

    /// The error message from the failed load.
    pub fn error_message(&self) -> &str {
        &self.error_message
    }
}

impl std::fmt::Display for InvalidArchiveNode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} [Invalid]", self.name)
    }
}

// ---------------------------------------------------------------------------
// DtBackgroundIcon
// ---------------------------------------------------------------------------

/// Icon descriptor for data type tree nodes.
///
/// In the Java version this wraps a Swing `Icon` that draws a
/// background highlight.  In Rust we represent the icon metadata
/// as a simple struct for rendering.
///
/// Ported from `ghidra.app.plugin.core.datamgr.tree.DtBackgroundIcon`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DtBackgroundIcon {
    /// The base icon identifier (e.g., "archive", "category", "datatype").
    pub icon_id: String,
    /// Width in pixels.
    pub width: u32,
    /// Height in pixels.
    pub height: u32,
    /// Whether to draw a background highlight.
    pub highlight: bool,
    /// Highlight color as RGBA.
    pub highlight_color: Option<[u8; 4]>,
}

impl DtBackgroundIcon {
    /// Create a new icon descriptor.
    pub fn new(icon_id: impl Into<String>) -> Self {
        Self {
            icon_id: icon_id.into(),
            width: 16,
            height: 16,
            highlight: false,
            highlight_color: None,
        }
    }

    /// Create an icon with a highlight background.
    pub fn with_highlight(mut self, color: [u8; 4]) -> Self {
        self.highlight = true;
        self.highlight_color = Some(color);
        self
    }

    /// Set the icon dimensions.
    pub fn with_size(mut self, width: u32, height: u32) -> Self {
        self.width = width;
        self.height = height;
        self
    }
}

impl Default for DtBackgroundIcon {
    fn default() -> Self {
        Self::new("default")
    }
}

// ---------------------------------------------------------------------------
// CenterVerticalIcon
// ---------------------------------------------------------------------------

/// Vertically-centered icon wrapper.
///
/// Used to render icons that need to be vertically aligned within a
/// table cell that may be taller than the icon.
///
/// Ported from `ghidra.app.plugin.core.datamgr.tree.CenterVerticalIcon`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CenterVerticalIcon {
    /// The inner icon being centered.
    pub inner: DtBackgroundIcon,
    /// The total height of the cell in which this icon is rendered.
    pub cell_height: u32,
}

impl CenterVerticalIcon {
    /// Create a new centered icon.
    pub fn new(inner: DtBackgroundIcon, cell_height: u32) -> Self {
        Self { inner, cell_height }
    }

    /// The Y offset to apply for vertical centering.
    pub fn y_offset(&self) -> u32 {
        if self.cell_height > self.inner.height {
            (self.cell_height - self.inner.height) / 2
        } else {
            0
        }
    }

    /// Whether centering is needed (cell is taller than icon).
    pub fn needs_centering(&self) -> bool {
        self.cell_height > self.inner.height
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_built_in_archive_node() {
        let node = BuiltInArchiveNode::new("BuiltInTypes");
        assert_eq!(node.display_name(), "BuiltInTypes");
        assert!(node.is_read_only());
        assert_eq!(node.archive_kind(), ArchiveKind::BuiltIn);
        assert_eq!(node.to_string(), "BuiltInTypes");
    }

    #[test]
    fn test_program_archive_node() {
        let node = ProgramArchiveNode::new("my_program.exe");
        assert_eq!(node.program_name(), "my_program.exe");
        assert_eq!(node.display_name(), "[my_program.exe]");
        assert_eq!(node.archive_kind(), ArchiveKind::Program);
    }

    #[test]
    fn test_project_archive_node() {
        let mut node = ProjectArchiveNode::new("StandardLib");
        assert_eq!(node.display_name(), "StandardLib");
        assert!(!node.is_open());
        assert!(!node.is_locked());
        assert_eq!(node.archive_kind(), ArchiveKind::Project);

        node.set_open(true);
        assert!(node.is_open());
        node.set_locked(true);
        assert!(node.is_locked());
    }

    #[test]
    fn test_invalid_archive_node() {
        let node = InvalidArchiveNode::new(
            "corrupted.gdt",
            Some("/path/to/corrupted.gdt".to_string()),
            "File not found",
        );
        assert_eq!(node.display_name(), "corrupted.gdt [Invalid]");
        assert_eq!(node.error_message(), "File not found");
        assert_eq!(node.archive_kind(), ArchiveKind::Invalid);
    }

    #[test]
    fn test_invalid_archive_node_no_path() {
        let node = InvalidArchiveNode::new("missing", None, "IO error");
        assert!(node.path.is_none());
    }

    #[test]
    fn test_dt_background_icon() {
        let icon = DtBackgroundIcon::new("archive")
            .with_size(24, 24)
            .with_highlight([0xFF, 0x00, 0x00, 0x80]);
        assert_eq!(icon.icon_id, "archive");
        assert_eq!(icon.width, 24);
        assert_eq!(icon.height, 24);
        assert!(icon.highlight);
        assert_eq!(icon.highlight_color, Some([0xFF, 0x00, 0x00, 0x80]));
    }

    #[test]
    fn test_dt_background_icon_default() {
        let icon = DtBackgroundIcon::default();
        assert_eq!(icon.icon_id, "default");
        assert_eq!(icon.width, 16);
        assert_eq!(icon.height, 16);
        assert!(!icon.highlight);
    }

    #[test]
    fn test_center_vertical_icon() {
        let inner = DtBackgroundIcon::new("category").with_size(16, 16);
        let centered = CenterVerticalIcon::new(inner, 32);
        assert!(centered.needs_centering());
        assert_eq!(centered.y_offset(), 8);
    }

    #[test]
    fn test_center_vertical_icon_no_centering() {
        let inner = DtBackgroundIcon::new("category").with_size(16, 16);
        let centered = CenterVerticalIcon::new(inner, 16);
        assert!(!centered.needs_centering());
        assert_eq!(centered.y_offset(), 0);
    }

    #[test]
    fn test_center_vertical_icon_shorter_cell() {
        let inner = DtBackgroundIcon::new("big").with_size(32, 32);
        let centered = CenterVerticalIcon::new(inner, 16);
        assert!(!centered.needs_centering());
        assert_eq!(centered.y_offset(), 0);
    }

    #[test]
    fn test_archive_root_node_listener_noop() {
        // Test that the trait compiles and can be implemented
        struct NoopListener;
        impl ArchiveRootNodeListener for NoopListener {
            fn on_archive_added(&self, _name: &str) {}
            fn on_archive_removed(&self, _name: &str) {}
            fn on_archive_reloaded(&self, _name: &str) {}
        }
        let listener = NoopListener;
        listener.on_archive_added("test");
        listener.on_archive_removed("test");
        listener.on_archive_reloaded("test");
    }
}
