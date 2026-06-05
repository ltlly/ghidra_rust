//! Resource icon definitions.
//!
//! Ported from `ghidra.app.plugin.core.resources` icon-related classes.
//!
//! Provides constants and utilities for Ghidra's built-in icons
//! used throughout the UI.

/// Icon identifiers for the Ghidra UI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IconId {
    /// A function icon.
    Function,
    /// A label/icon for a data item.
    Data,
    /// A code unit icon.
    CodeUnit,
    /// A bookmark icon.
    Bookmark,
    /// A warning/error icon.
    Warning,
    /// An info icon.
    Info,
    /// A lock icon.
    Lock,
    /// An unlocked icon.
    Unlock,
    /// A search icon.
    Search,
    /// A settings/gear icon.
    Settings,
    /// An add/plus icon.
    Add,
    /// A delete/trash icon.
    Delete,
    /// An edit/pencil icon.
    Edit,
    /// A copy icon.
    Copy,
    /// A paste icon.
    Paste,
    /// A folder icon.
    Folder,
    /// A file icon.
    File,
    /// A close/X icon.
    Close,
}

impl IconId {
    /// Get the icon resource path.
    pub fn resource_path(&self) -> &'static str {
        match self {
            Self::Function => "images/function.png",
            Self::Data => "images/data.png",
            Self::CodeUnit => "images/codeunit.png",
            Self::Bookmark => "images/bookmark.png",
            Self::Warning => "images/warning.png",
            Self::Info => "images/info.png",
            Self::Lock => "images/lock.png",
            Self::Unlock => "images/unlock.png",
            Self::Search => "images/search.png",
            Self::Settings => "images/settings.png",
            Self::Add => "images/add.png",
            Self::Delete => "images/delete.png",
            Self::Edit => "images/edit.png",
            Self::Copy => "images/copy.png",
            Self::Paste => "images/paste.png",
            Self::Folder => "images/folder.png",
            Self::File => "images/file.png",
            Self::Close => "images/close.png",
        }
    }

    /// Get a descriptive tooltip.
    pub fn tooltip(&self) -> &'static str {
        match self {
            Self::Function => "Function",
            Self::Data => "Data",
            Self::CodeUnit => "Code Unit",
            Self::Bookmark => "Bookmark",
            Self::Warning => "Warning",
            Self::Info => "Information",
            Self::Lock => "Locked",
            Self::Unlock => "Unlocked",
            Self::Search => "Search",
            Self::Settings => "Settings",
            Self::Add => "Add",
            Self::Delete => "Delete",
            Self::Edit => "Edit",
            Self::Copy => "Copy",
            Self::Paste => "Paste",
            Self::Folder => "Folder",
            Self::File => "File",
            Self::Close => "Close",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_icon_resource_paths() {
        assert_eq!(IconId::Function.resource_path(), "images/function.png");
        assert_eq!(IconId::Warning.resource_path(), "images/warning.png");
    }

    #[test]
    fn test_icon_tooltips() {
        assert_eq!(IconId::Search.tooltip(), "Search");
        assert_eq!(IconId::Settings.tooltip(), "Settings");
    }

    #[test]
    fn test_all_icons_have_paths() {
        let all = [
            IconId::Function, IconId::Data, IconId::CodeUnit,
            IconId::Bookmark, IconId::Warning, IconId::Info,
            IconId::Lock, IconId::Unlock, IconId::Search,
            IconId::Settings, IconId::Add, IconId::Delete,
            IconId::Edit, IconId::Copy, IconId::Paste,
            IconId::Folder, IconId::File, IconId::Close,
        ];
        for icon in &all {
            assert!(!icon.resource_path().is_empty());
            assert!(!icon.tooltip().is_empty());
        }
    }
}
