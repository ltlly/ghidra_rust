//! Decompiler location memento -- Rust port of
//! `ghidra.app.plugin.core.decompile.DecompilerLocationMemento`.
//!
//! A memento captures the state needed to restore the decompiler view
//! to a particular scroll position and cursor location.

/// A snapshot of the decompiler panel's viewing state.
///
/// When the user navigates away from the decompiler and returns, the
/// memento restores:
/// - The program file path.
/// - The current program location (address + component identifier).
/// - The viewer's scroll position (index and Y offset).
#[derive(Debug, Clone)]
pub struct DecompilerLocationMemento {
    /// The path of the program file (for persistence).
    pub program_path: String,
    /// The address the user was looking at.
    pub address_offset: u64,
    /// The scroll index in the field panel.
    pub viewer_index: usize,
    /// The Y pixel offset within the current scroll index.
    pub viewer_y_offset: usize,
}

impl DecompilerLocationMemento {
    /// Create a new location memento.
    pub fn new(
        program_path: impl Into<String>,
        address_offset: u64,
        viewer_index: usize,
        viewer_y_offset: usize,
    ) -> Self {
        Self {
            program_path: program_path.into(),
            address_offset,
            viewer_index,
            viewer_y_offset,
        }
    }

    /// Returns the viewer index (scroll position).
    pub fn get_viewer_index(&self) -> usize {
        self.viewer_index
    }

    /// Returns the viewer Y offset.
    pub fn get_viewer_y_offset(&self) -> usize {
        self.viewer_y_offset
    }

    /// Serialize to a simple key-value map for persistence.
    pub fn to_state(&self) -> Vec<(String, String)> {
        vec![
            ("Program Path".into(), self.program_path.clone()),
            ("Address".into(), format!("0x{:x}", self.address_offset)),
            ("INDEX".into(), self.viewer_index.to_string()),
            ("Y_OFFSET".into(), self.viewer_y_offset.to_string()),
        ]
    }

    /// Deserialize from a key-value map.
    pub fn from_state(state: &[(String, String)]) -> Option<Self> {
        let find = |key: &str| -> Option<String> {
            state.iter().find(|(k, _)| k == key).map(|(_, v)| v.clone())
        };

        let program_path = find("Program Path")?;
        let address = find("Address")
            .and_then(|s| {
                let s = s.trim_start_matches("0x");
                u64::from_str_radix(s, 16).ok()
            })
            .unwrap_or(0);
        let index = find("INDEX")
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        let y_offset = find("Y_OFFSET")
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);

        Some(Self::new(program_path, address, index, y_offset))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memento_new() {
        let m = DecompilerLocationMemento::new("/path/to/prog", 0x4000, 10, 42);
        assert_eq!(m.program_path, "/path/to/prog");
        assert_eq!(m.address_offset, 0x4000);
        assert_eq!(m.get_viewer_index(), 10);
        assert_eq!(m.get_viewer_y_offset(), 42);
    }

    #[test]
    fn test_memento_round_trip() {
        let m = DecompilerLocationMemento::new("test.elf", 0x1000, 5, 20);
        let state = m.to_state();
        let restored = DecompilerLocationMemento::from_state(&state).unwrap();
        assert_eq!(restored.program_path, "test.elf");
        assert_eq!(restored.address_offset, 0x1000);
        assert_eq!(restored.get_viewer_index(), 5);
        assert_eq!(restored.get_viewer_y_offset(), 20);
    }

    #[test]
    fn test_memento_from_empty_state() {
        assert!(DecompilerLocationMemento::from_state(&[]).is_none());
    }

    #[test]
    fn test_memento_partial_state() {
        let state = vec![("Program Path".into(), "a.bin".into())];
        let m = DecompilerLocationMemento::from_state(&state).unwrap();
        assert_eq!(m.program_path, "a.bin");
        assert_eq!(m.address_offset, 0);
        assert_eq!(m.get_viewer_index(), 0);
    }
}
