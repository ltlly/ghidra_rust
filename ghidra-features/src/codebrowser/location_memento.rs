//! Location memento for the code viewer.
//!
//! Ports `ghidra.app.plugin.core.codebrowser.CodeViewerLocationMemento`,
//! which extends the base `LocationMemento` with a cursor offset for
//! preserving/restoring the exact position within a listing field.

use std::collections::HashMap;
use std::fmt;

/// A serializable snapshot of the code viewer's position.
///
/// Captures both the program location (address + component offsets) and the
/// cursor offset within the listing field, so that the exact view can be
/// restored after navigation or tool restart.
///
/// Ported from Ghidra's `CodeViewerLocationMemento`.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct CodeViewerLocationMemento {
    /// The program identifier (domain file path or name).
    pub program_id: Option<String>,
    /// The program address as a hex string.
    pub address: Option<String>,
    /// Row within the current field.
    pub row: i32,
    /// Column within the current field.
    pub col: i32,
    /// Field number within the current layout row.
    pub field_num: i32,
    /// Row index in the layout.
    pub index: i32,
    /// X offset of the viewport.
    pub x_offset: i32,
    /// Y offset of the viewport.
    pub y_offset: i32,
    /// Cursor offset within the listing panel's field panel.
    cursor_offset: i32,
}

impl CodeViewerLocationMemento {
    /// Create a new memento with all fields specified.
    pub fn new(
        program_id: Option<String>,
        address: Option<String>,
        row: i32,
        col: i32,
        field_num: i32,
        index: i32,
        x_offset: i32,
        y_offset: i32,
        cursor_offset: i32,
    ) -> Self {
        Self {
            program_id,
            address,
            row,
            col,
            field_num,
            index,
            x_offset,
            y_offset,
            cursor_offset,
        }
    }

    /// Create a minimal memento with just an address and cursor offset.
    pub fn with_address(address: impl Into<String>, cursor_offset: i32) -> Self {
        Self {
            program_id: None,
            address: Some(address.into()),
            row: 0,
            col: 0,
            field_num: 0,
            index: 0,
            x_offset: 0,
            y_offset: 0,
            cursor_offset,
        }
    }

    /// Get the cursor offset.
    pub fn cursor_offset(&self) -> i32 {
        self.cursor_offset
    }

    /// Serialize this memento to a key-value map (for save-state persistence).
    ///
    /// Ports `CodeViewerLocationMemento.saveState(SaveState)`.
    pub fn save_state(&self) -> HashMap<String, String> {
        let mut map = HashMap::new();
        if let Some(ref pid) = self.program_id {
            map.insert("PROGRAM_ID".to_string(), pid.clone());
        }
        if let Some(ref addr) = self.address {
            map.insert("ADDRESS".to_string(), addr.clone());
        }
        map.insert("ROW".to_string(), self.row.to_string());
        map.insert("COL".to_string(), self.col.to_string());
        map.insert("FIELD_NUM".to_string(), self.field_num.to_string());
        map.insert("INDEX".to_string(), self.index.to_string());
        map.insert("X_OFFSET".to_string(), self.x_offset.to_string());
        map.insert("Y_OFFSET".to_string(), self.y_offset.to_string());
        map.insert("CURSOR_OFFSET".to_string(), self.cursor_offset.to_string());
        map
    }

    /// Restore a memento from a key-value map.
    ///
    /// Ports `CodeViewerLocationMemento(SaveState, Program[])`.
    pub fn from_state(state: &HashMap<String, String>) -> Self {
        let program_id = state.get("PROGRAM_ID").cloned();
        let address = state.get("ADDRESS").cloned();
        let row = state
            .get("ROW")
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        let col = state
            .get("COL")
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        let field_num = state
            .get("FIELD_NUM")
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        let index = state
            .get("INDEX")
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        let x_offset = state
            .get("X_OFFSET")
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        let y_offset = state
            .get("Y_OFFSET")
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        let cursor_offset = state
            .get("CURSOR_OFFSET")
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);

        Self::new(
            program_id, address, row, col, field_num, index, x_offset, y_offset, cursor_offset,
        )
    }
}

impl fmt::Display for CodeViewerLocationMemento {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "CodeViewerLocationMemento(addr={:?}, cursor_offset={})",
            self.address, self.cursor_offset
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memento_creation() {
        let m = CodeViewerLocationMemento::new(
            Some("test.exe".into()),
            Some("0x100000".into()),
            5,
            10,
            2,
            100,
            0,
            50,
            42,
        );
        assert_eq!(m.cursor_offset(), 42);
        assert_eq!(m.address.as_deref(), Some("0x100000"));
        assert_eq!(m.row, 5);
        assert_eq!(m.col, 10);
    }

    #[test]
    fn test_memento_with_address() {
        let m = CodeViewerLocationMemento::with_address("0xDEAD", 7);
        assert_eq!(m.address.as_deref(), Some("0xDEAD"));
        assert_eq!(m.cursor_offset(), 7);
        assert_eq!(m.row, 0);
        assert_eq!(m.col, 0);
    }

    #[test]
    fn test_save_restore_state() {
        let original = CodeViewerLocationMemento::new(
            Some("prog.gzf".into()),
            Some("0x401000".into()),
            3,
            7,
            1,
            50,
            10,
            20,
            15,
        );
        let state = original.save_state();
        let restored = CodeViewerLocationMemento::from_state(&state);

        assert_eq!(restored.program_id, Some("prog.gzf".into()));
        assert_eq!(restored.address, Some("0x401000".into()));
        assert_eq!(restored.row, 3);
        assert_eq!(restored.col, 7);
        assert_eq!(restored.field_num, 1);
        assert_eq!(restored.index, 50);
        assert_eq!(restored.x_offset, 10);
        assert_eq!(restored.y_offset, 20);
        assert_eq!(restored.cursor_offset(), 15);
    }

    #[test]
    fn test_from_state_defaults() {
        let state = HashMap::new();
        let m = CodeViewerLocationMemento::from_state(&state);
        assert_eq!(m.cursor_offset(), 0);
        assert!(m.address.is_none());
        assert!(m.program_id.is_none());
    }

    #[test]
    fn test_display() {
        let m = CodeViewerLocationMemento::with_address("0x1000", 3);
        let display = format!("{}", m);
        assert!(display.contains("0x1000"));
        assert!(display.contains("cursor_offset=3"));
    }

    #[test]
    fn test_serialization_roundtrip() {
        let m = CodeViewerLocationMemento::with_address("0x2000", 8);
        let json = serde_json::to_string(&m).unwrap();
        let deserialized: CodeViewerLocationMemento = serde_json::from_str(&json).unwrap();
        assert_eq!(m, deserialized);
    }
}
