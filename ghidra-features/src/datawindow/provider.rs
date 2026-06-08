//! Data window provider.
//!
//! Ported from `ghidra.app.plugin.core.datawindow.DataWindowProvider`.
//!
//! Provides a window that shows the data items at and around the
//! current address, with options to create new data, convert between

/// Actions available in the data window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataWindowAction {
    CreateData,
    CreateArray,
    CreatePointer,
    CreateString,
    CreateTerminatedCString,
    CreateUnicode,
    ClearData,
    CycleDataType,
    CycleForward,
    CycleBackward,
    EditData,
    RetypeData,
}

impl DataWindowAction {
    /// Get the action name.
    pub fn name(&self) -> &'static str {
        match self {
            Self::CreateData => "Create Data",
            Self::CreateArray => "Create Array",
            Self::CreatePointer => "Create Pointer",
            Self::CreateString => "Create String",
            Self::CreateTerminatedCString => "Create Terminated CString",
            Self::CreateUnicode => "Create Unicode",
            Self::ClearData => "Clear Data",
            Self::CycleDataType => "Cycle Data Type",
            Self::CycleForward => "Cycle Forward",
            Self::CycleBackward => "Cycle Backward",
            Self::EditData => "Edit Data",
            Self::RetypeData => "Retype Data",
        }
    }

    /// Get the key binding hint.
    pub fn key_binding(&self) -> Option<&'static str> {
        match self {
            Self::CreateData => Some("D"),
            Self::CreateArray => Some("[" ),
            Self::ClearData => Some("C"),
            Self::CycleForward => Some("."),
            Self::CycleBackward => Some(","),
            _ => None,
        }
    }

    /// Whether this action is enabled for the given context.
    pub fn is_enabled(&self, has_data: bool, has_selection: bool) -> bool {
        match self {
            Self::CreateData | Self::CreateArray | Self::CreatePointer
            | Self::CreateString | Self::CreateTerminatedCString | Self::CreateUnicode => {
                !has_data || has_selection
            }
            Self::ClearData => has_data,
            Self::CycleDataType | Self::CycleForward | Self::CycleBackward => has_data,
            Self::EditData | Self::RetypeData => has_data,
        }
    }
}

/// Information about a data item displayed in the data window.
#[derive(Debug, Clone)]
pub struct DataWindowEntry {
    /// Address of the data item.
    pub address: u64,
    /// Data type name.
    pub data_type: String,
    /// Representation of the value.
    pub value_repr: String,
    /// Size in bytes.
    pub size: usize,
    /// Whether the item is undefined.
    pub is_undefined: bool,
    /// Label at this address (if any).
    pub label: Option<String>,
}

/// Provider for the data window.
#[derive(Debug)]
pub struct DataWindowProvider {
    /// Data entries displayed in the window.
    entries: Vec<DataWindowEntry>,
    /// Selected index.
    selected: Option<usize>,
    /// Whether the provider is visible.
    visible: bool,
}

impl DataWindowProvider {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            selected: None,
            visible: false,
        }
    }

    pub fn set_entries(&mut self, entries: Vec<DataWindowEntry>) {
        self.entries = entries;
        self.selected = None;
    }

    pub fn entries(&self) -> &[DataWindowEntry] {
        &self.entries
    }

    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    pub fn select(&mut self, index: Option<usize>) {
        self.selected = index;
    }

    pub fn selected(&self) -> Option<&DataWindowEntry> {
        self.selected.and_then(|i| self.entries.get(i))
    }

    pub fn set_visible(&mut self, visible: bool) {
        self.visible = visible;
    }

    pub fn is_visible(&self) -> bool {
        self.visible
    }
}

impl Default for DataWindowProvider {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_data_window_action_names() {
        assert_eq!(DataWindowAction::CreateData.name(), "Create Data");
        assert_eq!(DataWindowAction::ClearData.key_binding(), Some("C"));
    }

    #[test]
    fn test_action_enabled() {
        assert!(DataWindowAction::ClearData.is_enabled(true, false));
        assert!(!DataWindowAction::ClearData.is_enabled(false, false));
        assert!(DataWindowAction::CreateData.is_enabled(false, false));
    }

    #[test]
    fn test_provider_entries() {
        let mut provider = DataWindowProvider::new();
        provider.set_entries(vec![
            DataWindowEntry {
                address: 0x1000,
                data_type: "dd".to_string(),
                value_repr: "0x12345678".to_string(),
                size: 4,
                is_undefined: false,
                label: Some("DAT_0x1000".to_string()),
            },
        ]);
        assert_eq!(provider.entry_count(), 1);
        provider.select(Some(0));
        assert_eq!(provider.selected().unwrap().address, 0x1000);
    }

    #[test]
    fn test_provider_visibility() {
        let mut provider = DataWindowProvider::new();
        assert!(!provider.is_visible());
        provider.set_visible(true);
        assert!(provider.is_visible());
    }
}
