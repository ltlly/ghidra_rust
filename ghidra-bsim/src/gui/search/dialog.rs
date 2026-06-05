//! BSim search dialog types.
//!
//! Ports `ghidra.features.bsim.gui.search.dialog` from Ghidra's Java source.

/// Configuration for creating a new BSim server info from the dialog.
#[derive(Debug, Clone)]
pub struct CreateBSimServerInfoDialog {
    /// Server name entered by the user.
    pub server_name: String,
    /// Backend type selected.
    pub backend_type: String,
    /// Hostname entered.
    pub hostname: String,
    /// Port entered.
    pub port: u16,
    /// Database name entered.
    pub database: String,
    /// Username entered.
    pub username: String,
}

impl Default for CreateBSimServerInfoDialog {
    fn default() -> Self {
        Self {
            server_name: String::new(),
            backend_type: "postgresql".into(),
            hostname: "localhost".into(),
            port: 5432,
            database: "bsim".into(),
            username: "bsim".into(),
        }
    }
}

impl CreateBSimServerInfoDialog {
    /// Validate the dialog inputs.
    pub fn validate(&self) -> Result<(), String> {
        if self.server_name.is_empty() {
            return Err("Server name is required".into());
        }
        if self.hostname.is_empty() {
            return Err("Hostname is required".into());
        }
        if self.database.is_empty() {
            return Err("Database name is required".into());
        }
        if self.port == 0 {
            return Err("Port must be non-zero".into());
        }
        Ok(())
    }
}

/// A dialog for selecting functions to search.
#[derive(Debug, Clone, Default)]
pub struct SelectedFunctionsTableDialog {
    /// Selected function entry points.
    pub selected_functions: Vec<u64>,
    /// Total functions available.
    pub total_functions: usize,
}

impl SelectedFunctionsTableDialog {
    /// Create a new dialog.
    pub fn new(total_functions: usize) -> Self {
        Self {
            selected_functions: Vec::new(),
            total_functions,
        }
    }

    /// Add a function to the selection.
    pub fn select(&mut self, entry_point: u64) {
        if !self.selected_functions.contains(&entry_point) {
            self.selected_functions.push(entry_point);
        }
    }

    /// Remove a function from the selection.
    pub fn deselect(&mut self, entry_point: u64) {
        self.selected_functions.retain(|&f| f != entry_point);
    }

    /// Toggle selection.
    pub fn toggle(&mut self, entry_point: u64) {
        if self.selected_functions.contains(&entry_point) {
            self.deselect(entry_point);
        } else {
            self.select(entry_point);
        }
    }

    /// Get the number of selected functions.
    pub fn selection_count(&self) -> usize {
        self.selected_functions.len()
    }

    /// Whether all functions are selected.
    pub fn is_all_selected(&self) -> bool {
        self.selected_functions.len() == self.total_functions
    }

    /// Select all functions.
    pub fn select_all(&mut self) {
        self.selected_functions = (0..self.total_functions as u64).collect();
    }

    /// Clear the selection.
    pub fn clear(&mut self) {
        self.selected_functions.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_dialog_validate() {
        let mut dialog = CreateBSimServerInfoDialog::default();
        assert!(dialog.validate().is_err()); // name is empty

        dialog.server_name = "test".into();
        assert!(dialog.validate().is_ok());
    }

    #[test]
    fn test_create_dialog_validate_empty_hostname() {
        let dialog = CreateBSimServerInfoDialog {
            server_name: "test".into(),
            hostname: String::new(),
            ..Default::default()
        };
        assert!(dialog.validate().is_err());
        assert!(dialog.validate().unwrap_err().contains("Hostname"));
    }

    #[test]
    fn test_selected_functions_dialog() {
        let mut dialog = SelectedFunctionsTableDialog::new(100);
        assert_eq!(dialog.selection_count(), 0);

        dialog.select(0x1000);
        dialog.select(0x2000);
        assert_eq!(dialog.selection_count(), 2);

        dialog.toggle(0x1000);
        assert_eq!(dialog.selection_count(), 1);

        dialog.toggle(0x3000);
        assert_eq!(dialog.selection_count(), 2);
    }

    #[test]
    fn test_selected_functions_select_all() {
        let mut dialog = SelectedFunctionsTableDialog::new(10);
        assert!(!dialog.is_all_selected());

        dialog.select_all();
        assert!(dialog.is_all_selected());
        assert_eq!(dialog.selection_count(), 10);

        dialog.clear();
        assert_eq!(dialog.selection_count(), 0);
        assert!(!dialog.is_all_selected());
    }
}
