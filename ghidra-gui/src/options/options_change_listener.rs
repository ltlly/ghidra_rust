//! Port of Ghidra's `ghidra.framework.options.OptionsChangeListener`.

/// Listener for option value changes.
pub trait OptionsChangeListener: Send + Sync {
    /// Called when an option value changes.
    fn option_changed(&self, _options_name: &str, _option_name: &str, _old_value: &str, _new_value: &str) {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[derive(Debug)]
    struct Mock { changes: Arc<Mutex<Vec<String>>> }
    impl OptionsChangeListener for Mock {
        fn option_changed(&self, opts: &str, name: &str, _old: &str, new: &str) {
            self.changes.lock().unwrap().push(format!("{}.{}={}", opts, name, new));
        }
    }

    #[test]
    fn test_option_change_listener() {
        let changes = Arc::new(Mutex::new(Vec::new()));
        let listener = Mock { changes: changes.clone() };
        listener.option_changed("tool", "fontSize", "12", "14");
        assert_eq!(changes.lock().unwrap()[0], "tool.fontSize=14");
    }
}
