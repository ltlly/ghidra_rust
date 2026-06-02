//! Emulator state: registers and flags.
//!
//! [`EmulatorState`] holds the current register and flag values during
//! emulation. Registers are keyed by string name (e.g., `"RAX"`, `"reg:0"`,
//! `"PC"`) and stored as raw byte vectors. Flags are boolean key-value pairs
//! (e.g., `"ZF"`, `"CF"`, `"SF"`, `"OF"`).

use std::collections::HashMap;

/// Holds register and flag state for the emulator.
///
/// Registers are byte vectors keyed by name. Flags are boolean values
/// representing condition codes and other processor state bits.
#[derive(Debug, Clone, Default)]
pub struct EmulatorState {
    /// Register values keyed by name (e.g., `"RAX"`, `"reg:0"`).
    pub registers: HashMap<String, Vec<u8>>,
    /// Boolean flags (e.g., `"ZF"`, `"CF"`, `"SF"`, `"OF"`).
    pub flags: HashMap<String, bool>,
}

impl EmulatorState {
    /// Create a new empty emulator state.
    pub fn new() -> Self {
        Self {
            registers: HashMap::new(),
            flags: HashMap::new(),
        }
    }

    /// Set a register value by name.
    ///
    /// The value is stored as raw bytes. If the register already exists its
    /// value is replaced.
    pub fn set_register(&mut self, name: impl Into<String>, value: &[u8]) {
        self.registers.insert(name.into(), value.to_vec());
    }

    /// Get a register value by name.
    ///
    /// Returns `None` if the register has not been set.
    pub fn get_register(&self, name: &str) -> Option<&[u8]> {
        self.registers.get(name).map(|v| v.as_slice())
    }

    /// Set a boolean flag.
    pub fn set_flag(&mut self, name: impl Into<String>, value: bool) {
        self.flags.insert(name.into(), value);
    }

    /// Get a boolean flag value.
    ///
    /// Returns `None` if the flag has not been set.
    pub fn get_flag(&self, name: &str) -> Option<bool> {
        self.flags.get(name).copied()
    }

    /// Clear all registers and flags.
    pub fn clear(&mut self) {
        self.registers.clear();
        self.flags.clear();
    }

    /// Take a snapshot of all register values.
    pub fn snapshot_registers(&self) -> HashMap<String, Vec<u8>> {
        self.registers.clone()
    }

    /// Compute the difference between two register snapshots.
    ///
    /// Returns a map of register name to `(old_value, new_value)` for
    /// registers that changed.
    pub fn diff_registers(
        before: &HashMap<String, Vec<u8>>,
        after: &HashMap<String, Vec<u8>>,
    ) -> HashMap<String, (Vec<u8>, Vec<u8>)> {
        let mut changes = HashMap::new();

        // Registers that changed or were added
        for (name, new_val) in after.iter() {
            match before.get(name) {
                Some(old_val) if old_val != new_val => {
                    changes.insert(name.clone(), (old_val.clone(), new_val.clone()));
                }
                None => {
                    // New register added
                    changes.insert(name.clone(), (Vec::new(), new_val.clone()));
                }
                _ => {}
            }
        }

        // Registers that were removed
        for (name, old_val) in before.iter() {
            if !after.contains_key(name) {
                changes.insert(name.clone(), (old_val.clone(), Vec::new()));
            }
        }

        changes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_set_get_register() {
        let mut state = EmulatorState::new();
        state.set_register("RAX", &[0x78, 0x56, 0x34, 0x12]);
        let val = state.get_register("RAX").unwrap();
        assert_eq!(val, &[0x78, 0x56, 0x34, 0x12]);
    }

    #[test]
    fn test_get_register_not_found() {
        let state = EmulatorState::new();
        assert!(state.get_register("NONEXISTENT").is_none());
    }

    #[test]
    fn test_flags() {
        let mut state = EmulatorState::new();
        state.set_flag("ZF", true);
        state.set_flag("CF", false);
        assert_eq!(state.get_flag("ZF"), Some(true));
        assert_eq!(state.get_flag("CF"), Some(false));
        assert_eq!(state.get_flag("OF"), None);
    }

    #[test]
    fn test_diff_registers() {
        let mut before = HashMap::new();
        before.insert("RAX".to_string(), vec![1, 0, 0, 0]);
        before.insert("RBX".to_string(), vec![2, 0, 0, 0]);

        let mut after = HashMap::new();
        after.insert("RAX".to_string(), vec![3, 0, 0, 0]); // changed
        after.insert("RBX".to_string(), vec![2, 0, 0, 0]); // unchanged
        after.insert("RCX".to_string(), vec![4, 0, 0, 0]); // new

        let changes = EmulatorState::diff_registers(&before, &after);
        assert_eq!(changes.len(), 2); // RAX changed, RCX added
        assert_eq!(
            changes.get("RAX").unwrap(),
            &(vec![1, 0, 0, 0], vec![3, 0, 0, 0])
        );
        assert_eq!(changes.get("RCX").unwrap(), &(vec![], vec![4, 0, 0, 0]));
    }
}
