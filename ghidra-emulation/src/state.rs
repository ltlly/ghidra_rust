//! Emulator state: registers, flags, and register definitions.
//!
//! [`EmulatorState`] holds the current register and flag values during
//! emulation. Registers are keyed by string name (e.g., `"RAX"`, `"reg:0"`,
//! `"PC"`) and stored as raw byte vectors. Flags are boolean key-value pairs
//! (e.g., `"ZF"`, `"CF"`, `"SF"`, `"OF"`).
//!
//! This module also provides [`RegisterDefinition`] for describing registers
//! and [`AccessReason`] for tracking why state is being read (mirroring
//! Ghidra's `PcodeExecutorStatePiece.Reason`).

use std::collections::HashMap;

// ---------------------------------------------------------------------------
// AccessReason
// ---------------------------------------------------------------------------

/// Why a register or memory location is being read.
///
/// Mirrors Ghidra's `PcodeExecutorStatePiece.Reason` enum, which allows
/// state implementations to behave differently during instruction decode
/// vs. execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AccessReason {
    /// Reading for initial program counter or disassembly context.
    Init,
    /// Reading as data during emulated instruction execution.
    ExecuteRead,
    /// Decoding an instruction for emulation.
    ExecuteDecode,
    /// Inspecting state outside of emulation (e.g., debugger UI).
    Inspect,
}

impl Default for AccessReason {
    fn default() -> Self {
        AccessReason::ExecuteRead
    }
}

// ---------------------------------------------------------------------------
// RegisterDefinition
// ---------------------------------------------------------------------------

/// Describes a single processor register.
///
/// Ported from Ghidra's `Register` class, this captures the register's
/// name, bit-offset within the register address space, size, and whether
/// it is a sub-register of a larger one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisterDefinition {
    /// Register name (e.g., `"RAX"`, `"EFLAGS"`, `"PC"`).
    pub name: String,
    /// Byte offset in the register address space.
    pub offset: u64,
    /// Size of the register in bytes.
    pub size: u32,
    /// If this is a sub-register, the name of the parent register.
    pub parent: Option<String>,
    /// Bit-length of the register (size * 8, or custom for flag bits).
    pub bit_length: u32,
}

impl RegisterDefinition {
    /// Create a new register definition.
    pub fn new(name: impl Into<String>, offset: u64, size: u32) -> Self {
        let n = name.into();
        Self {
            bit_length: size * 8,
            name: n,
            offset,
            size,
            parent: None,
        }
    }

    /// Create a sub-register definition (a slice of a parent register).
    pub fn sub_register(
        name: impl Into<String>,
        offset: u64,
        size: u32,
        parent: impl Into<String>,
    ) -> Self {
        Self {
            bit_length: size * 8,
            name: name.into(),
            offset,
            size,
            parent: Some(parent.into()),
        }
    }

    /// Return the key used to store this register in [`EmulatorState`].
    pub fn key(&self) -> String {
        format!("register:0x{:x}", self.offset)
    }
}

// ---------------------------------------------------------------------------
// EmulatorState
// ---------------------------------------------------------------------------

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
    /// Register definitions for this processor.
    register_defs: HashMap<String, RegisterDefinition>,
}

/// A full snapshot of emulator state, used for save/restore.
///
/// Ported from Ghidra's state snapshot concept: the emulator can save
/// its entire register/flag state before a dangerous operation and
/// roll back if the operation fails.
#[derive(Debug, Clone)]
pub struct StateSnapshot {
    /// All register values at the time of the snapshot.
    pub registers: HashMap<String, Vec<u8>>,
    /// All flag values at the time of the snapshot.
    pub flags: HashMap<String, bool>,
}

impl EmulatorState {
    /// Create a new empty emulator state.
    pub fn new() -> Self {
        Self {
            registers: HashMap::new(),
            flags: HashMap::new(),
            register_defs: HashMap::new(),
        }
    }

    // -- register access -------------------------------------------------

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

    /// Get a register value by name, returning a default of all zeros if
    /// the register has not been set.
    pub fn get_register_or_zero(&self, name: &str, size: usize) -> Vec<u8> {
        self.registers
            .get(name)
            .cloned()
            .unwrap_or_else(|| vec![0u8; size])
    }

    /// Delete a register from state.
    pub fn remove_register(&mut self, name: &str) -> Option<Vec<u8>> {
        self.registers.remove(name)
    }

    /// Return all register names.
    pub fn register_names(&self) -> Vec<&str> {
        self.registers.keys().map(|s| s.as_str()).collect()
    }

    // -- flag access ------------------------------------------------------

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

    /// Delete a flag from state.
    pub fn remove_flag(&mut self, name: &str) -> Option<bool> {
        self.flags.remove(name)
    }

    // -- register definitions --------------------------------------------

    /// Register a register definition.
    pub fn define_register(&mut self, def: RegisterDefinition) {
        self.register_defs.insert(def.name.clone(), def);
    }

    /// Get a register definition by name.
    pub fn get_register_def(&self, name: &str) -> Option<&RegisterDefinition> {
        self.register_defs.get(name)
    }

    /// Get a register definition by its offset-key form.
    pub fn get_register_def_by_key(&self, key: &str) -> Option<&RegisterDefinition> {
        self.register_defs.values().find(|d| d.key() == key)
    }

    /// Return all register definitions.
    pub fn register_definitions(&self) -> &HashMap<String, RegisterDefinition> {
        &self.register_defs
    }

    /// Write to a sub-register by name. The sub-register value is written
    /// into the correct byte range of the parent register.
    pub fn write_sub_register(
        &mut self,
        name: &str,
        value: &[u8],
    ) -> Result<(), String> {
        let def = self
            .register_defs
            .get(name)
            .cloned()
            .ok_or_else(|| format!("unknown register: {}", name))?;

        let parent_name = def.parent.as_deref().unwrap_or(name);
        let parent_def = self
            .register_defs
            .get(parent_name)
            .cloned()
            .unwrap_or_else(|| RegisterDefinition::new(parent_name, def.offset, def.size));

        let offset_in_parent = (def.offset - parent_def.offset) as usize;
        let mut parent_val =
            self.get_register(parent_name).map(|v| v.to_vec()).unwrap_or_else(|| {
                vec![0u8; parent_def.size as usize]
            });

        let write_len = value.len().min(def.size as usize);
        let end = (offset_in_parent + write_len).min(parent_val.len());
        if offset_in_parent < parent_val.len() {
            parent_val[offset_in_parent..end].copy_from_slice(&value[..end - offset_in_parent]);
        }
        self.set_register(parent_name, &parent_val);
        Ok(())
    }

    /// Read from a sub-register by name.
    pub fn read_sub_register(&self, name: &str) -> Result<Vec<u8>, String> {
        let def = self
            .register_defs
            .get(name)
            .ok_or_else(|| format!("unknown register: {}", name))?;

        let parent_name = def.parent.as_deref().unwrap_or(name);
        let parent_val = self.get_register(parent_name);
        let offset_in_parent = (def.offset - {
            self.register_defs
                .get(parent_name)
                .map(|d| d.offset)
                .unwrap_or(def.offset)
        }) as usize;

        match parent_val {
            Some(bytes) => {
                let end = (offset_in_parent + def.size as usize).min(bytes.len());
                if offset_in_parent < bytes.len() {
                    Ok(bytes[offset_in_parent..end].to_vec())
                } else {
                    Ok(vec![0u8; def.size as usize])
                }
            }
            None => Ok(vec![0u8; def.size as usize]),
        }
    }

    // -- snapshot / restore ----------------------------------------------

    /// Take a complete snapshot of all registers and flags.
    ///
    /// This mirrors Ghidra's state-save mechanism used before emulating
    /// potentially-failing instructions so that the state can be rolled
    /// back on error.
    pub fn save_snapshot(&self) -> StateSnapshot {
        StateSnapshot {
            registers: self.registers.clone(),
            flags: self.flags.clone(),
        }
    }

    /// Restore state from a previously-taken snapshot.
    ///
    /// All current registers and flags are replaced with the snapshot
    /// contents.
    pub fn restore_snapshot(&mut self, snapshot: &StateSnapshot) {
        self.registers = snapshot.registers.clone();
        self.flags = snapshot.flags.clone();
    }

    /// Take a snapshot of all register values only (for diff computation).
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

    /// Clear all registers and flags.
    pub fn clear(&mut self) {
        self.registers.clear();
        self.flags.clear();
    }

    /// Clear all registers and flags, preserving register definitions.
    pub fn clear_state(&mut self) {
        self.registers.clear();
        self.flags.clear();
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
    fn test_get_register_or_zero() {
        let mut state = EmulatorState::new();
        let zero = state.get_register_or_zero("RAX", 8);
        assert_eq!(zero, vec![0u8; 8]);

        state.set_register("RAX", &[1, 2, 3, 4]);
        let val = state.get_register_or_zero("RAX", 4);
        assert_eq!(val, vec![1, 2, 3, 4]);
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
    fn test_register_definitions() {
        let mut state = EmulatorState::new();
        state.define_register(RegisterDefinition::new("RAX", 0, 8));
        state.define_register(RegisterDefinition::sub_register("EAX", 0, 4, "RAX"));
        state.define_register(RegisterDefinition::sub_register("AX", 0, 2, "RAX"));

        let rax_def = state.get_register_def("RAX").unwrap();
        assert_eq!(rax_def.size, 8);

        let eax_def = state.get_register_def("EAX").unwrap();
        assert_eq!(eax_def.parent.as_deref(), Some("RAX"));
    }

    #[test]
    fn test_sub_register_write() {
        let mut state = EmulatorState::new();
        state.define_register(RegisterDefinition::new("RAX", 0, 8));
        state.define_register(RegisterDefinition::sub_register("EAX", 0, 4, "RAX"));

        state.set_register("RAX", &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
        state
            .write_sub_register("EAX", &[0x78, 0x56, 0x34, 0x12])
            .unwrap();

        let rax = state.get_register("RAX").unwrap();
        assert_eq!(&rax[..4], &[0x78, 0x56, 0x34, 0x12]);
        assert_eq!(&rax[4..], &[0xFF, 0xFF, 0xFF, 0xFF]);
    }

    #[test]
    fn test_sub_register_read() {
        let mut state = EmulatorState::new();
        state.define_register(RegisterDefinition::new("RAX", 0, 8));
        state.define_register(RegisterDefinition::sub_register("EAX", 0, 4, "RAX"));

        state.set_register("RAX", &[0x78, 0x56, 0x34, 0x12, 0x00, 0x00, 0x00, 0x00]);
        let eax = state.read_sub_register("EAX").unwrap();
        assert_eq!(eax, vec![0x78, 0x56, 0x34, 0x12]);
    }

    #[test]
    fn test_snapshot_restore() {
        let mut state = EmulatorState::new();
        state.set_register("RAX", &[1, 0, 0, 0, 0, 0, 0, 0]);
        state.set_register("RBX", &[2, 0, 0, 0, 0, 0, 0, 0]);
        state.set_flag("ZF", false);

        let snapshot = state.save_snapshot();

        // Modify state
        state.set_register("RAX", &[99, 0, 0, 0, 0, 0, 0, 0]);
        state.set_flag("ZF", true);
        state.set_register("RCX", &[3, 0, 0, 0, 0, 0, 0, 0]);

        // Restore
        state.restore_snapshot(&snapshot);

        assert_eq!(state.get_register("RAX").unwrap(), &[1, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(state.get_register("RBX").unwrap(), &[2, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(state.get_flag("ZF"), Some(false));
        assert!(state.get_register("RCX").is_none());
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

    #[test]
    fn test_register_names() {
        let mut state = EmulatorState::new();
        state.set_register("RAX", &[1]);
        state.set_register("RBX", &[2]);
        state.set_register("RCX", &[3]);

        let mut names: Vec<&str> = state.register_names();
        names.sort();
        assert_eq!(names, vec!["RAX", "RBX", "RCX"]);
    }

    #[test]
    fn test_access_reason_default() {
        let reason = AccessReason::default();
        assert_eq!(reason, AccessReason::ExecuteRead);
    }
}
