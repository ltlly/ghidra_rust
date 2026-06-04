//! Equate commands -- background operations that modify the equate table.
//!
//! Ported from the command classes in `ghidra.app.plugin.core.equate`:
//!
//! - [`CreateEquateCmd`] -- create equates over a range of code units
//! - [`RenameEquateCmd`] -- rename a single equate reference at one location
//! - [`RenameEquatesCmd`] -- rename all references of an equate
//! - [`RemoveEquateCmd`] -- remove one or more equates by name
//! - [`CreateEnumEquateCommand`] -- apply an enum's fields as equates
//! - [`ConvertCommand`] -- convert a scalar to a different display format
//!
//! Each command implements the [`Command`] trait.

use super::manager::{EquateManager, EquateTable};
use super::format::{format_scalar, FormatChoice};
use super::Scalar;
use ghidra_core::Address;
use std::collections::HashSet;

// ---------------------------------------------------------------------------
// Command trait -- mirrors ghidra.framework.cmd.Command
// ---------------------------------------------------------------------------

/// A command that can be applied to an [`EquateTable`].
///
/// Corresponds to Ghidra's `Command<Program>` interface.
pub trait Command {
    /// The human-readable name of this command.
    fn name(&self) -> &str;

    /// Apply the command. Returns `Ok(())` on success, or an error message.
    fn apply(&mut self, table: &mut EquateTable) -> Result<(), String>;

    /// The status message if `apply` failed.
    fn status_msg(&self) -> Option<&str> {
        None
    }
}

// ---------------------------------------------------------------------------
// CreateEquateCmd
// ---------------------------------------------------------------------------

/// Creates equates for all code units in a range whose scalar operand matches
/// the target value.
///
/// Corresponds to `ghidra.app.plugin.core.equate.CreateEquateCmd`.
#[derive(Debug)]
pub struct CreateEquateCmd {
    /// The scalar value to search for.
    target_value: i64,
    /// Code units to iterate over: (address, op_index, scalar_value) triples.
    locations: Vec<(Address, i32, i64)>,
    /// The name for the new equate (or `None` if using an enum).
    equate_name: Option<String>,
    /// Enum UUID + value -> formatted name (if using an enum).
    enum_uuid: Option<String>,
    /// Whether to overwrite existing equates.
    overwrite_existing: bool,
    /// Error message from the last `apply`.
    msg: Option<String>,
}

impl CreateEquateCmd {
    /// Create a command with an explicit equate name.
    pub fn new(
        scalar: &Scalar,
        locations: Vec<(Address, i32, i64)>,
        equate_name: impl Into<String>,
        overwrite_existing: bool,
    ) -> Self {
        Self {
            target_value: scalar.value(),
            locations,
            equate_name: Some(equate_name.into()),
            enum_uuid: None,
            overwrite_existing,
            msg: None,
        }
    }

    /// Create a command using an enum UUID to generate equate names.
    pub fn with_enum(
        scalar: &Scalar,
        locations: Vec<(Address, i32, i64)>,
        enum_uuid: impl Into<String>,
        overwrite_existing: bool,
    ) -> Self {
        Self {
            target_value: scalar.value(),
            locations,
            equate_name: None,
            enum_uuid: Some(enum_uuid.into()),
            overwrite_existing,
            msg: None,
        }
    }

    /// Compute the effective equate name for a given value.
    fn effective_name(&self, value: i64) -> String {
        if let Some(ref name) = self.equate_name {
            name.clone()
        } else if let Some(ref uuid) = self.enum_uuid {
            EquateManager::format_name_for_equate(uuid, value)
        } else {
            format!("EQU_{:x}", value)
        }
    }
}

impl Command for CreateEquateCmd {
    fn name(&self) -> &str {
        "Create New Equate"
    }

    fn apply(&mut self, table: &mut EquateTable) -> Result<(), String> {
        for &(addr, op_index, scalar_value) in &self.locations {
            if scalar_value != self.target_value {
                continue;
            }
            let name = self.effective_name(scalar_value);

            // Check if there's already an equate at this location with this value.
            if let Some(existing) = table.get_equate_at(&addr, op_index, scalar_value) {
                if self.overwrite_existing && existing.name != name {
                    let old_name = existing.name.clone();
                    // Rename at this location.
                    table.remove_reference(&old_name, &addr, op_index);
                    if !table.contains_key(&name) {
                        let _ = table.create_equate(&name, scalar_value);
                    }
                    table.add_reference(&name, addr, op_index);
                }
            } else {
                // No equate at this location -- create one.
                if table.get_equate(&name).is_none() {
                    let _ = table.create_equate(&name, scalar_value);
                }
                table.add_reference(&name, addr, op_index);
            }
        }
        Ok(())
    }

    fn status_msg(&self) -> Option<&str> {
        self.msg.as_deref()
    }
}

// ---------------------------------------------------------------------------
// RenameEquateCmd
// ---------------------------------------------------------------------------

/// Renames the equate at a single (address, op_index) location.
///
/// Corresponds to `ghidra.app.plugin.core.equate.RenameEquateCmd`.
#[derive(Debug)]
pub struct RenameEquateCmd {
    old_name: String,
    new_name: Option<String>,
    enum_uuid: Option<String>,
    addr: Address,
    op_index: i32,
    msg: Option<String>,
}

impl RenameEquateCmd {
    /// Create a rename command with explicit old and new names.
    pub fn new(
        old_name: impl Into<String>,
        new_name: impl Into<String>,
        addr: Address,
        op_index: i32,
    ) -> Self {
        Self {
            old_name: old_name.into(),
            new_name: Some(new_name.into()),
            enum_uuid: None,
            addr,
            op_index,
            msg: None,
        }
    }

    /// Create a rename command using an enum UUID (the new name is derived
    /// from the enum and the scalar value).
    pub fn with_enum(
        old_name: impl Into<String>,
        enum_uuid: impl Into<String>,
        addr: Address,
        op_index: i32,
    ) -> Self {
        Self {
            old_name: old_name.into(),
            new_name: None,
            enum_uuid: Some(enum_uuid.into()),
            addr,
            op_index,
            msg: None,
        }
    }

    fn effective_new_name(&self, value: i64) -> String {
        if let Some(ref name) = self.new_name {
            name.clone()
        } else if let Some(ref uuid) = self.enum_uuid {
            EquateManager::format_name_for_equate(uuid, value)
        } else {
            self.old_name.clone()
        }
    }
}

impl Command for RenameEquateCmd {
    fn name(&self) -> &str {
        "Rename Equate"
    }

    fn apply(&mut self, table: &mut EquateTable) -> Result<(), String> {
        // Look up the old equate.
        let from_value = match table.get_equate(&self.old_name) {
            Some(eq) => eq.value,
            None => {
                self.msg = Some(format!("Equate not found: {}", self.old_name));
                return Err(self.msg.clone().unwrap());
            }
        };

        let new_name = self.effective_new_name(from_value);

        // Remove the reference from the old equate.
        table.remove_reference(&self.old_name, &self.addr, self.op_index);

        // If old equate has no references left, remove it entirely.
        if let Some(eq) = table.get_equate(&self.old_name) {
            if eq.reference_count() == 0 {
                table.remove_equate(&self.old_name);
            }
        }

        // Ensure the new equate exists.
        if table.get_equate(&new_name).is_none() {
            let _ = table.create_equate(&new_name, from_value);
        }

        // Add the reference to the new equate.
        table.add_reference(&new_name, self.addr, self.op_index);

        Ok(())
    }

    fn status_msg(&self) -> Option<&str> {
        self.msg.as_deref()
    }
}

// ---------------------------------------------------------------------------
// RenameEquatesCmd
// ---------------------------------------------------------------------------

/// Renames *all* references of an equate to a new name.
///
/// Corresponds to `ghidra.app.plugin.core.equate.RenameEquatesCmd`.
#[derive(Debug)]
pub struct RenameEquatesCmd {
    old_name: String,
    new_name: String,
    msg: Option<String>,
}

impl RenameEquatesCmd {
    pub fn new(old_name: impl Into<String>, new_name: impl Into<String>) -> Self {
        Self {
            old_name: old_name.into(),
            new_name: new_name.into(),
            msg: None,
        }
    }
}

impl Command for RenameEquatesCmd {
    fn name(&self) -> &str {
        "Rename Equates"
    }

    fn apply(&mut self, table: &mut EquateTable) -> Result<(), String> {
        if !table.rename_equate(&self.old_name, &self.new_name) {
            self.msg = Some(format!("Failed to rename equate: {}", self.old_name));
            return Err(self.msg.clone().unwrap());
        }
        Ok(())
    }

    fn status_msg(&self) -> Option<&str> {
        self.msg.as_deref()
    }
}

// ---------------------------------------------------------------------------
// RemoveEquateCmd
// ---------------------------------------------------------------------------

/// Removes one or more equates by name.
///
/// Corresponds to `ghidra.app.plugin.core.equate.RemoveEquateCmd`.
#[derive(Debug)]
pub struct RemoveEquateCmd {
    equate_names: Vec<String>,
    msg: Option<String>,
}

impl RemoveEquateCmd {
    pub fn new(names: Vec<impl Into<String>>) -> Self {
        Self {
            equate_names: names.into_iter().map(|n| n.into()).collect(),
            msg: None,
        }
    }

    /// Convenience: remove a single equate.
    pub fn single(name: impl Into<String>) -> Self {
        Self {
            equate_names: vec![name.into()],
            msg: None,
        }
    }
}

impl Command for RemoveEquateCmd {
    fn name(&self) -> &str {
        if self.equate_names.len() > 1 {
            "Remove Equates"
        } else {
            "Remove Equate"
        }
    }

    fn apply(&mut self, table: &mut EquateTable) -> Result<(), String> {
        let mut all_ok = true;
        for name in &self.equate_names {
            if !table.remove_equate(name) {
                all_ok = false;
            }
        }
        if !all_ok {
            self.msg = Some("Failed to remove one or more equates".to_string());
            return Err(self.msg.clone().unwrap());
        }
        Ok(())
    }

    fn status_msg(&self) -> Option<&str> {
        self.msg.as_deref()
    }
}

// ---------------------------------------------------------------------------
// CreateEnumEquateCommand
// ---------------------------------------------------------------------------

/// Applies an enum's fields as equates to all matching scalars in a range
/// of addresses.
///
/// Corresponds to `ghidra.app.plugin.core.equate.CreateEnumEquateCommand`.
#[derive(Debug)]
pub struct CreateEnumEquateCommand {
    /// Locations to process: (address, op_index, scalar_value).
    locations: Vec<(Address, i32, i64)>,
    /// The enum UUID.
    enum_uuid: String,
    /// The set of valid values in the enum.
    enum_values: HashSet<i64>,
    /// Whether to apply to sub-operands as well.
    should_do_on_sub_ops: bool,
    msg: Option<String>,
}

impl CreateEnumEquateCommand {
    /// Create a new command.
    ///
    /// `enum_values` is the set of all values defined in the enum.
    pub fn new(
        locations: Vec<(Address, i32, i64)>,
        enum_uuid: impl Into<String>,
        enum_values: HashSet<i64>,
        should_do_on_sub_ops: bool,
    ) -> Self {
        Self {
            locations,
            enum_uuid: enum_uuid.into(),
            enum_values,
            should_do_on_sub_ops,
            msg: None,
        }
    }
}

impl Command for CreateEnumEquateCommand {
    fn name(&self) -> &str {
        "Create Enum Equate Command"
    }

    fn apply(&mut self, table: &mut EquateTable) -> Result<(), String> {
        for &(addr, op_index, value) in &self.locations {
            // Only process if the value matches an enum field.
            if !self.enum_values.contains(&value) {
                continue;
            }

            let equate_name = EquateManager::format_name_for_equate(&self.enum_uuid, value);

            // Remove existing equate at this location if it exists.
            if let Some(existing) = table.get_equate_at(&addr, op_index, value) {
                if existing.name != equate_name {
                    let old_name = existing.name.clone();
                    table.remove_reference(&old_name, &addr, op_index);
                    // If old equate is now empty, remove it.
                    if let Some(eq) = table.get_equate(&old_name) {
                        if eq.reference_count() == 0 {
                            table.remove_equate(&old_name);
                        }
                    }
                } else {
                    continue; // already set
                }
            }

            // Ensure the enum equate exists.
            if table.get_equate(&equate_name).is_none() {
                let _ = table.create_equate(&equate_name, value);
            }

            table.add_reference(&equate_name, addr, op_index);
        }
        Ok(())
    }

    fn status_msg(&self) -> Option<&str> {
        self.msg.as_deref()
    }
}

// ---------------------------------------------------------------------------
// ConvertCommand
// ---------------------------------------------------------------------------

/// Converts the scalar at a location (or over a selection) to a different
/// display format by creating/modifying equates.
///
/// Corresponds to `ghidra.app.plugin.core.equate.ConvertCommand`.
#[derive(Debug)]
pub struct ConvertCommand {
    /// Locations to process: (address, op_index, scalar_value).
    locations: Vec<(Address, i32, i64)>,
    /// The target format.
    format: FormatChoice,
    /// Whether the target format is signed.
    is_signed: bool,
    /// Whether this is operating on data items (vs instructions).
    is_data: bool,
    msg: Option<String>,
}

impl ConvertCommand {
    /// Create a new convert command.
    pub fn new(
        locations: Vec<(Address, i32, i64)>,
        format: FormatChoice,
        is_signed: bool,
        is_data: bool,
    ) -> Self {
        Self {
            locations,
            format,
            is_signed,
            is_data,
            msg: None,
        }
    }
}

impl Command for ConvertCommand {
    fn name(&self) -> &str {
        "Convert Command"
    }

    fn apply(&mut self, table: &mut EquateTable) -> Result<(), String> {
        for &(addr, op_index, raw_value) in &self.locations {
            let bit_length = 64; // assume full-width for generic conversion
            let scalar = if self.is_signed {
                Scalar::signed(bit_length, raw_value)
            } else {
                Scalar::unsigned(bit_length, raw_value as u64)
            };

            let equate_name = match format_scalar(&scalar, self.format, self.is_data) {
                Some(name) => name,
                None => continue,
            };

            if equate_name.is_empty() {
                continue;
            }

            // Check for conflicting equate with the same name but different value.
            if let Some(existing) = table.get_equate(&equate_name) {
                if existing.value != scalar.signed_value()
                    && existing.value != scalar.unsigned_value() as i64
                {
                    self.msg = Some(format!(
                        "Couldn't convert to {}. Equate named {} already exists with value {}.",
                        equate_name, equate_name, existing.value
                    ));
                    continue;
                }
            }

            // Remove any existing equates at this location with matching value.
            let existing_equates: Vec<String> = table
                .get_equates_at(&addr, op_index)
                .iter()
                .filter(|eq| eq.value == scalar.signed_value() || eq.value == scalar.unsigned_value() as i64)
                .map(|eq| eq.name.clone())
                .collect();
            for eq_name in existing_equates {
                table.clear_equate_at(&eq_name, &addr, op_index);
            }

            // Skip default hex if it's already the natural format.
            if self.format == FormatChoice::Hex && scalar.signed_value() >= 0 {
                continue;
            }

            // Create and add the new equate.
            if table.get_equate(&equate_name).is_none() {
                let _ = table.create_equate(&equate_name, scalar.value());
            }
            table.add_reference(&equate_name, addr, op_index);
        }

        Ok(())
    }

    fn status_msg(&self) -> Option<&str> {
        self.msg.as_deref()
    }
}

// ---------------------------------------------------------------------------
// Extensions on EquateTable for access by commands
// ---------------------------------------------------------------------------

impl EquateTable {
    /// Returns `true` if an equate with the given name exists.
    pub fn contains_key(&self, name: &str) -> bool {
        self.get_equate(name).is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::base::equate::manager::EquateTable;

    fn make_table() -> EquateTable {
        EquateTable::new()
    }

    #[test]
    fn test_create_equate_cmd() {
        let mut table = make_table();
        let scalar = Scalar::unsigned(32, 0xFF);
        let locs = vec![
            (Address::new(0x1000), 0, 0xFF),
            (Address::new(0x2000), 1, 0xFF),
            (Address::new(0x3000), 0, 0x42), // different value -- should be skipped
        ];
        let mut cmd = CreateEquateCmd::new(&scalar, locs, "BYTE_MAX", false);
        cmd.apply(&mut table).unwrap();

        let eq = table.get_equate("BYTE_MAX").unwrap();
        assert_eq!(eq.value, 0xFF);
        assert_eq!(eq.reference_count(), 2);
    }

    #[test]
    fn test_rename_equate_cmd() {
        let mut table = make_table();
        table.create_equate("OLD", 10).unwrap();
        table.add_reference("OLD", Address::new(0x1000), 0);

        let mut cmd = RenameEquateCmd::new("OLD", "NEW", Address::new(0x1000), 0);
        cmd.apply(&mut table).unwrap();

        assert!(table.get_equate("OLD").is_none());
        let eq = table.get_equate("NEW").unwrap();
        assert_eq!(eq.reference_count(), 1);
    }

    #[test]
    fn test_rename_equates_cmd() {
        let mut table = make_table();
        table.create_equate("OLD", 5).unwrap();
        table.add_reference("OLD", Address::new(0x1000), 0);
        table.add_reference("OLD", Address::new(0x2000), 1);

        let mut cmd = RenameEquatesCmd::new("OLD", "NEW");
        cmd.apply(&mut table).unwrap();

        assert!(table.get_equate("OLD").is_none());
        let eq = table.get_equate("NEW").unwrap();
        assert_eq!(eq.value, 5);
        assert_eq!(eq.reference_count(), 2);
    }

    #[test]
    fn test_remove_equate_cmd() {
        let mut table = make_table();
        table.create_equate("A", 1).unwrap();
        table.create_equate("B", 2).unwrap();

        let mut cmd = RemoveEquateCmd::new(vec!["A", "B"]);
        cmd.apply(&mut table).unwrap();
        assert!(table.is_empty());
    }

    #[test]
    fn test_remove_nonexistent_fails() {
        let mut table = make_table();
        let mut cmd = RemoveEquateCmd::single("NOPE");
        assert!(cmd.apply(&mut table).is_err());
    }

    #[test]
    fn test_create_enum_equate_command() {
        let mut table = make_table();
        let mut vals = HashSet::new();
        vals.insert(1);
        vals.insert(2);
        vals.insert(3);

        let locs = vec![
            (Address::new(0x1000), 0, 1),
            (Address::new(0x2000), 0, 2),
            (Address::new(0x3000), 0, 99), // not in enum
        ];

        let mut cmd = CreateEnumEquateCommand::new(locs, "test-uuid", vals, false);
        cmd.apply(&mut table).unwrap();

        let eq1_name = EquateManager::format_name_for_equate("test-uuid", 1);
        let eq2_name = EquateManager::format_name_for_equate("test-uuid", 2);
        let eq99_name = EquateManager::format_name_for_equate("test-uuid", 99);

        assert!(table.get_equate(&eq1_name).is_some());
        assert!(table.get_equate(&eq2_name).is_some());
        assert!(table.get_equate(&eq99_name).is_none()); // value 99 not in enum
    }

    #[test]
    fn test_convert_command() {
        let mut table = make_table();
        let locs = vec![(Address::new(0x1000), 0, 255)];
        let mut cmd = ConvertCommand::new(locs, FormatChoice::UnsignedDecimal, false, false);
        cmd.apply(&mut table).unwrap();

        // The equate name should be the decimal representation.
        let eq = table.get_equate("255");
        assert!(eq.is_some());
    }

    #[test]
    fn test_command_name() {
        let cmd = RemoveEquateCmd::new(vec!["A", "B"]);
        assert_eq!(cmd.name(), "Remove Equates");

        let cmd = RemoveEquateCmd::single("A");
        assert_eq!(cmd.name(), "Remove Equate");
    }
}
