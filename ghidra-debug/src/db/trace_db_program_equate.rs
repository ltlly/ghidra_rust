//! DBTraceProgramViewEquate - equate adapter for program views.
//!
//! Ported from `ghidra.trace.database.program.DBTraceProgramViewEquate`.
//! Wraps a `DBTraceEquate` and adapts it to the `Equate` interface used by
//! program views. Provides name/value queries, reference management, and
//! enum-based equate detection.


/// Equate view adapter for a trace program view.
///
/// Wraps a trace equate and adapts it for the program view's equate table.
/// Delegates most operations to the underlying equate, but scopes reference
/// operations to the current snapshot.
#[derive(Debug, Clone)]
pub struct DBTraceProgramViewEquate {
    /// The snapshot this view is pinned to.
    pub snap: i64,
    /// Name of the equate.
    pub name: String,
    /// Numeric value of the equate.
    pub value: i64,
    /// References to this equate.
    pub references: Vec<EquateReferenceEntry>,
    /// Whether this equate is backed by an enum.
    pub is_enum_based: bool,
    /// Optional enum UUID if this equate is enum-based.
    pub enum_uuid: Option<u64>,
}

/// A reference to an equate at a specific address and operand position.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EquateReferenceEntry {
    /// The address where the equate is referenced.
    pub address: u64,
    /// The operand position.
    pub operand_position: i32,
}

impl DBTraceProgramViewEquate {
    /// Create a new equate view for the given snap.
    pub fn new(snap: i64, name: String, value: i64) -> Self {
        Self {
            snap,
            name,
            value,
            references: Vec::new(),
            is_enum_based: false,
            enum_uuid: None,
        }
    }

    /// Get the equate name.
    pub fn get_name(&self) -> &str {
        &self.name
    }

    /// Get the display name (same as name for non-enum equates).
    pub fn get_display_name(&self) -> &str {
        &self.name
    }

    /// Get the numeric value.
    pub fn get_value(&self) -> i64 {
        self.value
    }

    /// Get the display value as a hex string.
    pub fn get_display_value(&self) -> String {
        format!("0x{:x}", self.value)
    }

    /// Get the number of references to this equate.
    pub fn get_reference_count(&self) -> usize {
        self.references.len()
    }

    /// Add a reference at the given address and operand position.
    pub fn add_reference(&mut self, address: u64, operand_position: i32) {
        self.references.push(EquateReferenceEntry {
            address,
            operand_position,
        });
    }

    /// Remove a reference at the given address and operand position.
    pub fn remove_reference(&mut self, address: u64, operand_position: i32) {
        self.references
            .retain(|r| !(r.address == address && r.operand_position == operand_position));
    }

    /// Get all references.
    pub fn get_references(&self) -> &[EquateReferenceEntry] {
        &self.references
    }

    /// Get references at a specific address.
    pub fn get_references_at(&self, address: u64) -> Vec<&EquateReferenceEntry> {
        self.references.iter().filter(|r| r.address == address).collect()
    }

    /// Rename this equate.
    pub fn rename(&mut self, new_name: String) -> Result<(), String> {
        if new_name.is_empty() {
            return Err("Equate name cannot be empty".into());
        }
        self.name = new_name;
        Ok(())
    }

    /// Check if this equate has a valid backing enum.
    pub fn has_valid_enum(&self) -> bool {
        self.is_enum_based && self.enum_uuid.is_some()
    }

    /// Check if this equate is based on an enum type.
    pub fn is_enum_based(&self) -> bool {
        self.is_enum_based
    }

    /// Get the enum UUID if this is an enum-based equate.
    pub fn get_enum_uuid(&self) -> Option<u64> {
        self.enum_uuid
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_equate_basic() {
        let eq = DBTraceProgramViewEquate::new(5, "MY_CONST".into(), 0x42);
        assert_eq!(eq.get_name(), "MY_CONST");
        assert_eq!(eq.get_display_name(), "MY_CONST");
        assert_eq!(eq.get_value(), 0x42);
        assert_eq!(eq.get_display_value(), "0x42");
        assert_eq!(eq.get_reference_count(), 0);
        assert!(!eq.is_enum_based());
        assert!(!eq.has_valid_enum());
        assert_eq!(eq.get_enum_uuid(), None);
    }

    #[test]
    fn test_equate_references() {
        let mut eq = DBTraceProgramViewEquate::new(0, "X".into(), 100);
        eq.add_reference(0x1000, 0);
        eq.add_reference(0x1004, 1);
        eq.add_reference(0x1000, 2);
        assert_eq!(eq.get_reference_count(), 3);

        let refs_at_1000 = eq.get_references_at(0x1000);
        assert_eq!(refs_at_1000.len(), 2);

        eq.remove_reference(0x1000, 0);
        assert_eq!(eq.get_reference_count(), 2);
        assert!(eq.get_references_at(0x1000).len() == 1);
    }

    #[test]
    fn test_equate_rename() {
        let mut eq = DBTraceProgramViewEquate::new(0, "OLD".into(), 1);
        assert!(eq.rename("NEW".into()).is_ok());
        assert_eq!(eq.get_name(), "NEW");

        assert!(eq.rename("".into()).is_err());
        assert_eq!(eq.get_name(), "NEW");
    }

    #[test]
    fn test_equate_enum_based() {
        let mut eq = DBTraceProgramViewEquate::new(0, "E".into(), 5);
        assert!(!eq.has_valid_enum());

        eq.is_enum_based = true;
        assert!(!eq.has_valid_enum()); // still no UUID

        eq.enum_uuid = Some(999);
        assert!(eq.has_valid_enum());
        assert_eq!(eq.get_enum_uuid(), Some(999));
    }

    #[test]
    fn test_display_value_hex() {
        let eq = DBTraceProgramViewEquate::new(0, "F".into(), 255);
        assert_eq!(eq.get_display_value(), "0xff");

        let eq2 = DBTraceProgramViewEquate::new(0, "Z".into(), 0);
        assert_eq!(eq2.get_display_value(), "0x0");
    }
}
