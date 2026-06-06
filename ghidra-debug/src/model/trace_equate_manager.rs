//! TraceEquateManager trait.
//!
//! Ported from Ghidra's `ghidra.trace.model.symbol.TraceEquateManager`.
//! Extends `TraceEquateOperations` with CRUD methods for equates and
//! equate spaces.

use super::equate_ops::TraceEquateOperations;
use super::lifespan::Lifespan;
use super::symbol::TraceEquate;

/// Validation: name must be non-empty and contain no whitespace.
///
/// Ported from `TraceEquateManager.validateName`.
pub fn validate_equate_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("name cannot be empty string".to_string());
    }
    if name.chars().any(|c| c.is_whitespace()) {
        return Err("name cannot contain whitespace".to_string());
    }
    Ok(())
}

/// Trait for managing equates in a trace.
///
/// Ported from Ghidra's `TraceEquateManager` interface.
/// Extends `TraceEquateOperations` with methods for creating, retrieving,
/// and listing equates across all address spaces.
pub trait TraceEquateManager: TraceEquateOperations {
    /// Create a new equate with the given name and value.
    ///
    /// Returns an error if the name is already in use or invalid.
    fn create_equate(&mut self, name: &str, value: i64) -> Result<(), String>;

    /// Get an equate by its exact name.
    fn get_equate_by_name(&self, name: &str) -> Option<&TraceEquate>;

    /// Get an equate by its key (unique identifier).
    fn get_equate_by_key(&self, key: i64) -> Option<&TraceEquate>;

    /// Get all equates with the given value.
    fn get_equates_by_value(&self, value: i64) -> Vec<&TraceEquate>;

    /// Get all equates.
    fn get_all_equates(&self) -> Vec<&TraceEquate>;

    /// Remove an equate by key.
    fn remove_equate(&mut self, key: i64) -> bool;

    /// Get the total number of equates.
    fn equate_count(&self) -> usize;
}

/// In-memory implementation of the equate manager.
#[derive(Debug, Clone, Default)]
pub struct TraceEquateManagerImpl {
    /// All equates keyed by their unique key.
    equates: std::collections::BTreeMap<i64, TraceEquate>,
    /// Name-to-key index.
    name_index: std::collections::BTreeMap<String, i64>,
    /// Value-to-keys index.
    value_index: std::collections::BTreeMap<i64, Vec<i64>>,
    /// Next auto-increment key.
    next_key: i64,
}

impl TraceEquateManagerImpl {
    /// Create a new empty equate manager.
    pub fn new() -> Self {
        Self::default()
    }

    /// Get the equates map (for testing/inspection).
    pub fn equates(&self) -> &std::collections::BTreeMap<i64, TraceEquate> {
        &self.equates
    }
}

impl TraceEquateOperations for TraceEquateManagerImpl {
    fn get_referring_addresses(&self, _span: &super::lifespan::Lifespan) -> Vec<u64> {
        Vec::new()
    }

    fn clear_references(&mut self, _span: &super::lifespan::Lifespan, _addresses: &[u64]) {}

    fn get_referenced_by_value(
        &self,
        _snap: i64,
        _address: u64,
        _operand_index: i32,
        value: i64,
    ) -> Option<&TraceEquate> {
        self.get_equates_by_value(value).into_iter().next()
    }

    fn get_referenced(
        &self,
        _snap: i64,
        _address: u64,
        _operand_index: i32,
    ) -> Vec<&TraceEquate> {
        Vec::new()
    }

    fn get_referenced_at(&self, _snap: i64, _address: u64) -> Vec<&TraceEquate> {
        Vec::new()
    }
}

impl TraceEquateManager for TraceEquateManagerImpl {
    fn create_equate(&mut self, name: &str, value: i64) -> Result<(), String> {
        validate_equate_name(name)?;
        if self.name_index.contains_key(name) {
            return Err(format!("Equate already exists: {}", name));
        }
        let key = self.next_key;
        self.next_key += 1;
        let equate = TraceEquate::new(key, name, value, Lifespan::span(0, i64::MAX));
        self.name_index.insert(name.to_string(), key);
        self.value_index.entry(value).or_default().push(key);
        self.equates.insert(key, equate);
        Ok(())
    }

    fn get_equate_by_name(&self, name: &str) -> Option<&TraceEquate> {
        self.name_index.get(name).and_then(|k| self.equates.get(k))
    }

    fn get_equate_by_key(&self, key: i64) -> Option<&TraceEquate> {
        self.equates.get(&key)
    }

    fn get_equates_by_value(&self, value: i64) -> Vec<&TraceEquate> {
        self.value_index
            .get(&value)
            .map(|keys| keys.iter().filter_map(|k| self.equates.get(k)).collect())
            .unwrap_or_default()
    }

    fn get_all_equates(&self) -> Vec<&TraceEquate> {
        self.equates.values().collect()
    }

    fn remove_equate(&mut self, key: i64) -> bool {
        if let Some(equate) = self.equates.remove(&key) {
            self.name_index.remove(&equate.name);
            if let Some(keys) = self.value_index.get_mut(&equate.value) {
                keys.retain(|&k| k != key);
                if keys.is_empty() {
                    self.value_index.remove(&equate.value);
                }
            }
            true
        } else {
            false
        }
    }

    fn equate_count(&self) -> usize {
        self.equates.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_name() {
        assert!(validate_equate_name("FOO").is_ok());
        assert!(validate_equate_name("").is_err());
        assert!(validate_equate_name("has space").is_err());
        assert!(validate_equate_name("has\ttab").is_err());
    }

    #[test]
    fn test_create_and_get() {
        let mut mgr = TraceEquateManagerImpl::new();
        mgr.create_equate("MY_CONST", 42).unwrap();
        assert_eq!(mgr.equate_count(), 1);

        let eq = mgr.get_equate_by_name("MY_CONST").unwrap();
        assert_eq!(eq.name, "MY_CONST");
        assert_eq!(eq.value, 42);
    }

    #[test]
    fn test_duplicate_rejected() {
        let mut mgr = TraceEquateManagerImpl::new();
        mgr.create_equate("FOO", 1).unwrap();
        let result = mgr.create_equate("FOO", 2);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("already exists"));
    }

    #[test]
    fn test_get_by_value() {
        let mut mgr = TraceEquateManagerImpl::new();
        mgr.create_equate("A", 10).unwrap();
        mgr.create_equate("B", 10).unwrap();
        mgr.create_equate("C", 20).unwrap();

        let eqs = mgr.get_equates_by_value(10);
        assert_eq!(eqs.len(), 2);
    }

    #[test]
    fn test_remove() {
        let mut mgr = TraceEquateManagerImpl::new();
        mgr.create_equate("DEL", 99).unwrap();
        let eq = mgr.get_equate_by_name("DEL").unwrap();
        let key = eq.key;
        assert!(mgr.remove_equate(key));
        assert_eq!(mgr.equate_count(), 0);
        assert!(mgr.get_equate_by_name("DEL").is_none());
    }

    #[test]
    fn test_get_by_key() {
        let mut mgr = TraceEquateManagerImpl::new();
        mgr.create_equate("KEY_TEST", 5).unwrap();
        let key = mgr.get_equate_by_name("KEY_TEST").unwrap().key;
        let eq = mgr.get_equate_by_key(key).unwrap();
        assert_eq!(eq.name, "KEY_TEST");
    }

    #[test]
    fn test_get_all() {
        let mut mgr = TraceEquateManagerImpl::new();
        mgr.create_equate("X", 1).unwrap();
        mgr.create_equate("Y", 2).unwrap();
        mgr.create_equate("Z", 3).unwrap();
        assert_eq!(mgr.get_all_equates().len(), 3);
    }
}
