//! Cycle groups for cycling through data types in the UI.
//!
//! Port of Ghidra's `CycleGroup.java`.
//!
//! A cycle group defines a set of data types that a single action can cycle
//! through. For example, pressing a shortcut key might cycle between
//! byte, word, dword, and qword data types.

use std::fmt;
use std::sync::Arc;

use super::types::DataType;

// ============================================================================
// CycleGroup
// ============================================================================

/// A set of data types that can be cycled through.
///
/// Port of Ghidra's `CycleGroup.java`. Cycle groups allow users to quickly
/// switch between related data types using a single action/keystroke.
#[derive(Debug, Clone)]
pub struct CycleGroup {
    /// The name of the cycle group (e.g., `"Cycle: byte,word,dword,qword"`).
    name: String,
    /// The data types in this group, in cycling order.
    data_types: Vec<Arc<dyn DataType>>,
    /// The name of the default key shortcut.
    key_name: Option<String>,
}

impl CycleGroup {
    /// Create a new cycle group with the given name and data types.
    pub fn new(
        name: impl Into<String>,
        data_types: Vec<Arc<dyn DataType>>,
    ) -> Self {
        Self {
            name: name.into(),
            data_types,
            key_name: None,
        }
    }

    /// Create an empty cycle group with the given name.
    pub fn empty(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            data_types: Vec::new(),
            key_name: None,
        }
    }

    /// Create a cycle group with a single data type.
    pub fn single(name: impl Into<String>, data_type: Arc<dyn DataType>) -> Self {
        Self {
            name: name.into(),
            data_types: vec![data_type],
            key_name: None,
        }
    }

    /// Set the key shortcut name.
    pub fn with_key_name(mut self, key_name: impl Into<String>) -> Self {
        self.key_name = Some(key_name.into());
        self
    }

    /// Get the name of this cycle group.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get the data types in this group.
    pub fn data_types(&self) -> &[Arc<dyn DataType>] {
        &self.data_types
    }

    /// Get the key shortcut name.
    pub fn key_name(&self) -> Option<&str> {
        self.key_name.as_deref()
    }

    /// Returns the number of types in this group.
    pub fn size(&self) -> usize {
        self.data_types.len()
    }

    /// Returns `true` if the group is empty.
    pub fn is_empty(&self) -> bool {
        self.data_types.is_empty()
    }

    /// Add a data type to the end of the group.
    pub fn add_data_type(&mut self, data_type: Arc<dyn DataType>) {
        if !self.exists(&*data_type) {
            self.data_types.push(data_type);
        }
    }

    /// Insert a data type at the beginning of the group.
    pub fn add_first(&mut self, data_type: Arc<dyn DataType>) {
        if !self.exists(&*data_type) {
            self.data_types.insert(0, data_type);
        }
    }

    /// Remove a data type from this group.
    pub fn remove_data_type(&mut self, data_type: &dyn DataType) {
        self.data_types
            .retain(|dt| !data_type.is_equivalent(dt.as_ref()));
    }

    /// Remove the first data type from the group.
    pub fn remove_first(&mut self) {
        if !self.data_types.is_empty() {
            self.data_types.remove(0);
        }
    }

    /// Remove the last data type from the group.
    pub fn remove_last(&mut self) {
        self.data_types.pop();
    }

    /// Returns `true` if the given data type (or an equivalent one) is in this group.
    pub fn contains(&self, data_type: &dyn DataType) -> bool {
        self.exists(data_type)
    }

    /// Internal check for existence using equivalence.
    fn exists(&self, data_type: &dyn DataType) -> bool {
        self.data_types
            .iter()
            .any(|dt| data_type.is_equivalent(dt.as_ref()))
    }

    /// Get the next data type in the cycle after the current one.
    ///
    /// If `current` is `None` or not in the group, returns the first type.
    pub fn get_next_data_type(&self, current: Option<&dyn DataType>) -> Option<Arc<dyn DataType>> {
        if self.data_types.is_empty() {
            return None;
        }

        if let Some(current_dt) = current {
            for (i, dt) in self.data_types.iter().enumerate() {
                if current_dt.is_equivalent(dt.as_ref()) {
                    let next_index = (i + 1) % self.data_types.len();
                    return Some(self.data_types[next_index].clone());
                }
            }
        }

        // Not found or no current: return the first type.
        Some(self.data_types[0].clone())
    }

    /// Get the index of a data type in this group, or `None` if not found.
    pub fn index_of(&self, data_type: &dyn DataType) -> Option<usize> {
        self.data_types
            .iter()
            .position(|dt| data_type.is_equivalent(dt.as_ref()))
    }
}

impl fmt::Display for CycleGroup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let names: Vec<&str> = self.data_types.iter().map(|dt| dt.name()).collect();
        write!(f, "{}: [{}]", self.name, names.join(", "))
    }
}

// ============================================================================
// Standard Cycle Groups
// ============================================================================

/// Well-known cycle group names.
pub mod well_known {
    /// The byte/word/dword/qword cycle group name.
    pub const BYTE_CYCLE_GROUP_NAME: &str = "Cycle: byte,word,dword,qword";

    /// The float/double/longdouble cycle group name.
    pub const FLOAT_CYCLE_GROUP_NAME: &str = "Cycle: float,double,longdouble";

    /// The char/string/unicode cycle group name.
    pub const STRING_CYCLE_GROUP_NAME: &str = "Cycle: char,string,unicode";
}

// ============================================================================
// CycleGroupManager
// ============================================================================

/// Manages a collection of cycle groups.
#[derive(Debug, Clone)]
pub struct CycleGroupManager {
    groups: Vec<CycleGroup>,
}

impl CycleGroupManager {
    /// Create a new empty cycle group manager.
    pub fn new() -> Self {
        Self { groups: Vec::new() }
    }

    /// Add a cycle group.
    pub fn add_group(&mut self, group: CycleGroup) {
        self.groups.push(group);
    }

    /// Get all cycle groups.
    pub fn groups(&self) -> &[CycleGroup] {
        &self.groups
    }

    /// Find a cycle group by name.
    pub fn find_group(&self, name: &str) -> Option<&CycleGroup> {
        self.groups.iter().find(|g| g.name() == name)
    }

    /// Find the cycle group that contains the given data type.
    pub fn find_group_for_type(&self, data_type: &dyn DataType) -> Option<&CycleGroup> {
        self.groups.iter().find(|g| g.contains(data_type))
    }

    /// Get the next data type in the appropriate cycle group.
    pub fn get_next_type(
        &self,
        current: &dyn DataType,
    ) -> Option<Arc<dyn DataType>> {
        for group in &self.groups {
            if group.contains(current) {
                return group.get_next_data_type(Some(current));
            }
        }
        None
    }

    /// The number of registered groups.
    pub fn group_count(&self) -> usize {
        self.groups.len()
    }

    /// Check if any cycle group is registered.
    pub fn is_empty(&self) -> bool {
        self.groups.is_empty()
    }
}

impl Default for CycleGroupManager {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for CycleGroupManager {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CycleGroupManager ({} groups)", self.groups.len())
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data::builtin_types::*;

    #[test]
    fn test_cycle_group_basic() {
        let group = CycleGroup::empty("test");
        assert_eq!(group.name(), "test");
        assert!(group.is_empty());
        assert_eq!(group.size(), 0);
    }

    #[test]
    fn test_cycle_group_add_contains() {
        let mut group = CycleGroup::empty("test");
        let byte_dt: Arc<dyn DataType> = Arc::new(ByteDataType::new());
        let word_dt: Arc<dyn DataType> = Arc::new(WordDataType::new());

        group.add_data_type(byte_dt.clone());
        group.add_data_type(word_dt.clone());

        assert_eq!(group.size(), 2);
        assert!(group.contains(&*byte_dt));
        assert!(group.contains(&*word_dt));
    }

    #[test]
    fn test_cycle_group_no_duplicates() {
        let mut group = CycleGroup::empty("test");
        let byte_dt: Arc<dyn DataType> = Arc::new(ByteDataType::new());
        group.add_data_type(byte_dt.clone());
        group.add_data_type(byte_dt.clone());
        assert_eq!(group.size(), 1);
    }

    #[test]
    fn test_cycle_group_get_next() {
        let mut group = CycleGroup::empty("test");
        let byte_dt: Arc<dyn DataType> = Arc::new(ByteDataType::new());
        let word_dt: Arc<dyn DataType> = Arc::new(WordDataType::new());
        let dword_dt: Arc<dyn DataType> = Arc::new(DWordDataType::new());

        group.add_data_type(byte_dt.clone());
        group.add_data_type(word_dt.clone());
        group.add_data_type(dword_dt.clone());

        // Next after byte -> word
        let next = group.get_next_data_type(Some(&*byte_dt)).unwrap();
        assert_eq!(next.name(), "word");

        // Next after dword -> byte (wrap around)
        let next = group.get_next_data_type(Some(&*dword_dt)).unwrap();
        assert_eq!(next.name(), "byte");

        // No current -> first
        let next = group.get_next_data_type(None).unwrap();
        assert_eq!(next.name(), "byte");
    }

    #[test]
    fn test_cycle_group_index_of() {
        let mut group = CycleGroup::empty("test");
        let byte_dt: Arc<dyn DataType> = Arc::new(ByteDataType::new());
        let word_dt: Arc<dyn DataType> = Arc::new(WordDataType::new());

        group.add_data_type(byte_dt.clone());
        group.add_data_type(word_dt.clone());

        assert_eq!(group.index_of(&*byte_dt), Some(0));
        assert_eq!(group.index_of(&*word_dt), Some(1));
    }

    #[test]
    fn test_cycle_group_remove() {
        let mut group = CycleGroup::empty("test");
        let byte_dt: Arc<dyn DataType> = Arc::new(ByteDataType::new());
        let word_dt: Arc<dyn DataType> = Arc::new(WordDataType::new());

        group.add_data_type(byte_dt.clone());
        group.add_data_type(word_dt.clone());
        group.remove_data_type(&*byte_dt);

        assert_eq!(group.size(), 1);
        assert!(!group.contains(&*byte_dt));
    }

    #[test]
    fn test_cycle_group_add_first() {
        let mut group = CycleGroup::empty("test");
        let byte_dt: Arc<dyn DataType> = Arc::new(ByteDataType::new());
        let word_dt: Arc<dyn DataType> = Arc::new(WordDataType::new());

        group.add_data_type(word_dt.clone());
        group.add_first(byte_dt.clone());

        assert_eq!(group.index_of(&*byte_dt), Some(0));
        assert_eq!(group.index_of(&*word_dt), Some(1));
    }

    #[test]
    fn test_cycle_group_display() {
        let mut group = CycleGroup::empty("test");
        let byte_dt: Arc<dyn DataType> = Arc::new(ByteDataType::new());
        group.add_data_type(byte_dt);

        let s = format!("{}", group);
        assert!(s.contains("test"));
        assert!(s.contains("byte"));
    }

    #[test]
    fn test_cycle_group_manager() {
        let mut manager = CycleGroupManager::new();
        let mut group = CycleGroup::empty("test");
        let byte_dt: Arc<dyn DataType> = Arc::new(ByteDataType::new());
        let word_dt: Arc<dyn DataType> = Arc::new(WordDataType::new());

        group.add_data_type(byte_dt.clone());
        group.add_data_type(word_dt.clone());
        manager.add_group(group);

        assert_eq!(manager.group_count(), 1);
        assert!(manager.find_group("test").is_some());
        assert!(manager.find_group_for_type(&*byte_dt).is_some());

        let next = manager.get_next_type(&*byte_dt).unwrap();
        assert_eq!(next.name(), "word");
    }

    #[test]
    fn test_with_key_name() {
        let group = CycleGroup::empty("test").with_key_name("B");
        assert_eq!(group.key_name(), Some("B"));
    }
}
