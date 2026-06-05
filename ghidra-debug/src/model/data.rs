//! TraceBasedDataTypeManager - data type management tied to a trace.
//!
//! Ported from Ghidra's `ghidra.trace.model.data.TraceBasedDataTypeManager`.
//!
//! Provides an interface for data type managers that are part of a `Trace`,
//! linking data type resolution, addition, and replacement to the trace's
//! platform and program view.

use std::fmt;

use serde::{Deserialize, Serialize};

/// Conflict handling strategy when adding data types with the same name.
///
/// Ported from Ghidra's `DataTypeConflictHandler`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DataTypeConflictHandler {
    /// Replace the existing data type with the new one.
    Replace,
    /// Keep the existing data type, discard the new one.
    Keep,
    /// Rename the new data type to avoid the conflict.
    Rename,
    /// Return an error on conflict.
    Error,
}

impl Default for DataTypeConflictHandler {
    fn default() -> Self {
        Self::Replace
    }
}

/// Error when a data type replacement would cause dependency issues.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataTypeDependencyException {
    /// The data type causing the dependency issue.
    pub data_type_name: String,
    /// Description of the dependency problem.
    pub message: String,
}

impl fmt::Display for DataTypeDependencyException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "DataTypeDependencyException for '{}': {}",
            self.data_type_name, self.message
        )
    }
}

impl std::error::Error for DataTypeDependencyException {}

/// A unique identifier for a data type within a manager.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DataTypeId(pub u64);

/// A simplified data type representation for trace-based management.
///
/// This is a simplified representation suitable for the trace data type
/// management system. Full Ghidra data types involve complex hierarchies,
/// but for trace-based management we need a serializable, lightweight form.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceDataType {
    /// The unique ID of this data type.
    pub id: DataTypeId,
    /// The name of the data type.
    pub name: String,
    /// The category path (e.g., "/my_category").
    pub category_path: String,
    /// The size in bytes (0 for variable-length types).
    pub size: usize,
    /// Whether this is a built-in type.
    pub builtin: bool,
}

impl TraceDataType {
    /// Create a new data type.
    pub fn new(id: DataTypeId, name: impl Into<String>, size: usize) -> Self {
        Self {
            id,
            name: name.into(),
            category_path: "/".to_string(),
            size,
            builtin: false,
        }
    }

    /// Set the category path.
    pub fn with_category(mut self, path: impl Into<String>) -> Self {
        self.category_path = path.into();
        self
    }

    /// Mark as built-in.
    pub fn as_builtin(mut self) -> Self {
        self.builtin = true;
        self
    }

    /// The full name including category path.
    pub fn full_name(&self) -> String {
        if self.category_path == "/" || self.category_path.is_empty() {
            self.name.clone()
        } else {
            format!("{}/{}", self.category_path, self.name)
        }
    }
}

/// A trait for data type managers that are part of a Trace.
///
/// Ported from Ghidra's `TraceBasedDataTypeManager` interface.
///
/// Provides data type resolution, addition, and replacement operations
/// tied to the trace's platform and program view.
pub trait TraceBasedDataTypeManager {
    /// Get the name of this data type manager.
    fn name(&self) -> &str;

    /// Get the ID of the trace this manager belongs to.
    fn trace_id(&self) -> &str;

    /// Get the platform name for which this data type manager is provided.
    fn platform_name(&self) -> &str;

    /// Resolve a data type, handling conflicts according to the handler.
    ///
    /// Returns the resolved (possibly existing) data type.
    fn resolve(
        &mut self,
        data_type: TraceDataType,
        handler: DataTypeConflictHandler,
    ) -> Result<TraceDataType, DataTypeDependencyException>;

    /// Add a data type, handling conflicts according to the handler.
    ///
    /// Returns the added (or existing) data type.
    fn add_data_type(
        &mut self,
        data_type: TraceDataType,
        handler: DataTypeConflictHandler,
    ) -> Result<TraceDataType, DataTypeDependencyException>;

    /// Replace an existing data type with a new one.
    ///
    /// Returns the replacement data type.
    fn replace_data_type(
        &mut self,
        existing: &DataTypeId,
        replacement: TraceDataType,
    ) -> Result<TraceDataType, DataTypeDependencyException>;

    /// Get a data type by ID.
    fn get_data_type(&self, id: &DataTypeId) -> Option<&TraceDataType>;

    /// Get a data type by name (simple lookup).
    fn get_data_type_by_name(&self, name: &str) -> Option<&TraceDataType>;

    /// Get all data types.
    fn all_data_types(&self) -> Vec<&TraceDataType>;

    /// Get the number of data types.
    fn data_type_count(&self) -> usize;
}

/// A concrete in-memory implementation of `TraceBasedDataTypeManager`.
///
/// Stores data types in a simple HashMap. Suitable for testing and
/// scenarios where a persistent store is not needed.
#[derive(Debug, Default)]
pub struct InMemoryTraceDataTypeManager {
    /// The manager name.
    pub manager_name: String,
    /// The owning trace ID.
    pub owning_trace_id: String,
    /// The platform name.
    pub owning_platform: String,
    /// The next data type ID to allocate.
    next_id: u64,
    /// Storage for data types.
    types: std::collections::HashMap<DataTypeId, TraceDataType>,
    /// Name-to-ID index.
    by_name: std::collections::HashMap<String, DataTypeId>,
}

impl InMemoryTraceDataTypeManager {
    /// Create a new in-memory data type manager.
    pub fn new(
        name: impl Into<String>,
        trace_id: impl Into<String>,
        platform: impl Into<String>,
    ) -> Self {
        Self {
            manager_name: name.into(),
            owning_trace_id: trace_id.into(),
            owning_platform: platform.into(),
            next_id: 1,
            types: std::collections::HashMap::new(),
            by_name: std::collections::HashMap::new(),
        }
    }

    fn alloc_id(&mut self) -> DataTypeId {
        let id = DataTypeId(self.next_id);
        self.next_id += 1;
        id
    }
}

impl TraceBasedDataTypeManager for InMemoryTraceDataTypeManager {
    fn name(&self) -> &str {
        &self.manager_name
    }

    fn trace_id(&self) -> &str {
        &self.owning_trace_id
    }

    fn platform_name(&self) -> &str {
        &self.owning_platform
    }

    fn resolve(
        &mut self,
        data_type: TraceDataType,
        handler: DataTypeConflictHandler,
    ) -> Result<TraceDataType, DataTypeDependencyException> {
        if let Some(&existing_id) = self.by_name.get(&data_type.name) {
            match handler {
                DataTypeConflictHandler::Keep => {
                    Ok(self.types[&existing_id].clone())
                }
                DataTypeConflictHandler::Replace => {
                    let mut replacement = data_type;
                    replacement.id = existing_id;
                    self.types.insert(existing_id, replacement.clone());
                    Ok(replacement)
                }
                DataTypeConflictHandler::Rename => {
                    let mut renamed = data_type;
                    renamed.id = self.alloc_id();
                    let original_name = renamed.name.clone();
                    renamed.name = format!("{}_{}", original_name, renamed.id.0);
                    self.by_name.insert(renamed.name.clone(), renamed.id);
                    self.types.insert(renamed.id, renamed.clone());
                    Ok(renamed)
                }
                DataTypeConflictHandler::Error => Err(DataTypeDependencyException {
                    data_type_name: data_type.name,
                    message: "Data type already exists".to_string(),
                }),
            }
        } else {
            let mut new_dt = data_type;
            if new_dt.id == DataTypeId(0) {
                new_dt.id = self.alloc_id();
            }
            self.by_name.insert(new_dt.name.clone(), new_dt.id);
            self.types.insert(new_dt.id, new_dt.clone());
            Ok(new_dt)
        }
    }

    fn add_data_type(
        &mut self,
        data_type: TraceDataType,
        handler: DataTypeConflictHandler,
    ) -> Result<TraceDataType, DataTypeDependencyException> {
        self.resolve(data_type, handler)
    }

    fn replace_data_type(
        &mut self,
        existing: &DataTypeId,
        replacement: TraceDataType,
    ) -> Result<TraceDataType, DataTypeDependencyException> {
        if !self.types.contains_key(existing) {
            return Err(DataTypeDependencyException {
                data_type_name: format!("{:?}", existing),
                message: "Existing data type not found".to_string(),
            });
        }
        let old_name = self.types[existing].name.clone();
        let mut new_dt = replacement;
        new_dt.id = *existing;
        self.by_name.remove(&old_name);
        self.by_name.insert(new_dt.name.clone(), new_dt.id);
        self.types.insert(*existing, new_dt.clone());
        Ok(new_dt)
    }

    fn get_data_type(&self, id: &DataTypeId) -> Option<&TraceDataType> {
        self.types.get(id)
    }

    fn get_data_type_by_name(&self, name: &str) -> Option<&TraceDataType> {
        self.by_name.get(name).and_then(|id| self.types.get(id))
    }

    fn all_data_types(&self) -> Vec<&TraceDataType> {
        self.types.values().collect()
    }

    fn data_type_count(&self) -> usize {
        self.types.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_data_type_creation() {
        let dt = TraceDataType::new(DataTypeId(1), "int", 4)
            .with_category("/C");
        assert_eq!(dt.name, "int");
        assert_eq!(dt.size, 4);
        assert_eq!(dt.full_name(), "/C/int");
    }

    #[test]
    fn test_data_type_full_name_root() {
        let dt = TraceDataType::new(DataTypeId(1), "void", 0);
        assert_eq!(dt.full_name(), "void");
    }

    #[test]
    fn test_in_memory_manager_add() {
        let mut mgr = InMemoryTraceDataTypeManager::new("dtm", "trace1", "x86:little:64");
        let dt = TraceDataType::new(DataTypeId(0), "int", 4);
        let resolved = mgr.add_data_type(dt, DataTypeConflictHandler::Replace).unwrap();
        assert_eq!(resolved.name, "int");
        assert!(resolved.id != DataTypeId(0));
        assert_eq!(mgr.data_type_count(), 1);
    }

    #[test]
    fn test_in_memory_manager_keep_conflict() {
        let mut mgr = InMemoryTraceDataTypeManager::new("dtm", "trace1", "x86");
        let dt1 = TraceDataType::new(DataTypeId(0), "int", 4);
        mgr.add_data_type(dt1, DataTypeConflictHandler::Replace).unwrap();

        let dt2 = TraceDataType::new(DataTypeId(0), "int", 8);
        let result = mgr.add_data_type(dt2, DataTypeConflictHandler::Keep).unwrap();
        assert_eq!(result.size, 4); // Kept original
        assert_eq!(mgr.data_type_count(), 1);
    }

    #[test]
    fn test_in_memory_manager_replace_conflict() {
        let mut mgr = InMemoryTraceDataTypeManager::new("dtm", "trace1", "x86");
        let dt1 = TraceDataType::new(DataTypeId(0), "int", 4);
        mgr.add_data_type(dt1, DataTypeConflictHandler::Replace).unwrap();

        let dt2 = TraceDataType::new(DataTypeId(0), "int", 8);
        let result = mgr.add_data_type(dt2, DataTypeConflictHandler::Replace).unwrap();
        assert_eq!(result.size, 8); // Replaced
        assert_eq!(mgr.data_type_count(), 1);
    }

    #[test]
    fn test_in_memory_manager_error_conflict() {
        let mut mgr = InMemoryTraceDataTypeManager::new("dtm", "trace1", "x86");
        let dt1 = TraceDataType::new(DataTypeId(0), "int", 4);
        mgr.add_data_type(dt1, DataTypeConflictHandler::Replace).unwrap();

        let dt2 = TraceDataType::new(DataTypeId(0), "int", 8);
        assert!(mgr.add_data_type(dt2, DataTypeConflictHandler::Error).is_err());
    }

    #[test]
    fn test_in_memory_manager_rename_conflict() {
        let mut mgr = InMemoryTraceDataTypeManager::new("dtm", "trace1", "x86");
        let dt1 = TraceDataType::new(DataTypeId(0), "int", 4);
        mgr.add_data_type(dt1, DataTypeConflictHandler::Replace).unwrap();

        let dt2 = TraceDataType::new(DataTypeId(0), "int", 8);
        let result = mgr.add_data_type(dt2, DataTypeConflictHandler::Rename).unwrap();
        assert!(result.name != "int"); // Renamed
        assert_eq!(mgr.data_type_count(), 2);
    }

    #[test]
    fn test_in_memory_manager_replace_data_type() {
        let mut mgr = InMemoryTraceDataTypeManager::new("dtm", "trace1", "x86");
        let dt = TraceDataType::new(DataTypeId(0), "int", 4);
        let added = mgr.add_data_type(dt, DataTypeConflictHandler::Replace).unwrap();
        let id = added.id;

        let replacement = TraceDataType::new(DataTypeId(0), "int32", 4);
        let result = mgr.replace_data_type(&id, replacement).unwrap();
        assert_eq!(result.name, "int32");
        assert_eq!(mgr.get_data_type_by_name("int32").unwrap().id, id);
        assert!(mgr.get_data_type_by_name("int").is_none());
    }

    #[test]
    fn test_in_memory_manager_get_by_name() {
        let mut mgr = InMemoryTraceDataTypeManager::new("dtm", "trace1", "x86");
        mgr.add_data_type(
            TraceDataType::new(DataTypeId(0), "float", 4),
            DataTypeConflictHandler::Replace,
        ).unwrap();
        mgr.add_data_type(
            TraceDataType::new(DataTypeId(0), "double", 8),
            DataTypeConflictHandler::Replace,
        ).unwrap();

        assert!(mgr.get_data_type_by_name("float").is_some());
        assert!(mgr.get_data_type_by_name("double").is_some());
        assert!(mgr.get_data_type_by_name("nonexistent").is_none());
        assert_eq!(mgr.data_type_count(), 2);
    }

    #[test]
    fn test_conflict_handler_default() {
        assert_eq!(DataTypeConflictHandler::default(), DataTypeConflictHandler::Replace);
    }

    #[test]
    fn test_dependency_exception_display() {
        let e = DataTypeDependencyException {
            data_type_name: "my_struct".into(),
            message: "Circular dependency".into(),
        };
        let s = format!("{}", e);
        assert!(s.contains("my_struct"));
        assert!(s.contains("Circular dependency"));
    }

    #[test]
    fn test_trace_data_type_serde() {
        let dt = TraceDataType::new(DataTypeId(42), "test_type", 16)
            .with_category("/custom");
        let json = serde_json::to_string(&dt).unwrap();
        let back: TraceDataType = serde_json::from_str(&json).unwrap();
        assert_eq!(back.name, "test_type");
        assert_eq!(back.size, 16);
        assert_eq!(back.category_path, "/custom");
    }

    #[test]
    fn test_builtin_data_type() {
        let dt = TraceDataType::new(DataTypeId(1), "bool", 1).as_builtin();
        assert!(dt.builtin);
    }
}
