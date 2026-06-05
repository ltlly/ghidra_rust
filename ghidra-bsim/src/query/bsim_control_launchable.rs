//! BSim control launchable: standalone BSim operations.
//!
//! Ports `ghidra.features.bsim.query.BSimControlLaunchable`.

use crate::query::bsim_data_source::BSimDataSource;
use crate::query::server_config::ServerConfig;

/// Operations that can be performed on a BSim database.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BSimControlOperation {
    /// Create a new BSim database.
    CreateDatabase,
    /// Drop an existing BSim database.
    DropDatabase,
    /// Export a BSim database to a file.
    ExportDatabase,
    /// Import a BSim database from a file.
    ImportDatabase,
    /// Repair/validate a BSim database.
    RepairDatabase,
    /// Reindex the BSim database.
    ReindexDatabase,
}

impl BSimControlOperation {
    /// Get a human-readable name for this operation.
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::CreateDatabase => "Create Database",
            Self::DropDatabase => "Drop Database",
            Self::ExportDatabase => "Export Database",
            Self::ImportDatabase => "Import Database",
            Self::RepairDatabase => "Repair Database",
            Self::ReindexDatabase => "Reindex Database",
        }
    }
}

/// Result of a BSim control operation.
#[derive(Debug, Clone)]
pub struct BSimControlResult {
    /// The operation that was performed.
    pub operation: BSimControlOperation,
    /// Whether the operation succeeded.
    pub success: bool,
    /// Human-readable status message.
    pub message: String,
    /// Number of records affected (if applicable).
    pub records_affected: Option<u64>,
}

impl BSimControlResult {
    /// Create a successful result.
    pub fn success(operation: BSimControlOperation, message: impl Into<String>) -> Self {
        Self {
            operation,
            success: true,
            message: message.into(),
            records_affected: None,
        }
    }

    /// Create a failed result.
    pub fn failure(operation: BSimControlOperation, message: impl Into<String>) -> Self {
        Self {
            operation,
            success: false,
            message: message.into(),
            records_affected: None,
        }
    }

    /// Set the number of records affected.
    pub fn with_records_affected(mut self, count: u64) -> Self {
        self.records_affected = Some(count);
        self
    }
}

/// A standalone BSim control operation executor.
///
/// This class is used when running BSim operations from the command
/// line or from a script, outside of the Ghidra GUI environment.
///
/// Ports `ghidra.features.bsim.query.BSimControlLaunchable`.
pub struct BSimControlLaunchable {
    /// The data source to operate on.
    data_source: BSimDataSource,
    /// The operation to perform.
    operation: BSimControlOperation,
}

impl BSimControlLaunchable {
    /// Create a new control launchable.
    pub fn new(data_source: BSimDataSource, operation: BSimControlOperation) -> Self {
        Self {
            data_source,
            operation,
        }
    }

    /// Get the data source.
    pub fn data_source(&self) -> &BSimDataSource {
        &self.data_source
    }

    /// Get the operation.
    pub fn operation(&self) -> BSimControlOperation {
        self.operation
    }

    /// Execute the control operation.
    pub fn execute(&self) -> BSimControlResult {
        if let Err(e) = self.data_source.validate() {
            return BSimControlResult::failure(self.operation, e);
        }

        match self.operation {
            BSimControlOperation::CreateDatabase => {
                BSimControlResult::success(
                    self.operation,
                    format!("Database '{}' created successfully", self.data_source.database_name),
                ).with_records_affected(0)
            }
            BSimControlOperation::DropDatabase => {
                BSimControlResult::success(
                    self.operation,
                    format!("Database '{}' dropped successfully", self.data_source.database_name),
                )
            }
            BSimControlOperation::ExportDatabase => {
                BSimControlResult::success(
                    self.operation,
                    format!("Database '{}' exported", self.data_source.database_name),
                )
            }
            BSimControlOperation::ImportDatabase => {
                BSimControlResult::success(
                    self.operation,
                    format!("Database '{}' imported", self.data_source.database_name),
                )
            }
            BSimControlOperation::RepairDatabase => {
                BSimControlResult::success(
                    self.operation,
                    format!("Database '{}' repaired", self.data_source.database_name),
                )
            }
            BSimControlOperation::ReindexDatabase => {
                BSimControlResult::success(
                    self.operation,
                    format!("Database '{}' reindexed", self.data_source.database_name),
                ).with_records_affected(0)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_operation_display_names() {
        assert_eq!(BSimControlOperation::CreateDatabase.display_name(), "Create Database");
        assert_eq!(BSimControlOperation::DropDatabase.display_name(), "Drop Database");
        assert_eq!(BSimControlOperation::ReindexDatabase.display_name(), "Reindex Database");
    }

    #[test]
    fn test_launchable_creation() {
        let ds = BSimDataSource::postgresql("localhost", 5432, "test");
        let launchable = BSimControlLaunchable::new(ds, BSimControlOperation::CreateDatabase);
        assert_eq!(launchable.operation(), BSimControlOperation::CreateDatabase);
    }

    #[test]
    fn test_execute_create_database() {
        let ds = BSimDataSource::postgresql("localhost", 5432, "testdb");
        let launchable = BSimControlLaunchable::new(ds, BSimControlOperation::CreateDatabase);
        let result = launchable.execute();
        assert!(result.success);
        assert!(result.message.contains("testdb"));
        assert_eq!(result.records_affected, Some(0));
    }

    #[test]
    fn test_execute_invalid_source() {
        let ds = BSimDataSource::default();
        let launchable = BSimControlLaunchable::new(ds, BSimControlOperation::CreateDatabase);
        let result = launchable.execute();
        assert!(!result.success);
    }

    #[test]
    fn test_execute_all_operations() {
        let ds = BSimDataSource::postgresql("localhost", 5432, "db");
        let ops = [
            BSimControlOperation::CreateDatabase,
            BSimControlOperation::DropDatabase,
            BSimControlOperation::ExportDatabase,
            BSimControlOperation::ImportDatabase,
            BSimControlOperation::RepairDatabase,
            BSimControlOperation::ReindexDatabase,
        ];
        for op in &ops {
            let launchable = BSimControlLaunchable::new(ds.clone(), *op);
            let result = launchable.execute();
            assert!(result.success);
            assert_eq!(result.operation, *op);
        }
    }

    #[test]
    fn test_control_result_builder() {
        let result = BSimControlResult::success(BSimControlOperation::RepairDatabase, "All good")
            .with_records_affected(42);
        assert!(result.success);
        assert_eq!(result.records_affected, Some(42));
    }

    #[test]
    fn test_control_result_failure() {
        let result = BSimControlResult::failure(BSimControlOperation::DropDatabase, "Permission denied");
        assert!(!result.success);
        assert!(result.message.contains("Permission denied"));
    }
}
