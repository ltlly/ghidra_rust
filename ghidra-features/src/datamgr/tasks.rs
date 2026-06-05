//! Background tasks for the data type manager.
//!
//! Ported from `ghidra.app.plugin.core.datamgr.DataTypeTreeDeleteTask`,
//! `DataTypeTreeCopyMoveTask`, and `OpenDomainFileTask`.

/// Result of a data type tree task.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaskResult {
    /// The task completed successfully.
    Success(String),
    /// The task was cancelled.
    Cancelled,
    /// The task failed with an error message.
    Failed(String),
}

/// Delete data types from the tree.
///
/// Ported from `ghidra.app.plugin.core.datamgr.DataTypeTreeDeleteTask`.
#[derive(Debug)]
pub struct DataTypeTreeDeleteTask {
    /// The data type paths to delete.
    pub paths: Vec<String>,
    /// Whether to force deletion even if the type is in use.
    pub force: bool,
    /// Results of the deletion.
    results: Vec<(String, TaskResult)>,
}

impl DataTypeTreeDeleteTask {
    /// Create a new delete task.
    pub fn new(paths: Vec<String>) -> Self {
        Self {
            paths,
            force: false,
            results: Vec::new(),
        }
    }

    /// Execute the delete task (model simulation).
    pub fn execute(&mut self) -> &[(String, TaskResult)] {
        self.results.clear();
        for path in &self.paths {
            // In the real implementation, this would check for references
            // and delete the data type. Here we simulate success.
            self.results
                .push((path.clone(), TaskResult::Success(format!("Deleted: {}", path))));
        }
        &self.results
    }

    /// Get the results.
    pub fn results(&self) -> &[(String, TaskResult)] {
        &self.results
    }

    /// Number of successful deletions.
    pub fn success_count(&self) -> usize {
        self.results
            .iter()
            .filter(|(_, r)| matches!(r, TaskResult::Success(_)))
            .count()
    }

    /// Number of failed deletions.
    pub fn failure_count(&self) -> usize {
        self.results
            .iter()
            .filter(|(_, r)| matches!(r, TaskResult::Failed(_)))
            .count()
    }
}

/// Copy or move data types between categories.
///
/// Ported from `ghidra.app.plugin.core.datamgr.DataTypeTreeCopyMoveTask`.
#[derive(Debug)]
pub struct DataTypeTreeCopyMoveTask {
    /// Source data type paths.
    pub source_paths: Vec<String>,
    /// Destination category path.
    pub destination: String,
    /// Whether to move (true) or copy (false).
    pub is_move: bool,
    /// Results.
    results: Vec<(String, TaskResult)>,
}

impl DataTypeTreeCopyMoveTask {
    /// Create a new copy/move task.
    pub fn new(
        source_paths: Vec<String>,
        destination: impl Into<String>,
        is_move: bool,
    ) -> Self {
        Self {
            source_paths,
            destination: destination.into(),
            is_move,
            results: Vec::new(),
        }
    }

    /// Execute the task (model simulation).
    pub fn execute(&mut self) -> &[(String, TaskResult)] {
        self.results.clear();
        let action = if self.is_move { "Moved" } else { "Copied" };
        for path in &self.source_paths {
            self.results.push((
                path.clone(),
                TaskResult::Success(format!("{}: {} -> {}", action, path, self.destination)),
            ));
        }
        &self.results
    }

    /// Get the results.
    pub fn results(&self) -> &[(String, TaskResult)] {
        &self.results
    }
}

/// Open a domain file as an archive.
///
/// Ported from `ghidra.app.plugin.core.datamgr.OpenDomainFileTask`.
#[derive(Debug)]
pub struct OpenDomainFileTask {
    /// The file path to open.
    pub file_path: String,
    /// Whether the file was successfully opened.
    opened: bool,
    /// Error message if the open failed.
    error: Option<String>,
}

impl OpenDomainFileTask {
    /// Create a new open-domain-file task.
    pub fn new(file_path: impl Into<String>) -> Self {
        Self {
            file_path: file_path.into(),
            opened: false,
            error: None,
        }
    }

    /// Execute the task (model simulation).
    pub fn execute(&mut self) -> Result<(), String> {
        if self.file_path.is_empty() {
            self.error = Some("No file path specified".into());
            return Err(self.error.clone().unwrap());
        }
        self.opened = true;
        Ok(())
    }

    /// Whether the file was successfully opened.
    pub fn is_opened(&self) -> bool {
        self.opened
    }

    /// Get the error message, if any.
    pub fn error(&self) -> Option<&str> {
        self.error.as_deref()
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_delete_task_basic() {
        let mut task = DataTypeTreeDeleteTask::new(vec![
            "/MyStruct".into(),
            "/MyEnum".into(),
        ]);
        assert_eq!(task.paths.len(), 2);

        task.execute();
        assert_eq!(task.success_count(), 2);
        assert_eq!(task.failure_count(), 0);
    }

    #[test]
    fn test_delete_task_empty() {
        let mut task = DataTypeTreeDeleteTask::new(vec![]);
        task.execute();
        assert_eq!(task.results().len(), 0);
    }

    #[test]
    fn test_copy_move_task_copy() {
        let mut task = DataTypeTreeCopyMoveTask::new(
            vec!["/Src/Type1".into(), "/Src/Type2".into()],
            "/Dst",
            false,
        );
        assert!(!task.is_move);

        task.execute();
        assert_eq!(task.results().len(), 2);
        for (_, result) in task.results() {
            assert!(matches!(result, TaskResult::Success(_)));
        }
    }

    #[test]
    fn test_copy_move_task_move() {
        let mut task = DataTypeTreeCopyMoveTask::new(
            vec!["/Src/Type1".into()],
            "/Dst",
            true,
        );
        assert!(task.is_move);

        task.execute();
        assert_eq!(task.results().len(), 1);
    }

    #[test]
    fn test_open_domain_file_task() {
        let mut task = OpenDomainFileTask::new("/path/to/archive.gdt");
        assert!(!task.is_opened());

        task.execute().unwrap();
        assert!(task.is_opened());
    }

    #[test]
    fn test_open_domain_file_task_empty_path() {
        let mut task = OpenDomainFileTask::new("");
        let result = task.execute();
        assert!(result.is_err());
        assert!(!task.is_opened());
        assert!(task.error().is_some());
    }

    #[test]
    fn test_task_result_variants() {
        assert_eq!(
            TaskResult::Success("ok".into()),
            TaskResult::Success("ok".into())
        );
        assert_ne!(
            TaskResult::Success("ok".into()),
            TaskResult::Failed("ok".into())
        );
        assert_eq!(TaskResult::Cancelled, TaskResult::Cancelled);
    }
}
