//! Diff service interface.
//!
//! Ported from Ghidra's `ghidra.app.services.DiffService` Java interface.
//!
//! Provides a service interface into the Diff Plugin for displaying
//! program differences between the current Program and another program.

/// Trait providing a service interface into the Diff Plugin for displaying
/// program differences between the current Program and another program.
///
/// Ported from Ghidra's `DiffService` Java interface.
pub trait DiffService {
    /// Launch the Diff dialog and display differences between the current program
    /// and the other program. This will force the current Diff, if active, to be terminated.
    ///
    /// # Arguments
    ///
    /// * `other_program_name` - The name/path of the program to diff the current program against.
    ///
    /// # Returns
    ///
    /// `true` if the second program is opened and successfully diffed. `false` if the diff
    /// fails to launch.
    fn launch_diff_by_name(&mut self, other_program_name: &str) -> bool;

    /// Launch the Diff dialog and display differences between the current program
    /// and the other program. This will force the current Diff, if active, to be terminated.
    ///
    /// # Arguments
    ///
    /// * `other_program_id` - The identifier of the program to diff the current program against.
    ///
    /// # Returns
    ///
    /// `true` if the second program is opened and successfully diffed. `false` if the diff
    /// fails to launch.
    fn launch_diff_by_id(&mut self, other_program_id: u64) -> bool;

    /// Determine if the Diff service is currently displaying a Diff within the Tool associated
    /// with this service.
    ///
    /// # Returns
    ///
    /// `true` if a Diff is currently active.
    fn is_diff_active(&self) -> bool;
}

/// A simple in-memory implementation of [`DiffService`] for testing.
///
/// This implementation tracks whether a diff is active but does not
/// perform actual program comparison (that would require a full program model).
#[derive(Debug, Clone, Default)]
pub struct SimpleDiffService {
    diff_active: bool,
    current_target: Option<String>,
}

impl SimpleDiffService {
    /// Create a new simple diff service.
    pub fn new() -> Self {
        Self::default()
    }

    /// Get the name of the currently diffed target program, if any.
    pub fn current_target(&self) -> Option<&str> {
        self.current_target.as_deref()
    }

    /// Close the current diff session.
    pub fn close_diff(&mut self) {
        self.diff_active = false;
        self.current_target = None;
    }
}

impl DiffService for SimpleDiffService {
    fn launch_diff_by_name(&mut self, other_program_name: &str) -> bool {
        self.diff_active = true;
        self.current_target = Some(other_program_name.to_string());
        true
    }

    fn launch_diff_by_id(&mut self, other_program_id: u64) -> bool {
        self.diff_active = true;
        self.current_target = Some(format!("program_{}", other_program_id));
        true
    }

    fn is_diff_active(&self) -> bool {
        self.diff_active
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_diff_service_initially_inactive() {
        let service = SimpleDiffService::new();
        assert!(!service.is_diff_active());
        assert!(service.current_target().is_none());
    }

    #[test]
    fn test_diff_service_launch_by_name() {
        let mut service = SimpleDiffService::new();
        assert!(service.launch_diff_by_name("test_program"));
        assert!(service.is_diff_active());
        assert_eq!(service.current_target(), Some("test_program"));
    }

    #[test]
    fn test_diff_service_launch_by_id() {
        let mut service = SimpleDiffService::new();
        assert!(service.launch_diff_by_id(42));
        assert!(service.is_diff_active());
        assert_eq!(service.current_target(), Some("program_42"));
    }

    #[test]
    fn test_diff_service_close() {
        let mut service = SimpleDiffService::new();
        service.launch_diff_by_name("test");
        assert!(service.is_diff_active());
        service.close_diff();
        assert!(!service.is_diff_active());
        assert!(service.current_target().is_none());
    }

    #[test]
    fn test_diff_service_relaunch() {
        let mut service = SimpleDiffService::new();
        service.launch_diff_by_name("first");
        assert_eq!(service.current_target(), Some("first"));
        service.launch_diff_by_name("second");
        assert_eq!(service.current_target(), Some("second"));
        assert!(service.is_diff_active());
    }
}
