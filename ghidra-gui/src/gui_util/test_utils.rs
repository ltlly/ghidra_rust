//! GUI test utilities.
//!
//! Ports `generic.test` and `ghidra.test` from Ghidra's Java source.
//!
//! Provides utilities for headless GUI testing, test fixtures, and
//! test environment management.

use std::collections::HashMap;

/// A test environment that manages GUI test setup and teardown.
///
/// Ports Ghidra's `TestEnv` concept for integration testing.
#[derive(Debug)]
pub struct TestEnvironment {
    /// The name of the test environment.
    pub name: String,
    /// Temporary directory for test files.
    pub temp_dir: Option<String>,
    /// Whether the environment has been initialized.
    pub initialized: bool,
    /// Registered tool configurations.
    pub tool_configs: HashMap<String, String>,
}

impl TestEnvironment {
    /// Create a new test environment.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            temp_dir: None,
            initialized: false,
            tool_configs: HashMap::new(),
        }
    }

    /// Initialize the test environment.
    pub fn initialize(&mut self) {
        self.initialized = true;
    }

    /// Whether the environment is initialized.
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Set the temporary directory.
    pub fn set_temp_dir(&mut self, dir: impl Into<String>) {
        self.temp_dir = Some(dir.into());
    }

    /// Register a tool configuration.
    pub fn register_tool_config(&mut self, name: impl Into<String>, config: impl Into<String>) {
        self.tool_configs.insert(name.into(), config.into());
    }

    /// Clean up the test environment.
    pub fn dispose(&mut self) {
        self.initialized = false;
        self.tool_configs.clear();
    }
}

impl Drop for TestEnvironment {
    fn drop(&mut self) {
        self.dispose();
    }
}

/// A mock provider for testing GUI components.
#[derive(Debug, Clone, Default)]
pub struct MockProvider {
    /// The provider name.
    pub name: String,
    /// Whether the provider is visible.
    pub visible: bool,
    /// The component title.
    pub title: String,
    /// Reported errors.
    pub errors: Vec<String>,
}

impl MockProvider {
    /// Create a new mock provider.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            visible: false,
            title: String::new(),
            errors: Vec::new(),
        }
    }

    /// Set the title.
    pub fn with_title(mut self, title: impl Into<String>) -> Self {
        self.title = title.into();
        self
    }

    /// Set visibility.
    pub fn set_visible(&mut self, visible: bool) {
        self.visible = visible;
    }

    /// Record an error.
    pub fn record_error(&mut self, error: impl Into<String>) {
        self.errors.push(error.into());
    }

    /// Get the number of errors.
    pub fn error_count(&self) -> usize {
        self.errors.len()
    }

    /// Clear errors.
    pub fn clear_errors(&mut self) {
        self.errors.clear();
    }
}

/// A test utility for running assertions on GUI component state.
///
/// Provides helper methods for common test patterns.
pub struct GuiTestAssertions;

impl GuiTestAssertions {
    /// Assert that a component is visible.
    pub fn assert_visible(visible: bool) {
        assert!(visible, "Expected component to be visible");
    }

    /// Assert that a component is not visible.
    pub fn assert_not_visible(visible: bool) {
        assert!(!visible, "Expected component to not be visible");
    }

    /// Assert that a string contains an expected substring.
    pub fn assert_contains(haystack: &str, needle: &str) {
        assert!(
            haystack.contains(needle),
            "Expected '{}' to contain '{}'",
            haystack,
            needle
        );
    }

    /// Assert that two floating-point values are approximately equal.
    pub fn assert_approx_eq(a: f64, b: f64, epsilon: f64) {
        assert!(
            (a - b).abs() < epsilon,
            "Expected {} to be approximately {} (epsilon={})",
            a,
            b,
            epsilon
        );
    }
}

/// A test for verifying tool state.
///
/// Ports Ghidra's test utility for checking the state of running tools.
#[derive(Debug, Clone)]
pub struct ToolStateVerifier {
    /// The tool name.
    pub tool_name: String,
    /// Registered checks.
    pub checks: Vec<String>,
    /// Passed checks.
    pub passed: Vec<String>,
    /// Failed checks.
    pub failed: Vec<String>,
}

impl ToolStateVerifier {
    /// Create a new verifier.
    pub fn new(tool_name: impl Into<String>) -> Self {
        Self {
            tool_name: tool_name.into(),
            checks: Vec::new(),
            passed: Vec::new(),
            failed: Vec::new(),
        }
    }

    /// Register a check.
    pub fn add_check(&mut self, check: impl Into<String>) {
        self.checks.push(check.into());
    }

    /// Mark a check as passed.
    pub fn pass(&mut self, check: &str) {
        self.passed.push(check.to_string());
    }

    /// Mark a check as failed.
    pub fn fail(&mut self, check: &str) {
        self.failed.push(check.to_string());
    }

    /// Whether all checks passed.
    pub fn all_passed(&self) -> bool {
        self.failed.is_empty() && self.passed.len() == self.checks.len()
    }

    /// Get the number of passed checks.
    pub fn pass_count(&self) -> usize {
        self.passed.len()
    }

    /// Get the number of failed checks.
    pub fn fail_count(&self) -> usize {
        self.failed.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_test_environment() {
        let mut env = TestEnvironment::new("test_env");
        assert!(!env.is_initialized());
        env.initialize();
        assert!(env.is_initialized());
        env.dispose();
        assert!(!env.is_initialized());
    }

    #[test]
    fn test_test_environment_drop() {
        {
            let mut env = TestEnvironment::new("test");
            env.initialize();
            env.register_tool_config("tool1", "config1");
            assert!(env.is_initialized());
        }
        // env dropped
    }

    #[test]
    fn test_mock_provider() {
        let mut provider = MockProvider::new("TestProvider")
            .with_title("Test Title");
        assert_eq!(provider.name, "TestProvider");
        assert_eq!(provider.title, "Test Title");
        assert!(!provider.visible);
        assert_eq!(provider.error_count(), 0);

        provider.set_visible(true);
        assert!(provider.visible);

        provider.record_error("an error occurred");
        assert_eq!(provider.error_count(), 1);

        provider.clear_errors();
        assert_eq!(provider.error_count(), 0);
    }

    #[test]
    fn test_tool_state_verifier() {
        let mut verifier = ToolStateVerifier::new("test_tool");
        verifier.add_check("check1");
        verifier.add_check("check2");
        verifier.add_check("check3");

        verifier.pass("check1");
        verifier.pass("check2");
        verifier.fail("check3");

        assert!(!verifier.all_passed());
        assert_eq!(verifier.pass_count(), 2);
        assert_eq!(verifier.fail_count(), 1);
    }

    #[test]
    fn test_tool_state_verifier_all_pass() {
        let mut verifier = ToolStateVerifier::new("test_tool");
        verifier.add_check("check1");
        verifier.add_check("check2");

        verifier.pass("check1");
        verifier.pass("check2");

        assert!(verifier.all_passed());
        assert_eq!(verifier.pass_count(), 2);
        assert_eq!(verifier.fail_count(), 0);
    }
}
