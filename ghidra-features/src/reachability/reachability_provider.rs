//! Function Reachability Provider -- manages the reachability analysis UI state.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.reachability.FunctionReachabilityProvider`.
//!
//! Holds the from/to function state, manages address validation, and
//! coordinates the results table model with the paths model.
//!
//! # Key Types
//!
//! - [`ReachabilityProvider`] -- Provider managing reachability analysis display
//! - [`ReachabilityProviderState`] -- Input state for from/to function addresses

use ghidra_core::Address;

use super::graph::FRPathsModel;
use super::table::ReachabilityModel;

// ---------------------------------------------------------------------------
// ReachabilityProviderState -- input state for from/to addresses
// ---------------------------------------------------------------------------

/// State of the from/to function inputs.
///
/// Ported from the UI input fields in `FunctionReachabilityProvider`.
#[derive(Debug, Clone)]
pub struct ReachabilityProviderState {
    /// The "from" address text.
    pub from_address_text: String,
    /// The resolved "from" function name.
    pub from_function_name: Option<String>,
    /// The resolved "from" function entry point.
    pub from_address: Option<Address>,
    /// The "to" address text.
    pub to_address_text: String,
    /// The resolved "to" function name.
    pub to_function_name: Option<String>,
    /// The resolved "to" function entry point.
    pub to_address: Option<Address>,
}

impl ReachabilityProviderState {
    /// Create a new empty state.
    pub fn new() -> Self {
        Self {
            from_address_text: String::new(),
            from_function_name: None,
            from_address: None,
            to_address_text: String::new(),
            to_function_name: None,
            to_address: None,
        }
    }

    /// Swap the from and to fields.
    ///
    /// Ported from the swap button action in `FunctionReachabilityProvider`.
    pub fn swap(&mut self) {
        std::mem::swap(&mut self.from_address_text, &mut self.to_address_text);
        std::mem::swap(&mut self.from_function_name, &mut self.to_function_name);
        std::mem::swap(&mut self.from_address, &mut self.to_address);
    }

    /// Check if the from input is valid (non-empty and resolved).
    pub fn is_from_valid(&self) -> bool {
        !self.from_address_text.is_empty() && self.from_address.is_some()
    }

    /// Check if the to input is valid (non-empty and resolved).
    pub fn is_to_valid(&self) -> bool {
        !self.to_address_text.is_empty() && self.to_address.is_some()
    }

    /// Check if both inputs are valid.
    pub fn is_ready(&self) -> bool {
        self.is_from_valid() && self.is_to_valid()
    }

    /// Clear the from fields.
    pub fn clear_from(&mut self) {
        self.from_address_text.clear();
        self.from_function_name = None;
        self.from_address = None;
    }

    /// Clear the to fields.
    pub fn clear_to(&mut self) {
        self.to_address_text.clear();
        self.to_function_name = None;
        self.to_address = None;
    }

    /// Clear all fields.
    pub fn clear(&mut self) {
        self.clear_from();
        self.clear_to();
    }
}

impl Default for ReachabilityProviderState {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// ReachabilityProvider -- provider managing reachability display
// ---------------------------------------------------------------------------

/// The reachability provider managing the analysis display.
///
/// Ported from `ghidra.app.plugin.core.reachability.FunctionReachabilityProvider`.
///
/// Manages the from/to function inputs, validates addresses against
/// the program's function manager, and coordinates the results and
/// paths table models.
#[derive(Debug)]
pub struct ReachabilityProvider {
    /// The current input state.
    state: ReachabilityProviderState,
    /// Results model for reachability queries.
    results_model: ReachabilityModel,
    /// Paths model for showing individual path entries.
    paths_model: FRPathsModel,
    /// The current program name (if any).
    program_name: Option<String>,
    /// Whether the provider is visible.
    visible: bool,
    /// Status message (error/info).
    status_message: Option<String>,
    /// Whether the status is an error.
    status_is_error: bool,
}

impl ReachabilityProvider {
    /// Create a new reachability provider.
    pub fn new() -> Self {
        Self {
            state: ReachabilityProviderState::new(),
            results_model: ReachabilityModel::new(),
            paths_model: FRPathsModel::new(),
            program_name: None,
            visible: false,
            status_message: None,
            status_is_error: false,
        }
    }

    /// Initialize the provider with a program and optional location.
    ///
    /// Ported from `FunctionReachabilityProvider.initialize(Program, ProgramLocation)`.
    pub fn initialize(&mut self, program_name: Option<String>, location: Option<Address>) {
        self.program_name = program_name;
        if let Some(addr) = location {
            self.set_from_address(addr);
        }
    }

    /// Get the current input state.
    pub fn state(&self) -> &ReachabilityProviderState {
        &self.state
    }

    /// Get a mutable reference to the input state.
    pub fn state_mut(&mut self) -> &mut ReachabilityProviderState {
        &mut self.state
    }

    /// Get the results model.
    pub fn results_model(&self) -> &ReachabilityModel {
        &self.results_model
    }

    /// Get a mutable reference to the results model.
    pub fn results_model_mut(&mut self) -> &mut ReachabilityModel {
        &mut self.results_model
    }

    /// Get the paths model.
    pub fn paths_model(&self) -> &FRPathsModel {
        &self.paths_model
    }

    /// Get a mutable reference to the paths model.
    pub fn paths_model_mut(&mut self) -> &mut FRPathsModel {
        &mut self.paths_model
    }

    /// Get the current program name.
    pub fn program_name(&self) -> Option<&str> {
        self.program_name.as_deref()
    }

    /// Whether the provider is visible.
    pub fn is_visible(&self) -> bool {
        self.visible
    }

    /// Set visibility.
    pub fn set_visible(&mut self, visible: bool) {
        self.visible = visible;
    }

    /// Get the current status message.
    pub fn status_message(&self) -> Option<&str> {
        self.status_message.as_deref()
    }

    /// Whether the status is an error.
    pub fn status_is_error(&self) -> bool {
        self.status_is_error
    }

    /// Set the "from" address.
    ///
    /// Ported from `FunctionReachabilityProvider.setFromFunction(Function)`.
    pub fn set_from_address(&mut self, address: Address) {
        self.state.from_address = Some(address);
        self.state.from_address_text = format!("0x{:x}", address.offset);
        self.state.from_function_name = Some(format!("FUN_{:x}", address.offset));
        self.clear_status();
    }

    /// Set the "to" address.
    pub fn set_to_address(&mut self, address: Address) {
        self.state.to_address = Some(address);
        self.state.to_address_text = format!("0x{:x}", address.offset);
        self.state.to_function_name = Some(format!("FUN_{:x}", address.offset));
        self.clear_status();
    }

    /// Set the "from" function name (for display).
    pub fn set_from_function_name(&mut self, name: impl Into<String>) {
        self.state.from_function_name = Some(name.into());
    }

    /// Set the "to" function name (for display).
    pub fn set_to_function_name(&mut self, name: impl Into<String>) {
        self.state.to_function_name = Some(name.into());
    }

    /// Swap from and to inputs.
    ///
    /// Ported from the swap button action in `FunctionReachabilityProvider`.
    pub fn swap_inputs(&mut self) {
        self.state.swap();
        self.clear_status();
    }

    /// Clear the status message.
    pub fn clear_status(&mut self) {
        self.status_message = None;
        self.status_is_error = false;
    }

    /// Set an info status message.
    pub fn set_status_info(&mut self, message: impl Into<String>) {
        self.status_message = Some(message.into());
        self.status_is_error = false;
    }

    /// Set an error status message.
    ///
    /// Ported from `tool.setStatusInfo(..., true)` in `FunctionReachabilityProvider`.
    pub fn set_status_error(&mut self, message: impl Into<String>) {
        self.status_message = Some(message.into());
        self.status_is_error = true;
    }

    /// Validate the from input.
    ///
    /// Ported from `FunctionReachabilityProvider.validateFunctions()`.
    pub fn validate_from(&mut self) -> bool {
        if self.state.from_address_text.is_empty() {
            self.set_status_error("Must input two valid functions: 'from' address is empty");
            return false;
        }
        if self.state.from_address.is_none() {
            self.set_status_error(format!(
                "Must input two valid functions: 'from' address is not in a function: {}",
                self.state.from_address_text
            ));
            return false;
        }
        true
    }

    /// Validate the to input.
    pub fn validate_to(&mut self) -> bool {
        if self.state.to_address_text.is_empty() {
            self.set_status_error("Must input two valid functions: 'to' address is empty");
            return false;
        }
        if self.state.to_address.is_none() {
            self.set_status_error(format!(
                "Must input two valid functions: 'to' address is not in a function: {}",
                self.state.to_address_text
            ));
            return false;
        }
        true
    }

    /// Validate both inputs and trigger the reachability analysis.
    ///
    /// Ported from `FunctionReachabilityProvider.findPaths()`.
    pub fn find_paths(&mut self) -> bool {
        if !self.validate_from() {
            return false;
        }
        if !self.validate_to() {
            return false;
        }

        self.clear_status();
        self.results_model.set_start(&self.state.from_address_text);
        true
    }

    /// Handle the provider being hidden.
    ///
    /// Ported from `FunctionReachabilityProvider.componentHidden()`.
    pub fn component_hidden(&mut self) {
        self.visible = false;
    }

    /// Clear all results and paths.
    pub fn clear_results(&mut self) {
        self.results_model = ReachabilityModel::new();
        self.paths_model.clear();
    }

    /// Dispose the provider.
    pub fn dispose(&mut self) {
        self.visible = false;
        self.clear_results();
        self.state.clear();
        self.program_name = None;
        self.clear_status();
    }
}

impl Default for ReachabilityProvider {
    fn default() -> Self {
        Self::new()
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_provider_state_new() {
        let state = ReachabilityProviderState::new();
        assert!(state.from_address_text.is_empty());
        assert!(state.from_function_name.is_none());
        assert!(state.from_address.is_none());
        assert!(state.to_address_text.is_empty());
        assert!(state.to_function_name.is_none());
        assert!(state.to_address.is_none());
    }

    #[test]
    fn test_provider_state_swap() {
        let mut state = ReachabilityProviderState::new();
        state.from_address_text = "0x1000".into();
        state.from_function_name = Some("main".into());
        state.from_address = Some(Address::new(0x1000));
        state.to_address_text = "0x2000".into();
        state.to_function_name = Some("foo".into());
        state.to_address = Some(Address::new(0x2000));

        state.swap();

        assert_eq!(state.from_address_text, "0x2000");
        assert_eq!(state.from_function_name.as_deref(), Some("foo"));
        assert_eq!(state.from_address, Some(Address::new(0x2000)));
        assert_eq!(state.to_address_text, "0x1000");
        assert_eq!(state.to_function_name.as_deref(), Some("main"));
        assert_eq!(state.to_address, Some(Address::new(0x1000)));
    }

    #[test]
    fn test_provider_state_validation() {
        let mut state = ReachabilityProviderState::new();
        assert!(!state.is_from_valid());
        assert!(!state.is_to_valid());
        assert!(!state.is_ready());

        state.from_address_text = "0x1000".into();
        state.from_address = Some(Address::new(0x1000));
        assert!(state.is_from_valid());
        assert!(!state.is_ready());

        state.to_address_text = "0x2000".into();
        state.to_address = Some(Address::new(0x2000));
        assert!(state.is_to_valid());
        assert!(state.is_ready());
    }

    #[test]
    fn test_provider_state_clear() {
        let mut state = ReachabilityProviderState::new();
        state.from_address_text = "0x1000".into();
        state.from_function_name = Some("main".into());
        state.from_address = Some(Address::new(0x1000));

        state.clear_from();
        assert!(state.from_address_text.is_empty());
        assert!(state.from_address.is_none());

        state.to_address_text = "0x2000".into();
        state.to_address = Some(Address::new(0x2000));
        state.clear();
        assert!(state.to_address_text.is_empty());
        assert!(state.to_address.is_none());
    }

    #[test]
    fn test_provider_state_default() {
        let state = ReachabilityProviderState::default();
        assert!(state.from_address_text.is_empty());
    }

    #[test]
    fn test_provider_new() {
        let provider = ReachabilityProvider::new();
        assert!(provider.program_name().is_none());
        assert!(!provider.is_visible());
        assert!(provider.status_message().is_none());
        assert!(!provider.status_is_error());
    }

    #[test]
    fn test_provider_initialize() {
        let mut provider = ReachabilityProvider::new();
        provider.initialize(
            Some("test.exe".into()),
            Some(Address::new(0x401000)),
        );

        assert_eq!(provider.program_name(), Some("test.exe"));
        assert!(provider.state().from_address.is_some());
        assert_eq!(provider.state().from_address, Some(Address::new(0x401000)));
    }

    #[test]
    fn test_provider_initialize_no_location() {
        let mut provider = ReachabilityProvider::new();
        provider.initialize(Some("test.exe".into()), None);

        assert_eq!(provider.program_name(), Some("test.exe"));
        assert!(provider.state().from_address.is_none());
    }

    #[test]
    fn test_provider_set_addresses() {
        let mut provider = ReachabilityProvider::new();
        provider.set_from_address(Address::new(0x1000));
        provider.set_to_address(Address::new(0x2000));

        assert_eq!(provider.state().from_address, Some(Address::new(0x1000)));
        assert_eq!(provider.state().to_address, Some(Address::new(0x2000)));
        assert_eq!(provider.state().from_address_text, "0x1000");
        assert_eq!(provider.state().to_address_text, "0x2000");
    }

    #[test]
    fn test_provider_set_function_names() {
        let mut provider = ReachabilityProvider::new();
        provider.set_from_address(Address::new(0x1000));
        provider.set_from_function_name("main");

        assert_eq!(provider.state().from_function_name.as_deref(), Some("main"));
    }

    #[test]
    fn test_provider_swap_inputs() {
        let mut provider = ReachabilityProvider::new();
        provider.set_from_address(Address::new(0x1000));
        provider.set_from_function_name("main");
        provider.set_to_address(Address::new(0x2000));
        provider.set_to_function_name("foo");

        provider.swap_inputs();

        assert_eq!(provider.state().from_address, Some(Address::new(0x2000)));
        assert_eq!(provider.state().from_function_name.as_deref(), Some("foo"));
        assert_eq!(provider.state().to_address, Some(Address::new(0x1000)));
        assert_eq!(provider.state().to_function_name.as_deref(), Some("main"));
    }

    #[test]
    fn test_provider_status_messages() {
        let mut provider = ReachabilityProvider::new();

        provider.set_status_info("Ready");
        assert_eq!(provider.status_message(), Some("Ready"));
        assert!(!provider.status_is_error());

        provider.set_status_error("Invalid address");
        assert_eq!(provider.status_message(), Some("Invalid address"));
        assert!(provider.status_is_error());

        provider.clear_status();
        assert!(provider.status_message().is_none());
    }

    #[test]
    fn test_provider_validate_from_empty() {
        let mut provider = ReachabilityProvider::new();
        assert!(!provider.validate_from());
        assert!(provider.status_is_error());
        assert!(provider.status_message().unwrap().contains("'from' address is empty"));
    }

    #[test]
    fn test_provider_validate_from_not_in_function() {
        let mut provider = ReachabilityProvider::new();
        provider.state_mut().from_address_text = "0x9999".into();
        // from_address is None, so validation fails
        assert!(!provider.validate_from());
        assert!(provider.status_is_error());
        assert!(provider.status_message().unwrap().contains("not in a function"));
    }

    #[test]
    fn test_provider_validate_from_valid() {
        let mut provider = ReachabilityProvider::new();
        provider.set_from_address(Address::new(0x1000));
        assert!(provider.validate_from());
        assert!(!provider.status_is_error());
    }

    #[test]
    fn test_provider_validate_to_empty() {
        let mut provider = ReachabilityProvider::new();
        provider.set_from_address(Address::new(0x1000));
        assert!(!provider.validate_to());
        assert!(provider.status_is_error());
        assert!(provider.status_message().unwrap().contains("'to' address is empty"));
    }

    #[test]
    fn test_provider_validate_to_not_in_function() {
        let mut provider = ReachabilityProvider::new();
        provider.state_mut().to_address_text = "0x9999".into();
        assert!(!provider.validate_to());
        assert!(provider.status_is_error());
        assert!(provider.status_message().unwrap().contains("not in a function"));
    }

    #[test]
    fn test_provider_validate_to_valid() {
        let mut provider = ReachabilityProvider::new();
        provider.set_to_address(Address::new(0x2000));
        assert!(provider.validate_to());
    }

    #[test]
    fn test_provider_find_paths_both_valid() {
        let mut provider = ReachabilityProvider::new();
        provider.set_from_address(Address::new(0x1000));
        provider.set_to_address(Address::new(0x2000));

        assert!(provider.find_paths());
        assert!(provider.status_message().is_none());
    }

    #[test]
    fn test_provider_find_paths_from_invalid() {
        let mut provider = ReachabilityProvider::new();
        provider.set_to_address(Address::new(0x2000));

        assert!(!provider.find_paths());
        assert!(provider.status_is_error());
    }

    #[test]
    fn test_provider_find_paths_to_invalid() {
        let mut provider = ReachabilityProvider::new();
        provider.set_from_address(Address::new(0x1000));

        assert!(!provider.find_paths());
        assert!(provider.status_is_error());
    }

    #[test]
    fn test_provider_visibility() {
        let mut provider = ReachabilityProvider::new();
        assert!(!provider.is_visible());

        provider.set_visible(true);
        assert!(provider.is_visible());

        provider.component_hidden();
        assert!(!provider.is_visible());
    }

    #[test]
    fn test_provider_clear_results() {
        let mut provider = ReachabilityProvider::new();
        provider.set_from_address(Address::new(0x1000));
        provider.set_to_address(Address::new(0x2000));
        provider.results_model_mut().set_start("0x1000");

        provider.clear_results();
        assert!(provider.results_model().is_empty());
    }

    #[test]
    fn test_provider_dispose() {
        let mut provider = ReachabilityProvider::new();
        provider.set_visible(true);
        provider.initialize(Some("test.exe".into()), Some(Address::new(0x1000)));
        provider.set_status_info("info");

        provider.dispose();

        assert!(!provider.is_visible());
        assert!(provider.program_name().is_none());
        assert!(provider.state().from_address.is_none());
        assert!(provider.status_message().is_none());
    }

    #[test]
    fn test_provider_default() {
        let provider = ReachabilityProvider::default();
        assert!(!provider.is_visible());
        assert!(provider.program_name().is_none());
    }

    #[test]
    fn test_provider_paths_model() {
        let mut provider = ReachabilityProvider::new();
        assert_eq!(provider.paths_model().vertex_count(), 0);

        provider
            .paths_model_mut()
            .add_vertex(super::super::graph::FRVertex::new(0x1000, "main"));
        assert_eq!(provider.paths_model().vertex_count(), 1);
    }
}
