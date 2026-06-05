//! Action context types for Ghidra's docking action framework.
//!
//! Ported from Ghidra's `ghidra.app.context` Java package. These types
//! carry context information (program, location, selection, navigatable)
//! when actions are invoked by the user.
//!
//! # Context hierarchy
//!
//! - [`ActionContext`] -- base trait (mirrors `docking.ActionContext`)
//! - [`ProgramActionContext`] -- carries a [`Program`] reference
//! - [`NavigatableActionContext`] -- adds a [`Navigatable`] (split view)
//! - [`ProgramLocationActionContext`] -- adds a [`ProgramLocation`]
//! - [`ListingActionContext`] -- the primary listing context
//! - [`ProgramSymbolActionContext`] -- context with symbol information
//!
//! Action base types:
//! - [`ListingContextAction`] -- action that operates on `ListingActionContext`
//! - [`ProgramContextAction`] -- action that operates on `ProgramActionContext`
//! - [`NavigatableContextAction`] -- action on `NavigatableActionContext`
//! - [`ProgramLocationContextAction`] -- action on `ProgramLocationActionContext`
//! - [`ProgramSymbolContextAction`] -- action on `ProgramSymbolActionContext`

use std::sync::{Arc, Weak};

// ---------------------------------------------------------------------------
// Forward-compatible placeholder types
// ---------------------------------------------------------------------------

/// Placeholder for a Ghidra Program.
#[derive(Debug, Clone)]
pub struct Program {
    pub name: String,
}

/// Placeholder for a program address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Address(pub u64);

/// Placeholder for a program location.
#[derive(Debug, Clone)]
pub struct ProgramLocation {
    pub address: Address,
}

/// Placeholder for a program selection.
#[derive(Debug, Clone, Default)]
pub struct ProgramSelection {
    pub ranges: Vec<(Address, Address)>,
}

/// Placeholder for a Navigatable (split/view panel).
pub trait Navigatable: std::fmt::Debug {
    fn get_program(&self) -> Option<Arc<Program>>;
    fn get_location(&self) -> Option<ProgramLocation>;
    fn get_selection(&self) -> ProgramSelection;
    fn get_highlight(&self) -> ProgramSelection;
    fn is_connected(&self) -> bool;
}

// ---------------------------------------------------------------------------
// Action context hierarchy
// ---------------------------------------------------------------------------

/// Base trait for all action contexts.
///
/// In Ghidra this is `docking.ActionContext`; here we model it as a trait
/// that provides the provider identity and whether the context is valid.
pub trait ActionContext: std::fmt::Debug {
    /// Returns the name of the component provider that created this context.
    fn provider_name(&self) -> &str;

    /// Returns true if this context is valid for action execution.
    fn is_valid(&self) -> bool {
        true
    }
}

/// Action context associated with a program.
#[derive(Debug)]
pub struct ProgramActionContext {
    provider: String,
    program: Option<Arc<Program>>,
    active_program: bool,
}

impl ProgramActionContext {
    pub fn new(provider: impl Into<String>, program: Option<Arc<Program>>) -> Self {
        Self {
            provider: provider.into(),
            program,
            active_program: true,
        }
    }

    pub fn get_program(&self) -> Option<&Arc<Program>> {
        self.program.as_ref()
    }

    /// Returns true if the program in this context is the globally active
    /// program in the tool.
    pub fn is_active_program(&self) -> bool {
        self.active_program
    }
}

impl ActionContext for ProgramActionContext {
    fn provider_name(&self) -> &str {
        &self.provider
    }
}

/// Action context associated with a navigatable panel.
#[derive(Debug)]
pub struct NavigatableActionContext {
    provider: String,
    navigatable: Option<Box<dyn Navigatable>>,
    program: Option<Arc<Program>>,
    location: Option<ProgramLocation>,
    selection: Option<ProgramSelection>,
    highlight: Option<ProgramSelection>,
}

impl NavigatableActionContext {
    pub fn new(
        provider: impl Into<String>,
        navigatable: Option<Box<dyn Navigatable>>,
    ) -> Self {
        let (program, location, selection, highlight) = if let Some(ref nav) = navigatable {
            (
                nav.get_program(),
                nav.get_location(),
                Some(nav.get_selection()),
                Some(nav.get_highlight()),
            )
        } else {
            (None, None, None, None)
        };

        Self {
            provider: provider.into(),
            navigatable,
            program,
            location,
            selection,
            highlight,
        }
    }

    pub fn with_full(
        provider: impl Into<String>,
        navigatable: Option<Box<dyn Navigatable>>,
        program: Option<Arc<Program>>,
        location: Option<ProgramLocation>,
        selection: Option<ProgramSelection>,
        highlight: Option<ProgramSelection>,
    ) -> Self {
        Self {
            provider: provider.into(),
            navigatable,
            program,
            location,
            selection,
            highlight,
        }
    }

    pub fn get_program(&self) -> Option<&Arc<Program>> {
        self.program.as_ref()
    }

    pub fn get_location(&self) -> Option<&ProgramLocation> {
        self.location.as_ref()
    }

    pub fn get_selection(&self) -> Option<&ProgramSelection> {
        self.selection.as_ref()
    }

    pub fn get_highlight(&self) -> Option<&ProgramSelection> {
        self.highlight.as_ref()
    }
}

impl ActionContext for NavigatableActionContext {
    fn provider_name(&self) -> &str {
        &self.provider
    }
}

/// Action context with a program location.
#[derive(Debug)]
pub struct ProgramLocationActionContext {
    provider: String,
    program: Option<Arc<Program>>,
    location: ProgramLocation,
}

impl ProgramLocationActionContext {
    pub fn new(
        provider: impl Into<String>,
        program: Option<Arc<Program>>,
        location: ProgramLocation,
    ) -> Self {
        Self {
            provider: provider.into(),
            program,
            location,
        }
    }

    pub fn get_program(&self) -> Option<&Arc<Program>> {
        self.program.as_ref()
    }

    pub fn get_location(&self) -> &ProgramLocation {
        &self.location
    }
}

impl ActionContext for ProgramLocationActionContext {
    fn provider_name(&self) -> &str {
        &self.provider
    }
}

/// Primary context for listing (code browser) actions.
#[derive(Debug)]
pub struct ListingActionContext {
    inner: NavigatableActionContext,
}

impl ListingActionContext {
    pub fn new(
        provider: impl Into<String>,
        navigatable: Option<Box<dyn Navigatable>>,
    ) -> Self {
        Self {
            inner: NavigatableActionContext::new(provider, navigatable),
        }
    }

    pub fn with_location(
        provider: impl Into<String>,
        navigatable: Option<Box<dyn Navigatable>>,
        location: ProgramLocation,
    ) -> Self {
        let mut inner = NavigatableActionContext::new(provider, navigatable);
        inner.location = Some(location);
        Self { inner }
    }

    pub fn with_full(
        provider: impl Into<String>,
        navigatable: Option<Box<dyn Navigatable>>,
        program: Option<Arc<Program>>,
        location: Option<ProgramLocation>,
        selection: Option<ProgramSelection>,
        highlight: Option<ProgramSelection>,
    ) -> Self {
        Self {
            inner: NavigatableActionContext::with_full(
                provider, navigatable, program, location, selection, highlight,
            ),
        }
    }

    pub fn get_program(&self) -> Option<&Arc<Program>> {
        self.inner.get_program()
    }

    pub fn get_location(&self) -> Option<&ProgramLocation> {
        self.inner.get_location()
    }

    pub fn get_selection(&self) -> Option<&ProgramSelection> {
        self.inner.get_selection()
    }

    pub fn get_highlight(&self) -> Option<&ProgramSelection> {
        self.inner.get_highlight()
    }
}

impl ActionContext for ListingActionContext {
    fn provider_name(&self) -> &str {
        self.inner.provider_name()
    }
}

/// Context carrying symbol information for a program.
#[derive(Debug)]
pub struct ProgramSymbolActionContext {
    inner: ProgramActionContext,
    symbol_name: Option<String>,
    symbol_address: Option<Address>,
}

impl ProgramSymbolActionContext {
    pub fn new(
        provider: impl Into<String>,
        program: Option<Arc<Program>>,
        symbol_name: Option<String>,
        symbol_address: Option<Address>,
    ) -> Self {
        Self {
            inner: ProgramActionContext::new(provider, program),
            symbol_name,
            symbol_address,
        }
    }

    pub fn get_symbol_name(&self) -> Option<&str> {
        self.symbol_name.as_deref()
    }

    pub fn get_symbol_address(&self) -> Option<Address> {
        self.symbol_address
    }

    pub fn get_program(&self) -> Option<&Arc<Program>> {
        self.inner.get_program()
    }
}

impl ActionContext for ProgramSymbolActionContext {
    fn provider_name(&self) -> &str {
        self.inner.provider_name()
    }
}

/// Context providing restricted address set information.
#[derive(Debug)]
pub struct RestrictedAddressSetContext {
    inner: NavigatableActionContext,
    restricted_ranges: Vec<(Address, Address)>,
}

impl RestrictedAddressSetContext {
    pub fn new(
        provider: impl Into<String>,
        navigatable: Option<Box<dyn Navigatable>>,
        restricted_ranges: Vec<(Address, Address)>,
    ) -> Self {
        Self {
            inner: NavigatableActionContext::new(provider, navigatable),
            restricted_ranges,
        }
    }

    pub fn get_restricted_ranges(&self) -> &[(Address, Address)] {
        &self.restricted_ranges
    }
}

impl ActionContext for RestrictedAddressSetContext {
    fn provider_name(&self) -> &str {
        self.inner.provider_name()
    }
}

/// Context providing a navigation action context (for nav actions).
#[derive(Debug)]
pub struct NavigationActionContext {
    inner: NavigatableActionContext,
}

impl NavigationActionContext {
    pub fn new(
        provider: impl Into<String>,
        navigatable: Option<Box<dyn Navigatable>>,
    ) -> Self {
        Self {
            inner: NavigatableActionContext::new(provider, navigatable),
        }
    }
}

impl ActionContext for NavigationActionContext {
    fn provider_name(&self) -> &str {
        self.inner.provider_name()
    }
}

/// Context providing a function supplier.
#[derive(Debug)]
pub struct FunctionSupplierContext {
    inner: ProgramActionContext,
    function_name: Option<String>,
    function_address: Option<Address>,
}

impl FunctionSupplierContext {
    pub fn new(
        provider: impl Into<String>,
        program: Option<Arc<Program>>,
        function_name: Option<String>,
        function_address: Option<Address>,
    ) -> Self {
        Self {
            inner: ProgramActionContext::new(provider, program),
            function_name,
            function_address,
        }
    }

    pub fn get_function_name(&self) -> Option<&str> {
        self.function_name.as_deref()
    }

    pub fn get_function_address(&self) -> Option<Address> {
        self.function_address
    }
}

impl ActionContext for FunctionSupplierContext {
    fn provider_name(&self) -> &str {
        self.inner.provider_name()
    }
}

/// Context providing a program location supplier.
#[derive(Debug)]
pub struct ProgramLocationSupplierContext {
    inner: ProgramActionContext,
    location: Option<ProgramLocation>,
}

impl ProgramLocationSupplierContext {
    pub fn new(
        provider: impl Into<String>,
        program: Option<Arc<Program>>,
        location: Option<ProgramLocation>,
    ) -> Self {
        Self {
            inner: ProgramActionContext::new(provider, program),
            location,
        }
    }

    pub fn get_location(&self) -> Option<&ProgramLocation> {
        self.location.as_ref()
    }
}

impl ActionContext for ProgramLocationSupplierContext {
    fn provider_name(&self) -> &str {
        self.inner.provider_name()
    }
}

/// Context with a list of data locations.
#[derive(Debug)]
pub struct DataLocationListContext {
    inner: ProgramActionContext,
    locations: Vec<Address>,
}

impl DataLocationListContext {
    pub fn new(
        provider: impl Into<String>,
        program: Option<Arc<Program>>,
        locations: Vec<Address>,
    ) -> Self {
        Self {
            inner: ProgramActionContext::new(provider, program),
            locations,
        }
    }

    pub fn get_locations(&self) -> &[Address] {
        &self.locations
    }
}

impl ActionContext for DataLocationListContext {
    fn provider_name(&self) -> &str {
        self.inner.provider_name()
    }
}

// ---------------------------------------------------------------------------
// Context action base types
// ---------------------------------------------------------------------------

/// A context action that operates on `ListingActionContext`.
///
/// This mirrors Ghidra's `ListingContextAction` abstract class.
#[derive(Debug)]
pub struct ListingContextActionDef {
    name: String,
    owner: String,
}

impl ListingContextActionDef {
    pub fn new(name: impl Into<String>, owner: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            owner: owner.into(),
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn owner(&self) -> &str {
        &self.owner
    }

    /// Check if the action is enabled for the given context.
    pub fn is_enabled_for(&self, _ctx: &ListingActionContext) -> bool {
        true
    }

    /// Check if the context is valid for this action.
    pub fn is_valid_context(&self, _ctx: &ListingActionContext) -> bool {
        true
    }

    /// Check if this action should be added to the popup menu.
    pub fn is_add_to_popup(&self, ctx: &ListingActionContext) -> bool {
        self.is_enabled_for(ctx)
    }
}

/// A context action that operates on `ProgramActionContext`.
#[derive(Debug)]
pub struct ProgramContextActionDef {
    name: String,
    owner: String,
}

impl ProgramContextActionDef {
    pub fn new(name: impl Into<String>, owner: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            owner: owner.into(),
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn owner(&self) -> &str {
        &self.owner
    }

    pub fn is_enabled_for(&self, _ctx: &ProgramActionContext) -> bool {
        true
    }
}

/// A context action that operates on `NavigatableActionContext`.
#[derive(Debug)]
pub struct NavigatableContextActionDef {
    name: String,
    owner: String,
}

impl NavigatableContextActionDef {
    pub fn new(name: impl Into<String>, owner: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            owner: owner.into(),
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn owner(&self) -> &str {
        &self.owner
    }

    pub fn is_enabled_for(&self, _ctx: &NavigatableActionContext) -> bool {
        true
    }
}

/// A context action that operates on `ProgramLocationActionContext`.
#[derive(Debug)]
pub struct ProgramLocationContextActionDef {
    name: String,
    owner: String,
}

impl ProgramLocationContextActionDef {
    pub fn new(name: impl Into<String>, owner: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            owner: owner.into(),
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn owner(&self) -> &str {
        &self.owner
    }

    pub fn is_enabled_for(&self, _ctx: &ProgramLocationActionContext) -> bool {
        true
    }
}

/// A context action that operates on `ProgramSymbolActionContext`.
#[derive(Debug)]
pub struct ProgramSymbolContextActionDef {
    name: String,
    owner: String,
}

impl ProgramSymbolContextActionDef {
    pub fn new(name: impl Into<String>, owner: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            owner: owner.into(),
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn owner(&self) -> &str {
        &self.owner
    }

    pub fn is_enabled_for(&self, _ctx: &ProgramSymbolActionContext) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug)]
    struct TestNavigatable {
        program: Option<Arc<Program>>,
        location: Option<ProgramLocation>,
    }

    impl Navigatable for TestNavigatable {
        fn get_program(&self) -> Option<Arc<Program>> {
            self.program.clone()
        }
        fn get_location(&self) -> Option<ProgramLocation> {
            self.location.clone()
        }
        fn get_selection(&self) -> ProgramSelection {
            ProgramSelection::default()
        }
        fn get_highlight(&self) -> ProgramSelection {
            ProgramSelection::default()
        }
        fn is_connected(&self) -> bool {
            true
        }
    }

    fn make_program() -> Arc<Program> {
        Arc::new(Program {
            name: "test.exe".into(),
        })
    }

    #[test]
    fn test_program_action_context() {
        let prog = make_program();
        let ctx = ProgramActionContext::new("CodeBrowser", Some(prog));
        assert_eq!(ctx.provider_name(), "CodeBrowser");
        assert!(ctx.is_active_program());
        assert!(ctx.get_program().is_some());
    }

    #[test]
    fn test_listing_action_context() {
        let prog = make_program();
        let nav = TestNavigatable {
            program: Some(prog),
            location: Some(ProgramLocation {
                address: Address(0x1000),
            }),
        };
        let ctx = ListingActionContext::new("CodeBrowser", Some(Box::new(nav)));
        assert_eq!(ctx.provider_name(), "CodeBrowser");
        assert!(ctx.get_program().is_some());
    }

    #[test]
    fn test_program_location_action_context() {
        let prog = make_program();
        let loc = ProgramLocation {
            address: Address(0x401000),
        };
        let ctx = ProgramLocationActionContext::new("TestProvider", Some(prog), loc);
        assert_eq!(ctx.get_location().address, Address(0x401000));
    }

    #[test]
    fn test_program_symbol_action_context() {
        let prog = make_program();
        let ctx = ProgramSymbolActionContext::new(
            "SymbolTree",
            Some(prog),
            Some("main".into()),
            Some(Address(0x401000)),
        );
        assert_eq!(ctx.get_symbol_name(), Some("main"));
        assert_eq!(ctx.get_symbol_address(), Some(Address(0x401000)));
    }

    #[test]
    fn test_restricted_address_set_context() {
        let ctx = RestrictedAddressSetContext::new(
            "TestProvider",
            None,
            vec![(Address(0x1000), Address(0x2000))],
        );
        assert_eq!(ctx.get_restricted_ranges().len(), 1);
    }

    #[test]
    fn test_function_supplier_context() {
        let prog = make_program();
        let ctx = FunctionSupplierContext::new(
            "FunctionWindow",
            Some(prog),
            Some("main".into()),
            Some(Address(0x400000)),
        );
        assert_eq!(ctx.get_function_name(), Some("main"));
    }

    #[test]
    fn test_data_location_list_context() {
        let prog = make_program();
        let ctx = DataLocationListContext::new(
            "TestProvider",
            Some(prog),
            vec![Address(0x1000), Address(0x2000)],
        );
        assert_eq!(ctx.get_locations().len(), 2);
    }

    #[test]
    fn test_listing_context_action_def() {
        let action = ListingContextActionDef::new("MyAction", "TestOwner");
        assert_eq!(action.name(), "MyAction");
        assert_eq!(action.owner(), "TestOwner");
    }

    #[test]
    fn test_program_context_action_def() {
        let action = ProgramContextActionDef::new("ProgramAction", "Owner");
        assert_eq!(action.name(), "ProgramAction");
    }

    #[test]
    fn test_navigatable_context_action_def() {
        let action = NavigatableContextActionDef::new("NavAction", "Owner");
        assert_eq!(action.name(), "NavAction");
    }

    #[test]
    fn test_program_location_context_action_def() {
        let action = ProgramLocationContextActionDef::new("LocAction", "Owner");
        assert_eq!(action.name(), "LocAction");
    }

    #[test]
    fn test_program_symbol_context_action_def() {
        let action = ProgramSymbolContextActionDef::new("SymAction", "Owner");
        assert_eq!(action.name(), "SymAction");
    }
}
