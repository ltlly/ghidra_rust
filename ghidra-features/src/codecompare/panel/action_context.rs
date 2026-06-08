//! Action contexts for code comparison views.
//!
//! Ported from Ghidra's `CodeComparisonActionContext` and
//! `CodeComparisonViewActionContext` Java classes in
//! `ghidra.features.base.codecompare.panel`.
//!
//! In Ghidra's docking framework, an `ActionContext` carries information about
//! where a user action was triggered -- which component had focus, what was
//! selected, etc. Code comparison views use specialized action contexts that
//! also carry a reference to the comparison view itself, so that actions can
//! determine which side is active and access the source/target functions.
//!
//! In this Rust port we capture the logical state without the Swing/docking
//! framework dependency.
//!
//! # Key types
//!
//! - [`ActionTrigger`] -- how the action was triggered
//! - [`ComparisonActionContext`] -- context for actions in a comparison view
//! - [`ListingComparisonActionContext`] -- context specific to listing comparisons
//! - [`DecompilerComparisonActionContext`] -- context specific to decompiler comparisons

use crate::codecompare::model::ComparisonSide;
use super::FunctionComparisonInfo;

/// How an action was triggered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ActionTrigger {
    /// Triggered by a mouse event (click, right-click, etc.).
    Mouse,
    /// Triggered by a keyboard shortcut.
    Keyboard,
    /// Triggered programmatically (e.g., from a menu).
    Programmatic,
}

/// The kind of mouse button that triggered the action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MouseButton {
    Left,
    Right,
    Middle,
}

/// A point in the component's coordinate space.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ComponentPoint {
    pub x: i32,
    pub y: i32,
}

impl ComponentPoint {
    pub fn new(x: i32, y: i32) -> Self {
        Self { x, y }
    }
}

/// Context for actions in a code comparison view.
///
/// This is the Rust equivalent of Ghidra's `CodeComparisonActionContext` Java
/// class. It carries information about which comparison view the action was
/// triggered in, which side is active, and the source/target functions.
///
/// In the original Java, `CodeComparisonActionContext` extends
/// `DefaultActionContext` and holds a reference to the Swing component that
/// had focus. Here we capture the logical state.
///
/// # Example
///
/// ```rust
/// use ghidra_features::codecompare::panel::action_context::*;
/// use ghidra_features::codecompare::model::ComparisonSide;
///
/// let ctx = ComparisonActionContext::new(
///     "ListingCodeComparisonView",
///     ComparisonSide::Left,
///     ActionTrigger::Mouse,
/// );
///
/// assert_eq!(ctx.active_side(), ComparisonSide::Left);
/// assert_eq!(ctx.inactive_side(), ComparisonSide::Right);
/// assert_eq!(ctx.trigger(), ActionTrigger::Mouse);
/// ```
#[derive(Debug, Clone)]
pub struct ComparisonActionContext {
    /// The name of the comparison view that generated this context.
    view_name: String,
    /// Which side is currently active.
    active_side: ComparisonSide,
    /// How the action was triggered.
    trigger: ActionTrigger,
    /// Mouse button, if triggered by mouse.
    mouse_button: Option<MouseButton>,
    /// Mouse position in component coordinates, if triggered by mouse.
    mouse_position: Option<ComponentPoint>,
    /// Source function info (the function on the inactive side).
    source_function: Option<FunctionComparisonInfo>,
    /// Target function info (the function on the active side).
    target_function: Option<FunctionComparisonInfo>,
    /// The address that was clicked/navigated to, if any.
    address: Option<u64>,
    /// Additional context object type name (e.g., "MarkerLocation", "FieldHeader").
    context_object_type: Option<String>,
}

impl ComparisonActionContext {
    /// Create a new action context.
    pub fn new(
        view_name: impl Into<String>,
        active_side: ComparisonSide,
        trigger: ActionTrigger,
    ) -> Self {
        Self {
            view_name: view_name.into(),
            active_side,
            trigger,
            mouse_button: None,
            mouse_position: None,
            source_function: None,
            target_function: None,
            address: None,
            context_object_type: None,
        }
    }

    /// Create a context for a mouse action.
    pub fn mouse(
        view_name: impl Into<String>,
        active_side: ComparisonSide,
        button: MouseButton,
        position: ComponentPoint,
    ) -> Self {
        Self {
            view_name: view_name.into(),
            active_side,
            trigger: ActionTrigger::Mouse,
            mouse_button: Some(button),
            mouse_position: Some(position),
            source_function: None,
            target_function: None,
            address: None,
            context_object_type: None,
        }
    }

    /// Create a context for a keyboard action.
    pub fn keyboard(
        view_name: impl Into<String>,
        active_side: ComparisonSide,
    ) -> Self {
        Self {
            view_name: view_name.into(),
            active_side,
            trigger: ActionTrigger::Keyboard,
            mouse_button: None,
            mouse_position: None,
            source_function: None,
            target_function: None,
            address: None,
            context_object_type: None,
        }
    }

    /// Get the view name.
    pub fn view_name(&self) -> &str {
        &self.view_name
    }

    /// Get the active side.
    pub fn active_side(&self) -> ComparisonSide {
        self.active_side
    }

    /// Get the inactive (other) side.
    pub fn inactive_side(&self) -> ComparisonSide {
        self.active_side.opposite()
    }

    /// Get how the action was triggered.
    pub fn trigger(&self) -> ActionTrigger {
        self.trigger
    }

    /// Get the mouse button, if triggered by mouse.
    pub fn mouse_button(&self) -> Option<MouseButton> {
        self.mouse_button
    }

    /// Get the mouse position, if triggered by mouse.
    pub fn mouse_position(&self) -> Option<ComponentPoint> {
        self.mouse_position
    }

    /// Set the source function (the function on the inactive side).
    ///
    /// This is the function to get information from.
    pub fn set_source_function(&mut self, func: FunctionComparisonInfo) {
        self.source_function = Some(func);
    }

    /// Get the source function (the function on the inactive side).
    pub fn source_function(&self) -> Option<&FunctionComparisonInfo> {
        self.source_function.as_ref()
    }

    /// Set the target function (the function on the active side).
    ///
    /// This is the function to apply information to.
    pub fn set_target_function(&mut self, func: FunctionComparisonInfo) {
        self.target_function = Some(func);
    }

    /// Get the target function (the function on the active side).
    pub fn target_function(&self) -> Option<&FunctionComparisonInfo> {
        self.target_function.as_ref()
    }

    /// Set the address associated with this action.
    pub fn set_address(&mut self, address: u64) {
        self.address = Some(address);
    }

    /// Get the address associated with this action.
    pub fn address(&self) -> Option<u64> {
        self.address
    }

    /// Set the context object type name.
    ///
    /// This indicates what kind of UI element the action was triggered on
    /// (e.g., "MarkerLocation", "FieldHeader", "OverviewProvider").
    pub fn set_context_object_type(&mut self, obj_type: impl Into<String>) {
        self.context_object_type = Some(obj_type.into());
    }

    /// Get the context object type name.
    pub fn context_object_type(&self) -> Option<&str> {
        self.context_object_type.as_deref()
    }

    /// Check if this context has both source and target functions.
    pub fn has_both_functions(&self) -> bool {
        self.source_function.is_some() && self.target_function.is_some()
    }
}

/// A specialized action context for listing code comparison views.
///
/// Ported from Ghidra's `ListingComparisonActionContext` Java class.
///
/// In addition to the base comparison context, this carries information
/// specific to listing comparisons: the field type that was clicked
/// (bytes, mnemonic, operand, etc.) and whether the click was on a
/// margin panel.
///
/// # Example
///
/// ```rust
/// use ghidra_features::codecompare::panel::action_context::*;
/// use ghidra_features::codecompare::model::ComparisonSide;
///
/// let ctx = ListingComparisonActionContext::new(
///     ComparisonSide::Left,
///     ActionTrigger::Mouse,
/// );
///
/// assert_eq!(ctx.active_side(), ComparisonSide::Left);
/// assert!(ctx.field_type().is_none());
/// ```
#[derive(Debug, Clone)]
pub struct ListingComparisonActionContext {
    base: ComparisonActionContext,
    /// The type of listing field that was clicked.
    field_type: Option<ListingFieldType>,
    /// Whether the click was on a margin panel (marker margin or overview).
    on_margin: bool,
    /// Whether the click was on the header area.
    on_header: bool,
}

/// The type of field in a listing that was interacted with.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ListingFieldType {
    /// The address field.
    Address,
    /// The bytes field (raw instruction bytes).
    Bytes,
    /// The mnemonic field (instruction name).
    Mnemonic,
    /// The operand field (instruction operands).
    Operand,
    /// The comment field.
    Comment,
    /// The EOL comment field.
    EolComment,
    /// The plate comment field (above a function).
    PlateComment,
    /// The field header (format header bar).
    FieldHeader,
}

impl ListingFieldType {
    /// A human-readable label for this field type.
    pub fn label(&self) -> &'static str {
        match self {
            Self::Address => "Address",
            Self::Bytes => "Bytes",
            Self::Mnemonic => "Mnemonic",
            Self::Operand => "Operand",
            Self::Comment => "Comment",
            Self::EolComment => "EOL Comment",
            Self::PlateComment => "Plate Comment",
            Self::FieldHeader => "Field Header",
        }
    }
}

impl ListingComparisonActionContext {
    /// Create a new listing comparison action context.
    pub fn new(
        active_side: ComparisonSide,
        trigger: ActionTrigger,
    ) -> Self {
        Self {
            base: ComparisonActionContext::new(
                "ListingCodeComparisonView",
                active_side,
                trigger,
            ),
            field_type: None,
            on_margin: false,
            on_header: false,
        }
    }

    /// Get the base action context.
    pub fn base(&self) -> &ComparisonActionContext {
        &self.base
    }

    /// Get a mutable reference to the base action context.
    pub fn base_mut(&mut self) -> &mut ComparisonActionContext {
        &mut self.base
    }

    /// Set the field type that was clicked.
    pub fn set_field_type(&mut self, field_type: ListingFieldType) {
        self.field_type = Some(field_type);
    }

    /// Get the field type that was clicked.
    pub fn field_type(&self) -> Option<ListingFieldType> {
        self.field_type
    }

    /// Set whether the click was on a margin panel.
    pub fn set_on_margin(&mut self, on_margin: bool) {
        self.on_margin = on_margin;
    }

    /// Check if the click was on a margin panel.
    pub fn is_on_margin(&self) -> bool {
        self.on_margin
    }

    /// Set whether the click was on the header area.
    pub fn set_on_header(&mut self, on_header: bool) {
        self.on_header = on_header;
    }

    /// Check if the click was on the header area.
    pub fn is_on_header(&self) -> bool {
        self.on_header
    }
}

/// A specialized action context for decompiler code comparison views.
///
/// In addition to the base comparison context, this carries information
/// specific to decompiler comparisons: the token that was clicked and
/// whether the click was on a matched token pair.
#[derive(Debug, Clone)]
pub struct DecompilerComparisonActionContext {
    base: ComparisonActionContext,
    /// The token text that was clicked.
    token_text: Option<String>,
    /// Whether the clicked token is part of a matched pair.
    is_matched_token: bool,
    /// The address associated with the clicked token.
    token_address: Option<u64>,
}

impl DecompilerComparisonActionContext {
    /// Create a new decompiler comparison action context.
    pub fn new(
        active_side: ComparisonSide,
        trigger: ActionTrigger,
    ) -> Self {
        Self {
            base: ComparisonActionContext::new(
                "DecompilerCodeComparisonView",
                active_side,
                trigger,
            ),
            token_text: None,
            is_matched_token: false,
            token_address: None,
        }
    }

    /// Get the base action context.
    pub fn base(&self) -> &ComparisonActionContext {
        &self.base
    }

    /// Get a mutable reference to the base action context.
    pub fn base_mut(&mut self) -> &mut ComparisonActionContext {
        &mut self.base
    }

    /// Set the token text that was clicked.
    pub fn set_token_text(&mut self, text: impl Into<String>) {
        self.token_text = Some(text.into());
    }

    /// Get the token text that was clicked.
    pub fn token_text(&self) -> Option<&str> {
        self.token_text.as_deref()
    }

    /// Set whether the clicked token is part of a matched pair.
    pub fn set_is_matched_token(&mut self, matched: bool) {
        self.is_matched_token = matched;
    }

    /// Check if the clicked token is part of a matched pair.
    pub fn is_matched_token(&self) -> bool {
        self.is_matched_token
    }

    /// Set the address associated with the clicked token.
    pub fn set_token_address(&mut self, address: u64) {
        self.token_address = Some(address);
    }

    /// Get the address associated with the clicked token.
    pub fn token_address(&self) -> Option<u64> {
        self.token_address
    }
}

/// Trait for objects that provide a code comparison view context.
///
/// Ported from Ghidra's `CodeComparisonViewActionContext` Java interface.
/// This is a marker trait that indicates the implementing type can provide
/// information about which comparison view generated an action context.
pub trait CodeComparisonViewContext {
    /// Get the name of the comparison view.
    fn view_name(&self) -> &str;

    /// Get the active side.
    fn active_side(&self) -> ComparisonSide;
}

impl CodeComparisonViewContext for ComparisonActionContext {
    fn view_name(&self) -> &str {
        &self.view_name
    }

    fn active_side(&self) -> ComparisonSide {
        self.active_side
    }
}

impl CodeComparisonViewContext for ListingComparisonActionContext {
    fn view_name(&self) -> &str {
        self.base.view_name()
    }

    fn active_side(&self) -> ComparisonSide {
        self.base.active_side()
    }
}

impl CodeComparisonViewContext for DecompilerComparisonActionContext {
    fn view_name(&self) -> &str {
        self.base.view_name()
    }

    fn active_side(&self) -> ComparisonSide {
        self.base.active_side()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codecompare::panel::{ProgramInfo, FunctionComparisonInfo};

    fn make_func_info(name: &str, entry: u64) -> FunctionComparisonInfo {
        let prog = ProgramInfo::new(1, "/project/test", "test");
        FunctionComparisonInfo::new(name, entry, entry, entry + 0x100, prog)
    }

    // --- ComparisonActionContext tests ---

    #[test]
    fn test_action_context_new() {
        let ctx = ComparisonActionContext::new("TestView", ComparisonSide::Left, ActionTrigger::Mouse);
        assert_eq!(ctx.view_name(), "TestView");
        assert_eq!(ctx.active_side(), ComparisonSide::Left);
        assert_eq!(ctx.inactive_side(), ComparisonSide::Right);
        assert_eq!(ctx.trigger(), ActionTrigger::Mouse);
        assert!(ctx.source_function().is_none());
        assert!(ctx.target_function().is_none());
        assert!(ctx.address().is_none());
        assert!(ctx.context_object_type().is_none());
    }

    #[test]
    fn test_action_context_mouse() {
        let ctx = ComparisonActionContext::mouse(
            "TestView",
            ComparisonSide::Right,
            MouseButton::Right,
            ComponentPoint::new(100, 200),
        );
        assert_eq!(ctx.trigger(), ActionTrigger::Mouse);
        assert_eq!(ctx.mouse_button(), Some(MouseButton::Right));
        let pos = ctx.mouse_position().unwrap();
        assert_eq!(pos.x, 100);
        assert_eq!(pos.y, 200);
    }

    #[test]
    fn test_action_context_keyboard() {
        let ctx = ComparisonActionContext::keyboard("TestView", ComparisonSide::Left);
        assert_eq!(ctx.trigger(), ActionTrigger::Keyboard);
        assert!(ctx.mouse_button().is_none());
        assert!(ctx.mouse_position().is_none());
    }

    #[test]
    fn test_action_context_functions() {
        let mut ctx = ComparisonActionContext::new("TestView", ComparisonSide::Left, ActionTrigger::Mouse);
        assert!(!ctx.has_both_functions());

        let src = make_func_info("source_func", 0x1000);
        let tgt = make_func_info("target_func", 0x2000);

        ctx.set_source_function(src);
        ctx.set_target_function(tgt);
        assert!(ctx.has_both_functions());
        assert_eq!(ctx.source_function().unwrap().name, "source_func");
        assert_eq!(ctx.target_function().unwrap().name, "target_func");
    }

    #[test]
    fn test_action_context_address() {
        let mut ctx = ComparisonActionContext::new("TestView", ComparisonSide::Left, ActionTrigger::Keyboard);
        assert!(ctx.address().is_none());

        ctx.set_address(0x1000);
        assert_eq!(ctx.address(), Some(0x1000));
    }

    #[test]
    fn test_action_context_object_type() {
        let mut ctx = ComparisonActionContext::new("TestView", ComparisonSide::Left, ActionTrigger::Mouse);
        assert!(ctx.context_object_type().is_none());

        ctx.set_context_object_type("MarkerLocation");
        assert_eq!(ctx.context_object_type(), Some("MarkerLocation"));
    }

    // --- ListingComparisonActionContext tests ---

    #[test]
    fn test_listing_context_new() {
        let ctx = ListingComparisonActionContext::new(ComparisonSide::Left, ActionTrigger::Mouse);
        assert_eq!(ctx.active_side(), ComparisonSide::Left);
        assert!(ctx.field_type().is_none());
        assert!(!ctx.is_on_margin());
        assert!(!ctx.is_on_header());
    }

    #[test]
    fn test_listing_context_field_type() {
        let mut ctx = ListingComparisonActionContext::new(ComparisonSide::Left, ActionTrigger::Mouse);
        ctx.set_field_type(ListingFieldType::Mnemonic);
        assert_eq!(ctx.field_type(), Some(ListingFieldType::Mnemonic));
    }

    #[test]
    fn test_listing_context_margin() {
        let mut ctx = ListingComparisonActionContext::new(ComparisonSide::Left, ActionTrigger::Mouse);
        ctx.set_on_margin(true);
        assert!(ctx.is_on_margin());
    }

    #[test]
    fn test_listing_context_header() {
        let mut ctx = ListingComparisonActionContext::new(ComparisonSide::Left, ActionTrigger::Mouse);
        ctx.set_on_header(true);
        assert!(ctx.is_on_header());
    }

    #[test]
    fn test_listing_context_base() {
        let mut ctx = ListingComparisonActionContext::new(ComparisonSide::Right, ActionTrigger::Keyboard);
        ctx.base_mut().set_address(0x2000);
        assert_eq!(ctx.base().address(), Some(0x2000));
    }

    // --- DecompilerComparisonActionContext tests ---

    #[test]
    fn test_decompiler_context_new() {
        let ctx = DecompilerComparisonActionContext::new(ComparisonSide::Left, ActionTrigger::Mouse);
        assert_eq!(ctx.active_side(), ComparisonSide::Left);
        assert!(ctx.token_text().is_none());
        assert!(!ctx.is_matched_token());
        assert!(ctx.token_address().is_none());
    }

    #[test]
    fn test_decompiler_context_token() {
        let mut ctx = DecompilerComparisonActionContext::new(ComparisonSide::Left, ActionTrigger::Mouse);
        ctx.set_token_text("x = 5");
        assert_eq!(ctx.token_text(), Some("x = 5"));
    }

    #[test]
    fn test_decompiler_context_matched() {
        let mut ctx = DecompilerComparisonActionContext::new(ComparisonSide::Left, ActionTrigger::Mouse);
        assert!(!ctx.is_matched_token());
        ctx.set_is_matched_token(true);
        assert!(ctx.is_matched_token());
    }

    #[test]
    fn test_decompiler_context_address() {
        let mut ctx = DecompilerComparisonActionContext::new(ComparisonSide::Left, ActionTrigger::Keyboard);
        ctx.set_token_address(0x3000);
        assert_eq!(ctx.token_address(), Some(0x3000));
    }

    // --- CodeComparisonViewContext trait tests ---

    #[test]
    fn test_view_context_trait() {
        let ctx = ComparisonActionContext::new("TestView", ComparisonSide::Right, ActionTrigger::Mouse);
        assert_eq!(ctx.view_name(), "TestView");
        assert_eq!(ctx.active_side(), ComparisonSide::Right);
    }

    #[test]
    fn test_listing_view_context_trait() {
        let ctx = ListingComparisonActionContext::new(ComparisonSide::Left, ActionTrigger::Keyboard);
        assert_eq!(ctx.view_name(), "ListingCodeComparisonView");
        assert_eq!(ctx.active_side(), ComparisonSide::Left);
    }

    #[test]
    fn test_decompiler_view_context_trait() {
        let ctx = DecompilerComparisonActionContext::new(ComparisonSide::Right, ActionTrigger::Mouse);
        assert_eq!(ctx.view_name(), "DecompilerCodeComparisonView");
        assert_eq!(ctx.active_side(), ComparisonSide::Right);
    }

    // --- ActionTrigger tests ---

    #[test]
    fn test_action_trigger_equality() {
        assert_eq!(ActionTrigger::Mouse, ActionTrigger::Mouse);
        assert_ne!(ActionTrigger::Mouse, ActionTrigger::Keyboard);
    }

    // --- MouseButton tests ---

    #[test]
    fn test_mouse_button() {
        assert_eq!(MouseButton::Left, MouseButton::Left);
        assert_ne!(MouseButton::Left, MouseButton::Right);
    }

    // --- ComponentPoint tests ---

    #[test]
    fn test_component_point() {
        let p = ComponentPoint::new(10, 20);
        assert_eq!(p.x, 10);
        assert_eq!(p.y, 20);
    }

    // --- ListingFieldType tests ---

    #[test]
    fn test_listing_field_type_label() {
        assert_eq!(ListingFieldType::Address.label(), "Address");
        assert_eq!(ListingFieldType::Bytes.label(), "Bytes");
        assert_eq!(ListingFieldType::Mnemonic.label(), "Mnemonic");
        assert_eq!(ListingFieldType::Operand.label(), "Operand");
        assert_eq!(ListingFieldType::Comment.label(), "Comment");
        assert_eq!(ListingFieldType::EolComment.label(), "EOL Comment");
        assert_eq!(ListingFieldType::PlateComment.label(), "Plate Comment");
        assert_eq!(ListingFieldType::FieldHeader.label(), "Field Header");
    }
}
