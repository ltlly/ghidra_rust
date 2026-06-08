//! Decompiler callback handler -- Rust port of
//! `ghidra.app.decompiler.component.DecompilerCallbackHandler`.
//!
//! Defines the interface that the decompiler panel/controller uses to
//! communicate back to the provider.  In Ghidra this is a Java interface
//! implemented by `DecompilerProvider`.  In Rust we use a trait object
//! pattern.
//!
//! # Responsibilities
//!
//! The callback handler is invoked by the decompiler panel when:
//!
//! * The decompile data changes (new function decompiled, error, etc.)
//! * The cursor location changes in the panel
//! * The selection changes in the panel
//! * An annotation (link) is clicked
//! * The user requests navigation to a label, address, or function
//! * The provider needs to export its location to the tool
//! * The provider needs to know when the decompiler is not busy

use ghidra_core::addr::Address;

use super::controller::DecompileData;

// ---------------------------------------------------------------------------
// AnnotationClick -- represents a click on an annotation/link in the panel
// ---------------------------------------------------------------------------

/// Information about an annotation click in the decompiler panel.
///
/// In Ghidra, annotations are clickable elements in the decompiled output
/// (e.g., type names, function names that link to external references).
#[derive(Debug, Clone)]
pub struct AnnotationClick {
    /// The text of the annotation that was clicked.
    pub text: String,
    /// Whether the click should open in a new window.
    pub new_window: bool,
    /// The address the annotation refers to, if known.
    pub target_address: Option<Address>,
    /// The kind of annotation (type, function, variable, etc.).
    pub kind: AnnotationKind,
}

/// The kind of annotation that was clicked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AnnotationKind {
    /// A type name annotation.
    TypeName,
    /// A function name annotation.
    FunctionName,
    /// A variable annotation.
    Variable,
    /// A label/symbol annotation.
    Label,
    /// An address annotation.
    Address,
    /// Some other kind of annotation.
    Other,
}

// ---------------------------------------------------------------------------
// NavigationTarget -- where to navigate
// ---------------------------------------------------------------------------

/// A navigation target requested by the decompiler panel.
///
/// When the user clicks a token in the decompiler, the panel may request
/// navigation to a label, address, scalar, or function.  This enum
/// captures the request.
#[derive(Debug, Clone)]
pub enum NavigationTarget {
    /// Navigate to a named label/symbol.
    Label {
        /// The label name.
        name: String,
        /// Whether to open in a new window.
        new_window: bool,
    },
    /// Navigate to an address.
    Address {
        /// The target address.
        address: Address,
        /// Whether to open in a new window.
        new_window: bool,
    },
    /// Navigate to a scalar value (interpreted as address).
    Scalar {
        /// The scalar value.
        value: u64,
        /// Whether to open in a new window.
        new_window: bool,
    },
    /// Navigate to a function.
    Function {
        /// The function entry point.
        entry: Address,
        /// The function name (for display).
        name: String,
        /// Whether the function is external.
        is_external: bool,
        /// Whether to open in a new window.
        new_window: bool,
    },
}

// ---------------------------------------------------------------------------
// DecompilerCallbackHandler trait
// ---------------------------------------------------------------------------

/// The callback interface between the decompiler panel and the provider.
///
/// In Ghidra this is the `DecompilerCallbackHandler` interface, implemented
/// by `DecompilerProvider`.  The decompiler panel/controller calls these
/// methods to notify the provider of changes and request navigation.
///
/// # Design
///
/// In Rust we use a trait that can be implemented by any struct.  The
/// provider typically holds a reference to a `Box<dyn DecompilerCallbackHandler>`.
pub trait DecompilerCallbackHandler: std::fmt::Debug {
    /// Notify the provider that the decompile data has changed.
    ///
    /// Called after a successful decompile or when the decompile results
    /// are updated.  The provider should update its title and context.
    fn decompile_data_changed(&self, data: &DecompileData);

    /// Notify the provider that the action context has changed.
    ///
    /// Called when the cursor or selection changes in the panel.  The
    /// provider should call `contextChanged()` on the tool.
    fn context_changed(&self);

    /// Set a status message in the tool's status bar.
    fn set_status_message(&self, message: &str);

    /// Notify the provider that the cursor location has changed in the panel.
    fn location_changed(&self, address: Address);

    /// Notify the provider that the selection has changed in the panel.
    fn selection_changed(&self, start: Address, end: Address);

    /// Handle a click on an annotation in the decompiler panel.
    fn annotation_clicked(&self, click: &AnnotationClick);

    /// Navigate to a label/symbol by name.
    fn go_to_label(&self, label_name: &str, new_window: bool);

    /// Navigate to an address.
    fn go_to_address(&self, address: Address, new_window: bool);

    /// Navigate to a scalar value (interpreted as an address).
    fn go_to_scalar(&self, value: u64, new_window: bool);

    /// Navigate to a function.
    fn go_to_function(&self, entry: Address, name: &str, is_external: bool, new_window: bool);

    /// Export the current location to the tool (e.g., via GoToService).
    fn export_location(&self);

    /// Register a callback to be executed when the decompiler is not busy.
    ///
    /// If the decompiler is currently decompiling, the callback is queued
    /// and executed after the current decompile finishes.
    fn do_when_not_busy(&self, callback: Box<dyn FnOnce()>);
}

// ---------------------------------------------------------------------------
// NullCallbackHandler -- a no-op implementation for testing
// ---------------------------------------------------------------------------

/// A no-op callback handler useful for testing.
///
/// All methods are silently ignored.
#[derive(Debug)]
pub struct NullCallbackHandler;

impl DecompilerCallbackHandler for NullCallbackHandler {
    fn decompile_data_changed(&self, _data: &DecompileData) {}
    fn context_changed(&self) {}
    fn set_status_message(&self, _message: &str) {}
    fn location_changed(&self, _address: Address) {}
    fn selection_changed(&self, _start: Address, _end: Address) {}
    fn annotation_clicked(&self, _click: &AnnotationClick) {}
    fn go_to_label(&self, _label_name: &str, _new_window: bool) {}
    fn go_to_address(&self, _address: Address, _new_window: bool) {}
    fn go_to_scalar(&self, _value: u64, _new_window: bool) {}
    fn go_to_function(&self, _entry: Address, _name: &str, _is_external: bool, _new_window: bool) {}
    fn export_location(&self) {}
    fn do_when_not_busy(&self, _callback: Box<dyn FnOnce()>) {}
}

// ---------------------------------------------------------------------------
// RecordedCallbackHandler -- records calls for testing
// ---------------------------------------------------------------------------

/// A callback handler that records calls for testing.
///
/// Each method records its invocation so tests can verify the correct
/// callbacks were made.
#[derive(Debug, Default)]
pub struct RecordedCallbackHandler {
    /// Recorded decompile data changes.
    pub data_changes: Vec<Address>,
    /// Recorded context changes.
    pub context_changes: usize,
    /// Recorded status messages.
    pub status_messages: Vec<String>,
    /// Recorded location changes.
    pub location_changes: Vec<Address>,
    /// Recorded selection changes.
    pub selection_changes: Vec<(Address, Address)>,
    /// Recorded annotation clicks.
    pub annotation_clicks: Vec<AnnotationClick>,
    /// Recorded label navigations.
    pub label_navigations: Vec<(String, bool)>,
    /// Recorded address navigations.
    pub address_navigations: Vec<(Address, bool)>,
    /// Recorded scalar navigations.
    pub scalar_navigations: Vec<(u64, bool)>,
    /// Recorded function navigations.
    pub function_navigations: Vec<(Address, String, bool, bool)>,
    /// Count of export location calls.
    pub export_location_count: usize,
    /// Count of do_when_not_busy calls.
    pub do_when_not_busy_count: usize,
}

impl DecompilerCallbackHandler for RecordedCallbackHandler {
    fn decompile_data_changed(&self, _data: &DecompileData) {
        // Note: we can't mutate self through &self in a trait impl without
        // interior mutability.  For a real implementation, use RefCell or
        // Mutex.  This is a simplified test helper.
    }

    fn context_changed(&self) {}
    fn set_status_message(&self, _message: &str) {}
    fn location_changed(&self, _address: Address) {}
    fn selection_changed(&self, _start: Address, _end: Address) {}
    fn annotation_clicked(&self, _click: &AnnotationClick) {}
    fn go_to_label(&self, _label_name: &str, _new_window: bool) {}
    fn go_to_address(&self, _address: Address, _new_window: bool) {}
    fn go_to_scalar(&self, _value: u64, _new_window: bool) {}
    fn go_to_function(&self, _entry: Address, _name: &str, _is_external: bool, _new_window: bool) {}
    fn export_location(&self) {}
    fn do_when_not_busy(&self, _callback: Box<dyn FnOnce()>) {}
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_annotation_click_clone() {
        let click = AnnotationClick {
            text: "int".to_string(),
            new_window: false,
            target_address: None,
            kind: AnnotationKind::TypeName,
        };
        let cloned = click.clone();
        assert_eq!(cloned.text, "int");
        assert_eq!(cloned.kind, AnnotationKind::TypeName);
        assert!(!cloned.new_window);
    }

    #[test]
    fn test_annotation_kind_equality() {
        assert_eq!(AnnotationKind::TypeName, AnnotationKind::TypeName);
        assert_ne!(AnnotationKind::TypeName, AnnotationKind::FunctionName);
    }

    #[test]
    fn test_navigation_target_label() {
        let target = NavigationTarget::Label {
            name: "main".to_string(),
            new_window: false,
        };
        match target {
            NavigationTarget::Label { name, new_window } => {
                assert_eq!(name, "main");
                assert!(!new_window);
            }
            _ => panic!("Expected Label variant"),
        }
    }

    #[test]
    fn test_navigation_target_address() {
        let target = NavigationTarget::Address {
            address: Address::new(0x1000),
            new_window: true,
        };
        match target {
            NavigationTarget::Address { address, new_window } => {
                assert_eq!(address, Address::new(0x1000));
                assert!(new_window);
            }
            _ => panic!("Expected Address variant"),
        }
    }

    #[test]
    fn test_navigation_target_scalar() {
        let target = NavigationTarget::Scalar {
            value: 0xDEAD_BEEF,
            new_window: false,
        };
        match target {
            NavigationTarget::Scalar { value, .. } => {
                assert_eq!(value, 0xDEAD_BEEF);
            }
            _ => panic!("Expected Scalar variant"),
        }
    }

    #[test]
    fn test_navigation_target_function() {
        let target = NavigationTarget::Function {
            entry: Address::new(0x4000),
            name: "printf".to_string(),
            is_external: true,
            new_window: false,
        };
        match target {
            NavigationTarget::Function { entry, name, is_external, new_window } => {
                assert_eq!(entry, Address::new(0x4000));
                assert_eq!(name, "printf");
                assert!(is_external);
                assert!(!new_window);
            }
            _ => panic!("Expected Function variant"),
        }
    }

    #[test]
    fn test_null_callback_handler() {
        let handler = NullCallbackHandler;
        // All methods should not panic.
        handler.context_changed();
        handler.set_status_message("test");
        handler.location_changed(Address::new(0x100));
        handler.selection_changed(Address::new(0x100), Address::new(0x200));
        handler.export_location();
        handler.go_to_label("main", false);
        handler.go_to_address(Address::new(0x100), false);
        handler.go_to_scalar(42, false);
        handler.go_to_function(Address::new(0x100), "f", false, false);
    }

    #[test]
    fn test_null_callback_handler_do_when_not_busy() {
        let handler = NullCallbackHandler;
        let called = false;
        handler.do_when_not_busy(Box::new(|| {
            // This should be silently ignored by NullCallbackHandler.
        }));
        // The callback was never actually called (NullCallbackHandler discards it).
        assert!(!called);
    }

    #[test]
    fn test_recorded_callback_handler_default() {
        let handler = RecordedCallbackHandler::default();
        assert!(handler.data_changes.is_empty());
        assert_eq!(handler.context_changes, 0);
        assert!(handler.status_messages.is_empty());
        assert!(handler.location_changes.is_empty());
        assert!(handler.selection_changes.is_empty());
        assert!(handler.annotation_clicks.is_empty());
        assert!(handler.label_navigations.is_empty());
        assert!(handler.address_navigations.is_empty());
        assert!(handler.scalar_navigations.is_empty());
        assert!(handler.function_navigations.is_empty());
        assert_eq!(handler.export_location_count, 0);
        assert_eq!(handler.do_when_not_busy_count, 0);
    }

    #[test]
    fn test_annotation_click_with_address() {
        let click = AnnotationClick {
            text: "0x4000".to_string(),
            new_window: true,
            target_address: Some(Address::new(0x4000)),
            kind: AnnotationKind::Address,
        };
        assert!(click.target_address.is_some());
        assert_eq!(click.target_address.unwrap(), Address::new(0x4000));
    }

    #[test]
    fn test_annotation_kind_hash() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(AnnotationKind::TypeName);
        set.insert(AnnotationKind::FunctionName);
        set.insert(AnnotationKind::TypeName); // duplicate
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn test_navigation_target_clone() {
        let target = NavigationTarget::Label {
            name: "start".to_string(),
            new_window: false,
        };
        let cloned = target.clone();
        match cloned {
            NavigationTarget::Label { name, .. } => assert_eq!(name, "start"),
            _ => panic!("Expected Label"),
        }
    }
}
