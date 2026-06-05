//! Callback handler interface for the decompiler component.
//!
//! Ports `ghidra.app.decompiler.component.DecompilerCallbackHandler`.

/// Trait for handling callbacks from the decompiler process.
///
/// In Ghidra, the decompiler component communicates with the native
/// decompiler process via callbacks. This trait defines the interface
/// for those callbacks.
pub trait DecompilerCallbackHandler: Send + Sync {
    /// Called when decompilation is complete.
    fn decompile_completed(&self, function_entry: u64, success: bool);

    /// Called when the decompiler encounters an error.
    fn decompile_error(&self, function_entry: u64, error: &str);

    /// Called when decompiler options need to be refreshed.
    fn options_changed(&self);

    /// Called when the decompiler display needs to be repainted.
    fn display_changed(&self);

    /// Called when the cursor position changes in the decompiler view.
    fn location_changed(&self, address: u64);

    /// Called when a field (token) is selected in the decompiler.
    fn field_selected(&self, field_text: &str, field_address: Option<u64>);
}

/// A no-op callback handler that does nothing.
#[derive(Debug, Default)]
pub struct NullCallbackHandler;

impl DecompilerCallbackHandler for NullCallbackHandler {
    fn decompile_completed(&self, _entry: u64, _success: bool) {}
    fn decompile_error(&self, _entry: u64, _error: &str) {}
    fn options_changed(&self) {}
    fn display_changed(&self) {}
    fn location_changed(&self, _address: u64) {}
    fn field_selected(&self, _text: &str, _addr: Option<u64>) {}
}

/// Adapter that forwards callbacks to closures.
pub struct CallbackHandlerAdapter {
    on_complete: Option<Box<dyn Fn(u64, bool) + Send + Sync>>,
    on_error: Option<Box<dyn Fn(u64, &str) + Send + Sync>>,
    on_display_changed: Option<Box<dyn Fn() + Send + Sync>>,
    on_location_changed: Option<Box<dyn Fn(u64) + Send + Sync>>,
}

impl CallbackHandlerAdapter {
    /// Create a new adapter.
    pub fn new() -> Self {
        Self {
            on_complete: None,
            on_error: None,
            on_display_changed: None,
            on_location_changed: None,
        }
    }

    /// Set the completion callback.
    pub fn on_complete(mut self, f: impl Fn(u64, bool) + Send + Sync + 'static) -> Self {
        self.on_complete = Some(Box::new(f));
        self
    }

    /// Set the error callback.
    pub fn on_error(mut self, f: impl Fn(u64, &str) + Send + Sync + 'static) -> Self {
        self.on_error = Some(Box::new(f));
        self
    }

    /// Set the display-changed callback.
    pub fn on_display_changed(mut self, f: impl Fn() + Send + Sync + 'static) -> Self {
        self.on_display_changed = Some(Box::new(f));
        self
    }

    /// Set the location-changed callback.
    pub fn on_location_changed(mut self, f: impl Fn(u64) + Send + Sync + 'static) -> Self {
        self.on_location_changed = Some(Box::new(f));
        self
    }
}

impl Default for CallbackHandlerAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl DecompilerCallbackHandler for CallbackHandlerAdapter {
    fn decompile_completed(&self, entry: u64, success: bool) {
        if let Some(ref f) = self.on_complete {
            f(entry, success);
        }
    }

    fn decompile_error(&self, entry: u64, error: &str) {
        if let Some(ref f) = self.on_error {
            f(entry, error);
        }
    }

    fn options_changed(&self) {}

    fn display_changed(&self) {
        if let Some(ref f) = self.on_display_changed {
            f();
        }
    }

    fn location_changed(&self, address: u64) {
        if let Some(ref f) = self.on_location_changed {
            f(address);
        }
    }

    fn field_selected(&self, _text: &str, _addr: Option<u64>) {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    #[test]
    fn test_null_handler() {
        let handler = NullCallbackHandler;
        handler.decompile_completed(0x1000, true);
        handler.decompile_error(0x1000, "test");
        // Should not panic
    }

    #[test]
    fn test_adapter_complete() {
        let called = Arc::new(AtomicBool::new(false));
        let called2 = called.clone();
        let handler = CallbackHandlerAdapter::new()
            .on_complete(move |_, _| { called2.store(true, Ordering::Relaxed); });
        handler.decompile_completed(0x1000, true);
        assert!(called.load(Ordering::Relaxed));
    }
}
