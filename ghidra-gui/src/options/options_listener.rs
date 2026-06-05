//! Options change listeners and veto exceptions.
//!
//! Ports Ghidra's `ghidra.framework.options.OptionsChangeListener` and
//! `ghidra.util.bean.opteditor.OptionsVetoException`.

use std::fmt;

/// Trait for receiving notifications when options values change.
///
/// Port of `ghidra.framework.options.OptionsChangeListener`.
pub trait OptionsChangeListener: Send + Sync + fmt::Debug {
    /// Called when an option value has changed.
    ///
    /// # Arguments
    /// * `options_name` - The name of the options category.
    /// * `option_name` - The name of the option that changed.
    /// * `old_value` - The previous value (as string).
    /// * `new_value` - The new value (as string).
    fn option_changed(
        &self,
        options_name: &str,
        option_name: &str,
        old_value: &str,
        new_value: &str,
    );

    /// Called when an option value change is about to happen.
    /// Return `Err(OptionsVetoException)` to reject the change.
    fn option_change_vetoable(
        &self,
        _options_name: &str,
        _option_name: &str,
        _old_value: &str,
        _new_value: &str,
    ) -> Result<(), OptionsVetoException> {
        Ok(())
    }
}

/// Exception thrown to veto (reject) an options change.
///
/// Port of `ghidra.util.bean.opteditor.OptionsVetoException`.
#[derive(Debug, Clone)]
pub struct OptionsVetoException {
    /// The message explaining why the change was vetoed.
    message: String,
}

impl OptionsVetoException {
    /// Create a new options veto exception.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    /// Get the veto message.
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for OptionsVetoException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Options change vetoed: {}", self.message)
    }
}

impl std::error::Error for OptionsVetoException {}
