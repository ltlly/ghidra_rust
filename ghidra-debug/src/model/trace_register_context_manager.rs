//! TraceRegisterContextManager trait.
//!
//! Ported from Ghidra's `ghidra.trace.model.context.TraceRegisterContextManager`.
//! Extends `TraceRegisterContextOperations` with methods to obtain
//! per-space and per-thread context spaces.

use super::context::{TraceRegisterContextOperations, TraceRegisterContextSpace};

/// Trait for managing register context spaces.
///
/// Ported from Ghidra's `TraceRegisterContextManager` interface.
/// Extends `TraceRegisterContextOperations` with methods to get or create
/// context spaces for a given address space or thread.
pub trait TraceRegisterContextManagerOps: TraceRegisterContextOperations {
    /// Get the register context space for a given address space.
    ///
    /// If `create_if_absent` is true and the space does not yet exist,
    /// a new one is created. Otherwise, returns `None` when not found.
    fn get_register_context_space(
        &self,
        address_space: &str,
        create_if_absent: bool,
    ) -> Option<TraceRegisterContextSpace>;

    /// Get the register context space for a given thread.
    ///
    /// Thread-scoped context spaces allow per-thread register context
    /// (e.g., x86 segment registers per thread).
    fn get_register_context_register_space(
        &self,
        thread_key: i64,
        create_if_absent: bool,
    ) -> Option<TraceRegisterContextSpace>;
}

/// Default implementation backing store for context spaces.
///
/// Stores context spaces by address-space name and thread key.
#[derive(Debug, Clone, Default)]
pub struct TraceRegisterContextManagerImpl {
    /// Context spaces keyed by address space name.
    spaces: std::collections::BTreeMap<String, TraceRegisterContextSpace>,
    /// Thread-scoped context spaces keyed by thread key.
    thread_spaces: std::collections::BTreeMap<i64, TraceRegisterContextSpace>,
    /// Default language id for new spaces.
    _default_language: String,
}

impl TraceRegisterContextManagerImpl {
    /// Create a new manager with the given default language.
    pub fn new(default_language: impl Into<String>) -> Self {
        Self {
            spaces: std::collections::BTreeMap::new(),
            thread_spaces: std::collections::BTreeMap::new(),
            _default_language: default_language.into(),
        }
    }

    /// Get the number of address-space context spaces.
    pub fn space_count(&self) -> usize {
        self.spaces.len()
    }

    /// Get the number of thread-scoped context spaces.
    pub fn thread_space_count(&self) -> usize {
        self.thread_spaces.len()
    }

    /// Check if a context space exists for the given address space.
    pub fn has_space(&self, address_space: &str) -> bool {
        self.spaces.contains_key(address_space)
    }

    /// Check if a thread-scoped context space exists.
    pub fn has_thread_space(&self, thread_key: i64) -> bool {
        self.thread_spaces.contains_key(&thread_key)
    }
}

#[cfg(test)]
mod tests {
    use super::super::context::LanguageId;
    use super::*;

    #[test]
    fn test_manager_impl_new() {
        let mgr = TraceRegisterContextManagerImpl::new("x86:LE:64:default");
        assert_eq!(mgr.space_count(), 0);
        assert_eq!(mgr.thread_space_count(), 0);
        assert_eq!(mgr._default_language, "x86:LE:64:default");
    }

    #[test]
    fn test_manager_impl_default() {
        let mgr = TraceRegisterContextManagerImpl::default();
        assert_eq!(mgr.space_count(), 0);
    }

    #[test]
    fn test_context_space_creation() {
        let lang = LanguageId::new("ARM:LE:32:v8");
        let space = TraceRegisterContextSpace::new("register", lang.clone());
        assert_eq!(space.space_name, "register");
        assert_eq!(space.language.id, "ARM:LE:32:v8");
    }

    #[test]
    fn test_manager_has_space_negative() {
        let mgr = TraceRegisterContextManagerImpl::new("x86:LE:64:default");
        assert!(!mgr.has_space("ram"));
        assert!(!mgr.has_thread_space(42));
    }
}
