//! Manager interface ported from Java's `ManagerDB`.
//!
//! Every sub-manager in a Ghidra program (MemoryMap, CodeManager,
//! SymbolManager, FunctionManager, ReferenceManager, etc.) implements
//! this trait so the top-level `ProgramDB` can drive lifecycle callbacks
//! in a uniform way.

use crate::addr::Address;
use crate::database::db::DbResult;
use std::fmt;

// ============================================================================
// OpenMode (port of Java OpenMode)
// ============================================================================

/// The mode in which a program database is opened.
///
/// Mirrors Java `ghidra.framework.data.OpenMode`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(non_camel_case_types)]
pub enum OpenMode {
    /// Normal read/write open.
    NORMAL,
    /// Read-only open (no modifications allowed).
    READ_ONLY,
    /// Upgrade from an older database version.
    UPGRADE,
    /// Create a brand-new program.
    CREATE,
}

// ============================================================================
// ManagerDB trait (port of Java ManagerDB interface)
// ============================================================================

/// Trait that all sub-managers of a program database must implement.
///
/// Port of Java `ghidra.program.database.ManagerDB`.  The top-level program
/// orchestrates lifecycle by calling these methods in a defined order:
///
/// 1. `set_program` (all managers, index 0..N)
/// 2. `program_ready` (all managers, index 0..N)
/// 3. `clear_cache` (all managers, index 0..N)
/// 4. `delete_address_range` (all managers, index N..0 -- reverse)
/// 5. `move_address_range` (all managers, index N..0 -- reverse)
pub trait ManagerDB: fmt::Debug + Send + Sync {
    /// Callback invoked once when all managers have been created.
    ///
    /// At this point all managers are instantiated but may not be fully
    /// initialized.  Implementations should store a reference to the
    /// program so they can access sibling managers.
    fn set_program(&mut self, _program_ctx: &ProgramContext) {
        // default: no-op
    }

    /// Callback invoked after all managers have been created and the
    /// program has completed initialization.
    ///
    /// Used for deferred upgrades or late-binding operations that need
    /// all sibling managers to be available.
    fn program_ready(
        &mut self,
        _open_mode: OpenMode,
        _current_revision: i32,
    ) -> DbResult<()> {
        Ok(())
    }

    /// Clear all in-memory caches.
    ///
    /// If `all` is false some managers may skip the clear if they can
    /// determine it is unnecessary.
    fn clear_cache(&mut self, _all: bool) {
        // default: no-op
    }

    /// Delete all data within the specified address range.
    ///
    /// Called when memory is being removed from the program.  Managers
    /// are called in reverse order (FunctionManager before SymbolManager
    /// before NamespaceManager) to satisfy dependency constraints.
    fn delete_address_range(
        &mut self,
        _start: &Address,
        _end: &Address,
    ) -> DbResult<()> {
        Ok(())
    }

    /// Move all data within the specified address range to a new location.
    fn move_address_range(
        &mut self,
        _from_addr: &Address,
        _to_addr: &Address,
        _length: u64,
    ) -> DbResult<()> {
        Ok(())
    }
}

// ============================================================================
// ProgramContext — minimal context passed to managers during set_program
// ============================================================================

/// Minimal program context passed to managers during `set_program`.
///
/// Provides the handles and factory pointers that every manager needs
/// without requiring a full `ProgramDB` reference (which would create
/// circular references).
#[derive(Debug)]
pub struct ProgramContext {
    /// Unique program id.
    pub program_id: u64,
    /// Database modification counter.
    pub mod_count: u64,
    /// Whether the program is in read-only mode.
    pub read_only: bool,
    /// Current program revision.
    pub revision: i32,
}

impl ProgramContext {
    /// Create a new program context.
    pub fn new(program_id: u64, revision: i32, read_only: bool) -> Self {
        Self {
            program_id,
            mod_count: 0,
            read_only,
            revision,
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug)]
    struct TestManager {
        program_set: bool,
        ready_called: bool,
        cache_cleared: bool,
    }

    impl TestManager {
        fn new() -> Self {
            Self {
                program_set: false,
                ready_called: false,
                cache_cleared: false,
            }
        }
    }

    impl ManagerDB for TestManager {
        fn set_program(&mut self, _ctx: &ProgramContext) {
            self.program_set = true;
        }

        fn program_ready(
            &mut self,
            _mode: OpenMode,
            _rev: i32,
        ) -> DbResult<()> {
            self.ready_called = true;
            Ok(())
        }

        fn clear_cache(&mut self, _all: bool) {
            self.cache_cleared = true;
        }
    }

    #[test]
    fn test_manager_lifecycle() {
        let mut mgr = TestManager::new();
        assert!(!mgr.program_set);
        assert!(!mgr.ready_called);
        assert!(!mgr.cache_cleared);

        let ctx = ProgramContext::new(1, 5, false);
        mgr.set_program(&ctx);
        assert!(mgr.program_set);

        mgr.program_ready(OpenMode::NORMAL, 5).unwrap();
        assert!(mgr.ready_called);

        mgr.clear_cache(true);
        assert!(mgr.cache_cleared);
    }

    #[test]
    fn test_open_mode_variants() {
        assert_ne!(OpenMode::NORMAL, OpenMode::READ_ONLY);
        assert_ne!(OpenMode::UPGRADE, OpenMode::CREATE);
    }

    #[test]
    fn test_default_manager_methods_compile() {
        // Verify that the default implementations compile and return Ok.
        #[derive(Debug)]
        struct NoOpManager;
        impl ManagerDB for NoOpManager {}

        let mut mgr = NoOpManager;
        let ctx = ProgramContext::new(0, 0, true);
        mgr.set_program(&ctx);
        mgr.program_ready(OpenMode::CREATE, 0).unwrap();
        mgr.clear_cache(false);
        let addr = Address::new(0);
        mgr.delete_address_range(&addr, &addr).unwrap();
        mgr.move_address_range(&addr, &addr, 100).unwrap();
    }
}
