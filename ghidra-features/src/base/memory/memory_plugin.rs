//! Memory map plugin -- orchestrates the memory map subsystem.
//!
//! Ported from `MemoryMapPlugin` in Ghidra's `ghidra.app.plugin.core.memory`.
//!
//! This module provides [`MemoryMapPlugin`], which manages the lifecycle of
//! the memory map view: activating/deactivating programs, listening for
//! domain-object changes (blocks added/removed/moved/split/joined), and
//! coordinating between the [`MemoryMapProvider`] (view) and the
//! [`MemoryMapManager`] (operations).
//!
//! In the Rust port the Swing-specific plugin infrastructure is replaced
//! with an event-driven state machine that tracks program activation,
//! visibility, and memory-change events.

use ghidra_core::addr::Address;
use ghidra_core::program::program::Program;

use super::map_manager::MemoryMapManager;
use super::memory_provider::MemoryMapProvider;

// ============================================================================
// Domain object event types (subset relevant to memory)
// ============================================================================

/// Events that can occur on a domain object's memory.
///
/// Mirrors the Java `DomainObjectEvent` / `ProgramEvent` constants used
/// by `MemoryMapPlugin.domainObjectChanged`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MemoryEvent {
    /// A new memory block was added.
    BlockAdded,
    /// A memory block was removed.
    BlockRemoved,
    /// A memory block was relocated.
    BlockMoved,
    /// A memory block was split into two.
    BlockSplit,
    /// Two or more memory blocks were joined.
    BlocksJoined,
    /// The program was restored (e.g., after undo/redo).
    Restored,
    /// A memory block's properties changed (name, permissions, etc.).
    BlockChanged,
}

// ============================================================================
// MemoryMapPlugin
// ============================================================================

/// Plugin state for the memory map view.
///
/// Ported from `MemoryMapPlugin` in Java. This struct manages:
/// - Program activation / deactivation
/// - Forwarding memory-change events to the provider
/// - Coordinating the [`MemoryMapManager`] and [`MemoryMapProvider`]
///
/// # Usage
///
/// ```ignore
/// let mut plugin = MemoryMapPlugin::new();
/// plugin.activate_program(program);
/// plugin.show();
/// // ... events arrive via `on_domain_object_changed` ...
/// plugin.deactivate_program();
/// plugin.dispose();
/// ```
#[derive(Debug)]
pub struct MemoryMapPlugin {
    /// The memory-map manager that executes block operations.
    mem_manager: MemoryMapManager,
    /// The provider (view state) for the memory map.
    provider: MemoryMapProvider,
    /// Whether the plugin has been disposed.
    disposed: bool,
}

impl MemoryMapPlugin {
    /// Create a new memory map plugin.
    pub fn new() -> Self {
        Self {
            mem_manager: MemoryMapManager::default(),
            provider: MemoryMapProvider::new(),
            disposed: false,
        }
    }

    /// Get a reference to the memory map manager.
    pub fn memory_map_manager(&self) -> &MemoryMapManager {
        &self.mem_manager
    }

    /// Get a mutable reference to the memory map manager.
    pub fn memory_map_manager_mut(&mut self) -> &mut MemoryMapManager {
        &mut self.mem_manager
    }

    /// Get a reference to the memory map provider.
    pub fn provider(&self) -> &MemoryMapProvider {
        &self.provider
    }

    /// Get a mutable reference to the memory map provider.
    pub fn provider_mut(&mut self) -> &mut MemoryMapProvider {
        &mut self.provider
    }

    /// Activate a program, making it the current program for the plugin.
    ///
    /// This corresponds to `MemoryMapPlugin.programActivated` in Java.
    pub fn activate_program(&mut self, program: &Program) {
        self.mem_manager = MemoryMapManager::new(program.get_name());
        self.provider.set_program(program);
    }

    /// Deactivate the current program.
    ///
    /// This corresponds to `MemoryMapPlugin.programDeactivated` in Java.
    pub fn deactivate_program(&mut self) {
        self.provider.clear_program();
    }

    /// Handle a domain-object changed event.
    ///
    /// This corresponds to `MemoryMapPlugin.domainObjectChanged` in Java.
    /// If the provider is visible and the event is memory-related, the
    /// provider's map or data is refreshed.
    pub fn on_domain_object_changed(&mut self, events: &[MemoryEvent], program: &Program) {
        if !self.provider.is_visible() {
            return;
        }

        let structural = events.iter().any(|e| {
            matches!(
                e,
                MemoryEvent::BlockAdded
                    | MemoryEvent::BlockRemoved
                    | MemoryEvent::BlockMoved
                    | MemoryEvent::BlockSplit
                    | MemoryEvent::BlocksJoined
                    | MemoryEvent::Restored
            )
        });

        if structural {
            self.provider.refresh_map(program);
        } else if events.contains(&MemoryEvent::BlockChanged) {
            self.provider.refresh_data();
        }
    }

    /// Handle a program-location change (e.g., user navigated to an address).
    ///
    /// If the provider is set to follow location changes, the corresponding
    /// block is selected.
    pub fn on_location_changed(&mut self, address: Option<Address>, program: &Program) {
        self.provider.select_block_at_address(address, program);
    }

    /// Show the memory map provider.
    pub fn show(&mut self) {
        self.provider.set_visible(true);
    }

    /// Hide the memory map provider.
    pub fn hide(&mut self) {
        self.provider.set_visible(false);
    }

    /// Dispose of the plugin, releasing resources.
    ///
    /// This corresponds to `MemoryMapPlugin.dispose` in Java.
    pub fn dispose(&mut self) {
        self.provider.dispose();
        self.disposed = true;
    }

    /// Whether the plugin has been disposed.
    pub fn is_disposed(&self) -> bool {
        self.disposed
    }
}

impl Default for MemoryMapPlugin {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use ghidra_core::addr::Address;
    use ghidra_core::mem::MemoryMap;

    fn make_program() -> Program {
        let memory = MemoryMap::new(false);
        let mut p = Program::with_memory("test", Address::new(0x10000), Box::new(memory));
        let _ = p.memory.create_initialized_block(
            ".text",
            Address::new(0x10000),
            vec![0u8; 0x1000],
            false,
        );
        let _ = p.memory.create_initialized_block(
            ".data",
            Address::new(0x11000),
            vec![0u8; 0x800],
            false,
        );
        p
    }

    #[test]
    fn test_plugin_new() {
        let plugin = MemoryMapPlugin::new();
        assert!(!plugin.is_disposed());
        assert!(!plugin.provider().is_visible());
    }

    #[test]
    fn test_plugin_activate_program() {
        let program = make_program();
        let mut plugin = MemoryMapPlugin::new();
        plugin.activate_program(&program);
        assert_eq!(plugin.provider().block_count(), 2);
    }

    #[test]
    fn test_plugin_deactivate_program() {
        let program = make_program();
        let mut plugin = MemoryMapPlugin::new();
        plugin.activate_program(&program);
        assert_eq!(plugin.provider().block_count(), 2);
        plugin.deactivate_program();
        assert_eq!(plugin.provider().block_count(), 0);
    }

    #[test]
    fn test_plugin_show_hide() {
        let mut plugin = MemoryMapPlugin::new();
        plugin.show();
        assert!(plugin.provider().is_visible());
        plugin.hide();
        assert!(!plugin.provider().is_visible());
    }

    #[test]
    fn test_plugin_event_forwarding() {
        let program = make_program();
        let mut plugin = MemoryMapPlugin::new();
        plugin.show();
        plugin.activate_program(&program);

        // A structural event should trigger a refresh
        plugin.on_domain_object_changed(&[MemoryEvent::BlockAdded], &program);
        // No panic, provider updated

        // A non-structural event should trigger data refresh only
        plugin.on_domain_object_changed(&[MemoryEvent::BlockChanged], &program);
    }

    #[test]
    fn test_plugin_event_ignored_when_not_visible() {
        let program = make_program();
        let mut plugin = MemoryMapPlugin::new();
        // Not visible -- events should be ignored
        plugin.activate_program(&program);
        plugin.on_domain_object_changed(&[MemoryEvent::BlockAdded], &program);
        // Should not panic
    }

    #[test]
    fn test_plugin_dispose() {
        let mut plugin = MemoryMapPlugin::new();
        plugin.dispose();
        assert!(plugin.is_disposed());
        assert!(!plugin.provider().is_visible());
    }

    #[test]
    fn test_plugin_default() {
        let plugin = MemoryMapPlugin::default();
        assert!(!plugin.is_disposed());
    }

    #[test]
    fn test_memory_event_equality() {
        assert_eq!(MemoryEvent::BlockAdded, MemoryEvent::BlockAdded);
        assert_ne!(MemoryEvent::BlockAdded, MemoryEvent::BlockRemoved);
    }
}
