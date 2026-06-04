//! Decompile plugin -- Rust port of
//! `ghidra.app.plugin.core.decompile.DecompilePlugin`.
//!
//! The plugin is the top-level owner of all decompiler providers.  It
//! routes program events (activate, close, location, selection) to the
//! appropriate provider and manages the lifecycle of connected and
//! disconnected providers.

use std::collections::HashMap;

use ghidra_core::addr::Address;

use super::provider::{DecompilerProvider, ProviderState};

// ---------------------------------------------------------------------------
// Program event types
// ---------------------------------------------------------------------------

/// Events that the decompile plugin processes.
#[derive(Debug, Clone)]
pub enum ProgramEvent {
    /// A program was activated in the tool.
    ProgramActivated {
        /// The name of the activated program.
        program_name: String,
    },
    /// A program was opened.
    ProgramOpened {
        /// The name of the opened program.
        program_name: String,
    },
    /// The user navigated to a new location.
    LocationChanged {
        /// The program name.
        program_name: String,
        /// The address the user navigated to.
        address: Address,
    },
    /// The user changed the selection.
    SelectionChanged {
        /// The program name.
        program_name: String,
        /// The selected address range (start, end).
        range: (Address, Address),
    },
    /// A program was closed.
    ProgramClosed {
        /// The name of the closed program.
        program_name: String,
    },
}

// ---------------------------------------------------------------------------
// DecompilePlugin
// ---------------------------------------------------------------------------

/// The decompiler plugin.
///
/// Owns the primary (connected) decompiler provider and zero or more
/// "disconnected" providers (snapshots).  Processes tool events and
/// dispatches them to providers.
///
/// # Lifecycle
///
/// 1. Created by the tool infrastructure.
/// 2. On `ProgramActivated`, the primary provider is set to the new
///    program.
/// 3. On `LocationChanged`, the primary provider is asked to display
///    the new address (with a debounce delay).
/// 4. On `ProgramClosed`, any disconnected providers for that program
///    are removed.
#[derive(Debug)]
pub struct DecompilePlugin {
    /// The plugin's display name.
    name: String,
    /// The primary (connected) provider.
    connected_provider: DecompilerProvider,
    /// Disconnected providers (snapshots).
    disconnected_providers: Vec<DecompilerProvider>,
    /// The currently active program name.
    current_program: Option<String>,
    /// The current location (address offset).
    current_location: Option<Address>,
    /// Count of disconnected providers created.
    next_disconnected_id: usize,
}

impl DecompilePlugin {
    /// Plugin option category name.
    pub const OPTIONS_TITLE: &'static str = "Decompiler";

    /// Create a new decompile plugin.
    pub fn new() -> Self {
        Self {
            name: "Decompile".to_string(),
            connected_provider: DecompilerProvider::new_connected(0),
            disconnected_providers: Vec::new(),
            current_program: None,
            current_location: None,
            next_disconnected_id: 1,
        }
    }

    /// The plugin name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns a reference to the connected (primary) provider.
    pub fn connected_provider(&self) -> &DecompilerProvider {
        &self.connected_provider
    }

    /// Returns a mutable reference to the connected (primary) provider.
    pub fn connected_provider_mut(&mut self) -> &mut DecompilerProvider {
        &mut self.connected_provider
    }

    /// Returns the number of disconnected providers.
    pub fn disconnected_count(&self) -> usize {
        self.disconnected_providers.len()
    }

    /// Create a new disconnected provider (snapshot window).
    pub fn create_disconnected_provider(&mut self) -> usize {
        let id = self.next_disconnected_id;
        self.next_disconnected_id += 1;
        let provider = DecompilerProvider::new_disconnected(id);
        self.disconnected_providers.push(provider);
        id
    }

    /// Process a program event.
    pub fn process_event(&mut self, event: ProgramEvent) {
        match event {
            ProgramEvent::ProgramActivated { program_name } => {
                self.current_program = Some(program_name.clone());
                self.connected_provider.set_program(Some(program_name));
            }
            ProgramEvent::LocationChanged { program_name, address } => {
                // Only update if the program matches the current one.
                if self.current_program.as_deref() == Some(&program_name) {
                    self.current_location = Some(address);
                    self.connected_provider.set_location(Some(address));
                }
            }
            ProgramEvent::SelectionChanged { program_name, range } => {
                if self.current_program.as_deref() == Some(&program_name) {
                    self.connected_provider.set_selection(Some(range));
                }
            }
            ProgramEvent::ProgramClosed { program_name } => {
                // Remove disconnected providers for the closed program.
                self.disconnected_providers
                    .retain(|p| p.program_name() != Some(&program_name));
                // If the active program was closed, clear the connected provider.
                if self.current_program.as_deref() == Some(&program_name) {
                    self.current_program = None;
                    self.current_location = None;
                    self.connected_provider.set_program(None);
                }
            }
            ProgramEvent::ProgramOpened { .. } => {
                // No action needed on open; activation will follow.
            }
        }
    }

    /// Handle a token rename broadcast to all providers.
    pub fn handle_token_renamed(&mut self, old_name: &str, new_name: &str) {
        self.connected_provider
            .notify_token_renamed(old_name, new_name);
        for provider in &mut self.disconnected_providers {
            provider.notify_token_renamed(old_name, new_name);
        }
    }

    /// Get the current location.
    pub fn current_location(&self) -> Option<Address> {
        self.current_location
    }

    /// Close a provider by its id.  Returns `true` if found and removed.
    pub fn close_disconnected_provider(&mut self, id: usize) -> bool {
        let len_before = self.disconnected_providers.len();
        self.disconnected_providers.retain(|p| p.id() != id);
        self.disconnected_providers.len() < len_before
    }

    /// Dispose the plugin, cleaning up all providers.
    pub fn dispose(&mut self) {
        self.current_program = None;
        self.current_location = None;
        self.connected_provider.dispose();
        for p in &mut self.disconnected_providers {
            p.dispose();
        }
        self.disconnected_providers.clear();
    }
}

impl Default for DecompilePlugin {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plugin_new() {
        let plugin = DecompilePlugin::new();
        assert_eq!(plugin.name(), "Decompile");
        assert_eq!(plugin.disconnected_count(), 0);
        assert!(plugin.current_location().is_none());
    }

    #[test]
    fn test_plugin_program_activated() {
        let mut plugin = DecompilePlugin::new();
        plugin.process_event(ProgramEvent::ProgramActivated {
            program_name: "test.elf".into(),
        });
        assert_eq!(plugin.current_program.as_deref(), Some("test.elf"));
        assert_eq!(
            plugin.connected_provider().program_name(),
            Some("test.elf")
        );
    }

    #[test]
    fn test_plugin_location_changed() {
        let mut plugin = DecompilePlugin::new();
        plugin.process_event(ProgramEvent::ProgramActivated {
            program_name: "a.bin".into(),
        });
        plugin.process_event(ProgramEvent::LocationChanged {
            program_name: "a.bin".into(),
            address: Address::new(0x1000),
        });
        assert_eq!(plugin.current_location(), Some(Address::new(0x1000)));
    }

    #[test]
    fn test_plugin_location_changed_wrong_program() {
        let mut plugin = DecompilePlugin::new();
        plugin.process_event(ProgramEvent::ProgramActivated {
            program_name: "a.bin".into(),
        });
        plugin.process_event(ProgramEvent::LocationChanged {
            program_name: "b.bin".into(),
            address: Address::new(0x2000),
        });
        assert!(plugin.current_location().is_none());
    }

    #[test]
    fn test_plugin_create_disconnected() {
        let mut plugin = DecompilePlugin::new();
        let id1 = plugin.create_disconnected_provider();
        let id2 = plugin.create_disconnected_provider();
        assert_eq!(plugin.disconnected_count(), 2);
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_plugin_close_disconnected() {
        let mut plugin = DecompilePlugin::new();
        let id = plugin.create_disconnected_provider();
        assert_eq!(plugin.disconnected_count(), 1);
        assert!(plugin.close_disconnected_provider(id));
        assert_eq!(plugin.disconnected_count(), 0);
        assert!(!plugin.close_disconnected_provider(id)); // already closed
    }

    #[test]
    fn test_plugin_program_closed() {
        let mut plugin = DecompilePlugin::new();
        plugin.process_event(ProgramEvent::ProgramActivated {
            program_name: "x.bin".into(),
        });
        plugin.create_disconnected_provider();
        plugin.process_event(ProgramEvent::ProgramClosed {
            program_name: "x.bin".into(),
        });
        assert!(plugin.current_program.is_none());
    }

    #[test]
    fn test_plugin_dispose() {
        let mut plugin = DecompilePlugin::new();
        plugin.process_event(ProgramEvent::ProgramActivated {
            program_name: "test".into(),
        });
        plugin.create_disconnected_provider();
        plugin.dispose();
        assert!(plugin.current_program.is_none());
        assert_eq!(plugin.disconnected_count(), 0);
    }

    #[test]
    fn test_plugin_handle_token_renamed() {
        let mut plugin = DecompilePlugin::new();
        // Should not panic even with no active program.
        plugin.handle_token_renamed("old", "new");
    }
}
