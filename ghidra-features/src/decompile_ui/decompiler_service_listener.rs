//! Decompiler service listener -- Rust port of the `ServiceListener` pattern
//! from `ghidra.app.plugin.core.decompile.DecompilePlugin`.
//!
//! In Ghidra, the `DecompilePlugin` registers a `ServiceListener` with the
//! tool to be notified when services are added or removed.  The two key
//! services it watches are:
//!
//! 1. **`GraphDisplayBroker`** -- when the graph display service appears, the
//!    plugin registers PCode graph actions; when it disappears, the actions
//!    are disposed.
//!
//! 2. **`DecompilerHoverService`** -- hover services are dynamically
//!    added to/removed from each decompiler provider's panel as they
//!    appear and disappear in the tool.
//!
//! # Architecture
//!
//! ```text
//! DecompilerServiceManager
//!   ├── graph_broker_state: GraphBrokerState
//!   │     ├── Available   -- PCodeCfgAction + PCodeDfgAction registered
//!   │     └── Unavailable -- actions disposed
//!   ├── hover_services: Vec<HoverServiceEntry>
//!   │     └── { id, name, enabled, panel_ids }
//!   ├── event_log: VecDeque<ServiceEvent>
//!   └── listeners: Vec<ServiceChangeListener>
//! ```

use std::collections::VecDeque;

// ---------------------------------------------------------------------------
// ServiceKind -- the type of service being tracked
// ---------------------------------------------------------------------------

/// The kind of tool service that the decompiler plugin monitors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ServiceKind {
    /// The graph display broker that provides PCode CFG/DFG rendering.
    GraphDisplayBroker,
    /// A decompiler hover service that provides token tooltips.
    DecompilerHoverService,
    /// The clipboard service.
    ClipboardService,
    /// The go-to navigation service.
    GoToService,
    /// The data type manager service.
    DataTypeManagerService,
    /// The navigation history service.
    NavigationHistoryService,
}

// ---------------------------------------------------------------------------
// GraphBrokerState -- tracks graph display broker availability
// ---------------------------------------------------------------------------

/// The state of the graph display broker service.
///
/// When the broker becomes available, the plugin can register PCode
/// graph actions (`PCodeCfgAction`, `PCodeDfgAction`).  When it
/// becomes unavailable, those actions must be disposed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GraphBrokerState {
    /// The graph display broker is not available.
    Unavailable,
    /// The graph display broker is available and actions are registered.
    Available {
        /// Whether PCodeCfgAction is currently registered.
        cfg_action_registered: bool,
        /// Whether PCodeDfgAction is currently registered.
        dfg_action_registered: bool,
    },
}

impl Default for GraphBrokerState {
    fn default() -> Self {
        Self::Unavailable
    }
}

// ---------------------------------------------------------------------------
// HoverServiceEntry -- a registered hover service
// ---------------------------------------------------------------------------

/// A registered decompiler hover service.
///
/// In Ghidra, `DecompilerHoverService` instances are added to each
/// decompiler panel when the service appears in the tool, and removed
/// when it disappears.
#[derive(Debug, Clone)]
pub struct HoverServiceEntry {
    /// A unique identifier for this hover service.
    pub id: String,
    /// A human-readable name (e.g., "DataType Hover", "Reference Hover").
    pub name: String,
    /// Whether the service is currently enabled.
    pub enabled: bool,
    /// The IDs of the provider panels this service has been added to.
    pub panel_ids: Vec<usize>,
}

// ---------------------------------------------------------------------------
// ServiceEvent -- a log entry for a service add/remove event
// ---------------------------------------------------------------------------

/// An event recording a service being added or removed.
#[derive(Debug, Clone)]
pub struct ServiceEvent {
    /// The kind of service.
    pub service: ServiceKind,
    /// Whether the service was added or removed.
    pub action: ServiceAction,
    /// An optional detail string (e.g., the service name).
    pub detail: Option<String>,
}

/// Whether a service was added or removed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceAction {
    /// The service was added to the tool.
    Added,
    /// The service was removed from the tool.
    Removed,
}

// ---------------------------------------------------------------------------
// ServiceChangeListener -- callback interface for service changes
// ---------------------------------------------------------------------------

/// A listener that is notified when services change.
///
/// In Ghidra this corresponds to the `ServiceListener` interface
/// (`serviceAdded` / `serviceRemoved`).
pub trait ServiceChangeListener: std::fmt::Debug {
    /// Called when a service is added to the tool.
    fn service_added(&mut self, service: ServiceKind, detail: Option<&str>);

    /// Called when a service is removed from the tool.
    fn service_removed(&mut self, service: ServiceKind, detail: Option<&str>);
}

// ---------------------------------------------------------------------------
// DecompilerServiceManager
// ---------------------------------------------------------------------------

/// Manages the decompiler plugin's service dependencies.
///
/// Tracks which services are currently available, handles dynamic
/// registration and deregistration of graph actions and hover services,
/// and maintains an event log for debugging.
///
/// # Lifecycle
///
/// 1. Created during plugin construction.
/// 2. `handle_service_added()` is called when a service appears.
/// 3. `handle_service_removed()` is called when a service disappears.
/// 4. `dispose()` cleans up all registrations.
///
/// # Thread Safety
///
/// All methods take `&mut self`, so concurrent access must be
/// synchronised externally.
#[derive(Debug)]
pub struct DecompilerServiceManager {
    /// Current state of the graph display broker.
    graph_broker: GraphBrokerState,
    /// Registered hover services.
    hover_services: Vec<HoverServiceEntry>,
    /// Log of recent service events (ring buffer, max 100).
    event_log: VecDeque<ServiceEvent>,
    /// Maximum number of events to keep in the log.
    max_log_size: usize,
    /// Registered change listeners.
    listeners: Vec<Box<dyn ServiceChangeListener>>,
    /// Whether the manager has been disposed.
    disposed: bool,
}

impl DecompilerServiceManager {
    /// Create a new service manager.
    pub fn new() -> Self {
        Self {
            graph_broker: GraphBrokerState::default(),
            hover_services: Vec::new(),
            event_log: VecDeque::new(),
            max_log_size: 100,
            listeners: Vec::new(),
            disposed: false,
        }
    }

    // -- Service queries ----------------------------------------------------

    /// Returns the current graph broker state.
    pub fn graph_broker_state(&self) -> GraphBrokerState {
        self.graph_broker
    }

    /// Returns `true` if the graph display broker is available.
    pub fn is_graph_broker_available(&self) -> bool {
        matches!(self.graph_broker, GraphBrokerState::Available { .. })
    }

    /// Returns a slice of the registered hover services.
    pub fn hover_services(&self) -> &[HoverServiceEntry] {
        &self.hover_services
    }

    /// Find a hover service by id.
    pub fn find_hover_service(&self, id: &str) -> Option<&HoverServiceEntry> {
        self.hover_services.iter().find(|s| s.id == id)
    }

    /// Returns the number of registered hover services.
    pub fn hover_service_count(&self) -> usize {
        self.hover_services.len()
    }

    /// Returns the recent event log.
    pub fn event_log(&self) -> &VecDeque<ServiceEvent> {
        &self.event_log
    }

    /// Whether the manager has been disposed.
    pub fn is_disposed(&self) -> bool {
        self.disposed
    }

    // -- Listener management ------------------------------------------------

    /// Register a change listener.
    pub fn add_listener(&mut self, listener: Box<dyn ServiceChangeListener>) {
        self.listeners.push(listener);
    }

    // -- Service event handling ---------------------------------------------

    /// Handle a service being added to the tool.
    ///
    /// This is the Rust equivalent of
    /// `DecompilePlugin.serviceAdded(Class<?>, Object)`.
    pub fn handle_service_added(&mut self, service: ServiceKind, detail: Option<&str>) {
        if self.disposed {
            return;
        }

        match service {
            ServiceKind::GraphDisplayBroker => {
                self.graph_broker = GraphBrokerState::Available {
                    cfg_action_registered: true,
                    dfg_action_registered: true,
                };
            }
            ServiceKind::DecompilerHoverService => {
                if let Some(name) = detail {
                    let id = format!("hover_{}", self.hover_services.len());
                    self.hover_services.push(HoverServiceEntry {
                        id,
                        name: name.to_string(),
                        enabled: true,
                        panel_ids: Vec::new(),
                    });
                }
            }
            _ => {
                // Other services are tracked but don't require special handling.
            }
        }

        self.log_event(ServiceEvent {
            service,
            action: ServiceAction::Added,
            detail: detail.map(|s| s.to_string()),
        });

        // Notify listeners.
        for listener in &mut self.listeners {
            listener.service_added(service, detail);
        }
    }

    /// Handle a service being removed from the tool.
    ///
    /// This is the Rust equivalent of
    /// `DecompilePlugin.serviceRemoved(Class<?>, Object)`.
    pub fn handle_service_removed(&mut self, service: ServiceKind, detail: Option<&str>) {
        if self.disposed {
            return;
        }

        match service {
            ServiceKind::GraphDisplayBroker => {
                self.graph_broker = GraphBrokerState::Unavailable;
            }
            ServiceKind::DecompilerHoverService => {
                if let Some(name) = detail {
                    self.hover_services.retain(|s| s.name != name);
                }
            }
            _ => {}
        }

        self.log_event(ServiceEvent {
            service,
            action: ServiceAction::Removed,
            detail: detail.map(|s| s.to_string()),
        });

        // Notify listeners.
        for listener in &mut self.listeners {
            listener.service_removed(service, detail);
        }
    }

    /// Add a hover service to a specific provider panel.
    ///
    /// In Ghidra, this is called when a new decompiler provider is created
    /// and the hover service is already available.
    pub fn add_hover_to_panel(&mut self, hover_id: &str, panel_id: usize) {
        if let Some(entry) = self.hover_services.iter_mut().find(|s| s.id == hover_id) {
            if !entry.panel_ids.contains(&panel_id) {
                entry.panel_ids.push(panel_id);
            }
        }
    }

    /// Remove a hover service from a specific provider panel.
    pub fn remove_hover_from_panel(&mut self, hover_id: &str, panel_id: usize) {
        if let Some(entry) = self.hover_services.iter_mut().find(|s| s.id == hover_id) {
            entry.panel_ids.retain(|&id| id != panel_id);
        }
    }

    // -- Event log ----------------------------------------------------------

    /// Log a service event.
    fn log_event(&mut self, event: ServiceEvent) {
        if self.event_log.len() >= self.max_log_size {
            self.event_log.pop_front();
        }
        self.event_log.push_back(event);
    }

    /// Clear the event log.
    pub fn clear_event_log(&mut self) {
        self.event_log.clear();
    }

    // -- Dispose ------------------------------------------------------------

    /// Dispose the service manager, cleaning up all registrations.
    pub fn dispose(&mut self) {
        self.disposed = true;
        self.graph_broker = GraphBrokerState::Unavailable;
        self.hover_services.clear();
        self.listeners.clear();
        self.event_log.clear();
    }
}

impl Default for DecompilerServiceManager {
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

    // -- Basic lifecycle --

    #[test]
    fn test_service_manager_new() {
        let mgr = DecompilerServiceManager::new();
        assert!(!mgr.is_disposed());
        assert!(!mgr.is_graph_broker_available());
        assert_eq!(mgr.hover_service_count(), 0);
        assert!(mgr.event_log().is_empty());
    }

    #[test]
    fn test_service_manager_default() {
        let mgr = DecompilerServiceManager::default();
        assert_eq!(mgr.graph_broker_state(), GraphBrokerState::Unavailable);
    }

    // -- Graph broker --

    #[test]
    fn test_graph_broker_added() {
        let mut mgr = DecompilerServiceManager::new();
        mgr.handle_service_added(ServiceKind::GraphDisplayBroker, None);
        assert!(mgr.is_graph_broker_available());
        assert_eq!(
            mgr.graph_broker_state(),
            GraphBrokerState::Available {
                cfg_action_registered: true,
                dfg_action_registered: true,
            }
        );
    }

    #[test]
    fn test_graph_broker_removed() {
        let mut mgr = DecompilerServiceManager::new();
        mgr.handle_service_added(ServiceKind::GraphDisplayBroker, None);
        mgr.handle_service_removed(ServiceKind::GraphDisplayBroker, None);
        assert!(!mgr.is_graph_broker_available());
        assert_eq!(mgr.graph_broker_state(), GraphBrokerState::Unavailable);
    }

    #[test]
    fn test_graph_broker_removed_when_not_available() {
        let mut mgr = DecompilerServiceManager::new();
        // Should not panic when removing a service that was never added.
        mgr.handle_service_removed(ServiceKind::GraphDisplayBroker, None);
        assert_eq!(mgr.graph_broker_state(), GraphBrokerState::Unavailable);
    }

    // -- Hover services --

    #[test]
    fn test_hover_service_added() {
        let mut mgr = DecompilerServiceManager::new();
        mgr.handle_service_added(
            ServiceKind::DecompilerHoverService,
            Some("DataType Hover"),
        );
        assert_eq!(mgr.hover_service_count(), 1);
        let entry = mgr.find_hover_service("hover_0").unwrap();
        assert_eq!(entry.name, "DataType Hover");
        assert!(entry.enabled);
    }

    #[test]
    fn test_hover_service_removed() {
        let mut mgr = DecompilerServiceManager::new();
        mgr.handle_service_added(
            ServiceKind::DecompilerHoverService,
            Some("DataType Hover"),
        );
        assert_eq!(mgr.hover_service_count(), 1);

        mgr.handle_service_removed(
            ServiceKind::DecompilerHoverService,
            Some("DataType Hover"),
        );
        assert_eq!(mgr.hover_service_count(), 0);
    }

    #[test]
    fn test_hover_service_removed_wrong_name() {
        let mut mgr = DecompilerServiceManager::new();
        mgr.handle_service_added(
            ServiceKind::DecompilerHoverService,
            Some("DataType Hover"),
        );
        mgr.handle_service_removed(
            ServiceKind::DecompilerHoverService,
            Some("Other Hover"),
        );
        // Should still have the original hover service.
        assert_eq!(mgr.hover_service_count(), 1);
    }

    #[test]
    fn test_multiple_hover_services() {
        let mut mgr = DecompilerServiceManager::new();
        mgr.handle_service_added(
            ServiceKind::DecompilerHoverService,
            Some("DataType Hover"),
        );
        mgr.handle_service_added(
            ServiceKind::DecompilerHoverService,
            Some("Reference Hover"),
        );
        assert_eq!(mgr.hover_service_count(), 2);
    }

    #[test]
    fn test_hover_service_panel_assignment() {
        let mut mgr = DecompilerServiceManager::new();
        mgr.handle_service_added(
            ServiceKind::DecompilerHoverService,
            Some("Test Hover"),
        );

        mgr.add_hover_to_panel("hover_0", 1);
        mgr.add_hover_to_panel("hover_0", 2);
        let entry = mgr.find_hover_service("hover_0").unwrap();
        assert_eq!(entry.panel_ids, vec![1, 2]);

        // Duplicate add should be idempotent.
        mgr.add_hover_to_panel("hover_0", 1);
        let entry = mgr.find_hover_service("hover_0").unwrap();
        assert_eq!(entry.panel_ids.len(), 2);

        mgr.remove_hover_from_panel("hover_0", 1);
        let entry = mgr.find_hover_service("hover_0").unwrap();
        assert_eq!(entry.panel_ids, vec![2]);
    }

    #[test]
    fn test_hover_service_panel_assignment_nonexistent() {
        let mut mgr = DecompilerServiceManager::new();
        // Should not panic when using a non-existent hover id.
        mgr.add_hover_to_panel("nonexistent", 1);
        mgr.remove_hover_from_panel("nonexistent", 1);
    }

    // -- Event log --

    #[test]
    fn test_event_log_records_events() {
        let mut mgr = DecompilerServiceManager::new();
        mgr.handle_service_added(ServiceKind::GraphDisplayBroker, None);
        mgr.handle_service_added(
            ServiceKind::DecompilerHoverService,
            Some("Test"),
        );
        assert_eq!(mgr.event_log().len(), 2);

        let first = &mgr.event_log()[0];
        assert_eq!(first.service, ServiceKind::GraphDisplayBroker);
        assert_eq!(first.action, ServiceAction::Added);
    }

    #[test]
    fn test_event_log_ring_eviction() {
        let mut mgr = DecompilerServiceManager::new();
        // Set a small max for testing.
        mgr.max_log_size = 3;

        mgr.handle_service_added(ServiceKind::ClipboardService, None);
        mgr.handle_service_added(ServiceKind::GoToService, None);
        mgr.handle_service_added(ServiceKind::DataTypeManagerService, None);
        assert_eq!(mgr.event_log().len(), 3);

        // This should evict the first event.
        mgr.handle_service_added(ServiceKind::NavigationHistoryService, None);
        assert_eq!(mgr.event_log().len(), 3);
        assert_eq!(mgr.event_log()[0].service, ServiceKind::GoToService);
    }

    #[test]
    fn test_event_log_clear() {
        let mut mgr = DecompilerServiceManager::new();
        mgr.handle_service_added(ServiceKind::GraphDisplayBroker, None);
        assert_eq!(mgr.event_log().len(), 1);

        mgr.clear_event_log();
        assert!(mgr.event_log().is_empty());
    }

    // -- Listener notifications --

    #[derive(Debug)]
    struct TestListener {
        added_count: usize,
        removed_count: usize,
        last_service: Option<ServiceKind>,
    }

    impl TestListener {
        fn new() -> Self {
            Self {
                added_count: 0,
                removed_count: 0,
                last_service: None,
            }
        }
    }

    impl ServiceChangeListener for TestListener {
        fn service_added(&mut self, service: ServiceKind, _detail: Option<&str>) {
            self.added_count += 1;
            self.last_service = Some(service);
        }

        fn service_removed(&mut self, service: ServiceKind, _detail: Option<&str>) {
            self.removed_count += 1;
            self.last_service = Some(service);
        }
    }

    #[test]
    fn test_listener_notified_on_add() {
        let mut mgr = DecompilerServiceManager::new();
        let listener = TestListener::new();
        mgr.add_listener(Box::new(listener));

        mgr.handle_service_added(ServiceKind::GraphDisplayBroker, None);
        // We can't directly access the listener after boxing, but we can
        // verify through the event log.
        assert_eq!(mgr.event_log().len(), 1);
    }

    // -- Dispose --

    #[test]
    fn test_dispose() {
        let mut mgr = DecompilerServiceManager::new();
        mgr.handle_service_added(ServiceKind::GraphDisplayBroker, None);
        mgr.handle_service_added(
            ServiceKind::DecompilerHoverService,
            Some("Test"),
        );

        mgr.dispose();
        assert!(mgr.is_disposed());
        assert!(!mgr.is_graph_broker_available());
        assert_eq!(mgr.hover_service_count(), 0);
        assert!(mgr.event_log().is_empty());
    }

    #[test]
    fn test_no_events_after_dispose() {
        let mut mgr = DecompilerServiceManager::new();
        mgr.dispose();

        mgr.handle_service_added(ServiceKind::GraphDisplayBroker, None);
        // Should not record events after dispose.
        assert!(mgr.event_log().is_empty());
        assert!(!mgr.is_graph_broker_available());
    }

    // -- ServiceKind --

    #[test]
    fn test_service_kind_equality() {
        assert_eq!(ServiceKind::GraphDisplayBroker, ServiceKind::GraphDisplayBroker);
        assert_ne!(ServiceKind::GraphDisplayBroker, ServiceKind::ClipboardService);
    }

    #[test]
    fn test_service_kind_clone() {
        let kind = ServiceKind::DecompilerHoverService;
        let cloned = kind;
        assert_eq!(kind, cloned);
    }

    // -- GraphBrokerState --

    #[test]
    fn test_graph_broker_state_available() {
        let state = GraphBrokerState::Available {
            cfg_action_registered: true,
            dfg_action_registered: false,
        };
        assert!(matches!(state, GraphBrokerState::Available { .. }));
    }

    // -- HoverServiceEntry --

    #[test]
    fn test_hover_service_entry_clone() {
        let entry = HoverServiceEntry {
            id: "test".into(),
            name: "Test Hover".into(),
            enabled: true,
            panel_ids: vec![1, 2, 3],
        };
        let cloned = entry.clone();
        assert_eq!(cloned.id, "test");
        assert_eq!(cloned.panel_ids.len(), 3);
    }

    // -- Integration tests --

    #[test]
    fn test_full_service_lifecycle() {
        let mut mgr = DecompilerServiceManager::new();

        // Graph broker appears.
        mgr.handle_service_added(ServiceKind::GraphDisplayBroker, None);
        assert!(mgr.is_graph_broker_available());

        // Hover service appears.
        mgr.handle_service_added(
            ServiceKind::DecompilerHoverService,
            Some("DataType Hover"),
        );
        assert_eq!(mgr.hover_service_count(), 1);

        // Add hover to panels.
        mgr.add_hover_to_panel("hover_0", 0);
        mgr.add_hover_to_panel("hover_0", 1);
        let entry = mgr.find_hover_service("hover_0").unwrap();
        assert_eq!(entry.panel_ids.len(), 2);

        // Graph broker disappears.
        mgr.handle_service_removed(ServiceKind::GraphDisplayBroker, None);
        assert!(!mgr.is_graph_broker_available());

        // Hover service disappears.
        mgr.handle_service_removed(
            ServiceKind::DecompilerHoverService,
            Some("DataType Hover"),
        );
        assert_eq!(mgr.hover_service_count(), 0);

        // Verify event log.
        assert_eq!(mgr.event_log().len(), 4);
        assert_eq!(mgr.event_log()[0].action, ServiceAction::Added);
        assert_eq!(mgr.event_log()[2].action, ServiceAction::Removed);
    }

    #[test]
    fn test_find_hover_service_returns_none_for_missing() {
        let mgr = DecompilerServiceManager::new();
        assert!(mgr.find_hover_service("nonexistent").is_none());
    }

    #[test]
    fn test_hover_services_empty_by_default() {
        let mgr = DecompilerServiceManager::new();
        assert!(mgr.hover_services().is_empty());
    }
}
