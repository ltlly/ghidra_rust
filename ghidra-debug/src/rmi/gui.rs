//! GUI types for Trace RMI connection management and launcher.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.debug.gui.tracermi` package.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use super::service::ConnectMode;

// ---------------------------------------------------------------------------
// Connection Manager
// ---------------------------------------------------------------------------

/// A node in the connection manager tree.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RmiManagerNode {
    /// Root node.
    Root {
        /// Child service nodes.
        children: Vec<RmiManagerNode>,
    },
    /// A service (listens for connections).
    Service {
        /// Service name.
        name: String,
        /// Bind address.
        address: String,
        /// Child acceptor nodes.
        acceptors: Vec<RmiManagerNode>,
    },
    /// An acceptor (accepts connections from a specific address).
    Acceptor {
        /// Acceptor address.
        address: String,
        /// Child connection nodes.
        connections: Vec<RmiManagerNode>,
    },
    /// A connected client or server.
    Connection {
        /// Remote address.
        remote_address: String,
        /// Connection mode.
        mode: ConnectMode,
        /// Whether this connection is active.
        active: bool,
        /// Child target nodes.
        targets: Vec<RmiManagerNode>,
    },
    /// A target within a connection.
    Target {
        /// Target ID.
        target_id: String,
        /// Display name.
        display_name: String,
        /// PID if attached.
        pid: Option<u64>,
    },
}

impl RmiManagerNode {
    /// Whether this node has children.
    pub fn has_children(&self) -> bool {
        match self {
            Self::Root { children } => !children.is_empty(),
            Self::Service { acceptors, .. } => !acceptors.is_empty(),
            Self::Acceptor { connections, .. } => !connections.is_empty(),
            Self::Connection { targets, .. } => !targets.is_empty(),
            Self::Target { .. } => false,
        }
    }

    /// Get the display label for this node.
    pub fn label(&self) -> String {
        match self {
            Self::Root { .. } => "Trace RMI Connections".into(),
            Self::Service { name, address, .. } => format!("{} ({})", name, address),
            Self::Acceptor { address, .. } => address.clone(),
            Self::Connection {
                remote_address,
                mode,
                active,
                ..
            } => {
                let status = if *active { "active" } else { "inactive" };
                format!("{} [{}] ({})", remote_address, status, mode_label(mode))
            }
            Self::Target {
                display_name,
                pid,
                ..
            } => {
                if let Some(pid) = pid {
                    format!("{} (PID {})", display_name, pid)
                } else {
                    display_name.clone()
                }
            }
        }
    }
}

fn mode_label(mode: &ConnectMode) -> &'static str {
    match mode {
        ConnectMode::Server => "server",
        ConnectMode::Client => "client",
    }
}

// ---------------------------------------------------------------------------
// Connection Manager Plugin
// ---------------------------------------------------------------------------

/// Data model for the RMI connection manager provider.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionManagerModel {
    /// The root of the connection tree.
    pub root: RmiManagerNode,
    /// Whether auto-refresh is enabled.
    pub auto_refresh: bool,
    /// Refresh interval in milliseconds.
    pub refresh_interval_ms: u64,
}

impl ConnectionManagerModel {
    /// Create a new model.
    pub fn new() -> Self {
        Self {
            root: RmiManagerNode::Root {
                children: Vec::new(),
            },
            auto_refresh: false,
            refresh_interval_ms: 1000,
        }
    }

    /// Add a service node.
    pub fn add_service(&mut self, name: impl Into<String>, address: impl Into<String>) {
        if let RmiManagerNode::Root { children } = &mut self.root {
            children.push(RmiManagerNode::Service {
                name: name.into(),
                address: address.into(),
                acceptors: Vec::new(),
            });
        }
    }
}

// ---------------------------------------------------------------------------
// Launch Dialog / Offer
// ---------------------------------------------------------------------------

/// A launch offer from a TraceRmi launch opinion.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceRmiLaunchOffer {
    /// The offer name (e.g., "gdb", "lldb").
    pub name: String,
    /// Display label.
    pub display_label: String,
    /// Script path to launch.
    pub script_path: Option<String>,
    /// Default launch parameters.
    pub default_parameters: BTreeMap<String, String>,
    /// Whether the offer is currently available.
    pub available: bool,
    /// Priority (lower = higher priority).
    pub priority: u32,
}

impl TraceRmiLaunchOffer {
    /// Create a new launch offer.
    pub fn new(name: impl Into<String>, display_label: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            display_label: display_label.into(),
            script_path: None,
            default_parameters: BTreeMap::new(),
            available: false,
            priority: 100,
        }
    }

    /// Set the script path.
    pub fn with_script(mut self, path: impl Into<String>) -> Self {
        self.script_path = Some(path.into());
        self
    }

    /// Add a default parameter.
    pub fn with_default_param(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.default_parameters.insert(key.into(), value.into());
        self
    }

    /// Set availability.
    pub fn with_available(mut self, available: bool) -> Self {
        self.available = available;
        self
    }

    /// Set priority.
    pub fn with_priority(mut self, priority: u32) -> Self {
        self.priority = priority;
        self
    }
}

/// A launch opinion (factory for launch offers).
///
/// Ported from Ghidra's `TraceRmiLaunchOpinion` SPI.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceRmiLaunchOpinion {
    /// Opinion name.
    pub name: String,
    /// Offers generated by this opinion.
    pub offers: Vec<TraceRmiLaunchOffer>,
    /// Whether the opinion is enabled.
    pub enabled: bool,
}

impl TraceRmiLaunchOpinion {
    /// Create a new opinion.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            offers: Vec::new(),
            enabled: true,
        }
    }

    /// Add an offer.
    pub fn add_offer(&mut self, offer: TraceRmiLaunchOffer) {
        self.offers.push(offer);
    }

    /// Get available offers.
    pub fn available_offers(&self) -> impl Iterator<Item = &TraceRmiLaunchOffer> {
        self.offers.iter().filter(|o| o.available)
    }
}

// ---------------------------------------------------------------------------
// Launch Dialog Model
// ---------------------------------------------------------------------------

/// Data model for the launch dialog.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LaunchDialogModel {
    /// All registered opinions.
    pub opinions: Vec<TraceRmiLaunchOpinion>,
    /// The currently selected offer, if any.
    pub selected_offer: Option<usize>,
    /// User-provided parameters.
    pub parameters: BTreeMap<String, String>,
}

impl LaunchDialogModel {
    /// Create a new launch dialog model.
    pub fn new() -> Self {
        Self {
            opinions: Vec::new(),
            selected_offer: None,
            parameters: BTreeMap::new(),
        }
    }

    /// Get all available offers across all opinions.
    pub fn all_available_offers(&self) -> Vec<&TraceRmiLaunchOffer> {
        self.opinions
            .iter()
            .flat_map(|o| o.available_offers())
            .collect()
    }

    /// Get the selected offer.
    pub fn get_selected_offer(&self) -> Option<&TraceRmiLaunchOffer> {
        let idx = self.selected_offer?;
        self.opinions
            .iter()
            .flat_map(|o| o.offers.iter())
            .nth(idx)
    }
}

/// A result of a launch action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LaunchResult {
    /// Whether the launch succeeded.
    pub success: bool,
    /// Connection address (if successful).
    pub address: Option<String>,
    /// Error message (if failed).
    pub error: Option<String>,
}

impl LaunchResult {
    /// A successful launch.
    pub fn success(address: impl Into<String>) -> Self {
        Self {
            success: true,
            address: Some(address.into()),
            error: None,
        }
    }

    /// A failed launch.
    pub fn failure(error: impl Into<String>) -> Self {
        Self {
            success: false,
            address: None,
            error: Some(error.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_manager_node_root() {
        let root = RmiManagerNode::Root {
            children: vec![],
        };
        assert!(!root.has_children());
        assert_eq!(root.label(), "Trace RMI Connections");
    }

    #[test]
    fn test_manager_node_service() {
        let node = RmiManagerNode::Service {
            name: "GDB".into(),
            address: "127.0.0.1:5000".into(),
            acceptors: vec![],
        };
        assert!(!node.has_children());
        assert!(node.label().contains("GDB"));
    }

    #[test]
    fn test_manager_node_connection() {
        let node = RmiManagerNode::Connection {
            remote_address: "10.0.0.1:1234".into(),
            mode: ConnectMode::Client,
            active: true,
            targets: vec![],
        };
        assert!(!node.has_children());
        assert!(node.label().contains("active"));
    }

    #[test]
    fn test_manager_node_target() {
        let node = RmiManagerNode::Target {
            target_id: "gdb-1".into(),
            display_name: "GDB".into(),
            pid: Some(42),
        };
        assert!(!node.has_children());
        assert!(node.label().contains("42"));
    }

    #[test]
    fn test_manager_node_target_no_pid() {
        let node = RmiManagerNode::Target {
            target_id: "gdb-1".into(),
            display_name: "GDB".into(),
            pid: None,
        };
        assert_eq!(node.label(), "GDB");
    }

    #[test]
    fn test_connection_manager_model() {
        let mut model = ConnectionManagerModel::new();
        model.add_service("GDB", "127.0.0.1:5000");
        if let RmiManagerNode::Root { children } = &model.root {
            assert_eq!(children.len(), 1);
            assert!(model.root.has_children());
        } else {
            panic!("Expected root node");
        }
    }

    #[test]
    fn test_launch_offer() {
        let offer = TraceRmiLaunchOffer::new("gdb", "GDB Remote")
            .with_script("/path/to/script")
            .with_available(true)
            .with_priority(10)
            .with_default_param("host", "localhost");

        assert_eq!(offer.name, "gdb");
        assert!(offer.available);
        assert_eq!(offer.priority, 10);
        assert_eq!(offer.script_path.as_deref(), Some("/path/to/script"));
        assert_eq!(
            offer.default_parameters.get("host").map(|s| s.as_str()),
            Some("localhost")
        );
    }

    #[test]
    fn test_launch_opinion() {
        let mut opinion = TraceRmiLaunchOpinion::new("gdb");
        opinion.add_offer(TraceRmiLaunchOffer::new("gdb", "GDB").with_available(true));
        opinion.add_offer(TraceRmiLaunchOffer::new("gdb-pipe", "GDB Pipe").with_available(false));

        let available: Vec<_> = opinion.available_offers().collect();
        assert_eq!(available.len(), 1);
        assert_eq!(available[0].name, "gdb");
    }

    #[test]
    fn test_launch_dialog_model() {
        let mut model = LaunchDialogModel::new();
        let mut opinion = TraceRmiLaunchOpinion::new("gdb");
        opinion.add_offer(TraceRmiLaunchOffer::new("gdb", "GDB").with_available(true));
        model.opinions.push(opinion);

        let offers = model.all_available_offers();
        assert_eq!(offers.len(), 1);

        // Nothing selected yet
        assert!(model.get_selected_offer().is_none());
    }

    #[test]
    fn test_launch_result() {
        let ok = LaunchResult::success("127.0.0.1:5000");
        assert!(ok.success);
        assert!(ok.error.is_none());

        let fail = LaunchResult::failure("connection refused");
        assert!(!fail.success);
        assert_eq!(fail.error.as_deref(), Some("connection refused"));
    }
}
