//! TraceRmiService - service for Trace RMI (Remote Method Invocation).
//!
//! Ported from Ghidra's `ghidra.app.services.TraceRmiService`.

use serde::{Deserialize, Serialize};

/// A launch parameter for Trace RMI.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LaunchParameter {
    /// The parameter name.
    pub name: String,
    /// The parameter type (string, int, boolean, etc.).
    pub param_type: String,
    /// Default value, if any.
    pub default_value: Option<String>,
    /// Description.
    pub description: String,
    /// Whether this parameter is required.
    pub required: bool,
}

/// A launch offer from a Trace RMI connector.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceRmiLaunchOffer {
    /// The offer name (e.g., "gdb", "lldb").
    pub name: String,
    /// Description.
    pub description: String,
    /// Available launch parameters.
    pub parameters: Vec<LaunchParameter>,
    /// Whether this offer supports attaching.
    pub can_attach: bool,
    /// Whether this offer supports launching.
    pub can_launch: bool,
}

/// Service interface for Trace RMI.
pub trait TraceRmiServiceExt {
    /// Get available launch offers.
    fn launch_offers(&self) -> Vec<TraceRmiLaunchOffer>;

    /// Launch using a specific offer.
    fn launch(
        &mut self,
        offer_name: &str,
        params: &[(String, String)],
    ) -> Result<i64, String>;

    /// Attach to a process using a specific offer.
    fn attach(
        &mut self,
        offer_name: &str,
        pid: i64,
    ) -> Result<i64, String>;

    /// Get the list of active connections.
    fn active_connections(&self) -> Vec<i64>;

    /// Close a connection.
    fn close_connection(&mut self, connection_key: i64) -> Result<(), String>;
}

/// Service interface for launching Trace RMI connections.
pub trait TraceRmiLauncherServiceExt {
    /// Get available launchers.
    fn available_launchers(&self) -> Vec<TraceRmiLaunchOffer>;

    /// Launch a new connection.
    fn launch_connection(
        &mut self,
        launcher_name: &str,
        params: &[(String, String)],
    ) -> Result<i64, String>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_launch_parameter() {
        let param = LaunchParameter {
            name: "executable".into(),
            param_type: "string".into(),
            default_value: None,
            description: "Path to executable".into(),
            required: true,
        };
        assert!(param.required);
        assert_eq!(param.name, "executable");
    }

    #[test]
    fn test_trace_rmi_launch_offer() {
        let offer = TraceRmiLaunchOffer {
            name: "gdb".into(),
            description: "GDB connector".into(),
            parameters: vec![],
            can_attach: true,
            can_launch: true,
        };
        assert!(offer.can_launch);
        assert!(offer.can_attach);
    }
}
