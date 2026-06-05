//! TraceRmiLauncherService - launcher service for Trace RMI.
//!
//! Ported from Ghidra's `ghidra.app.services.TraceRmiLauncherService`.

use super::trace_rmi_service::{TraceRmiLaunchOffer, LaunchParameter};

/// Registry of available Trace RMI launchers.
#[derive(Debug, Clone, Default)]
pub struct TraceRmiLauncherRegistry {
    /// Registered launchers.
    pub launchers: Vec<TraceRmiLaunchOffer>,
}

impl TraceRmiLauncherRegistry {
    /// Create a new empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a launcher.
    pub fn register(&mut self, offer: TraceRmiLaunchOffer) {
        self.launchers.push(offer);
    }

    /// Find a launcher by name.
    pub fn find(&self, name: &str) -> Option<&TraceRmiLaunchOffer> {
        self.launchers.iter().find(|o| o.name == name)
    }

    /// Get all launchers.
    pub fn all(&self) -> &[TraceRmiLaunchOffer] {
        &self.launchers
    }

    /// Get launcher names.
    pub fn names(&self) -> Vec<&str> {
        self.launchers.iter().map(|o| o.name.as_str()).collect()
    }

    /// Check if a launcher exists.
    pub fn has_launcher(&self, name: &str) -> bool {
        self.launchers.iter().any(|o| o.name == name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_launcher_registry() {
        let mut registry = TraceRmiLauncherRegistry::new();
        assert!(registry.all().is_empty());

        registry.register(TraceRmiLaunchOffer {
            name: "gdb".into(),
            description: "GDB".into(),
            parameters: vec![
                LaunchParameter {
                    name: "exe".into(),
                    param_type: "string".into(),
                    default_value: None,
                    description: "Executable".into(),
                    required: true,
                },
            ],
            can_attach: true,
            can_launch: true,
        });

        assert!(registry.has_launcher("gdb"));
        assert!(!registry.has_launcher("lldb"));

        let gdb = registry.find("gdb").unwrap();
        assert_eq!(gdb.parameters.len(), 1);
    }

    #[test]
    fn test_registry_names() {
        let mut registry = TraceRmiLauncherRegistry::new();
        registry.register(TraceRmiLaunchOffer {
            name: "gdb".into(),
            description: "".into(),
            parameters: vec![],
            can_attach: true,
            can_launch: true,
        });
        registry.register(TraceRmiLaunchOffer {
            name: "lldb".into(),
            description: "".into(),
            parameters: vec![],
            can_attach: true,
            can_launch: true,
        });

        let names = registry.names();
        assert_eq!(names, vec!["gdb", "lldb"]);
    }
}
