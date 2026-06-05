//! DebuggerPlatformService - service for managing debugger platform connections.
//!
//! Ported from Ghidra's `ghidra.app.services.DebuggerPlatformService`.

use serde::{Deserialize, Serialize};

/// Information about an available debugger platform.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlatformOffer {
    /// The platform name (e.g., "gdb", "lldb", "dbgeng").
    pub name: String,
    /// Human-readable description.
    pub description: String,
    /// The connector type identifier.
    pub connector_type: String,
    /// Supported architecture IDs.
    pub supported_languages: Vec<String>,
    /// Whether this platform can launch targets.
    pub can_launch: bool,
    /// Whether this platform can attach to running processes.
    pub can_attach: bool,
    /// Whether this platform supports connection to remote targets.
    pub can_connect_remote: bool,
}

/// Platform opinion about what language/platform to use for a given target.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlatformOpinion {
    /// The language ID.
    pub language_id: String,
    /// The compiler spec ID.
    pub compiler_spec_id: String,
    /// Confidence score (0.0 to 1.0).
    pub confidence: f64,
    /// The source of this opinion.
    pub source: String,
}

/// Service interface for managing debugger platform connections.
pub trait DebuggerPlatformServiceExt {
    /// Get available platform offers.
    fn available_platforms(&self) -> Vec<PlatformOffer>;

    /// Get opinions about what language to use for a target.
    fn get_opinions(
        &self,
        connector_type: &str,
        target_info: &str,
    ) -> Vec<PlatformOpinion>;

    /// Register a new platform offer.
    fn register_platform(&mut self, offer: PlatformOffer);

    /// Get the current platform for a connection.
    fn current_platform(&self, connection_key: i64) -> Option<&PlatformOffer>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_platform_offer() {
        let offer = PlatformOffer {
            name: "gdb".into(),
            description: "GNU Debugger".into(),
            connector_type: "gdb-remote".into(),
            supported_languages: vec!["x86:LE:64:default".into()],
            can_launch: true,
            can_attach: true,
            can_connect_remote: true,
        };
        assert!(offer.can_launch);
        assert_eq!(offer.name, "gdb");
    }

    #[test]
    fn test_platform_opinion() {
        let opinion = PlatformOpinion {
            language_id: "x86:LE:64:default".into(),
            compiler_spec_id: "default".into(),
            confidence: 0.9,
            source: "ELF header".into(),
        };
        assert!(opinion.confidence > 0.5);
    }
}
