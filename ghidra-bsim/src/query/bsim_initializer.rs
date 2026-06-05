//! BSim module initializer.
//!
//! Ports Ghidra's `ghidra.features.bsim.query.BSimInitializer`.
//! Responsible for registering protocol handlers and performing one-time
//! module initialization when the BSim feature is loaded.

use super::super::query::server_config::ServerConfig;

/// Initializes the BSim module.
///
/// Ports Ghidra's `BSimInitializer`. In the Java version, this implements
/// `ModuleInitializer` and calls `Handler.registerHandler()`. In Rust, we
/// register protocol handlers and perform any needed static initialization.
pub struct BSimInitializer {
    /// Whether initialization has been performed.
    initialized: bool,
    /// Registered protocol names.
    registered_protocols: Vec<String>,
}

impl BSimInitializer {
    /// Create a new BSim initializer.
    pub fn new() -> Self {
        Self {
            initialized: false,
            registered_protocols: Vec::new(),
        }
    }

    /// Run the initialization.
    ///
    /// Registers the "postgresql" and "elastic" protocol handlers
    /// and performs any other one-time setup.
    pub fn run(&mut self) {
        if self.initialized {
            return;
        }
        self.registered_protocols.push("postgresql".to_string());
        self.registered_protocols.push("elastic".to_string());
        self.registered_protocols.push("bsimfile".to_string());
        self.initialized = true;
    }

    /// Whether the module has been initialized.
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Get the module name.
    pub fn name(&self) -> &str {
        "BSim Module"
    }

    /// Get the registered protocol names.
    pub fn registered_protocols(&self) -> &[String] {
        &self.registered_protocols
    }

    /// Check whether a given protocol is supported.
    pub fn supports_protocol(&self, protocol: &str) -> bool {
        self.registered_protocols.iter().any(|p| p == protocol)
    }

    /// Create a default server config for a given protocol.
    pub fn default_server_config(&self, protocol: &str) -> Option<ServerConfig> {
        if !self.supports_protocol(protocol) {
            return None;
        }
        match protocol {
            "postgresql" => Some(ServerConfig::postgresql("localhost", "bsim")),
            "elastic" => Some(ServerConfig::elasticsearch("localhost", 9200)),
            "bsimfile" => Some(ServerConfig::file("bsim_data")),
            _ => None,
        }
    }
}

impl Default for BSimInitializer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_initializer() {
        let init = BSimInitializer::new();
        assert!(!init.is_initialized());
        assert_eq!(init.name(), "BSim Module");
    }

    #[test]
    fn run_registers_protocols() {
        let mut init = BSimInitializer::new();
        init.run();
        assert!(init.is_initialized());
        assert_eq!(init.registered_protocols().len(), 3);
        assert!(init.supports_protocol("postgresql"));
        assert!(init.supports_protocol("elastic"));
        assert!(init.supports_protocol("bsimfile"));
        assert!(!init.supports_protocol("unknown"));
    }

    #[test]
    fn run_idempotent() {
        let mut init = BSimInitializer::new();
        init.run();
        init.run();
        assert_eq!(init.registered_protocols().len(), 3);
    }

    #[test]
    fn default_server_config() {
        let mut init = BSimInitializer::new();
        init.run();

        let config = init.default_server_config("postgresql");
        assert!(config.is_some());

        let config = init.default_server_config("unknown");
        assert!(config.is_none());
    }

    #[test]
    fn default_trait() {
        let init = BSimInitializer::default();
        assert!(!init.is_initialized());
    }
}
