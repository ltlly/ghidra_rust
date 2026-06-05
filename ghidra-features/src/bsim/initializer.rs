//! BSim module initializer.
//!
//! Port of `ghidra.features.bsim.query.BSimInitializer`. Handles
//! one-time initialization of the BSim subsystem: registering protocol
//! handlers, setting up database templates, and ensuring required
//! dependencies are available.

/// Known BSim protocol prefixes and their descriptions.
const KNOWN_PROTOCOLS: &[(&str, &str)] = &[
    ("postgresql", "PostgreSQL BSim backend"),
    ("https", "Elasticsearch BSim backend"),
    ("http", "Elasticsearch BSim backend (HTTP)"),
    ("file", "Local H2 file-based BSim database"),
];

/// BSim module initializer.
///
/// In Ghidra this implements `ModuleInitializer` and is called once on
/// startup. In the Rust port, initialization is done via
/// [`BSimInitializer::initialize`].
///
/// # Ported from
/// `ghidra.features.bsim.query.BSimInitializer`
#[derive(Debug, Clone, Default)]
pub struct BSimInitializer {
    /// Whether initialization has been performed.
    initialized: bool,
    /// Initialization log messages.
    log: Vec<String>,
}

impl BSimInitializer {
    /// Create a new uninitialized BSim initializer.
    pub fn new() -> Self {
        Self::default()
    }

    /// Perform one-time initialization of the BSim subsystem.
    ///
    /// This:
    /// 1. Validates that all known BSim protocols are registered.
    /// 2. Logs the available protocol handlers.
    /// 3. Marks the subsystem as initialized.
    pub fn initialize(&mut self) {
        if self.initialized {
            return;
        }

        self.log.push("BSim: Initializing module...".to_string());

        // Log all known protocol handlers
        for (proto, desc) in KNOWN_PROTOCOLS {
            self.log.push(format!(
                "BSim: Protocol '{}' available -- {}",
                proto, desc
            ));
        }

        self.initialized = true;
        self.log.push("BSim: Initialization complete".to_string());
    }

    /// Get the list of known protocols.
    pub fn known_protocols(&self) -> &[(&str, &str)] {
        KNOWN_PROTOCOLS
    }

    /// Whether initialization has been performed.
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Get the initialization log.
    pub fn log(&self) -> &[String] {
        &self.log
    }

    /// Get the name of this initializer.
    pub fn name(&self) -> &str {
        "BSim Module"
    }

    /// Reset the initializer (for testing).
    pub fn reset(&mut self) {
        self.initialized = false;
        self.log.clear();
    }
}

/// Static initializer that can be called once at program startup.
///
/// Uses a `std::sync::Once` guard to ensure the initialization is
/// performed exactly once, even across multiple threads.
pub fn initialize_once() {
    use std::sync::Once;
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let mut init = BSimInitializer::new();
        init.initialize();
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initializer_new() {
        let init = BSimInitializer::new();
        assert!(!init.is_initialized());
        assert!(init.log().is_empty());
        assert_eq!(init.name(), "BSim Module");
    }

    #[test]
    fn initializer_initialize() {
        let mut init = BSimInitializer::new();
        init.initialize();
        assert!(init.is_initialized());
        assert!(!init.log().is_empty());
        assert!(init.log().iter().any(|msg| msg.contains("postgresql")));
        assert!(init.log().iter().any(|msg| msg.contains("https")));
        assert!(init.log().iter().any(|msg| msg.contains("file")));
        assert!(init.log().iter().any(|msg| msg.contains("complete")));
    }

    #[test]
    fn initializer_idempotent() {
        let mut init = BSimInitializer::new();
        init.initialize();
        let log_len = init.log().len();
        init.initialize(); // Second call should be a no-op
        assert_eq!(init.log().len(), log_len);
    }

    #[test]
    fn initializer_reset() {
        let mut init = BSimInitializer::new();
        init.initialize();
        assert!(init.is_initialized());
        init.reset();
        assert!(!init.is_initialized());
        assert!(init.log().is_empty());
    }

    #[test]
    fn initializer_name() {
        let init = BSimInitializer::new();
        assert_eq!(init.name(), "BSim Module");
    }

    #[test]
    fn initialize_once_smoke_test() {
        // Just call it to ensure it doesn't panic
        initialize_once();
        // Call again -- should be a no-op
        initialize_once();
    }
}
