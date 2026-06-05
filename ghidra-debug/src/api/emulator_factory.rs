//! EmulatorFactory - factory for creating trace emulators.
//!
//! Ported from Ghidra's `ghidra.debug.api.EmulatorFactory`.

/// A factory that creates emulators for a particular language/processor.
///
/// Ported from Ghidra's `EmulatorFactory`. Each factory is registered
/// for a specific language ID and produces emulators compatible with that language.
pub trait EmulatorFactory: std::fmt::Debug + Send + Sync {
    /// Get the language ID this factory supports.
    fn language_id(&self) -> &str;

    /// Get the display name for this emulator type.
    fn display_name(&self) -> &str;

    /// Get the compiler spec ID this factory uses.
    fn compiler_spec_id(&self) -> &str;

    /// Whether this emulator supports hardware breakpoints.
    fn supports_hardware_breakpoints(&self) -> bool {
        false
    }

    /// Whether this emulator supports software breakpoints.
    fn supports_software_breakpoints(&self) -> bool {
        true
    }

    /// Whether this emulator supports step-over.
    fn supports_step_over(&self) -> bool {
        true
    }

    /// Whether this emulator supports step-into.
    fn supports_step_into(&self) -> bool {
        true
    }

    /// Whether this emulator supports step-out.
    fn supports_step_out(&self) -> bool {
        true
    }

    /// Maximum number of steps before auto-stopping.
    fn max_steps(&self) -> u64 {
        10000
    }
}

/// A registry of emulator factories.
#[derive(Debug, Default)]
pub struct EmulatorFactoryRegistry {
    factories: Vec<Box<dyn EmulatorFactory>>,
}

impl EmulatorFactoryRegistry {
    /// Create a new empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register an emulator factory.
    pub fn register(&mut self, factory: Box<dyn EmulatorFactory>) {
        self.factories.push(factory);
    }

    /// Find a factory by language ID.
    pub fn find_by_language(&self, language_id: &str) -> Option<&dyn EmulatorFactory> {
        self.factories
            .iter()
            .find(|f| f.language_id() == language_id)
            .map(|f| f.as_ref())
    }

    /// Get all registered factories.
    pub fn all(&self) -> Vec<&dyn EmulatorFactory> {
        self.factories.iter().map(|f| f.as_ref()).collect()
    }

    /// Get the number of registered factories.
    pub fn len(&self) -> usize {
        self.factories.len()
    }

    /// Whether the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.factories.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug)]
    struct TestEmulatorFactory {
        lang_id: String,
    }

    impl EmulatorFactory for TestEmulatorFactory {
        fn language_id(&self) -> &str {
            &self.lang_id
        }
        fn display_name(&self) -> &str {
            "Test Emulator"
        }
        fn compiler_spec_id(&self) -> &str {
            "default"
        }
    }

    #[test]
    fn test_registry_register() {
        let mut reg = EmulatorFactoryRegistry::new();
        reg.register(Box::new(TestEmulatorFactory {
            lang_id: "x86:LE:64:default".into(),
        }));
        assert_eq!(reg.len(), 1);
        assert!(!reg.is_empty());
    }

    #[test]
    fn test_registry_find() {
        let mut reg = EmulatorFactoryRegistry::new();
        reg.register(Box::new(TestEmulatorFactory {
            lang_id: "ARM:LE:32:v8".into(),
        }));
        assert!(reg.find_by_language("ARM:LE:32:v8").is_some());
        assert!(reg.find_by_language("x86:LE:64:default").is_none());
    }

    #[test]
    fn test_factory_defaults() {
        let f = TestEmulatorFactory {
            lang_id: "test".into(),
        };
        assert!(!f.supports_hardware_breakpoints());
        assert!(f.supports_software_breakpoints());
        assert!(f.supports_step_over());
        assert_eq!(f.max_steps(), 10000);
    }

    #[test]
    fn test_empty_registry() {
        let reg = EmulatorFactoryRegistry::new();
        assert!(reg.is_empty());
        assert!(reg.all().is_empty());
    }
}
