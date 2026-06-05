//! AbstractDebuggerPlugin - base types for debugger plugin lifecycle.
//!
//! Ported from Ghidra's `AbstractDebuggerPlugin` and `DebuggerPluginPackage`
//! in `ghidra.app.plugin.core.debug`.

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// The phase of the debugger plugin lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PluginPhase {
    /// Plugin is being initialized.
    Initializing,
    /// Plugin is active and running.
    Active,
    /// Plugin is being disposed/closed.
    Disposing,
    /// Plugin has been disposed.
    Disposed,
}

/// An extension point type identifier for plugins.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ExtensionPointId {
    /// The class name (Java) or type name (Rust) of the extension.
    pub class_name: String,
}

impl ExtensionPointId {
    /// Create a new extension point identifier.
    pub fn new(class_name: impl Into<String>) -> Self {
        Self {
            class_name: class_name.into(),
        }
    }
}

/// Configuration for a debugger plugin package.
///
/// Ported from Ghidra's `DebuggerPluginPackage`. Defines the set
/// of plugins that work together to provide the debugger UI.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DebuggerPluginPackage {
    /// The package name.
    pub name: String,
    /// The set of plugin class names in this package.
    pub plugins: BTreeSet<String>,
    /// The description of the package.
    pub description: String,
    /// The priority (lower = loaded earlier).
    pub priority: u32,
}

impl DebuggerPluginPackage {
    /// Create a new plugin package.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            plugins: BTreeSet::new(),
            description: String::new(),
            priority: 100,
        }
    }

    /// Add a plugin to this package.
    pub fn add_plugin(&mut self, class_name: impl Into<String>) {
        self.plugins.insert(class_name.into());
    }

    /// Set the description.
    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = desc.into();
        self
    }

    /// Set the priority.
    pub fn with_priority(mut self, priority: u32) -> Self {
        self.priority = priority;
        self
    }

    /// Whether this package contains the given plugin.
    pub fn contains(&self, class_name: &str) -> bool {
        self.plugins.contains(class_name)
    }
}

/// Standard debugger plugin packages.
pub mod packages {
    use super::*;

    /// The core debugger plugin package (target management, trace manager).
    pub fn core() -> DebuggerPluginPackage {
        DebuggerPluginPackage::new("Debugger Core")
            .with_description("Core debugger target and trace management")
            .with_priority(10)
    }

    /// The control plugin package (connect, resume, step, etc.).
    pub fn control() -> DebuggerPluginPackage {
        DebuggerPluginPackage::new("Debugger Control")
            .with_description("Execution control: connect, resume, step, suspend, disconnect")
            .with_priority(20)
    }

    /// The breakpoint plugin package.
    pub fn breakpoints() -> DebuggerPluginPackage {
        DebuggerPluginPackage::new("Debugger Breakpoints")
            .with_description("Breakpoint management and display")
            .with_priority(30)
    }

    /// The listing integration plugin package.
    pub fn listing() -> DebuggerPluginPackage {
        DebuggerPluginPackage::new("Debugger Listing")
            .with_description("Listing view integration for traces")
            .with_priority(40)
    }

    /// The memory view plugin package.
    pub fn memory() -> DebuggerPluginPackage {
        DebuggerPluginPackage::new("Debugger Memory")
            .with_description("Memory view and memory bytes panel")
            .with_priority(50)
    }
}

/// Plugin lifecycle events.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PluginLifecycleEvent {
    /// Plugin has been initialized.
    Initialized {
        /// The plugin class name.
        plugin_class: String,
    },
    /// Plugin is being disposed.
    Disposing {
        /// The plugin class name.
        plugin_class: String,
    },
    /// Plugin registered a service.
    ServiceRegistered {
        /// The plugin class name.
        plugin_class: String,
        /// The service interface name.
        service_name: String,
    },
    /// Plugin unregistered a service.
    ServiceUnregistered {
        /// The plugin class name.
        plugin_class: String,
        /// The service interface name.
        service_name: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plugin_phase() {
        assert_ne!(PluginPhase::Initializing, PluginPhase::Active);
        assert_ne!(PluginPhase::Active, PluginPhase::Disposed);
    }

    #[test]
    fn test_extension_point_id() {
        let id = ExtensionPointId::new("com.example.MyInject");
        assert_eq!(id.class_name, "com.example.MyInject");
    }

    #[test]
    fn test_plugin_package() {
        let mut pkg = DebuggerPluginPackage::new("Test")
            .with_description("A test package")
            .with_priority(50);
        pkg.add_plugin("PluginA");
        pkg.add_plugin("PluginB");

        assert!(pkg.contains("PluginA"));
        assert!(pkg.contains("PluginB"));
        assert!(!pkg.contains("PluginC"));
        assert_eq!(pkg.priority, 50);
    }

    #[test]
    fn test_core_packages() {
        let core = packages::core();
        assert_eq!(core.name, "Debugger Core");
        assert_eq!(core.priority, 10);

        let control = packages::control();
        assert_eq!(control.name, "Debugger Control");
        assert_eq!(control.priority, 20);

        let bp = packages::breakpoints();
        assert_eq!(bp.priority, 30);
    }

    #[test]
    fn test_plugin_lifecycle_event() {
        let event = PluginLifecycleEvent::Initialized {
            plugin_class: "TestPlugin".into(),
        };
        assert_eq!(
            event,
            PluginLifecycleEvent::Initialized {
                plugin_class: "TestPlugin".into()
            }
        );
    }

    #[test]
    fn test_plugin_package_serde() {
        let pkg = packages::core();
        let json = serde_json::to_string(&pkg).unwrap();
        let back: DebuggerPluginPackage = serde_json::from_str(&json).unwrap();
        assert_eq!(back.name, "Debugger Core");
    }
}
