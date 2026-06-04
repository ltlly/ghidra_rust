//! Sample extensions -- example plugins and utilities.
//!
//! This module ports the sample extension from Ghidra's Java source.
//! It provides example plugins demonstrating Ghidra extension patterns,
//! including:
//!
//! - [`HelloWorldPlugin`] -- A minimal Ghidra plugin example.
//! - [`HelloWorldService`] -- A service interface example.
//! - [`EntropyFieldFactory`] -- A custom field factory for displaying
//!   entropy values in the listing.
//! - [`SampleGraph`] -- A sample graph data structure for the graph
//!   visualization framework.

pub mod graph;
pub mod plugins;

/// A minimal Ghidra plugin example.
///
/// Demonstrates the basic plugin pattern: registering actions
/// and providing menu items.
#[derive(Debug)]
pub struct HelloWorldPlugin {
    /// Plugin name.
    pub name: String,
    /// Whether the plugin is enabled.
    enabled: bool,
}

impl HelloWorldPlugin {
    /// Create a new hello world plugin.
    pub fn new() -> Self {
        Self {
            name: "HelloWorld".to_string(),
            enabled: true,
        }
    }

    /// Get the plugin name.
    pub fn plugin_name(&self) -> &str {
        &self.name
    }

    /// Whether the plugin is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// The greeting message.
    pub fn greeting(&self) -> &str {
        "Hello, Ghidra!"
    }
}

impl Default for HelloWorldPlugin {
    fn default() -> Self {
        Self::new()
    }
}

/// A service interface example.
///
/// Demonstrates the Ghidra service pattern: an interface that plugins
/// can provide and other components can consume.
pub trait HelloWorldService: Send + Sync {
    /// Get a greeting.
    fn greet(&self, name: &str) -> String;

    /// Get the service version.
    fn version(&self) -> &str;
}

/// Default implementation of `HelloWorldService`.
#[derive(Debug)]
pub struct DefaultHelloWorldService;

impl HelloWorldService for DefaultHelloWorldService {
    fn greet(&self, name: &str) -> String {
        format!("Hello, {name}!")
    }

    fn version(&self) -> &str {
        "1.0.0"
    }
}

/// A custom field factory for displaying entropy values.
///
/// Ported from `EntropyFieldFactory.java` in the sample extension.
///
/// This factory creates field objects that display the Shannon entropy
/// of byte sequences in the listing view.
#[derive(Debug)]
pub struct EntropyFieldFactory {
    /// The field name.
    pub name: String,
    /// Width of the entropy display in characters.
    pub width: u32,
}

impl EntropyFieldFactory {
    /// Create a new entropy field factory.
    pub fn new() -> Self {
        Self {
            name: "Entropy".to_string(),
            width: 8,
        }
    }

    /// Calculate Shannon entropy of a byte slice.
    ///
    /// Returns a value between 0.0 (all bytes identical) and 8.0
    /// (uniformly distributed).
    pub fn calculate_entropy(data: &[u8]) -> f64 {
        if data.is_empty() {
            return 0.0;
        }

        let mut counts = [0u64; 256];
        for &b in data {
            counts[b as usize] += 1;
        }

        let len = data.len() as f64;
        let mut entropy = 0.0;

        for &count in &counts {
            if count > 0 {
                let p = count as f64 / len;
                entropy -= p * p.log2();
            }
        }

        entropy
    }

    /// Format an entropy value as a display string.
    pub fn format_entropy(entropy: f64) -> String {
        format!("{:.3}", entropy)
    }
}

impl Default for EntropyFieldFactory {
    fn default() -> Self {
        Self::new()
    }
}

/// An entropy field location (address + entropy value).
#[derive(Debug, Clone)]
pub struct EntropyFieldLocation {
    /// The address.
    pub address: u64,
    /// The entropy value at this address.
    pub entropy: f64,
    /// The window size used to compute entropy.
    pub window_size: usize,
}

impl EntropyFieldLocation {
    /// Create a new entropy field location.
    pub fn new(address: u64, entropy: f64, window_size: usize) -> Self {
        Self {
            address,
            entropy,
            window_size,
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hello_world_plugin() {
        let plugin = HelloWorldPlugin::new();
        assert_eq!(plugin.plugin_name(), "HelloWorld");
        assert_eq!(plugin.greeting(), "Hello, Ghidra!");
    }

    #[test]
    fn test_hello_world_service() {
        let service = DefaultHelloWorldService;
        assert_eq!(service.greet("World"), "Hello, World!");
        assert_eq!(service.version(), "1.0.0");
    }

    #[test]
    fn test_entropy_uniform() {
        // All same bytes -> entropy = 0
        let data = vec![0xAA; 100];
        let entropy = EntropyFieldFactory::calculate_entropy(&data);
        assert!(entropy.abs() < 0.001);
    }

    #[test]
    fn test_entropy_mixed() {
        // Mix of 0x00 and 0xFF -> entropy = 1.0
        let mut data = vec![0x00; 50];
        data.extend(vec![0xFF; 50]);
        let entropy = EntropyFieldFactory::calculate_entropy(&data);
        assert!((entropy - 1.0).abs() < 0.001);
    }

    #[test]
    fn test_entropy_empty() {
        let data: Vec<u8> = vec![];
        let entropy = EntropyFieldFactory::calculate_entropy(&data);
        assert!(entropy.abs() < 0.001);
    }

    #[test]
    fn test_entropy_format() {
        assert_eq!(EntropyFieldFactory::format_entropy(3.14159), "3.142");
    }

    #[test]
    fn test_entropy_field_location() {
        let loc = EntropyFieldLocation::new(0x1000, 4.5, 256);
        assert_eq!(loc.address, 0x1000);
        assert_eq!(loc.window_size, 256);
    }
}
