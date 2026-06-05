//! BSim plugin package registration.
//!
//! Ports Ghidra's `ghidra.features.bsim.query.BsimPluginPackage`.
//! Defines the plugin package metadata for the BSim feature plugin.

/// Metadata for the BSim plugin package.
///
/// Ports Ghidra's `BsimPluginPackage`. In the Java version, this is registered
/// with the Ghidra plugin framework. In Rust, it serves as a module descriptor
/// with metadata about the BSim feature.
#[derive(Debug, Clone)]
pub struct BSimPluginPackage {
    /// Package name.
    pub name: String,
    /// Package description.
    pub description: String,
    /// Package version.
    pub version: String,
    /// Author or organization.
    pub author: String,
    /// Supported protocol names.
    pub supported_protocols: Vec<String>,
}

impl BSimPluginPackage {
    /// Create the default BSim plugin package.
    pub fn ghidra_bsim() -> Self {
        Self {
            name: "GhidraBSim".to_string(),
            description: "Binary Similarity analysis for Ghidra".to_string(),
            version: "1.0.0".to_string(),
            author: "Ghidra/NSA".to_string(),
            supported_protocols: vec![
                "postgresql".to_string(),
                "elastic".to_string(),
                "bsimfile".to_string(),
            ],
        }
    }

    /// Check if this package supports a given protocol.
    pub fn supports_protocol(&self, protocol: &str) -> bool {
        self.supported_protocols.iter().any(|p| p == protocol)
    }

    /// Get the package name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get the package description.
    pub fn description(&self) -> &str {
        &self.description
    }

    /// Get the package version.
    pub fn version(&self) -> &str {
        &self.version
    }
}

impl Default for BSimPluginPackage {
    fn default() -> Self {
        Self::ghidra_bsim()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_package() {
        let pkg = BSimPluginPackage::default();
        assert_eq!(pkg.name(), "GhidraBSim");
        assert!(pkg.description().contains("Binary Similarity"));
        assert_eq!(pkg.version(), "1.0.0");
    }

    #[test]
    fn supports_protocols() {
        let pkg = BSimPluginPackage::ghidra_bsim();
        assert!(pkg.supports_protocol("postgresql"));
        assert!(pkg.supports_protocol("elastic"));
        assert!(pkg.supports_protocol("bsimfile"));
        assert!(!pkg.supports_protocol("ftp"));
    }

    #[test]
    fn clone_works() {
        let pkg = BSimPluginPackage::ghidra_bsim();
        let cloned = pkg.clone();
        assert_eq!(pkg.name, cloned.name);
        assert_eq!(pkg.supported_protocols.len(), cloned.supported_protocols.len());
    }
}
