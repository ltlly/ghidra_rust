//! OSGi bundle manager.
//!
//! Ported from `ghidra.app.plugin.core.osgi` classes.
//!
//! Manages OSGi bundles for Ghidra's plugin framework, providing
//! lifecycle management for bundles (install, start, stop, uninstall).

/// Bundle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BundleState {
    /// Bundle is installed but not resolved.
    Installed,
    /// Bundle is resolved (dependencies met).
    Resolved,
    /// Bundle is starting.
    Starting,
    /// Bundle is active/running.
    Active,
    /// Bundle is stopping.
    Stopping,
    /// Bundle is uninstalled.
    Uninstalled,
}

impl BundleState {
    /// Get the display name.
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::Installed => "Installed",
            Self::Resolved => "Resolved",
            Self::Starting => "Starting",
            Self::Active => "Active",
            Self::Stopping => "Stopping",
            Self::Uninstalled => "Uninstalled",
        }
    }

    /// Whether the bundle is in a running state.
    pub fn is_running(&self) -> bool {
        *self == Self::Active || *self == Self::Starting
    }
}

/// A managed bundle.
#[derive(Debug, Clone)]
pub struct BundleInfo {
    /// Bundle ID.
    pub id: u64,
    /// Bundle symbolic name.
    pub symbolic_name: String,
    /// Bundle version.
    pub version: String,
    /// Bundle state.
    pub state: BundleState,
    /// Bundle location (URL or file path).
    pub location: String,
}

/// Manager for OSGi bundles.
#[derive(Debug)]
pub struct BundleManager {
    /// Managed bundles.
    bundles: Vec<BundleInfo>,
    /// Next bundle ID.
    next_id: u64,
}

impl BundleManager {
    pub fn new() -> Self {
        Self {
            bundles: Vec::new(),
            next_id: 1,
        }
    }

    /// Install a bundle.
    pub fn install(&mut self, name: &str, version: &str, location: &str) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        self.bundles.push(BundleInfo {
            id,
            symbolic_name: name.to_string(),
            version: version.to_string(),
            state: BundleState::Installed,
            location: location.to_string(),
        });
        id
    }

    /// Start a bundle by ID.
    pub fn start(&mut self, id: u64) -> bool {
        if let Some(bundle) = self.bundles.iter_mut().find(|b| b.id == id) {
            if bundle.state == BundleState::Installed || bundle.state == BundleState::Resolved {
                bundle.state = BundleState::Active;
                return true;
            }
        }
        false
    }

    /// Stop a bundle by ID.
    pub fn stop(&mut self, id: u64) -> bool {
        if let Some(bundle) = self.bundles.iter_mut().find(|b| b.id == id) {
            if bundle.state == BundleState::Active {
                bundle.state = BundleState::Installed;
                return true;
            }
        }
        false
    }

    /// Uninstall a bundle by ID.
    pub fn uninstall(&mut self, id: u64) -> bool {
        if let Some(idx) = self.bundles.iter().position(|b| b.id == id) {
            self.bundles.remove(idx);
            return true;
        }
        false
    }

    /// Get all bundles.
    pub fn bundles(&self) -> &[BundleInfo] {
        &self.bundles
    }

    /// Get a bundle by ID.
    pub fn get(&self, id: u64) -> Option<&BundleInfo> {
        self.bundles.iter().find(|b| b.id == id)
    }

    /// Get bundle count.
    pub fn bundle_count(&self) -> usize {
        self.bundles.len()
    }

    /// Get count of active bundles.
    pub fn active_count(&self) -> usize {
        self.bundles.iter().filter(|b| b.state.is_running()).count()
    }
}

impl Default for BundleManager {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_install_bundle() {
        let mut mgr = BundleManager::new();
        let id = mgr.install("com.example.plugin", "1.0.0", "file:///plugin.jar");
        assert_eq!(mgr.bundle_count(), 1);
        let bundle = mgr.get(id).unwrap();
        assert_eq!(bundle.symbolic_name, "com.example.plugin");
        assert_eq!(bundle.state, BundleState::Installed);
    }

    #[test]
    fn test_start_stop() {
        let mut mgr = BundleManager::new();
        let id = mgr.install("test", "1.0", "loc");
        assert!(mgr.start(id));
        assert_eq!(mgr.get(id).unwrap().state, BundleState::Active);
        assert_eq!(mgr.active_count(), 1);
        assert!(mgr.stop(id));
        assert_eq!(mgr.get(id).unwrap().state, BundleState::Installed);
    }

    #[test]
    fn test_uninstall() {
        let mut mgr = BundleManager::new();
        let id = mgr.install("test", "1.0", "loc");
        assert!(mgr.uninstall(id));
        assert_eq!(mgr.bundle_count(), 0);
    }

    #[test]
    fn test_bundle_state() {
        assert!(BundleState::Active.is_running());
        assert!(BundleState::Starting.is_running());
        assert!(!BundleState::Installed.is_running());
        assert_eq!(BundleState::Resolved.display_name(), "Resolved");
    }
}
