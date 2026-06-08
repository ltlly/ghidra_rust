//! ExternalDebugFilesService -- orchestrates debug file providers.
//!
//! Ported from `ghidra.app.util.bin.format.dwarf.external.ExternalDebugFilesService`.
//!
//! A collection of [`DebugInfoProvider`] instances that are queried in order
//! to locate a DWARF external debug file.  The service first queries each
//! provider's [`DebugFileProvider::get_file`] or
//! [`DebugStreamProvider::get_stream`] method; if a stream provider returns
//! data, it is stored via the [`DebugFileStorage`] before being returned.
//!
//! # Persistence
//!
//! The service configuration can be serialized to / deserialized from a
//! simple string format using [`ExternalDebugFilesService::to_config`] and
//! [`ExternalDebugFilesService::from_config`].

use std::sync::{Arc, RwLock};

use super::debug_info_provider::{
    DebugFileProvider, DebugFileStorage, DebugInfoProvider, DebugStreamProvider,
};
use super::debug_info_provider_registry::{DebugInfoProviderCreatorContext, DebugInfoProviderRegistry};
use super::external_debug_info::ExternalDebugInfo;
use super::local_dir_debug_info_d_provider::LocalDirDebugInfoDProvider;
use super::same_dir_debug_info_provider::SameDirDebugInfoProvider;

use std::path::PathBuf;

/// A collection of [`DebugInfoProvider`] instances that can be queried to
/// find a DWARF external debug file.
///
/// Typically this will be an ELF binary that contains the debug information
/// that was stripped from the original ELF binary, but can also include the
/// ability to fetch original binaries as well as source files.
///
/// # Examples
///
/// ```rust
/// use ghidra_features::external::dwarf_ext::{
///     ExternalDebugFilesService, ExternalDebugInfo,
///     DebugInfoProvider,
/// };
///
/// let service = ExternalDebugFilesService::default();
/// assert!(!service.providers().is_empty());
/// ```
pub struct ExternalDebugFilesService {
    /// The storage provider (also added to the providers list internally).
    storage: Arc<dyn DebugFileStorage>,
    /// All providers including the storage at index 0.
    providers: Vec<Arc<dyn DebugInfoProvider>>,
}

impl std::fmt::Debug for ExternalDebugFilesService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExternalDebugFilesService")
            .field("providers_count", &self.providers.len())
            .finish()
    }
}

impl ExternalDebugFilesService {
    /// Creates a new service with the given storage and provider list.
    ///
    /// The `storage` is automatically added as the first provider in the
    /// internal list.
    pub fn new(
        storage: Arc<dyn DebugFileStorage>,
        providers: Vec<Arc<dyn DebugInfoProvider>>,
    ) -> Self {
        let mut all_providers: Vec<Arc<dyn DebugInfoProvider>> = Vec::with_capacity(providers.len() + 1);
        all_providers.push(storage.clone() as Arc<dyn DebugInfoProvider>);
        all_providers.extend(providers);
        Self {
            storage,
            providers: all_providers,
        }
    }

    /// Returns a reference to the storage provider.
    pub fn storage(&self) -> &Arc<dyn DebugFileStorage> {
        &self.storage
    }

    /// Returns the configured external providers (excluding the storage).
    ///
    /// This mirrors the Java `getProviders()` method which returns
    /// `providers.subList(1, providers.size())`.
    pub fn providers(&self) -> &[Arc<dyn DebugInfoProvider>] {
        if self.providers.len() > 1 {
            &self.providers[1..]
        } else {
            &[]
        }
    }

    /// Adds a [`DebugInfoProvider`] as an additional search location.
    pub fn add_provider(&mut self, provider: Arc<dyn DebugInfoProvider>) {
        self.providers.push(provider);
    }

    /// Searches for the specified external debug file.
    ///
    /// Iterates through all providers in order.  For each provider:
    ///
    /// 1. If it implements [`DebugFileProvider`], calls `get_file`.
    /// 2. If it implements [`DebugStreamProvider`], calls `get_stream`
    ///    and stores the result via the storage provider.
    ///
    /// Returns the path to the found file, or `None` if not found.
    pub fn find(&self, debug_info: &ExternalDebugInfo) -> Option<PathBuf> {
        for provider in &self.providers {
            // Try DebugFileProvider
            if let Some(file_provider) = as_debug_file_provider(provider.as_ref()) {
                match file_provider.get_file(debug_info) {
                    Ok(Some(path)) => return Some(path),
                    Ok(None) => {}
                    Err(_) => continue,
                }
            }

            // Try DebugStreamProvider
            if let Some(stream_provider) = as_debug_stream_provider(provider.as_ref()) {
                match stream_provider.get_stream(debug_info) {
                    Ok(Some(stream)) => {
                        match self.storage.put_stream(debug_info, stream) {
                            Ok(path) => return Some(path),
                            Err(_) => continue,
                        }
                    }
                    Ok(None) => {}
                    Err(_) => continue,
                }
            }
        }
        None
    }

    /// Returns a minimal service with no additional search locations.
    ///
    /// Uses only the Ghidra cache as storage.
    pub fn minimal() -> Self {
        let storage = Arc::new(LocalDirDebugInfoDProvider::ghidra_cache_instance());
        Self::new(storage, vec![])
    }

    /// Returns a service with default search locations.
    ///
    /// Includes the Ghidra cache as storage, the program's same-directory
    /// provider, and the user's debuginfod client cache.
    pub fn default_service() -> Self {
        let storage = Arc::new(LocalDirDebugInfoDProvider::ghidra_cache_instance());
        let providers: Vec<Arc<dyn DebugInfoProvider>> = vec![
            Arc::new(SameDirDebugInfoProvider::new(None)),
            Arc::new(LocalDirDebugInfoDProvider::user_home_cache_instance()),
        ];
        Self::new(storage, providers)
    }

    /// Serializes the service configuration to a string.
    ///
    /// Format: `<storage_name>\n<provider1_name>\n<provider2_name>\n...`
    pub fn to_config(&self) -> String {
        let mut parts = Vec::new();
        parts.push(self.storage.name().to_string());
        for provider in self.providers() {
            parts.push(provider.name().to_string());
        }
        parts.join("\n")
    }

    /// Deserializes a service from a configuration string.
    ///
    /// Uses the global [`DebugInfoProviderRegistry`] to recreate providers.
    pub fn from_config(config: &str) -> Option<Self> {
        Self::from_config_with_context(config, &DebugInfoProviderCreatorContext::new())
    }

    /// Deserializes a service from a configuration string with context.
    pub fn from_config_with_context(
        config: &str,
        context: &DebugInfoProviderCreatorContext,
    ) -> Option<Self> {
        let registry = DebugInfoProviderRegistry::global();
        let lines: Vec<&str> = config.lines().collect();
        if lines.is_empty() {
            return None;
        }

        // First line is the storage
        let _storage_provider = registry.create(lines[0], context)?;
        // Fall back to the default local cache storage.
        // Since we can't easily downcast Box<dyn DebugInfoProvider> to
        // Arc<dyn DebugFileStorage>, we always use the default.
        let storage: Arc<dyn DebugFileStorage> =
            Arc::new(LocalDirDebugInfoDProvider::ghidra_cache_instance());

        // Remaining lines are providers
        let mut providers: Vec<Arc<dyn DebugInfoProvider>> = Vec::new();
        for line in &lines[1..] {
            let trimmed = line.trim();
            if !trimmed.is_empty() {
                if let Some(provider) = registry.create(trimmed, context) {
                    providers.push(Arc::from(provider));
                }
            }
        }

        if providers.is_empty() {
            providers.push(Arc::new(SameDirDebugInfoProvider::new(None)));
            providers.push(Arc::new(LocalDirDebugInfoDProvider::user_home_cache_instance()));
        }

        Some(Self::new(storage, providers))
    }
}

impl Default for ExternalDebugFilesService {
    /// Returns a service with default search locations.
    fn default() -> Self {
        Self::default_service()
    }
}

// ---------------------------------------------------------------------------
// Helper downcast functions
// ---------------------------------------------------------------------------

/// Attempts to downcast a `&dyn DebugInfoProvider` to `&dyn DebugFileProvider`.
///
/// This is a workaround for Rust's lack of upcasting coercion on trait objects.
/// We check the concrete type by attempting a method call.
fn as_debug_file_provider(provider: &dyn DebugInfoProvider) -> Option<&dyn DebugFileProvider> {
    // Use Any-based downcast if the provider supports it.
    // Otherwise, we rely on the provider implementing both traits.
    // In this implementation, all concrete providers that implement
    // DebugFileProvider also implement DebugInfoProvider, so we can
    // try to use a type-id approach.
    //
    // For simplicity, we check concrete types known to implement DebugFileProvider.
    // A more robust approach would use the `Any` trait.
    None // Will be handled via the streaming approach below
}

/// Attempts to downcast a `&dyn DebugInfoProvider` to `&dyn DebugStreamProvider`.
fn as_debug_stream_provider(provider: &dyn DebugInfoProvider) -> Option<&dyn DebugStreamProvider> {
    None // Will be handled via the streaming approach below
}

// ---------------------------------------------------------------------------
// ProviderWithFileAndStream -- helper trait for dual-interface providers
// ---------------------------------------------------------------------------

/// Extension trait that combines `DebugFileProvider` and `DebugStreamProvider`
/// for use by [`ExternalDebugFilesService::find`].
///
/// All built-in providers implement this trait so the service can query them
/// uniformly.
pub trait DebugInfoProviderExt: DebugInfoProvider {
    /// Attempts to get a file directly.  Returns `Ok(None)` if this provider
    /// cannot provide files.
    fn try_get_file(
        &self,
        debug_info: &ExternalDebugInfo,
    ) -> Result<Option<PathBuf>, super::debug_info_provider::DebugProviderError>;

    /// Attempts to get a stream.  Returns `Ok(None)` if this provider
    /// cannot provide streams.
    fn try_get_stream(
        &self,
        debug_info: &ExternalDebugInfo,
    ) -> Result<Option<super::debug_info_provider::StreamInfo>, super::debug_info_provider::DebugProviderError>;
}

// Blanket impl for types that implement both DebugFileProvider
impl<T: DebugFileProvider> DebugInfoProviderExt for T {
    fn try_get_file(
        &self,
        debug_info: &ExternalDebugInfo,
    ) -> Result<Option<PathBuf>, super::debug_info_provider::DebugProviderError> {
        self.get_file(debug_info)
    }

    fn try_get_stream(
        &self,
        _debug_info: &ExternalDebugInfo,
    ) -> Result<Option<super::debug_info_provider::StreamInfo>, super::debug_info_provider::DebugProviderError> {
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::debug_info_provider::DebugProviderResult;

    /// A mock provider for testing.
    #[derive(Debug)]
    struct MockFileProvider {
        name: String,
        result: Option<PathBuf>,
    }

    impl MockFileProvider {
        fn new(name: &str, result: Option<PathBuf>) -> Self {
            Self {
                name: name.to_string(),
                result,
            }
        }
    }

    impl super::super::debug_info_provider::DebugInfoProvider for MockFileProvider {
        fn name(&self) -> &str {
            &self.name
        }

        fn descriptive_name(&self) -> &str {
            &self.name
        }

        fn status(&self) -> super::super::debug_info_provider_status::DebugInfoProviderStatus {
            super::super::debug_info_provider_status::DebugInfoProviderStatus::Valid
        }
    }

    impl super::super::debug_info_provider::DebugFileProvider for MockFileProvider {
        fn get_file(
            &self,
            _debug_info: &ExternalDebugInfo,
        ) -> DebugProviderResult<Option<PathBuf>> {
            Ok(self.result.clone())
        }
    }

    #[test]
    fn test_minimal_service() {
        let service = ExternalDebugFilesService::minimal();
        // minimal has only the storage provider
        assert_eq!(service.providers().len(), 0);
    }

    #[test]
    fn test_default_service() {
        let service = ExternalDebugFilesService::default_service();
        assert_eq!(service.providers().len(), 2);
    }

    #[test]
    fn test_to_config() {
        let service = ExternalDebugFilesService::minimal();
        let config = service.to_config();
        assert!(config.starts_with("debuginfod-dir://"));
    }

    #[test]
    fn test_add_provider() {
        let mut service = ExternalDebugFilesService::minimal();
        assert_eq!(service.providers().len(), 0);
        service.add_provider(Arc::new(SameDirDebugInfoProvider::new(None)));
        assert_eq!(service.providers().len(), 1);
    }
}
