//! DebugInfoProviderRegistry -- registry of provider types for deserialization.
//!
//! Ported from `ghidra.app.util.bin.format.dwarf.external.DebugInfoProviderRegistry`.
//!
//! Maintains a list of [`DebugInfoProvider`] creation functions, each paired
//! with a predicate that tests whether a serialized name string belongs to
//! that provider type.  When deserializing a saved configuration, the
//! registry iterates through its entries and returns the first provider
//! whose predicate matches the name.

use super::build_id_debug_file_provider::BuildIdDebugFileProvider;
use super::debug_info_provider::DebugInfoProvider;
use super::disabled_debug_info_provider::DisabledDebugInfoProvider;
use super::http_debuginfo_d_provider::HttpDebugInfoDProvider;
use super::local_dir_debug_info_d_provider::LocalDirDebugInfoDProvider;
use super::local_dir_debug_link_provider::LocalDirDebugLinkProvider;
use super::same_dir_debug_info_provider::SameDirDebugInfoProvider;

// ---------------------------------------------------------------------------
// DebugInfoProviderCreatorContext
// ---------------------------------------------------------------------------

/// Contextual information needed to create a new [`DebugInfoProvider`].
///
/// In the Java version this also holds a reference to the `Program`; here
/// we carry an optional program directory path for providers that need it
/// (e.g. [`SameDirDebugInfoProvider`]).
#[derive(Debug, Clone, Default)]
pub struct DebugInfoProviderCreatorContext {
    /// The directory of the program being analysed, if known.
    program_dir: Option<std::path::PathBuf>,
}

impl DebugInfoProviderCreatorContext {
    /// Creates a new context with no program directory.
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a new context with the given program directory.
    pub fn with_program_dir(program_dir: std::path::PathBuf) -> Self {
        Self {
            program_dir: Some(program_dir),
        }
    }

    /// Returns the program directory, if set.
    pub fn program_dir(&self) -> Option<&std::path::Path> {
        self.program_dir.as_deref()
    }
}

// ---------------------------------------------------------------------------
// Provider creation function types
// ---------------------------------------------------------------------------

/// A function that tests whether a serialized name string belongs to a
/// particular provider type.
type MatcherFn = Box<dyn Fn(&str) -> bool + Send + Sync>;

/// A function that creates a new [`DebugInfoProvider`] from a serialized
/// name string and context.
type CreatorFn =
    Box<dyn Fn(&str, &DebugInfoProviderCreatorContext) -> Option<Box<dyn DebugInfoProvider>> + Send + Sync>;

/// A registered entry pairing a matcher with a creator.
struct RegistryEntry {
    matcher: MatcherFn,
    creator: CreatorFn,
}

// ---------------------------------------------------------------------------
// DebugInfoProviderRegistry
// ---------------------------------------------------------------------------

/// A registry of [`DebugInfoProvider`] types that can be saved / restored
/// from a configuration string.
///
/// Each entry consists of a predicate that tests a serialized name string
/// and a creator function that instantiates the matching provider.
///
/// A global singleton is available via [`DebugInfoProviderRegistry::global`].
///
/// # Examples
///
/// ```rust
/// use ghidra_features::external::dwarf_ext::{
///     DebugInfoProviderRegistry, DebugInfoProviderCreatorContext,
///     DebugInfoProvider,
/// };
///
/// let registry = DebugInfoProviderRegistry::global();
/// let ctx = DebugInfoProviderCreatorContext::new();
///
/// let provider = registry.create(".", &ctx);
/// assert!(provider.is_some());
/// assert_eq!(provider.unwrap().name(), ".");
/// ```
pub struct DebugInfoProviderRegistry {
    entries: Vec<RegistryEntry>,
}

impl std::fmt::Debug for DebugInfoProviderRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DebugInfoProviderRegistry")
            .field("entries_count", &self.entries.len())
            .finish()
    }
}

impl DebugInfoProviderRegistry {
    /// Creates a new empty registry.
    pub fn new() -> Self {
        Self { entries: Vec::new() }
    }

    /// Creates a new registry pre-populated with all built-in provider
    /// types.
    pub fn with_defaults() -> Self {
        let mut registry = Self::new();
        registry.register_defaults();
        registry
    }

    /// Returns a reference to the global singleton registry.
    pub fn global() -> &'static DebugInfoProviderRegistry {
        lazy_static::lazy_static! {
            static ref INSTANCE: DebugInfoProviderRegistry =
                DebugInfoProviderRegistry::with_defaults();
        }
        &INSTANCE
    }

    /// Registers the built-in provider types.
    fn register_defaults(&mut self) {
        // DisabledDebugInfoProvider
        self.register(
            |name| DisabledDebugInfoProvider::matches(name),
            |name, _ctx| {
                // Disabled providers store the original name after the prefix.
                // We create a placeholder that represents the disabled state.
                Some(Box::new(DisabledDebugInfoProvider::new(Box::new(
                    PlaceholderProvider::new(
                        name.to_string(),
                        "Disabled".to_string(),
                    ),
                ))))
            },
        );

        // LocalDirDebugLinkProvider
        self.register(
            |name| LocalDirDebugLinkProvider::matches(name),
            |name, _ctx| {
                let inner = &name[super::local_dir_debug_link_provider::DEBUGLINK_NAME_PREFIX.len()..];
                Some(Box::new(LocalDirDebugLinkProvider::new(
                    std::path::PathBuf::from(inner),
                )))
            },
        );

        // SameDirDebugInfoProvider
        self.register(
            |name| SameDirDebugInfoProvider::matches(name),
            |_name, ctx| {
                Some(Box::new(SameDirDebugInfoProvider::new(
                    ctx.program_dir().map(std::path::PathBuf::from),
                )))
            },
        );

        // BuildIdDebugFileProvider
        self.register(
            |name| BuildIdDebugFileProvider::matches(name),
            |name, _ctx| {
                let inner = &name[super::build_id_debug_file_provider::BUILDID_NAME_PREFIX.len()..];
                Some(Box::new(BuildIdDebugFileProvider::new(
                    std::path::PathBuf::from(inner),
                )))
            },
        );

        // LocalDirDebugInfoDProvider
        self.register(
            |name| LocalDirDebugInfoDProvider::matches(name),
            |name, _ctx| {
                LocalDirDebugInfoDProvider::from_name(name).map(|p| {
                    Box::new(p) as Box<dyn DebugInfoProvider>
                })
            },
        );

        // HttpDebugInfoDProvider
        self.register(
            |name| HttpDebugInfoDProvider::matches(name),
            |name, _ctx| {
                HttpDebugInfoDProvider::from_name(name).map(|p| {
                    Box::new(p) as Box<dyn DebugInfoProvider>
                })
            },
        );
    }

    /// Adds a provider type to the registry.
    ///
    /// # Arguments
    ///
    /// * `matcher` -- tests whether a serialized name belongs to this type.
    /// * `creator` -- creates a new provider instance from the name.
    pub fn register<M, C>(&mut self, matcher: M, creator: C)
    where
        M: Fn(&str) -> bool + Send + Sync + 'static,
        C: Fn(&str, &DebugInfoProviderCreatorContext) -> Option<Box<dyn DebugInfoProvider>>
            + Send
            + Sync
            + 'static,
    {
        self.entries.push(RegistryEntry {
            matcher: Box::new(matcher),
            creator: Box::new(creator),
        });
    }

    /// Creates a [`DebugInfoProvider`] using the specified serialized name
    /// string.
    ///
    /// Returns `None` if no registered provider matches the name.
    pub fn create(
        &self,
        name: &str,
        context: &DebugInfoProviderCreatorContext,
    ) -> Option<Box<dyn DebugInfoProvider>> {
        for entry in &self.entries {
            if (entry.matcher)(name) {
                return (entry.creator)(name, context);
            }
        }
        None
    }

    /// Returns the number of registered provider types.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` if no provider types are registered.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl Default for DebugInfoProviderRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// PlaceholderProvider (used to wrap disabled provider delegates)
// ---------------------------------------------------------------------------

/// A minimal [`DebugInfoProvider`] used as a delegate placeholder inside
/// [`DisabledDebugInfoProvider`].
#[derive(Debug)]
struct PlaceholderProvider {
    name: String,
    descriptive_name: String,
}

impl PlaceholderProvider {
    fn new(name: String, descriptive_name: String) -> Self {
        Self {
            name,
            descriptive_name,
        }
    }
}

impl super::debug_info_provider::DebugInfoProvider for PlaceholderProvider {
    fn name(&self) -> &str {
        &self.name
    }

    fn descriptive_name(&self) -> &str {
        &self.descriptive_name
    }

    fn status(&self) -> super::debug_info_provider_status::DebugInfoProviderStatus {
        super::debug_info_provider_status::DebugInfoProviderStatus::Unknown
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registry_create_same_dir() {
        let registry = DebugInfoProviderRegistry::with_defaults();
        let ctx = DebugInfoProviderCreatorContext::new();
        let provider = registry.create(".", &ctx);
        assert!(provider.is_some());
        assert_eq!(provider.unwrap().name(), ".");
    }

    #[test]
    fn test_registry_create_debuglink() {
        let registry = DebugInfoProviderRegistry::with_defaults();
        let ctx = DebugInfoProviderCreatorContext::new();
        let provider = registry.create("debuglink:///usr/lib/debug", &ctx);
        assert!(provider.is_some());
        assert!(provider.unwrap().name().starts_with("debuglink://"));
    }

    #[test]
    fn test_registry_create_buildid() {
        let registry = DebugInfoProviderRegistry::with_defaults();
        let ctx = DebugInfoProviderCreatorContext::new();
        let provider = registry.create("build-id:///usr/lib/debug/.build-id", &ctx);
        assert!(provider.is_some());
        assert!(provider.unwrap().name().starts_with("build-id://"));
    }

    #[test]
    fn test_registry_create_debuginfod_dir() {
        let registry = DebugInfoProviderRegistry::with_defaults();
        let ctx = DebugInfoProviderCreatorContext::new();
        let provider = registry.create("debuginfod-dir:///tmp/cache", &ctx);
        assert!(provider.is_some());
        assert!(provider.unwrap().name().starts_with("debuginfod-dir://"));
    }

    #[test]
    fn test_registry_create_debuginfod_dir_default() {
        let registry = DebugInfoProviderRegistry::with_defaults();
        let ctx = DebugInfoProviderCreatorContext::new();
        let provider = registry.create("debuginfod-dir://$DEFAULT", &ctx);
        assert!(provider.is_some());
        assert_eq!(provider.unwrap().name(), "debuginfod-dir://$DEFAULT");
    }

    #[test]
    fn test_registry_create_disabled() {
        let registry = DebugInfoProviderRegistry::with_defaults();
        let ctx = DebugInfoProviderCreatorContext::new();
        let provider = registry.create("disabled://debuglink:///usr/lib/debug", &ctx);
        assert!(provider.is_some());
    }

    #[test]
    fn test_registry_create_http() {
        let registry = DebugInfoProviderRegistry::with_defaults();
        let ctx = DebugInfoProviderCreatorContext::new();
        let provider = registry.create("https://debuginfod.example.com/", &ctx);
        assert!(provider.is_some());
        assert!(provider.unwrap().name().starts_with("https://"));
    }

    #[test]
    fn test_registry_create_unknown() {
        let registry = DebugInfoProviderRegistry::with_defaults();
        let ctx = DebugInfoProviderCreatorContext::new();
        let provider = registry.create("unknown-scheme://something", &ctx);
        assert!(provider.is_none());
    }

    #[test]
    fn test_registry_len() {
        let registry = DebugInfoProviderRegistry::with_defaults();
        assert_eq!(registry.len(), 6); // 6 built-in provider types
        assert!(!registry.is_empty());
    }

    #[test]
    fn test_registry_empty() {
        let registry = DebugInfoProviderRegistry::new();
        assert!(registry.is_empty());
        assert_eq!(registry.len(), 0);
    }

    #[test]
    fn test_registry_custom_provider() {
        let mut registry = DebugInfoProviderRegistry::new();
        registry.register(
            |name| name.starts_with("custom://"),
            |name, _ctx| {
                Some(Box::new(PlaceholderProvider::new(
                    name.to_string(),
                    "Custom Provider".to_string(),
                )))
            },
        );

        let ctx = DebugInfoProviderCreatorContext::new();
        let provider = registry.create("custom://test", &ctx);
        assert!(provider.is_some());
        assert_eq!(provider.unwrap().name(), "custom://test");

        let provider = registry.create("other://test", &ctx);
        assert!(provider.is_none());
    }

    #[test]
    fn test_global_registry() {
        let registry = DebugInfoProviderRegistry::global();
        assert!(!registry.is_empty());
    }

    #[test]
    fn test_creator_context_with_dir() {
        let ctx = DebugInfoProviderCreatorContext::with_program_dir(
            std::path::PathBuf::from("/usr/bin"),
        );
        assert_eq!(ctx.program_dir(), Some(std::path::Path::new("/usr/bin")));
    }

    #[test]
    fn test_creator_context_default() {
        let ctx = DebugInfoProviderCreatorContext::new();
        assert!(ctx.program_dir().is_none());
    }
}
