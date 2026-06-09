//! Demangler options -- ported from `DemanglerOptions.java`.
//!
//! Provides a unified options struct that governs the behavior of all
//! demangler implementations (Microsoft, GNU, etc.).

/// Options that control demangler behavior.
///
/// Corresponds to Java's `DemanglerOptions`. This is the base options
/// struct shared across all demangler implementations. Each demangler
/// may define its own extended options (e.g. `MicrosoftDemanglerOptions`,
/// `GnuDemanglerOptions`) but should be convertible to/from this base.
#[derive(Debug, Clone)]
pub struct DemanglerOptions {
    /// Whether to apply the recovered function signature to the program.
    apply_signature: bool,
    /// Whether to apply the recovered calling convention.
    apply_calling_convention: bool,
    /// Whether to demangle only symbols matching known patterns.
    demangle_only_known_patterns: bool,
    /// Whether to use encoded anonymous namespace names.
    use_encoded_anonymous_namespace: bool,
    /// Whether to apply UDT (user-defined type) argument type tags.
    apply_udt_argument_type_tag: bool,
    /// Architecture pointer size in bits (32 or 64).
    architecture_size: u32,
    /// Whether to prefer demangled namespace labels.
    prefer_demangled_namespace: bool,
    /// Maximum number of symbols to demangle in a single pass (0 = unlimited).
    max_symbols: u32,
    /// Whether to apply datatypes recovered from demangling.
    apply_datatypes: bool,
    /// Whether to ignore the `extern "C"` linkage when demangling.
    ignore_extern_c: bool,
}

impl DemanglerOptions {
    /// Create new options with project-level defaults.
    pub fn new() -> Self {
        Self {
            apply_signature: true,
            apply_calling_convention: true,
            demangle_only_known_patterns: false,
            use_encoded_anonymous_namespace: false,
            apply_udt_argument_type_tag: true,
            architecture_size: 64,
            prefer_demangled_namespace: true,
            max_symbols: 0,
            apply_datatypes: true,
            ignore_extern_c: false,
        }
    }

    // -- apply_signature ---------------------------------------------------

    /// Whether to apply the recovered function signature.
    pub fn apply_signature(&self) -> bool {
        self.apply_signature
    }

    /// Set whether to apply the recovered function signature.
    pub fn set_apply_signature(&mut self, value: bool) {
        self.apply_signature = value;
    }

    // -- apply_calling_convention ------------------------------------------

    /// Whether to apply the recovered calling convention.
    pub fn apply_calling_convention(&self) -> bool {
        self.apply_calling_convention
    }

    /// Set whether to apply the recovered calling convention.
    pub fn set_apply_calling_convention(&mut self, value: bool) {
        self.apply_calling_convention = value;
    }

    // -- demangle_only_known_patterns --------------------------------------

    /// Whether to demangle only known patterns.
    pub fn demangle_only_known_patterns(&self) -> bool {
        self.demangle_only_known_patterns
    }

    /// Set whether to demangle only known patterns.
    pub fn set_demangle_only_known_patterns(&mut self, value: bool) {
        self.demangle_only_known_patterns = value;
    }

    // -- use_encoded_anonymous_namespace -----------------------------------

    /// Whether to use encoded anonymous namespace names.
    pub fn use_encoded_anonymous_namespace(&self) -> bool {
        self.use_encoded_anonymous_namespace
    }

    /// Set whether to use encoded anonymous namespace names.
    pub fn set_use_encoded_anonymous_namespace(&mut self, value: bool) {
        self.use_encoded_anonymous_namespace = value;
    }

    // -- apply_udt_argument_type_tag ---------------------------------------

    /// Whether to apply UDT argument type tags.
    pub fn apply_udt_argument_type_tag(&self) -> bool {
        self.apply_udt_argument_type_tag
    }

    /// Set whether to apply UDT argument type tags.
    pub fn set_apply_udt_argument_type_tag(&mut self, value: bool) {
        self.apply_udt_argument_type_tag = value;
    }

    // -- architecture_size -------------------------------------------------

    /// Get the architecture pointer size in bits.
    pub fn architecture_size(&self) -> u32 {
        self.architecture_size
    }

    /// Set the architecture pointer size in bits.
    pub fn set_architecture_size(&mut self, bits: u32) {
        self.architecture_size = bits;
    }

    // -- prefer_demangled_namespace ----------------------------------------

    /// Whether to prefer demangled namespace labels.
    pub fn prefer_demangled_namespace(&self) -> bool {
        self.prefer_demangled_namespace
    }

    /// Set whether to prefer demangled namespace labels.
    pub fn set_prefer_demangled_namespace(&mut self, value: bool) {
        self.prefer_demangled_namespace = value;
    }

    // -- max_symbols -------------------------------------------------------

    /// Get the maximum number of symbols to demangle (0 = unlimited).
    pub fn max_symbols(&self) -> u32 {
        self.max_symbols
    }

    /// Set the maximum number of symbols to demangle (0 = unlimited).
    pub fn set_max_symbols(&mut self, max: u32) {
        self.max_symbols = max;
    }

    // -- apply_datatypes ---------------------------------------------------

    /// Whether to apply recovered datatypes to the program.
    pub fn apply_datatypes(&self) -> bool {
        self.apply_datatypes
    }

    /// Set whether to apply recovered datatypes.
    pub fn set_apply_datatypes(&mut self, value: bool) {
        self.apply_datatypes = value;
    }

    // -- ignore_extern_c ---------------------------------------------------

    /// Whether to ignore `extern "C"` linkage when demangling.
    pub fn ignore_extern_c(&self) -> bool {
        self.ignore_extern_c
    }

    /// Set whether to ignore `extern "C"` linkage.
    pub fn set_ignore_extern_c(&mut self, value: bool) {
        self.ignore_extern_c = value;
    }
}

impl Default for DemanglerOptions {
    fn default() -> Self {
        Self::new()
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_options() {
        let opts = DemanglerOptions::new();
        assert!(opts.apply_signature());
        assert!(opts.apply_calling_convention());
        assert!(!opts.demangle_only_known_patterns());
        assert!(!opts.use_encoded_anonymous_namespace());
        assert!(opts.apply_udt_argument_type_tag());
        assert_eq!(opts.architecture_size(), 64);
        assert!(opts.prefer_demangled_namespace());
        assert_eq!(opts.max_symbols(), 0);
        assert!(opts.apply_datatypes());
        assert!(!opts.ignore_extern_c());
    }

    #[test]
    fn test_set_apply_signature() {
        let mut opts = DemanglerOptions::new();
        opts.set_apply_signature(false);
        assert!(!opts.apply_signature());
    }

    #[test]
    fn test_set_apply_calling_convention() {
        let mut opts = DemanglerOptions::new();
        opts.set_apply_calling_convention(false);
        assert!(!opts.apply_calling_convention());
    }

    #[test]
    fn test_set_demangle_only_known_patterns() {
        let mut opts = DemanglerOptions::new();
        opts.set_demangle_only_known_patterns(true);
        assert!(opts.demangle_only_known_patterns());
    }

    #[test]
    fn test_set_architecture_size() {
        let mut opts = DemanglerOptions::new();
        opts.set_architecture_size(32);
        assert_eq!(opts.architecture_size(), 32);
    }

    #[test]
    fn test_set_max_symbols() {
        let mut opts = DemanglerOptions::new();
        opts.set_max_symbols(1000);
        assert_eq!(opts.max_symbols(), 1000);
    }

    #[test]
    fn test_set_use_encoded_anonymous_namespace() {
        let mut opts = DemanglerOptions::new();
        opts.set_use_encoded_anonymous_namespace(true);
        assert!(opts.use_encoded_anonymous_namespace());
    }

    #[test]
    fn test_set_apply_udt_argument_type_tag() {
        let mut opts = DemanglerOptions::new();
        opts.set_apply_udt_argument_type_tag(false);
        assert!(!opts.apply_udt_argument_type_tag());
    }

    #[test]
    fn test_set_prefer_demangled_namespace() {
        let mut opts = DemanglerOptions::new();
        opts.set_prefer_demangled_namespace(false);
        assert!(!opts.prefer_demangled_namespace());
    }

    #[test]
    fn test_set_apply_datatypes() {
        let mut opts = DemanglerOptions::new();
        opts.set_apply_datatypes(false);
        assert!(!opts.apply_datatypes());
    }

    #[test]
    fn test_set_ignore_extern_c() {
        let mut opts = DemanglerOptions::new();
        opts.set_ignore_extern_c(true);
        assert!(opts.ignore_extern_c());
    }

    #[test]
    fn test_default_trait() {
        let opts = DemanglerOptions::default();
        assert!(opts.apply_signature());
        assert_eq!(opts.architecture_size(), 64);
    }

    #[test]
    fn test_clone() {
        let opts = DemanglerOptions::new();
        let cloned = opts.clone();
        assert_eq!(cloned.apply_signature(), opts.apply_signature());
        assert_eq!(cloned.architecture_size(), opts.architecture_size());
    }
}
