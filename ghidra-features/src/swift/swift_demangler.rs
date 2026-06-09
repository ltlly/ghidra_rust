//! High-level Swift demangler with options, batch processing, and statistics.
//!
//! Wraps the core [`demangle`](super::demangle) function with configurable
//! behaviour (toolchain path, prefix policy, symbol filters) and provides
//! convenience methods for demangling entire symbol tables at once.
//!
//! Ported from Ghidra's `SwiftDemangler.java`.

use std::collections::HashMap;
use std::fmt;

use super::options::SwiftDemanglerOptions;
use super::{demangle, demangle_or_original, is_swift_mangled, is_swift_runtime_fn, DemangleError};

// ---------------------------------------------------------------------------
// Demangle result
// ---------------------------------------------------------------------------

/// The outcome of demangling a single symbol.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DemangleResult {
    /// The original mangled symbol.
    pub original: String,
    /// The demangled name, or `None` if demangling failed.
    pub demangled: Option<String>,
    /// Error that occurred during demangling, if any.
    pub error: Option<DemangleError>,
    /// Whether the symbol was recognized as a Swift mangled name.
    pub is_swift: bool,
    /// Whether the symbol is a Swift runtime function.
    pub is_runtime: bool,
}

impl DemangleResult {
    /// Return the best available name: demangled if available, original otherwise.
    pub fn best_name(&self) -> &str {
        self.demangled
            .as_deref()
            .unwrap_or(self.original.as_str())
    }

    /// Return the display label, applying prefix policy from the options.
    pub fn display_label(&self, opts: &SwiftDemanglerOptions) -> String {
        match &self.demangled {
            Some(name) => name.clone(),
            None => {
                if self.is_swift {
                    format!("{}{}", opts.incomplete_prefix(), self.original)
                } else {
                    format!("{}{}", opts.unsupported_prefix(), self.original)
                }
            }
        }
    }
}

impl fmt::Display for DemangleResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.best_name())
    }
}

// ---------------------------------------------------------------------------
// Demangle statistics
// ---------------------------------------------------------------------------

/// Statistics accumulated during batch demangling.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DemangleStats {
    /// Total symbols processed.
    pub total: usize,
    /// Symbols recognized as Swift mangled names.
    pub swift_symbols: usize,
    /// Symbols successfully demangled.
    pub demangled: usize,
    /// Symbols that failed demangling.
    pub failed: usize,
    /// Symbols that were not Swift mangled names.
    pub not_swift: usize,
    /// Swift runtime function symbols.
    pub runtime_symbols: usize,
}

impl DemangleStats {
    /// Success rate as a fraction in [0, 1].
    pub fn success_rate(&self) -> f64 {
        if self.total == 0 {
            0.0
        } else {
            self.demangled as f64 / self.total as f64
        }
    }

    /// Return a human-readable summary.
    pub fn summary(&self) -> String {
        format!(
            "total={}, swift={}, demangled={}, failed={}, runtime={}, rate={:.1}%",
            self.total,
            self.swift_symbols,
            self.demangled,
            self.failed,
            self.runtime_symbols,
            self.success_rate() * 100.0,
        )
    }
}

// ---------------------------------------------------------------------------
// SwiftDemangler
// ---------------------------------------------------------------------------

/// High-level Swift demangler.
///
/// Wraps the core demangling functions with configurable options and
/// provides batch-processing capabilities for symbol tables.
///
/// # Example
///
/// ```ignore
/// use ghidra_features::swift::swift_demangler::SwiftDemangler;
///
/// let demangler = SwiftDemangler::new();
/// let result = demangler.demangle_symbol("$s10MyModule14MyViewControllerC5titleSSvp");
/// assert!(result.demangled.is_some());
/// ```
#[derive(Debug, Clone)]
pub struct SwiftDemangler {
    options: SwiftDemanglerOptions,
}

impl SwiftDemangler {
    /// Create a new demangler with default options.
    pub fn new() -> Self {
        Self {
            options: SwiftDemanglerOptions::new(),
        }
    }

    /// Create a demangler with the given options.
    pub fn with_options(options: SwiftDemanglerOptions) -> Self {
        Self { options }
    }

    /// Get the current options.
    pub fn options(&self) -> &SwiftDemanglerOptions {
        &self.options
    }

    /// Get a mutable reference to the options.
    pub fn options_mut(&mut self) -> &mut SwiftDemanglerOptions {
        &mut self.options
    }

    /// Set the options.
    pub fn set_options(&mut self, options: SwiftDemanglerOptions) {
        self.options = options;
    }

    /// Demangle a single symbol.
    ///
    /// Returns a [`DemangleResult`] containing the original symbol, the
    /// demangled name (if successful), and metadata about the symbol.
    pub fn demangle_symbol(&self, symbol: &str) -> DemangleResult {
        let is_swift = is_swift_mangled(symbol);
        let is_runtime = is_swift_runtime_fn(symbol);

        if !is_swift && !is_runtime {
            return DemangleResult {
                original: symbol.to_string(),
                demangled: None,
                error: None,
                is_swift: false,
                is_runtime,
            };
        }

        match demangle(symbol) {
            Ok(demangled) => DemangleResult {
                original: symbol.to_string(),
                demangled: Some(demangled),
                error: None,
                is_swift,
                is_runtime,
            },
            Err(e) => DemangleResult {
                original: symbol.to_string(),
                demangled: None,
                error: Some(e),
                is_swift,
                is_runtime,
            },
        }
    }

    /// Demangle a symbol, returning the best name with prefix policy applied.
    ///
    /// This is the primary method for label generation in a disassembler.
    pub fn demangle_label(&self, symbol: &str) -> String {
        let result = self.demangle_symbol(symbol);
        result.display_label(&self.options)
    }

    /// Demangle a collection of symbols, returning results and statistics.
    ///
    /// Symbols that are not Swift mangled names are included in the results
    /// with `demangled = None`.
    pub fn demangle_batch(&self, symbols: &[String]) -> (Vec<DemangleResult>, DemangleStats) {
        let mut results = Vec::with_capacity(symbols.len());
        let mut stats = DemangleStats::default();

        for symbol in symbols {
            let result = self.demangle_symbol(symbol);
            stats.total += 1;
            if result.is_swift {
                stats.swift_symbols += 1;
            }
            if result.is_runtime {
                stats.runtime_symbols += 1;
            }
            if result.demangled.is_some() {
                stats.demangled += 1;
            } else if result.is_swift {
                stats.failed += 1;
            } else {
                stats.not_swift += 1;
            }
            results.push(result);
        }

        (results, stats)
    }

    /// Demangle a symbol table (address -> name mapping), returning
    /// a new map with demangled names.
    pub fn demangle_symbol_table(
        &self,
        table: &HashMap<u64, String>,
    ) -> (HashMap<u64, String>, DemangleStats) {
        let mut result = HashMap::with_capacity(table.len());
        let mut stats = DemangleStats::default();

        for (addr, symbol) in table {
            let dr = self.demangle_symbol(symbol);
            stats.total += 1;
            if dr.is_swift {
                stats.swift_symbols += 1;
            }
            if dr.is_runtime {
                stats.runtime_symbols += 1;
            }
            if dr.demangled.is_some() {
                stats.demangled += 1;
                result.insert(*addr, dr.best_name().to_string());
            } else if dr.is_swift {
                stats.failed += 1;
                result.insert(*addr, dr.display_label(&self.options));
            } else {
                stats.not_swift += 1;
                result.insert(*addr, symbol.clone());
            }
        }

        (result, stats)
    }

    /// Filter a list of symbols, returning only those that are Swift mangled.
    pub fn filter_swift_symbols<'a>(&self, symbols: &'a [String]) -> Vec<&'a str> {
        symbols
            .iter()
            .filter(|s| is_swift_mangled(s))
            .map(|s| s.as_str())
            .collect()
    }

    /// Check if a symbol is a Swift mangled name.
    pub fn is_swift_mangled(&self, symbol: &str) -> bool {
        is_swift_mangled(symbol)
    }

    /// Check if a symbol is a Swift runtime function.
    pub fn is_swift_runtime_fn(&self, symbol: &str) -> bool {
        is_swift_runtime_fn(symbol)
    }
}

impl Default for SwiftDemangler {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_demangle_symbol_swift() {
        let demangler = SwiftDemangler::new();
        let result = demangler.demangle_symbol("$s10MyModule14MyViewControllerC5titleSSvp");
        assert!(result.is_swift);
        assert!(result.demangled.is_some());
    }

    #[test]
    fn test_demangle_symbol_not_swift() {
        let demangler = SwiftDemangler::new();
        let result = demangler.demangle_symbol("_ZN3std6string3newE");
        assert!(!result.is_swift);
        assert!(result.demangled.is_none());
    }

    #[test]
    fn test_demangle_label() {
        let demangler = SwiftDemangler::new();
        let label = demangler.demangle_label("$s4main3fooyyF");
        assert!(!label.is_empty());
    }

    #[test]
    fn test_demangle_label_non_swift_with_prefix() {
        let demangler = SwiftDemangler::new();
        let label = demangler.demangle_label("_ZN3foo3barE");
        assert!(label.starts_with("$$"));
    }

    #[test]
    fn test_demangle_batch() {
        let demangler = SwiftDemangler::new();
        let symbols = vec![
            "$s4main3fooyyF".to_string(),
            "_ZN3std6string3newE".to_string(),
            "_swift_allocObject".to_string(),
        ];
        let (results, stats) = demangler.demangle_batch(&symbols);
        assert_eq!(results.len(), 3);
        assert_eq!(stats.total, 3);
        assert!(stats.runtime_symbols >= 1);
    }

    #[test]
    fn test_demangle_symbol_table() {
        let demangler = SwiftDemangler::new();
        let mut table = HashMap::new();
        table.insert(0x1000, "$s4main3fooyyF".to_string());
        table.insert(0x2000, "regular_function".to_string());
        let (result_table, stats) = demangler.demangle_symbol_table(&table);
        assert_eq!(result_table.len(), 2);
        assert_eq!(stats.total, 2);
    }

    #[test]
    fn test_filter_swift_symbols() {
        let demangler = SwiftDemangler::new();
        let symbols = vec![
            "$s4main3fooyyF".to_string(),
            "not_swift".to_string(),
            "$S10Module5ClassC".to_string(),
        ];
        let filtered = demangler.filter_swift_symbols(&symbols);
        assert_eq!(filtered.len(), 2);
    }

    #[test]
    fn test_demangle_stats_success_rate() {
        let stats = DemangleStats {
            total: 10,
            demangled: 7,
            ..Default::default()
        };
        assert!((stats.success_rate() - 0.7).abs() < f64::EPSILON);
    }

    #[test]
    fn test_demangle_stats_zero() {
        let stats = DemangleStats::default();
        assert_eq!(stats.success_rate(), 0.0);
    }

    #[test]
    fn test_demangle_result_display() {
        let result = DemangleResult {
            original: "$s4main3fooyyF".to_string(),
            demangled: Some("main.foo()".to_string()),
            error: None,
            is_swift: true,
            is_runtime: false,
        };
        assert_eq!(result.to_string(), "main.foo()");
    }

    #[test]
    fn test_is_swift_runtime_fn() {
        let demangler = SwiftDemangler::new();
        assert!(demangler.is_swift_runtime_fn("_swift_allocObject"));
        assert!(demangler.is_swift_runtime_fn("swift_retain"));
        assert!(!demangler.is_swift_runtime_fn("malloc"));
    }

    #[test]
    fn test_custom_options() {
        let mut opts = SwiftDemanglerOptions::new();
        opts.set_incomplete_prefix(false);
        opts.set_unsupported_prefix(false);
        let demangler = SwiftDemangler::with_options(opts);
        let label = demangler.demangle_label("_ZN3foo3barE");
        assert!(!label.starts_with("$$"));
    }
}
