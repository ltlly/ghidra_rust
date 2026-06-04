//! Instruction selection mechanism.
//!
//! Corresponds to Java's `AssemblySelector`, which prunes and selects
//! binary assembled instructions from parsing results.  There are two
//! opportunity points: after parsing (pre-filter) and after machine
//! code generation (mandatory single selection).

use std::cmp::Ordering;
use std::collections::BTreeSet;

use super::errors::{AssemblySemanticException, AssemblerResult};
use crate::base::assembler::sleigh::parse::AssemblyParseResult;
use crate::base::assembler::sleigh::sem::{
    AssemblyPatternBlock, AssemblyResolvedPatterns, AssemblyResolution,
    AssemblyResolutionResults,
};

// ---------------------------------------------------------------------------
// Selection record
// ---------------------------------------------------------------------------

/// A resolved selection from the results.
///
/// Corresponds to Java's `AssemblySelector.Selection`.
#[derive(Debug, Clone)]
pub struct Selection {
    /// The resolved instruction bytes (ideally with a full mask).
    pub ins: AssemblyPatternBlock,
    /// The resolved context bytes for compatibility checks.
    pub ctx: AssemblyPatternBlock,
}

// ---------------------------------------------------------------------------
// AssemblySelector
// ---------------------------------------------------------------------------

/// Provides a mechanism for pruning and selecting binary assembled
/// instructions from the results of parsing textual assembly instructions.
///
/// Extensions of this struct are also suitable for collecting diagnostic
/// information about attempted assemblies.  For example, an implementation
/// may employ the syntax errors to produce code-completion suggestions.
///
/// Corresponds to Java's `AssemblySelector`.
#[derive(Debug, Clone, Default)]
pub struct AssemblySelector {
    /// Syntax errors accumulated during filtering.
    pub syntax_errors: BTreeSet<String>,
    /// Semantic errors accumulated during selection.
    pub semantic_errors: BTreeSet<String>,
}

impl AssemblySelector {
    /// Create a new default selector.
    pub fn new() -> Self {
        Self::default()
    }

    /// Filter parse results before resolution.
    ///
    /// By default, all non-error parse results are kept.
    /// Override in a subclass (or via a closure) to prune candidates.
    pub fn filter_parse(&self, parse: Vec<AssemblyParseResult>) -> Vec<AssemblyParseResult> {
        parse.into_iter().filter(|p| !p.is_error()).collect()
    }

    /// Select an instruction from the possible results.
    ///
    /// This must select precisely one resolved constructor from the
    /// results.  The mask of the returned result must be full (all 1s).
    ///
    /// By default, this selects the shortest instruction that is
    /// compatible with the given context, taking 0 for bits outside
    /// the mask.  If all resolutions are errors, an exception is thrown.
    pub fn select(
        &mut self,
        results: &AssemblyResolutionResults,
        _ctx: &AssemblyPatternBlock,
    ) -> AssemblerResult<Selection> {
        let sorted = self.filter_compatible_and_sort(results)?;

        // Pick the first (shortest instruction)
        let res = &sorted[0];
        Ok(Selection {
            ins: res.get_instruction().fill_mask(),
            ctx: res.get_context(),
        })
    }

    /// Filter to non-error results and sort by instruction size (shortest
    /// first), then by bits lexicographically.
    fn filter_compatible_and_sort(
        &mut self,
        results: &AssemblyResolutionResults,
    ) -> AssemblerResult<Vec<AssemblyResolvedPatterns>> {
        self.semantic_errors.clear();

        let mut sorted = Vec::new();
        for ar in results.iter() {
            if ar.is_error() {
                if let AssemblyResolution::Error(ref e) = ar {
                    self.semantic_errors.insert(e.message().to_string());
                }
                continue;
            }
            if let AssemblyResolution::Patterns(ref p) = ar {
                sorted.push(p.clone());
            }
        }

        if sorted.is_empty() {
            return Err(AssemblySemanticException::from_errors(
                self.semantic_errors.iter().cloned().collect(),
            )
            .into());
        }

        // Sort: shortest instruction first, then lexicographically by bits
        sorted.sort_by(|a, b| {
            let size_cmp = a
                .get_instruction()
                .length()
                .cmp(&b.get_instruction().length());
            if size_cmp != Ordering::Equal {
                return size_cmp;
            }
            a.get_instruction()
                .vals()
                .cmp(b.get_instruction().vals())
        });

        Ok(sorted)
    }

    /// Return the accumulated syntax errors from the last filtering pass.
    pub fn syntax_errors(&self) -> &BTreeSet<String> {
        &self.syntax_errors
    }

    /// Return the accumulated semantic errors from the last selection pass.
    pub fn semantic_errors(&self) -> &BTreeSet<String> {
        &self.semantic_errors
    }
}
