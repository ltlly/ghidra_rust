//! Assembler builder trait.
//!
//! Corresponds to Java's `GenericAssemblerBuilder` and `AssemblerBuilder`.

use super::assembler_trait::Assembler;
use super::selector::AssemblySelector;
use crate::base::analyzer::core::{Language, Program};

/// A trait for building assemblers for a given language.
///
/// The builder caches expensive state (parser, grammar, context graph)
/// and creates lightweight `Assembler` instances on demand.
pub trait AssemblerBuilder: Send + Sync {
    /// Get the language for which this builder constructs assemblers.
    fn get_language(&self) -> &Language;

    /// Build an assembler with the given selector callback.
    fn get_assembler(
        &self,
        selector: AssemblySelector,
    ) -> Box<dyn Assembler>;

    /// Build an assembler with the given selector and program binding.
    fn get_assembler_for_program(
        &self,
        selector: AssemblySelector,
        program: &Program,
    ) -> Box<dyn Assembler>;
}
