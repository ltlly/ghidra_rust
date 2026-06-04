//! Decompiler module: complete port of Ghidra's `ghidra.app.decompiler` package.
//!
//! This module provides the full decompiler API surface including:
//! - **Clang AST**: Structured C code representation as a tree of tokens and groups
//! - **DecompInterface**: Main client-facing interface for decompilation
//! - **DecompileResults**: Results from a decompiler decompileFunction call
//! - **DecompileProcess**: Communication with the native decompiler process
//! - **DecompileCallback**: Callbacks from the decompiler to the database
//! - **DecompileOptions**: Configuration options for the decompiler
//! - **PrettyPrinter**: Converts Clang AST into readable C code
//! - **TokenIterator**: Walks the Clang AST returning leaf tokens
//! - **Parallel**: Utilities for parallel decompilation
//! - **Signature**: Signature analysis for functions
//! - **Location**: Decompiler cursor/location types
//! - **Component**: UI-adjacent data structures and interfaces
//! - **Util**: Utility functions for Clang AST manipulation
//!
//! # Architecture
//!
//! ```text
//! ┌──────────────────────────────────────────────┐
//! │            DecompInterface                    │
//! │  Client-facing API for decompilation          │
//! └──────────────────────────────────────────────┘
//!     │                        │
//!     ▼                        ▼
//! ┌──────────────┐    ┌──────────────────┐
//! │DecompileProc │    │DecompileResults  │
//! │  (native IPC)│    │  (ClangNode tree)│
//! └──────────────┘    └──────────────────┘
//!                             │
//!                     ┌───────┴───────┐
//!                     ▼               ▼
//!             ┌──────────────┐  ┌──────────────┐
//!             │  ClangNode   │  │PrettyPrinter │
//!             │    Arena     │  │  (C output)  │
//!             └──────────────┘  └──────────────┘
//! ```
//!
//! # Java Package Mapping
//!
//! | Java Package | Rust Module |
//! |---|---|
//! | `ghidra.app.decompiler.ClangNode` | `clang_node` |
//! | `ghidra.app.decompiler.ClangToken` | `clang_node` (as ClangNodeKind variants) |
//! | `ghidra.app.decompiler.ClangLine` | `clang_line` |
//! | `ghidra.app.decompiler.DecompInterface` | `decomp_interface` |
//! | `ghidra.app.decompiler.DecompileResults` | `decompile_results` |
//! | `ghidra.app.decompiler.DecompileProcess` | `decompile_process` |
//! | `ghidra.app.decompiler.DecompileCallback` | `decompile_callback` |
//! | `ghidra.app.decompiler.DecompileOptions` | `decompile_options` |
//! | `ghidra.app.decompiler.DecompiledFunction` | `decompiled_function` |
//! | `ghidra.app.decompiler.DecompileException` | `decompile_exception` |
//! | `ghidra.app.decompiler.PrettyPrinter` | `pretty_printer` |
//! | `ghidra.app.decompiler.TokenIterator` | `token_iterator` |
//! | `ghidra.app.decompiler.DecompileDebug` | `decompile_debug` |
//! | `ghidra.app.decompiler.DecompilerHighlighter` | `highlighter` |
//! | `ghidra.app.decompiler.DecompilerLocation` | `location` |
//! | `ghidra.app.decompiler.parallel.*` | `parallel` |
//! | `ghidra.app.decompiler.signature.*` | `signature` |
//! | `ghidra.app.decompiler.component.*` | `component` |
//! | `ghidra.app.decompiler.util.*` | `util` |

pub mod clang_line;
pub mod clang_node;
pub mod component;
pub mod decompile_callback;
pub mod decompile_debug;
pub mod decompile_exception;
pub mod decompile_options;
pub mod decompile_process;
pub mod decompile_results;
pub mod decompiled_function;
pub mod decomp_interface;
pub mod disposer;
pub mod highlighter;
pub mod location;
pub mod parallel;
pub mod pretty_printer;
pub mod signature;
pub mod token_iterator;
pub mod util;

// ============================================================================
// Re-exports for convenience
// ============================================================================

// Clang AST types
pub use clang_node::{
    ClangBitFieldTokenData, ClangBreakData, ClangCaseTokenData, ClangCommentTokenData,
    ClangFieldTokenData, ClangFuncNameTokenData, ClangFuncProtoData, ClangFunctionData,
    ClangLabelTokenData, ClangNodeArena, ClangNodeId, ClangNodeKind, ClangOpTokenData,
    ClangReturnTypeData, ClangStatementData, ClangSyntaxTokenData, ClangTokenData,
    ClangTokenGroupData, ClangTypeTokenData, ClangVariableDeclData, ClangVariableTokenData,
    SyntaxType, COMMENT_COLOR, CONST_COLOR, DEFAULT_COLOR, ERROR_COLOR, FUNCTION_COLOR,
    GLOBAL_COLOR, KEYWORD_COLOR, MAX_COLOR, NULL_NODE, PARAMETER_COLOR, SPECIAL_COLOR,
    TYPE_COLOR, VARIABLE_COLOR,
};

// ClangLine
pub use clang_line::ClangLine;

// Decompiler API types
pub use decompile_callback::{DecompileCallbackHandler, FunctionInfo, NullCallbackHandler, StringData, SymbolInfo};
pub use decompile_debug::DecompileDebug;
pub use decompile_exception::DecompileException;
pub use decompile_options::{BraceStyle, CommentStyle, DecompileOptions, IntegerFormat, NanIgnore};
pub use decompile_process::{DecompileProcess, DecompileProcessError, DisposeState, ProcessStatus};
pub use decompile_results::DecompileResults;
pub use decompiled_function::DecompiledFunction;
pub use decomp_interface::DecompInterface;
pub use pretty_printer::PrettyPrinter;
pub use token_iterator::TokenIterator;

// Signature types
pub use signature::{BlockSignature, CopySignature, DebugSignature, SignatureResult, VarnodeSignature};

// Location types
pub use location::{
    DecompilerLocation, DecompilerLocationInfo, DefaultDecompilerLocation,
    FunctionNameDecompilerLocation, VariableDecompilerLocation,
};

// Parallel types
pub use parallel::{
    ChunkingParallelDecompiler, DecompileConfigurer, DecompilerCallback, DecompilerMapFunction,
    DecompilerResult, NullDecompilerCallback, ParallelDecompiler,
};

// Component types
pub use component::{
    ClangFieldElement, ColorProvider, DecompileData, DecompileResultsListener,
    DefaultColorProvider, EmptyDecompileData, HighlightToken, NameTokenMatcher, TokenHighlights,
    TokenKey, UserHighlights,
};

// Highlighter types
pub use highlighter::{CTokenHighlightMatcher, DecompilerHighlighter, TokenHighlightColors};

// Process factory
pub use decompile_process::DecompileProcessFactory;

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_module_exports_compile() {
        // Verify all major types are accessible
        let _arena = ClangNodeArena::new();
        let _opts = DecompileOptions::default();
        let _iface = DecompInterface::new();
        let _debug = DecompileDebug::new();
        let _colors = TokenHighlightColors::default();
        let _data = DecompileData::new(0);
        let _highlights = TokenHighlights::new();
    }

    #[test]
    fn test_decompile_results_types() {
        // Verify the decompiler-level DecompileResults works
        let arena = ClangNodeArena::new();
        let mut arena2 = ClangNodeArena::new();
        let root = arena2.alloc(ClangNodeKind::TokenGroup(ClangTokenGroupData::default()));
        let results = DecompileResults::success(0x1000, Some("main".to_string()), root, arena2);
        assert!(results.decompile_completed());
        assert_eq!(results.function_entry, 0x1000);
    }

    #[test]
    fn test_decompile_exception_types() {
        let e = DecompileException::new("process", "timeout");
        assert!(format!("{}", e).contains("timeout"));
    }

    #[test]
    fn test_dispose_state_variants() {
        assert_eq!(DisposeState::NotDisposed, DisposeState::default());
        assert_ne!(DisposeState::DisposedOnTimeout, DisposeState::NotDisposed);
    }

    #[test]
    fn test_syntax_type_variants() {
        let t = SyntaxType::from_i32(0);
        assert_eq!(t, SyntaxType::Keyword);
        let t = SyntaxType::from_i32(99);
        assert_eq!(t, SyntaxType::Default);
    }

    #[test]
    fn test_parallel_basic() {
        let functions = vec![
            DecompilerMapFunction::new(0x1000),
            DecompilerMapFunction::new(0x2000),
        ];
        let results = ParallelDecompiler::decompile_batch(&functions, |f| {
            Ok(format!("fn_{}", f.entry_point))
        });
        assert_eq!(results.len(), 2);
    }
}
