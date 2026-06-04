//! Stack analysis -- ported from Ghidra's `FunctionStackAnalysisCmd.java`,
//! `NewFunctionStackAnalysisCmd.java`, and `FunctionResultStateStackAnalysisCmd.java`.
//!
//! This module provides the core stack analysis commands that:
//!
//! 1. Walk function bodies to discover stack-pointer references
//! 2. Create local variables and parameters in the function's stack frame
//! 3. Compute the stack purge (bytes removed by the epilogue)
//!
//! | Rust type                            | Java class                                |
//! |--------------------------------------|-------------------------------------------|
//! | [`StackAnalysisConfig`]              | (common parameters)                       |
//! | [`StackVariableInfo`]                | (accumulated stack variable data)         |
//! | [`FunctionStackAnalyzer`]            | `FunctionStackAnalysisCmd`                |
//! | [`NewFunctionStackAnalyzer`]         | `NewFunctionStackAnalysisCmd`             |
//! | [`ResultStateStackAnalyzer`]         | `FunctionResultStateStackAnalysisCmd`     |
//! | [`CallDepthChangeInfo`]              | `CallDepthChangeInfo`                     |
//! | [`StackReferenceRecord`]             | (stack reference record)                  |

mod config;
mod var_info;
mod call_depth;
mod ref_record;
mod legacy_analyzer;
mod new_analyzer;
mod result_state_analyzer;

pub use config::*;
pub use var_info::*;
pub use call_depth::*;
pub use ref_record::*;
pub use legacy_analyzer::*;
pub use new_analyzer::*;
pub use result_state_analyzer::*;
