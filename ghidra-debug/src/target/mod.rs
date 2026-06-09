//! Debug target model types.
//!
//! The target model represents the directory-like tree of objects that a
//! debugger exposes. Ported from Ghidra's `TraceObject`, `KeyPath`, and
//! related target model types.
//!
//! Sub-modules:
//! - `key_path`: Immutable paths of keys for the target tree.
//! - `trace_object`: Trace objects and the object manager.
//! - `path_pattern`: Single path patterns with wildcard support.
//! - `path_matcher`: Composite path filters (OR of patterns).
//! - `visitors`: Tree traversal visitors.
//! - `info`: Trace object interface metadata and registration.
//! - `schema_context`: Schema context and schema implementations.

pub mod info;
pub mod key_path;
pub mod path_filter_expr;
pub mod path_matcher;
pub mod path_pattern;
pub mod schema_context;
pub mod target_execution_stateful;
pub mod target_method;
pub mod target_object;
pub mod trace_object;
pub mod visitors;

pub use key_path::KeyPath;
pub use path_filter_expr::PathFilterExpr;
pub use path_matcher::{NoneFilter, PathFilter, PathMatcher};
pub use path_pattern::{Align, PathPattern};
pub use target_execution_stateful::{ExecutionStateTransition, TargetExecutionStateful};
pub use target_method::{
    InvokeArguments, InvokeResult, InvokeValue, TargetMethod, TargetMethodParameter,
};
pub use target_object::{
    InterfaceSet, TargetEntry, TargetObject, TargetObjectManager, TargetValue,
};
pub use trace_object::{ObjectEntry, ObjectValue, TraceObject, TraceObjectManager};
pub use visitors::{
    AllPathsVisitor, AncestorsRelativeVisitor, AncestorsRootVisitor,
    CanonicalSuccessorsRelativeVisitor, OrderedSuccessorsVisitor,
    SuccessorsRelativeVisitor, VisitResult, TreeVisitor,
    all_descendants, all_paths_under, ancestor_paths,
};
