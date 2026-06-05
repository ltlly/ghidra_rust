//! Database-backed listing code unit hierarchy.
//!
//! Ported from Ghidra's `ghidra.trace.database.listing` package (34 files).
//!
//! Provides:
//! - `code_unit`: Abstract and concrete code unit types.
//! - `code_space`: Per-space code unit management.
//! - `code_manager`: Top-level code unit manager.
//! - `data_types`: Data type adapter for code units.
//! - `view_types`: View and memory view abstractions.
//! - `instruction`: Instruction code unit.
//! - `undefined`: Undefined data code unit.
//! - `adapter`: Code unit adapter trait.

pub mod adapter;
pub mod code_manager;
pub mod code_space;
pub mod code_unit;
pub mod data_types;
pub mod instruction;
pub mod undefined;
pub mod view_types;

pub use adapter::{CodeUnitAdapter, CommentAdapter, DataAdapter, DefinedDataAdapter};
pub use code_manager::DbTraceCodeManager;
pub use code_space::DbTraceCodeSpace;
pub use code_unit::{
    AbstractCodeUnit, CodeUnitKind, DbTraceData, DbTraceDataArrayElement,
    DbTraceDataCompositeField,
};
pub use data_types::TraceCodeDataType;
pub use instruction::DbTraceInstruction;
pub use undefined::UndefinedDbTraceData;
pub use view_types::{
    CodeUnitsMemoryView, CodeUnitsView, DefinedDataMemoryView, DefinedDataView,
    DefinedUnitsMemoryView, DefinedUnitsView, InstructionsMemoryView, InstructionsView,
    UndefinedDataMemoryView, UndefinedDataView,
};
