//! Microsoft Code Analyzer -- RTTI, vtables, and SEH (Structured Exception Handling).
//!
//! This module ports the key analysis features from Ghidra's
//! `MicrosoftCodeAnalyzer` plugin:
//!
//! - **RTTI** (Run-Time Type Information): MSVC class hierarchy structures
//!   RTTI0 (TypeDescriptor), RTTI1 (BaseClassDescriptor), RTTI2
//!   (BaseClassArray), RTTI3 (ClassHierarchyDescriptor), and RTTI4
//!   (CompleteObjectLocator).
//! - **VfTable**: Virtual function table analysis associated with RTTI4.
//! - **SEH / EH**: Structured Exception Handling data structures used by
//!   MSVC -- FuncInfo, UnwindMapEntry, TryBlockMapEntry, HandlerType,
//!   IPToStateMapEntry, and ESTypeList.

pub mod rtti;
pub mod eh;
pub mod vftable;

pub use rtti::*;
pub use eh::*;
pub use vftable::*;
