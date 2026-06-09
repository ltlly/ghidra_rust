//! Demangler features for Ghidra Rust.
//!
//! This module provides demangling support for:
//! - Microsoft Visual Studio mangled names (MSVC/Itanium-ABI for MSVC)
//! - GNU/GCC mangled names (via integration with `c++filt` or similar)
//!
//! The base types (`DemangledObject`, `DemangledFunction`, `DemangledVariable`,
//! `DemangledDataType`, `DemanglerOptions`, and the `Demangler` trait) are
//! shared across all demangler implementations.

pub mod demangled_data_type;
pub mod demangled_function;
pub mod demangled_object;
pub mod demangled_variable;
pub mod demangler;
pub mod demangler_options;
pub mod gnu;
pub mod microsoft;
