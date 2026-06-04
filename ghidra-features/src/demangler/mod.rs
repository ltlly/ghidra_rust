//! Demangler features for Ghidra Rust.
//!
//! This module provides demangling support for:
//! - Microsoft Visual Studio mangled names (MSVC/Itanium-ABI for MSVC)
//! - GNU/GCC mangled names (via integration with `c++filt` or similar)

pub mod microsoft;
pub mod gnu;
