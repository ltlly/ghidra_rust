//! Ghidra Rust - Debug extensions.
//!
//! This crate provides the Rust port of Ghidra's Debug framework:
//!
//! - **`model`**: Core trace modeling types (Lifespan, TraceSnapshot,
//!   TraceThread, TraceModule, TraceBreakpointKind, TraceMemoryState, etc.)
//!   Ported from `Framework-TraceModeling`.
//!
//! - **`target`**: Debug target object model (KeyPath, TraceObject,
//!   TraceObjectManager). Ported from `Framework-TraceModeling/target`.
//!
//! - **`api`**: High-level debug API types (ActionName, Target trait,
//!   LogicalBreakpoint, ControlMode). Ported from `Debugger-api`.
//!
//! - **`services`**: Service interfaces (TraceManagerService,
//!   LogicalBreakpointService, EmulationService, etc.). Ported from
//!   `Debugger-api/ghidra.app.services`.
//!
//! - **`db`**: SQLite-backed trace storage (TraceDatabase). Ported from
//!   `Framework-TraceModeling/ghidra.trace.database`.

pub mod api;
pub mod db;
pub mod model;
pub mod services;
pub mod target;
