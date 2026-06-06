//! Ghidra Rust - Debug extensions.
//!
//! This crate provides the Rust port of Ghidra's Debug framework:
//!
//! - **`model`**: Core trace modeling types (Lifespan, TraceSnapshot,
//!   TraceThread, TraceModule, TraceBreakpointKind, TraceMemoryState,
//!   TraceProgramView, TraceObjectSchema, time scheduling, etc.)
//!   Ported from `Framework-TraceModeling`.
//!
//! - **`target`**: Debug target object model (KeyPath, TraceObject,
//!   TraceObjectManager). Ported from `Framework-TraceModeling/target`.
//!
//! - **`api`**: High-level debug API types (ActionName, Target trait,
//!   LogicalBreakpoint, ControlMode, FlatDebuggerApi, PlatformDescription).
//!   Ported from `Debugger-api`.
//!
//! - **`services`**: Service interfaces (TraceManagerService,
//!   LogicalBreakpointService, EmulationService, etc.). Ported from
//!   `Debugger-api/ghidra.app.services`.
//!
//! - **`db`**: SQLite-backed trace storage (TraceDatabase, context, listing,
//!   map, module, program, property, space, stack, time, data managers).
//!   Ported from `Framework-TraceModeling/ghidra.trace.database`.
//!
//! - **`util`**: Trace utilities (data adapters, iterators, event dispatch,
//!   change management, coordinate helpers).
//!   Ported from `Framework-TraceModeling/ghidra.trace.util`.
//!
//! - **`plugin`**: Debugger plugin framework and events.
//!   Ported from `Debugger/ghidra.app.plugin.core.debug`.
//!
//! - **`pcode`**: Pcode trace execution and data access.
//!   Ported from `Framework-TraceModeling/ghidra.pcode.exec.trace`.

pub mod api;
pub mod db;
mod debug_comprehensive_port_tests;
mod debug_final_integration_test;
mod debug_remaining_comprehensive_test;
mod debug_final_port_test;
mod debug_integration_test;
mod debug_new_modules_test;
mod debug_port_integration_test;
mod debug_port_modules_test;
mod debug_port_new_modules_test;
mod debug_remaining_gui_types_test;
mod debug_remaining_modules_test;
mod debug_remaining_port_test;
mod debug_schedule_integration_test;
mod debug_final_port_tests;
mod debug_new_calltree_panels_test;
mod debug_new_comprehensive_tests;
mod debug_remaining_modules_final_test;
mod debug_remaining_final_test;
pub mod framework;
pub mod isf;
pub mod jdi;
pub mod model;
mod new_port_tests;
pub mod pcode;
pub mod plugin;
pub mod proposed_utils;
pub mod rmi;
pub mod services;
pub mod stack;
pub mod target;
pub mod taint_analysis;
pub mod util;
