//! P-code trace data access shims.
//!
//! Ported from Ghidra's `ghidra.pcode.exec.trace.data` package.

pub mod pcodetrace_access;
pub use pcodetrace_access::PcodeTraceAccess;
pub mod pcodetrace_data_access;
pub use pcodetrace_data_access::PcodeTraceDataAccess;
pub mod pcodetrace_memory_access;
pub use pcodetrace_memory_access::PcodeTraceMemoryAccess;
pub mod pcodetrace_registers_access;
pub use pcodetrace_registers_access::PcodeTraceRegistersAccess;
pub mod pcodetrace_thread_access;
pub use pcodetrace_thread_access::PcodeTraceThreadAccess;
pub mod pcodetrace_property_access;
pub use pcodetrace_property_access::PcodeTracePropertyAccess;
pub mod default_pcodetrace_access;
pub use default_pcodetrace_access::DefaultPcodeTraceAccess;
pub mod default_pcodetrace_memory_access;
pub use default_pcodetrace_memory_access::DefaultPcodeTraceMemoryAccess;
pub mod default_pcodetrace_registers_access;
pub use default_pcodetrace_registers_access::DefaultPcodeTraceRegistersAccess;
pub mod default_pcodetrace_thread_access;
pub use default_pcodetrace_thread_access::DefaultPcodeTraceThreadAccess;
pub mod default_pcodetrace_property_access;
pub use default_pcodetrace_property_access::DefaultPcodeTracePropertyAccess;
pub mod abstract_pcodetrace_access;
pub use abstract_pcodetrace_access::AbstractPcodeTraceAccess;
pub mod abstract_pcodetrace_data_access;
pub use abstract_pcodetrace_data_access::AbstractPcodeTraceDataAccess;
pub mod internal_pcodetrace_data_access;
pub use internal_pcodetrace_data_access::InternalPcodeTraceDataAccess;
