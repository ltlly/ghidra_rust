//! Extended operations traits for the trace model.
//!
//! Ported from various model packages:
//! - `TraceAddressSnapRangePropertyMapOperations.java`
//! - `TraceAddressSnapRangePropertyMapSpace.java`
//! - `TracePropertyMapOperations.java`
//! - `TracePropertyMapSpace.java`
//! - `TraceMemoryOperations.java`
//! - `TraceStaticMappingManager.java`
//! - `TraceReferenceManager.java`
//! - `TraceThreadManager.java`
//! - `TraceBaseDefinedUnitsView.java`
//! - `BadSchemaException.java`
//! - `AbstractStep.java`, `SkipStep.java` (time schedule)

use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::Lifespan;

// ============================================================================
// Address Snap Range Property Map Operations
// ============================================================================

/// Operations on address-snap range property maps.
///
/// Ported from `TraceAddressSnapRangePropertyMapOperations.java`.
pub trait AddressSnapPropertyMapOps<V: Clone + std::fmt::Debug> {
    /// Get the value at a specific point.
    fn get(&self, space: &str, offset: u64, snap: i64) -> Option<&V>;

    /// Set a value spanning a range.
    fn set(&mut self, space: &str, offset_min: u64, offset_max: u64, snap_min: i64, snap_max: i64, value: V);

    /// Remove a value.
    fn remove(&mut self, space: &str, offset: u64, snap: i64) -> Option<V>;

    /// Get all entries in a range.
    fn entries_in_range(&self, space: &str, offset_min: u64, offset_max: u64, snap_min: i64, snap_max: i64) -> Vec<(u64, u64, i64, i64, &V)>;
}

/// Operations on address-snap range property map spaces.
///
/// Ported from `TraceAddressSnapRangePropertyMapSpace.java`.
pub trait AddressSnapPropertyMapSpaceOps<V: Clone + std::fmt::Debug> {
    /// Get the space name.
    fn space_name(&self) -> &str;

    /// Get a value at a point.
    fn get(&self, offset: u64, snap: i64) -> Option<&V>;

    /// Set a value spanning a range.
    fn set(&mut self, offset_min: u64, offset_max: u64, snap_min: i64, snap_max: i64, value: V);

    /// Remove a value.
    fn remove(&mut self, offset: u64, snap: i64) -> Option<V>;
}

// ============================================================================
// Property Map Operations
// ============================================================================

/// Operations on simple (address-only) property maps.
///
/// Ported from `TracePropertyMapOperations.java`.
pub trait PropertyMapOps<V: Clone + std::fmt::Debug> {
    /// Get a value at an address.
    fn get(&self, space: &str, offset: u64) -> Option<&V>;

    /// Set a value at an address range.
    fn set(&mut self, space: &str, offset_min: u64, offset_max: u64, value: V);

    /// Remove a value at an address.
    fn remove(&mut self, space: &str, offset: u64) -> Option<V>;
}

/// Operations on property map spaces.
///
/// Ported from `TracePropertyMapSpace.java`.
pub trait PropertyMapSpaceOps<V: Clone + std::fmt::Debug> {
    /// Get the space name.
    fn space_name(&self) -> &str;

    /// Get a value at an offset.
    fn get(&self, offset: u64) -> Option<&V>;

    /// Set a value spanning a range.
    fn set(&mut self, offset_min: u64, offset_max: u64, value: V);
}

// ============================================================================
// Memory Operations
// ============================================================================

/// Operations on trace memory.
///
/// Ported from `TraceMemoryOperations.java`.
pub trait TraceMemoryOperations {
    /// Read bytes from memory.
    fn read_memory(&self, space: &str, snap: i64, offset: u64, length: usize) -> Option<Vec<u8>>;

    /// Write bytes to memory.
    fn write_memory(&mut self, space: &str, snap: i64, offset: u64, data: &[u8]);

    /// Get memory regions.
    fn regions(&self, space: &str, snap: i64) -> Vec<MemoryRegionInfo>;
}

/// Info about a memory region.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryRegionInfo {
    /// Region name.
    pub name: String,
    /// Start offset.
    pub offset_min: u64,
    /// End offset.
    pub offset_max: u64,
    /// Readable.
    pub readable: bool,
    /// Writable.
    pub writable: bool,
    /// Executable.
    pub executable: bool,
}

// ============================================================================
// Static Mapping Manager Trait
// ============================================================================

/// Operations on static mappings.
///
/// Ported from `TraceStaticMappingManager.java`.
pub trait TraceStaticMappingManagerOps {
    /// Add a static mapping.
    fn add_mapping(
        &mut self,
        program_url: &str,
        program_min: u64,
        program_max: u64,
        trace_min: u64,
        trace_max: u64,
        lifespan: &Lifespan,
    ) -> u64;

    /// Remove a mapping by ID.
    fn remove_mapping(&mut self, id: u64) -> bool;

    /// Get all mappings.
    fn mappings(&self) -> Vec<StaticMappingInfo>;

    /// Translate program address to trace address.
    fn program_to_trace(&self, program_url: &str, program_addr: u64, snap: i64) -> Option<u64>;

    /// Translate trace address to program address.
    fn trace_to_program(&self, trace_addr: u64, snap: i64) -> Option<(String, u64)>;
}

/// Info about a static mapping.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StaticMappingInfo {
    /// Mapping ID.
    pub id: u64,
    /// Program URL.
    pub program_url: String,
    /// Program min offset.
    pub program_min: u64,
    /// Program max offset.
    pub program_max: u64,
    /// Trace min offset.
    pub trace_min: u64,
    /// Trace max offset.
    pub trace_max: u64,
    /// Lifespan.
    pub lifespan: Lifespan,
}

// ============================================================================
// Reference Manager Trait
// ============================================================================

/// Operations on trace references.
///
/// Ported from `TraceReferenceManager.java`.
pub trait TraceReferenceManagerOps {
    /// Add a memory reference.
    fn add_memory_reference(
        &mut self,
        from_space: &str,
        from_offset: u64,
        to_space: &str,
        to_offset: u64,
        ref_type: &str,
        lifespan: &Lifespan,
    ) -> u64;

    /// Get references from an address.
    fn references_from(&self, space: &str, snap: i64, offset: u64) -> Vec<ReferenceInfo>;

    /// Get references to an address.
    fn references_to(&self, space: &str, snap: i64, offset: u64) -> Vec<ReferenceInfo>;

    /// Clear references from a range.
    fn clear_references_from(&mut self, space: &str, lifespan: &Lifespan, offset_min: u64, offset_max: u64);
}

/// Info about a reference.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReferenceInfo {
    /// Reference ID.
    pub id: u64,
    /// From offset.
    pub from_offset: u64,
    /// To offset.
    pub to_offset: u64,
    /// Reference type.
    pub ref_type: String,
    /// Operand index.
    pub operand_index: u32,
}

// ============================================================================
// Thread Manager Trait
// ====================================================================

/// Operations on trace threads.
///
/// Ported from `TraceThreadManager.java`.
pub trait TraceThreadManagerOps {
    /// Add a thread.
    fn add_thread(&mut self, name: &str, lifespan: &Lifespan) -> u64;

    /// Remove a thread.
    fn remove_thread(&mut self, id: u64) -> bool;

    /// Get a thread by ID.
    fn get_thread(&self, id: u64) -> Option<ThreadInfo>;

    /// Get all threads at a snap.
    fn threads_at_snap(&self, snap: i64) -> Vec<ThreadInfo>;

    /// Get a thread by name.
    fn thread_by_name(&self, name: &str, snap: i64) -> Option<ThreadInfo>;
}

/// Info about a thread.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreadInfo {
    /// Thread ID.
    pub id: u64,
    /// Thread name.
    pub name: String,
    /// Lifespan.
    pub lifespan: Lifespan,
    /// Process ID.
    pub process_id: u64,
}

// ============================================================================
// Base Defined Units View
// ============================================================================

/// View over defined code units.
///
/// Ported from `TraceBaseDefinedUnitsView.java`.
pub trait BaseDefinedUnitsView: std::fmt::Debug {
    /// Get the number of defined units at a snap.
    fn count(&self, snap: i64) -> usize;

    /// Get all defined unit offsets at a snap.
    fn offsets(&self, snap: i64) -> Vec<u64>;
}

// ============================================================================
// Schema Exceptions
// ============================================================================

/// Exception for bad schema definitions.
///
/// Ported from `BadSchemaException.java`.
#[derive(Debug, Error)]
#[error("Bad schema: {message}")]
pub struct BadSchemaException {
    /// The error message.
    pub message: String,
    /// The schema name, if known.
    pub schema_name: Option<String>,
}

impl BadSchemaException {
    /// Create a new exception.
    pub fn new(message: String) -> Self {
        Self {
            message,
            schema_name: None,
        }
    }

    /// Create with schema name.
    pub fn with_schema(mut self, name: String) -> Self {
        self.schema_name = Some(name);
        self
    }
}

// ============================================================================
// Time Schedule: AbstractStep and SkipStep
// ============================================================================

/// Base trait for schedule steps.
///
/// Ported from `AbstractStep.java`.
pub trait ScheduleStepTrait: std::fmt::Debug {
    /// The snap at which this step occurs.
    fn snap(&self) -> i64;

    /// The thread key for this step.
    fn thread_key(&self) -> Option<i64>;

    /// Whether this step is a skip.
    fn is_skip(&self) -> bool {
        false
    }
}

/// A step that skips execution (used in scheduling).
///
/// Ported from `SkipStep.java`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkipStep {
    /// The snap to skip to.
    pub snap: i64,
    /// The thread key.
    pub thread_key: Option<i64>,
}

impl SkipStep {
    /// Create a new skip step.
    pub fn new(snap: i64) -> Self {
        Self {
            snap,
            thread_key: None,
        }
    }

    /// Set the thread key.
    pub fn with_thread(mut self, thread_key: i64) -> Self {
        self.thread_key = Some(thread_key);
        self
    }
}

impl ScheduleStepTrait for SkipStep {
    fn snap(&self) -> i64 {
        self.snap
    }

    fn thread_key(&self) -> Option<i64> {
        self.thread_key
    }

    fn is_skip(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bad_schema_exception() {
        let ex = BadSchemaException::new("invalid field".into())
            .with_schema("MySchema".into());
        assert_eq!(ex.message, "invalid field");
        assert_eq!(ex.schema_name, Some("MySchema".into()));
    }

    #[test]
    fn test_skip_step() {
        let step = SkipStep::new(42).with_thread(1);
        assert_eq!(step.snap(), 42);
        assert!(step.is_skip());
        assert_eq!(step.thread_key(), Some(1));
    }

    #[test]
    fn test_memory_region_info() {
        let info = MemoryRegionInfo {
            name: ".text".into(),
            offset_min: 0x400000,
            offset_max: 0x401000,
            readable: true,
            writable: false,
            executable: true,
        };
        assert_eq!(info.name, ".text");
        assert!(info.executable);
    }

    #[test]
    fn test_reference_info() {
        let info = ReferenceInfo {
            id: 1,
            from_offset: 0x1000,
            to_offset: 0x2000,
            ref_type: "jump".into(),
            operand_index: 0,
        };
        assert_eq!(info.from_offset, 0x1000);
    }

    #[test]
    fn test_thread_info() {
        let info = ThreadInfo {
            id: 1,
            name: "main".into(),
            lifespan: Lifespan::span(0, 100),
            process_id: 1,
        };
        assert_eq!(info.name, "main");
    }

    #[test]
    fn test_static_mapping_info() {
        let info = StaticMappingInfo {
            id: 1,
            program_url: "file:///tmp/test".into(),
            program_min: 0x1000,
            program_max: 0x2000,
            trace_min: 0x400000,
            trace_max: 0x401000,
            lifespan: Lifespan::span(0, 100),
        };
        assert_eq!(info.program_url, "file:///tmp/test");
    }
}
