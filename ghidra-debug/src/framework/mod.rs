//! Framework utilities ported from Ghidra's Framework-TraceModeling support packages.
//!
//! Provides:
//! - `event_queues`: DomainObjectEventQueues for managing trace change event dispatch.
//! - `domain_object_event_queues`: Full DomainObjectEventQueues implementation with
//!   private queue support, event enable/disable, and listener management.
//! - `gspan_field`: GSpanField widget model for span display in docking components.

pub mod byte_cache;
pub mod domain_object_event_queues;
pub mod event_queues;
pub mod gspan_field;
