//! Domain event types for the function window.
//!
//! Ported from Ghidra's `DomainObjectListenerBuilder` pattern used in
//! `FunctionWindowPlugin.createDomainObjectListener()`.
//!
//! These events model the domain-object changes that the function window
//! reacts to: program lifecycle, memory layout changes, code changes,
//! function CRUD, and symbol changes.

use super::FunctionRef;

/// High-level domain events that the function window listens for.
///
/// These correspond to the event categories in the Java
/// `DomainObjectListenerBuilder` chain:
///
/// ```text
/// .any(RESTORED, MEMORY_BLOCK_MOVED, MEMORY_BLOCK_REMOVED).terminate(provider::reload)
/// .any(CODE_ADDED, CODE_REMOVED).call(swingMgr::update)
/// .each(FUNCTION_ADDED).call(this::functionAdded)
/// .each(FUNCTION_REMOVED).call(this::functionRemoved)
/// .each(FUNCTION_CHANGED).call(this::functionChanged)
/// .each(SYMBOL_ADDED, SYMBOL_PRIMARY_STATE_CHANGED).call(this::symbolChanged)
/// .each(SYMBOL_RENAMED).call(this::symbolRenamed)
/// ```
#[derive(Debug, Clone)]
pub enum FunctionWindowEvent {
    /// Program was restored from disk or memory blocks were moved/removed.
    /// Triggers a full reload.
    Restored,

    /// A memory block was moved.
    MemoryBlockMoved {
        /// The old block name.
        old_name: String,
        /// The new block name.
        new_name: String,
    },

    /// A memory block was removed.
    MemoryBlockRemoved {
        /// The block name.
        name: String,
    },

    /// Code was added to the program (batch operation).
    CodeAdded,

    /// Code was removed from the program (batch operation).
    CodeRemoved,

    /// A function was added to the program.
    FunctionAdded(FunctionRef),

    /// A function was removed from the program.
    FunctionRemoved(FunctionRef),

    /// A function was changed (signature, body, etc.).
    FunctionChanged(FunctionRef),

    /// A symbol was added at an address.
    SymbolAdded {
        /// The symbol name.
        name: String,
        /// The address of the symbol.
        address: u64,
    },

    /// A symbol's primary state changed.
    SymbolPrimaryStateChanged {
        /// The symbol name.
        name: String,
        /// The address of the symbol.
        address: u64,
    },

    /// A symbol was renamed.
    SymbolRenamed {
        /// The old name.
        old_name: String,
        /// The new name.
        new_name: String,
        /// The address of the symbol.
        address: u64,
    },

    /// Program was closed.
    ProgramClosed,
}

impl FunctionWindowEvent {
    /// Whether this event requires a full model reload.
    pub fn requires_reload(&self) -> bool {
        matches!(
            self,
            Self::Restored
                | Self::MemoryBlockMoved { .. }
                | Self::MemoryBlockRemoved { .. }
        )
    }

    /// Whether this event should be batched (debounced) rather than
    /// applied immediately.
    pub fn is_batch_event(&self) -> bool {
        matches!(self, Self::CodeAdded | Self::CodeRemoved)
    }

    /// Whether this event is a function-level change that can be
    /// applied as an incremental update.
    pub fn is_incremental(&self) -> bool {
        matches!(
            self,
            Self::FunctionAdded(_)
                | Self::FunctionRemoved(_)
                | Self::FunctionChanged(_)
                | Self::SymbolAdded { .. }
                | Self::SymbolPrimaryStateChanged { .. }
                | Self::SymbolRenamed { .. }
        )
    }

    /// Extract the address from symbol events (for lookup).
    pub fn symbol_address(&self) -> Option<u64> {
        match self {
            Self::SymbolAdded { address, .. }
            | Self::SymbolPrimaryStateChanged { address, .. }
            | Self::SymbolRenamed { address, .. } => Some(*address),
            _ => None,
        }
    }

    /// Extract the function from function events.
    pub fn function(&self) -> Option<&FunctionRef> {
        match self {
            Self::FunctionAdded(f)
            | Self::FunctionRemoved(f)
            | Self::FunctionChanged(f) => Some(f),
            _ => None,
        }
    }
}

/// An event queue that buffers domain events and dispatches them.
///
/// This replaces the Java `SwingUpdateManager` pattern, providing
/// debounced/batched event delivery.
#[derive(Debug)]
pub struct EventQueue {
    /// Buffered events.
    pending: Vec<FunctionWindowEvent>,
    /// Batch interval in milliseconds.
    batch_interval_ms: u64,
    /// Whether a batch is pending.
    has_pending_batch: bool,
}

impl EventQueue {
    /// Create a new event queue with the given batch interval.
    pub fn new(batch_interval_ms: u64) -> Self {
        Self {
            pending: Vec::new(),
            batch_interval_ms,
            has_pending_batch: false,
        }
    }

    /// Push an event into the queue.
    pub fn push(&mut self, event: FunctionWindowEvent) {
        if event.requires_reload() {
            // Reload events supersede all pending incremental events.
            self.pending.clear();
            self.pending.push(event);
            self.has_pending_batch = false;
        } else if event.is_batch_event() {
            self.pending.push(event);
            self.has_pending_batch = true;
        } else {
            self.pending.push(event);
        }
    }

    /// Drain all pending events.
    pub fn drain(&mut self) -> Vec<FunctionWindowEvent> {
        self.has_pending_batch = false;
        std::mem::take(&mut self.pending)
    }

    /// Whether there are pending events.
    pub fn has_pending(&self) -> bool {
        !self.pending.is_empty()
    }

    /// Whether there is a batch (code add/remove) pending.
    pub fn has_pending_batch(&self) -> bool {
        self.has_pending_batch
    }

    /// Get the batch interval.
    pub fn batch_interval_ms(&self) -> u64 {
        self.batch_interval_ms
    }

    /// Clear all pending events.
    pub fn clear(&mut self) {
        self.pending.clear();
        self.has_pending_batch = false;
    }
}

impl Default for EventQueue {
    fn default() -> Self {
        Self::new(1000)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_func(id: u64, name: &str) -> FunctionRef {
        FunctionRef::new(id, name, super::super::Address::new(0x1000), "void f()")
    }

    #[test]
    fn test_event_requires_reload() {
        assert!(FunctionWindowEvent::Restored.requires_reload());
        assert!(FunctionWindowEvent::MemoryBlockMoved {
            old_name: "old".into(),
            new_name: "new".into(),
        }
        .requires_reload());
        assert!(FunctionWindowEvent::MemoryBlockRemoved {
            name: "block".into(),
        }
        .requires_reload());
        assert!(!FunctionWindowEvent::CodeAdded.requires_reload());
        assert!(!FunctionWindowEvent::FunctionAdded(make_func(1, "f")).requires_reload());
    }

    #[test]
    fn test_event_is_batch() {
        assert!(FunctionWindowEvent::CodeAdded.is_batch_event());
        assert!(FunctionWindowEvent::CodeRemoved.is_batch_event());
        assert!(!FunctionWindowEvent::Restored.is_batch_event());
    }

    #[test]
    fn test_event_is_incremental() {
        assert!(FunctionWindowEvent::FunctionAdded(make_func(1, "f")).is_incremental());
        assert!(FunctionWindowEvent::FunctionRemoved(make_func(1, "f")).is_incremental());
        assert!(FunctionWindowEvent::FunctionChanged(make_func(1, "f")).is_incremental());
        assert!(FunctionWindowEvent::SymbolRenamed {
            old_name: "a".into(),
            new_name: "b".into(),
            address: 0x1000,
        }
        .is_incremental());
        assert!(!FunctionWindowEvent::Restored.is_incremental());
    }

    #[test]
    fn test_event_symbol_address() {
        let event = FunctionWindowEvent::SymbolRenamed {
            old_name: "a".into(),
            new_name: "b".into(),
            address: 0x401000,
        };
        assert_eq!(event.symbol_address(), Some(0x401000));
        assert_eq!(FunctionWindowEvent::Restored.symbol_address(), None);
    }

    #[test]
    fn test_event_function() {
        let func = make_func(42, "test");
        let event = FunctionWindowEvent::FunctionAdded(func.clone());
        assert_eq!(event.function().unwrap().id, 42);
        assert!(FunctionWindowEvent::Restored.function().is_none());
    }

    #[test]
    fn test_event_queue_push_drain() {
        let mut queue = EventQueue::new(1000);
        assert!(!queue.has_pending());

        queue.push(FunctionWindowEvent::FunctionAdded(make_func(1, "f")));
        queue.push(FunctionWindowEvent::FunctionAdded(make_func(2, "g")));
        assert!(queue.has_pending());

        let events = queue.drain();
        assert_eq!(events.len(), 2);
        assert!(!queue.has_pending());
    }

    #[test]
    fn test_event_queue_reload_supersedes() {
        let mut queue = EventQueue::new(1000);
        queue.push(FunctionWindowEvent::FunctionAdded(make_func(1, "f")));
        queue.push(FunctionWindowEvent::CodeAdded);
        queue.push(FunctionWindowEvent::Restored);

        let events = queue.drain();
        assert_eq!(events.len(), 1);
        assert!(events[0].requires_reload());
    }

    #[test]
    fn test_event_queue_batch_tracking() {
        let mut queue = EventQueue::new(1000);
        assert!(!queue.has_pending_batch());

        queue.push(FunctionWindowEvent::CodeAdded);
        assert!(queue.has_pending_batch());

        queue.drain();
        assert!(!queue.has_pending_batch());
    }

    #[test]
    fn test_event_queue_clear() {
        let mut queue = EventQueue::new(1000);
        queue.push(FunctionWindowEvent::CodeAdded);
        queue.push(FunctionWindowEvent::FunctionAdded(make_func(1, "f")));
        queue.clear();
        assert!(!queue.has_pending());
        assert!(!queue.has_pending_batch());
    }

    #[test]
    fn test_event_queue_default() {
        let queue = EventQueue::default();
        assert_eq!(queue.batch_interval_ms(), 1000);
    }
}
