//! Instruction panel listener -- ported from `InstructionPanelListener.java`.
//!
//! Defines the callback interface for instruction panel events in the
//! references viewer.  When the user navigates instructions in the
//! reference panel, implementors are notified so they can update the
//! main listing position.
//!
//! # Example
//!
//! ```
//! use ghidra_features::base::references::instruction_listener::*;
//!
//! #[derive(Debug)]
//! struct MyListener;
//!
//! impl InstructionPanelListener for MyListener {
//!     fn on_instruction_selected(&self, addr: u64) {
//!         // update the listing position
//!     }
//!     fn on_references_changed(&self, count: usize) {
//!         // update the reference count display
//!     }
//! }
//!
//! let listener = MyListener;
//! listener.on_instruction_selected(0x401000);
//! listener.on_references_changed(3);
//! ```

/// Callback interface for instruction panel events.
///
/// Ported from `InstructionPanelListener.java`.  Implementors receive
/// notifications when the user selects an instruction in the reference
/// panel or when the set of references displayed changes.
pub trait InstructionPanelListener: std::fmt::Debug {
    /// Called when the user selects an instruction in the panel.
    ///
    /// The `address` is the address of the selected instruction.
    fn on_instruction_selected(&self, address: u64);

    /// Called when the set of displayed references changes.
    ///
    /// The `count` is the new number of references displayed.
    fn on_references_changed(&self, count: usize);
}

/// A no-op listener that does nothing on events.
#[derive(Debug)]
pub struct DummyInstructionPanelListener;

impl InstructionPanelListener for DummyInstructionPanelListener {
    fn on_instruction_selected(&self, _address: u64) {}
    fn on_references_changed(&self, _count: usize) {}
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug)]
    struct RecordingListener {
        last_address: std::sync::Mutex<Option<u64>>,
        last_count: std::sync::Mutex<Option<usize>>,
    }

    impl RecordingListener {
        fn new() -> Self {
            Self {
                last_address: std::sync::Mutex::new(None),
                last_count: std::sync::Mutex::new(None),
            }
        }
    }

    impl InstructionPanelListener for RecordingListener {
        fn on_instruction_selected(&self, address: u64) {
            *self.last_address.lock().unwrap() = Some(address);
        }
        fn on_references_changed(&self, count: usize) {
            *self.last_count.lock().unwrap() = Some(count);
        }
    }

    #[test]
    fn test_dummy_listener() {
        let listener = DummyInstructionPanelListener;
        listener.on_instruction_selected(0x401000);
        listener.on_references_changed(5);
        // no panic
    }

    #[test]
    fn test_recording_listener() {
        let listener = RecordingListener::new();
        listener.on_instruction_selected(0x401000);
        assert_eq!(*listener.last_address.lock().unwrap(), Some(0x401000));

        listener.on_references_changed(3);
        assert_eq!(*listener.last_count.lock().unwrap(), Some(3));
    }

    #[test]
    fn test_listener_multiple_calls() {
        let listener = RecordingListener::new();
        listener.on_instruction_selected(0x1000);
        listener.on_instruction_selected(0x2000);
        assert_eq!(*listener.last_address.lock().unwrap(), Some(0x2000));
    }

    #[test]
    fn test_dummy_listener_is_debug() {
        let listener = DummyInstructionPanelListener;
        let debug_str = format!("{:?}", listener);
        assert!(debug_str.contains("DummyInstructionPanelListener"));
    }
}
