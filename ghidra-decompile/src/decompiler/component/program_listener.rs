//! Program change listener for the decompiler component.
//!
//! Ports `ghidra.app.decompiler.component.DecompilerProgramListener`.

/// Types of program changes the decompiler cares about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProgramChangeKind {
    /// A function was added.
    FunctionAdded,
    /// A function was removed.
    FunctionRemoved,
    /// A function's body changed.
    FunctionBodyChanged,
    /// A function's name changed.
    FunctionRenamed,
    /// A function's signature changed.
    FunctionSignatureChanged,
    /// Memory was changed.
    MemoryChanged,
    /// A bookmark was added/removed.
    BookmarkChanged,
    /// A comment was added/changed/removed.
    CommentChanged,
    /// Equate changed.
    EquateChanged,
    /// Symbol added/changed/removed.
    SymbolChanged,
    /// The program was saved.
    Saved,
    /// The program was closed.
    Closed,
}

/// A change event in the program.
#[derive(Debug, Clone)]
pub struct ProgramChangeEvent {
    /// The type of change.
    pub kind: ProgramChangeKind,
    /// The address associated with the change (if applicable).
    pub address: Option<u64>,
    /// The function entry point (if applicable).
    pub function_entry: Option<u64>,
}

impl ProgramChangeEvent {
    /// Create a new event.
    pub fn new(kind: ProgramChangeKind) -> Self {
        Self {
            kind,
            address: None,
            function_entry: None,
        }
    }

    /// Create with a function entry.
    pub fn for_function(kind: ProgramChangeKind, function_entry: u64) -> Self {
        Self {
            kind,
            address: None,
            function_entry: Some(function_entry),
        }
    }

    /// Check if this event affects a specific function.
    pub fn affects_function(&self, function_entry: u64) -> bool {
        self.function_entry == Some(function_entry)
    }

    /// Check if this event requires re-decompilation.
    pub fn requires_redecompile(&self) -> bool {
        matches!(
            self.kind,
            ProgramChangeKind::FunctionBodyChanged
                | ProgramChangeKind::FunctionSignatureChanged
                | ProgramChangeKind::MemoryChanged
                | ProgramChangeKind::CommentChanged
                | ProgramChangeKind::EquateChanged
        )
    }
}

/// Trait for receiving program change notifications.
pub trait DecompilerProgramListener: Send + Sync {
    /// Called when the program changes.
    fn program_changed(&self, event: &ProgramChangeEvent);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_requires_redecompile() {
        let e = ProgramChangeEvent::for_function(ProgramChangeKind::FunctionBodyChanged, 0x1000);
        assert!(e.requires_redecompile());
        assert!(e.affects_function(0x1000));
        assert!(!e.affects_function(0x2000));
    }

    #[test]
    fn test_event_saved_not_redecompile() {
        let e = ProgramChangeEvent::new(ProgramChangeKind::Saved);
        assert!(!e.requires_redecompile());
    }
}
