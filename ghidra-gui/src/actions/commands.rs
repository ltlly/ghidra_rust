//! Action command types and the shared command queue.
//!
//! Actions built by this module push [`ActionCommand`] values into a shared
//! [`CommandQueue`]. The application loop drains the queue each frame and
//! carries out the corresponding work.

use ghidra_core::addr::Address;
use std::sync::{Arc, Mutex};

// ── ActionCommand ────────────────────────────────────────────────────────────

/// Every high-level operation a DockingAction can request.
///
/// The GUI application reads these commands from the shared queue and
/// executes the corresponding logic (modifying the program, updating views,
/// launching dialogs, etc.).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ActionCommand {
    // ── Edit ─────────────────────────────────────────────────────────────
    /// Undo the last operation.
    Undo,
    /// Redo the previously undone operation.
    Redo,
    /// Cut the current selection to the clipboard.
    Cut,
    /// Copy the current selection to the clipboard.
    Copy,
    /// Paste clipboard contents at the cursor.
    Paste,
    /// Delete the current selection.
    Delete,
    /// Select everything in the active view.
    SelectAll,
    /// Open the Find dialog.
    Find,
    /// Open the Replace dialog.
    Replace,

    // ── Navigation ───────────────────────────────────────────────────────
    /// Open the Go-To-Address dialog.
    GoTo,
    /// Navigate backward in history.
    Back,
    /// Navigate forward in history.
    Forward,
    /// Jump to the next function definition.
    NextFunction,
    /// Jump to the previous function definition.
    PreviousFunction,
    /// Move cursor to the next instruction.
    NextInstruction,
    /// Move cursor to the previous instruction.
    PreviousInstruction,
    /// Navigate to the next labelled address.
    NextLabel,
    /// Navigate to the next cross-reference target.
    NextReference,
    /// Navigate to the program entry point.
    GoToEntryPoint,
    /// Navigate to an external location.
    GoToExternalLocation,

    // ── Analysis ─────────────────────────────────────────────────────────
    /// Run auto-analysis on the entire program.
    AutoAnalyze,
    /// Run a single analysis pass (one-shot).
    AnalyzeOneShot,
    /// Disassemble starting at the cursor address.
    Disassemble,
    /// Create a function at the cursor address.
    CreateFunction,
    /// Create a data item at the cursor address.
    CreateData,
    /// Create a label at the cursor address.
    CreateLabel,
    /// Create or edit a comment at the cursor address.
    CreateComment,
    /// Clear / undefine code bytes at the cursor.
    ClearCodeBytes,
    /// Define a specific data type at the cursor.
    DefineData(String),
    /// Edit the function signature at the cursor.
    EditFunctionSignature,
    /// Rename a local variable in the current function.
    RenameVariable,
    /// Set a register value at the cursor.
    SetRegisterValue,

    // ── Search ───────────────────────────────────────────────────────────
    /// Search raw memory bytes for a pattern.
    SearchMemory,
    /// Search program text (disassembly + labels + comments).
    SearchProgramText,
    /// Search for printable strings.
    SearchForStrings,
    /// Search for direct address references.
    SearchForDirectReferences,
    /// Search for instruction byte patterns.
    SearchForInstructionPatterns,
    /// Search for address tables.
    SearchForAddressTables,
    /// Jump to the next search hit.
    SearchNext,
    /// Jump to the previous search hit.
    SearchPrevious,

    // ── Tools ────────────────────────────────────────────────────────────
    /// Show the Program Differences dialog.
    ProgramDifferences,
    /// Show the Function Call Graph.
    FunctionGraph,
    /// Toggle the Data Type Manager panel.
    DataTypeManager,
    /// Show the Memory Map window.
    MemoryMap,
    /// Show the Register Manager window.
    RegisterManager,
    /// Show the Script Manager window.
    ScriptManager,

    // ── Help ─────────────────────────────────────────────────────────────
    /// Show the About dialog.
    About,
    /// Show the Key Bindings reference.
    KeyBindings,
    /// Search the Ghidra help system.
    SearchHelp,
    /// Open the Ghidra Help table of contents.
    GhidraHelp,
}

// ── CommandQueue ─────────────────────────────────────────────────────────────

/// A thread-safe FIFO queue of [`ActionCommand`] values.
///
/// Actions push commands into this queue, and the application loop drains
/// and handles them once per frame.
pub type CommandQueue = Arc<Mutex<Vec<ActionCommand>>>;

/// Create a new, empty command queue.
pub fn new_command_queue() -> CommandQueue {
    Arc::new(Mutex::new(Vec::new()))
}

/// Push a command onto the queue.
pub fn enqueue(queue: &CommandQueue, cmd: ActionCommand) {
    if let Ok(mut q) = queue.lock() {
        q.push(cmd);
    }
}

/// Drain all pending commands from the queue, returning them in FIFO order.
pub fn drain(queue: &CommandQueue) -> Vec<ActionCommand> {
    match queue.lock() {
        Ok(mut q) => std::mem::take(&mut *q),
        Err(_) => Vec::new(),
    }
}
