//! Delete-function command -- standalone entry point.
//!
//! Re-exports [`DeleteFunctionCmd`] from the parent `function` module
//! for direct use as a single-file import.
//!
//! Ported from `ghidra.app.cmd.function.DeleteFunctionCmd`.

pub use super::DeleteFunctionCmd;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_delete_function() {
        let cmd = DeleteFunctionCmd::new(0x401000);
        assert!(cmd.apply_to("test"));
    }

    #[test]
    fn test_delete_function_debug() {
        let cmd = DeleteFunctionCmd::new(0x402000);
        let dbg = format!("{:?}", cmd);
        assert!(dbg.contains("DeleteFunctionCmd"));
    }
}
