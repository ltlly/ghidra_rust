//! BreakTableCallBack: a basic breakpoint table implementation.
//!
//! Ported from Java: `ghidra.pcode.emulate.BreakTableCallBack`.
//!
//! This object allows breakpoints to be registered via either:
//! - [`register_pcode_callback`] -- for pcode-operation-based breakpoints
//! - [`register_address_callback`] -- for address-based breakpoints
//!
//! Breakpoints are stored in hash maps, and the core [`BreakTable`] methods
//! search these containers.

use ghidra_core::addr::Address;
use ghidra_decompile::pcode::PcodeOperation;
use std::collections::HashMap;

use super::break_table::{BreakTable, EmulateContext};

/// Default pcode callback name: matches all user-defined pcode ops.
pub const DEFAULT_NAME: &str = "*";

/// A callback function for breakpoints.
///
/// The callback returns `true` if the breakpoint action should replace
/// the normal operation of the pcode op or machine instruction.
pub trait BreakCallBack: std::fmt::Debug {
    /// Invoked when the breakpoint fires for a pcode operation.
    ///
    /// Returns `true` if the normal pcode op action should be skipped.
    fn pcode_callback(&mut self, op: &PcodeOperation, emu: &mut dyn EmulateContext) -> bool {
        let _ = (op, emu);
        false
    }

    /// Invoked when the breakpoint fires for a machine address.
    ///
    /// Returns `true` if the machine instruction should be skipped.
    fn address_callback(&mut self, addr: &Address, emu: &mut dyn EmulateContext) -> bool {
        let _ = (addr, emu);
        false
    }
}

/// A basic instantiation of a breakpoint table.
///
/// Breakpoints are stored in hash maps keyed by address (for address
/// callbacks) or by pcode userop index (for pcode callbacks). The core
/// [`BreakTable`] methods search in these containers.
///
/// Ported from Java: `ghidra.pcode.emulate.BreakTableCallBack` (deprecated
/// since 12.1).
pub struct BreakTableCallBack {
    /// Address-based breakpoints.
    address_callbacks: HashMap<Address, Box<dyn BreakCallBack>>,
    /// Pcode userop-index-based breakpoints.
    pcode_callbacks: HashMap<u64, Box<dyn BreakCallBack>>,
    /// Default pcode callback (matches all userops not individually registered).
    default_pcode_callback: Option<Box<dyn BreakCallBack>>,
    /// Userop name-to-index mapping.
    userop_names: HashMap<String, u64>,
}

impl std::fmt::Debug for BreakTableCallBack {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BreakTableCallBack")
            .field("address_callbacks_count", &self.address_callbacks.len())
            .field("pcode_callbacks_count", &self.pcode_callbacks.len())
            .field("has_default_pcode_callback", &self.default_pcode_callback.is_some())
            .finish()
    }
}

impl BreakTableCallBack {
    /// Create a new break table callback with no registered userop names.
    pub fn new() -> Self {
        Self {
            address_callbacks: HashMap::new(),
            pcode_callbacks: HashMap::new(),
            default_pcode_callback: None,
            userop_names: HashMap::new(),
        }
    }

    /// Create a new break table callback with userop name-to-index mapping.
    pub fn with_userop_names(userop_names: HashMap<String, u64>) -> Self {
        Self {
            address_callbacks: HashMap::new(),
            pcode_callbacks: HashMap::new(),
            default_pcode_callback: None,
            userop_names,
        }
    }

    /// Register a pcode callback by userop name.
    ///
    /// If the name is [`DEFAULT_NAME`], the callback becomes the default
    /// for all user-defined pcode ops that do not have an explicit callback.
    ///
    /// # Errors
    /// Returns an error if the name is not found in the userop mapping
    /// and is not the default name.
    pub fn register_pcode_callback(
        &mut self,
        name: &str,
        func: Box<dyn BreakCallBack>,
    ) -> Result<(), String> {
        if name == DEFAULT_NAME {
            self.default_pcode_callback = Some(func);
            return Ok(());
        }

        let index = self
            .userop_names
            .get(name)
            .copied()
            .ok_or_else(|| {
                let available: Vec<&str> = self.userop_names.keys().map(|s| s.as_str()).collect();
                format!(
                    "Bad userop name: {}\nMust be one of:\n{}",
                    name,
                    available.join(", ")
                )
            })?;

        self.pcode_callbacks.insert(index, func);
        Ok(())
    }

    /// Unregister the pcode callback for the given userop name.
    ///
    /// # Errors
    /// Returns an error if the name is not found in the userop mapping.
    pub fn unregister_pcode_callback(&mut self, name: &str) -> Result<(), String> {
        if name == DEFAULT_NAME {
            self.default_pcode_callback = None;
            return Ok(());
        }

        let index = self
            .userop_names
            .get(name)
            .copied()
            .ok_or_else(|| format!("Bad userop name: {}", name))?;

        self.pcode_callbacks.remove(&index);
        Ok(())
    }

    /// Register an address callback at the given address.
    pub fn register_address_callback(&mut self, addr: Address, func: Box<dyn BreakCallBack>) {
        self.address_callbacks.insert(addr, func);
    }

    /// Unregister the address callback at the given address.
    pub fn unregister_address_callback(&mut self, addr: &Address) {
        self.address_callbacks.remove(addr);
    }

    /// Get the number of registered address callbacks.
    pub fn address_callback_count(&self) -> usize {
        self.address_callbacks.len()
    }

    /// Get the number of registered pcode callbacks (excluding default).
    pub fn pcode_callback_count(&self) -> usize {
        self.pcode_callbacks.len()
    }

    /// Check if a default pcode callback is registered.
    pub fn has_default_pcode_callback(&self) -> bool {
        self.default_pcode_callback.is_some()
    }
}

impl Default for BreakTableCallBack {
    fn default() -> Self {
        Self::new()
    }
}

impl BreakTable for BreakTableCallBack {
    fn set_emulate(&mut self, _emu_context: &dyn EmulateContext) {
        // In the Java version, this sets the emulator on each callback.
        // In Rust, the emulator reference is passed to each callback method
        // directly, so this is a no-op.
    }

    fn do_pcode_op_break(&mut self, curop: &PcodeOperation) -> bool {
        // The pcode userop index is the first input's offset.
        let val = curop.inputs.first().map(|vn| vn.offset).unwrap_or(0);

        if let Some(_callback) = self.pcode_callbacks.get_mut(&val) {
            // We need an EmulateContext to call the callback.
            // In the legacy framework, the emulator is set beforehand.
            // Here we use a null context pattern -- the caller should
            // provide context via a wrapper if needed.
            return false; // Placeholder: real usage requires context
        }

        if let Some(ref mut _default_cb) = self.default_pcode_callback {
            return false; // Placeholder: real usage requires context
        }

        false
    }

    fn do_address_break(&mut self, addr: &Address) -> bool {
        if let Some(callback) = self.address_callbacks.get_mut(addr) {
            let _ = callback;
            return false; // Placeholder: real usage requires context
        }
        false
    }
}

/// A context-aware wrapper around [`BreakTableCallBack`] that carries
/// an emulator reference for callback invocation.
///
/// This provides the actual `do_pcode_op_break` and `do_address_break`
/// implementations that forward the emulation context to callbacks.
pub struct ContextualBreakTable {
    inner: BreakTableCallBack,
}

impl std::fmt::Debug for ContextualBreakTable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ContextualBreakTable")
            .field("inner", &self.inner)
            .finish()
    }
}

impl ContextualBreakTable {
    /// Create a new contextual break table.
    pub fn new(inner: BreakTableCallBack) -> Self {
        Self { inner }
    }

    /// Get a reference to the inner break table.
    pub fn inner(&self) -> &BreakTableCallBack {
        &self.inner
    }

    /// Get a mutable reference to the inner break table.
    pub fn inner_mut(&mut self) -> &mut BreakTableCallBack {
        &mut self.inner
    }

    /// Invoke pcode op breakpoints with emulation context.
    pub fn do_pcode_op_break_with_context(
        &mut self,
        curop: &PcodeOperation,
        emu: &mut dyn EmulateContext,
    ) -> bool {
        let val = curop.inputs.first().map(|vn| vn.offset).unwrap_or(0);

        if let Some(callback) = self.inner.pcode_callbacks.get_mut(&val) {
            return callback.pcode_callback(curop, emu);
        }

        if let Some(ref mut default_cb) = self.inner.default_pcode_callback {
            return default_cb.pcode_callback(curop, emu);
        }

        false
    }

    /// Invoke address breakpoints with emulation context.
    pub fn do_address_break_with_context(
        &mut self,
        addr: &Address,
        emu: &mut dyn EmulateContext,
    ) -> bool {
        if let Some(callback) = self.inner.address_callbacks.get_mut(addr) {
            return callback.address_callback(addr, emu);
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ghidra_core::addr::{AddressSpace, AddrSpaceType};
    use ghidra_decompile::pcode::{OpCode, Varnode};

    struct MockContext {
        addr: Address,
        halted: bool,
    }

    impl MockContext {
        fn new(addr: u64) -> Self {
            Self {
                addr: Address::new(addr),
                halted: false,
            }
        }
    }

    impl EmulateContext for MockContext {
        fn execute_pcode_op(&mut self, _op: &PcodeOperation) {}
        fn get_execution_address(&self) -> Address {
            self.addr
        }
        fn get_register(&self, _name: &str) -> Option<&[u8]> {
            None
        }
        fn set_register(&mut self, _name: &str, _value: &[u8]) {}
    }

    #[derive(Debug)]
    struct HaltCallback;

    impl BreakCallBack for HaltCallback {
        fn pcode_callback(&mut self, _op: &PcodeOperation, emu: &mut dyn EmulateContext) -> bool {
            let _ = emu;
            true // replace normal behavior
        }

        fn address_callback(&mut self, _addr: &Address, emu: &mut dyn EmulateContext) -> bool {
            let _ = emu;
            true // replace normal behavior
        }
    }

    #[derive(Debug)]
    struct ContinueCallback;

    impl BreakCallBack for ContinueCallback {
        fn pcode_callback(&mut self, _op: &PcodeOperation, _emu: &mut dyn EmulateContext) -> bool {
            false // do not replace
        }

        fn address_callback(&mut self, _addr: &Address, _emu: &mut dyn EmulateContext) -> bool {
            false // do not replace
        }
    }

    #[test]
    fn test_break_table_callback_creation() {
        let table = BreakTableCallBack::new();
        assert_eq!(table.address_callback_count(), 0);
        assert_eq!(table.pcode_callback_count(), 0);
        assert!(!table.has_default_pcode_callback());
    }

    #[test]
    fn test_register_address_callback() {
        let mut table = BreakTableCallBack::new();
        table.register_address_callback(Address::new(0x1000), Box::new(HaltCallback));
        assert_eq!(table.address_callback_count(), 1);
    }

    #[test]
    fn test_unregister_address_callback() {
        let mut table = BreakTableCallBack::new();
        table.register_address_callback(Address::new(0x1000), Box::new(HaltCallback));
        table.unregister_address_callback(&Address::new(0x1000));
        assert_eq!(table.address_callback_count(), 0);
    }

    #[test]
    fn test_register_pcode_callback_by_name() {
        let mut names = HashMap::new();
        names.insert("my_userop".to_string(), 0u64);

        let mut table = BreakTableCallBack::with_userop_names(names);
        table
            .register_pcode_callback("my_userop", Box::new(HaltCallback))
            .unwrap();
        assert_eq!(table.pcode_callback_count(), 1);
    }

    #[test]
    fn test_register_pcode_callback_bad_name() {
        let mut table = BreakTableCallBack::new();
        let result = table.register_pcode_callback("nonexistent", Box::new(HaltCallback));
        assert!(result.is_err());
    }

    #[test]
    fn test_register_default_pcode_callback() {
        let mut table = BreakTableCallBack::new();
        table
            .register_pcode_callback(DEFAULT_NAME, Box::new(HaltCallback))
            .unwrap();
        assert!(table.has_default_pcode_callback());
    }

    #[test]
    fn test_contextual_address_break() {
        let mut table = BreakTableCallBack::new();
        table.register_address_callback(Address::new(0x1000), Box::new(HaltCallback));

        let mut ctx_table = ContextualBreakTable::new(table);
        let mut ctx = MockContext::new(0x1000);

        assert!(ctx_table.do_address_break_with_context(&Address::new(0x1000), &mut ctx));
        assert!(!ctx_table.do_address_break_with_context(&Address::new(0x2000), &mut ctx));
    }

    #[test]
    fn test_contextual_pcode_break() {
        let mut names = HashMap::new();
        names.insert("my_op".to_string(), 42u64);

        let mut table = BreakTableCallBack::with_userop_names(names);
        table
            .register_pcode_callback("my_op", Box::new(HaltCallback))
            .unwrap();

        let mut ctx_table = ContextualBreakTable::new(table);
        let mut ctx = MockContext::new(0x1000);

        let space = AddressSpace::new("unique", 8, false, AddrSpaceType::Unique, 0);
        let op = PcodeOperation::new_unannotated(
            OpCode::CALLOTHER,
            None,
            vec![Varnode::new(space, 42, 8)],
        );

        assert!(ctx_table.do_pcode_op_break_with_context(&op, &mut ctx));

        let space2 = AddressSpace::new("unique", 8, false, AddrSpaceType::Unique, 0);
        let op2 = PcodeOperation::new_unannotated(
            OpCode::CALLOTHER,
            None,
            vec![Varnode::new(space2, 99, 8)],
        );

        assert!(!ctx_table.do_pcode_op_break_with_context(&op2, &mut ctx));
    }
}
