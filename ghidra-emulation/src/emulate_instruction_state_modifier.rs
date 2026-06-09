//! EmulateInstructionStateModifier: language-specific emulation state modifier.
//!
//! Ported from Java: `ghidra.pcode.emulate.EmulateInstructionStateModifier`.
//!
//! This defines a language-specific handler to assist emulation with adjusting
//! the current execution state and providing support for custom pcodeops
//! (i.e., CALLOTHER). Processor-specific implementations (e.g., x86, ARM)
//! provide custom behaviors for architecture-specific operations like flag
//! updates, coprocessor register access, etc.

use ghidra_core::addr::Address;
use ghidra_core::program::lang::Language;
use ghidra_decompile::pcode::PcodeOperation;
use std::collections::HashMap;

use super::break_table::EmulateContext;

/// Trait for a custom CALLOTHER pcode operation behavior.
///
/// Each implementation handles a specific user-defined pcode op.
/// Ported from Java: `ghidra.pcode.emulate.callother.OpBehaviorOther`.
pub trait PcodeOpBehaviorOther: std::fmt::Debug {
    /// Evaluate the custom pcode operation.
    ///
    /// The emulator context provides access to registers and memory.
    /// The first input (the userop index) is stripped before passing.
    ///
    /// Returns `true` if the operation was handled, `false` otherwise.
    fn evaluate(
        &self,
        emu: &mut dyn EmulateContext,
        output: Option<&ghidra_decompile::pcode::Varnode>,
        inputs: &[ghidra_decompile::pcode::Varnode],
    ) -> bool;
}

/// Language-specific handler for adjusting emulation state.
///
/// The implementation provides a mechanism for:
/// - Registering custom pcode op behaviors for CALLOTHER instructions
/// - Callbacks before the first instruction is executed (initial setup)
/// - Callbacks after each instruction is executed (context/state updates)
///
/// Ported from Java: `ghidra.pcode.emulate.EmulateInstructionStateModifier`
/// (deprecated since 12.1 in favor of `PcodeUseropLibrary`).
pub struct EmulateInstructionStateModifier {
    /// The processor language.
    language: Language,
    /// Map from userop index to custom pcode op behavior.
    pcode_op_map: HashMap<u64, Box<dyn PcodeOpBehaviorOther>>,
}

impl std::fmt::Debug for EmulateInstructionStateModifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EmulateInstructionStateModifier")
            .field("language", &self.language.name)
            .field("pcode_op_count", &self.pcode_op_map.len())
            .finish()
    }
}

impl EmulateInstructionStateModifier {
    /// Create a new state modifier for the given language.
    pub fn new(language: Language) -> Self {
        Self {
            language,
            pcode_op_map: HashMap::new(),
        }
    }

    /// Get the processor language.
    pub fn language(&self) -> &Language {
        &self.language
    }

    /// Register a pcodeop behavior corresponding to a CALLOTHER opcode.
    ///
    /// The `op_name` must be a user-defined pcode op name known to the
    /// language (defined via "define pcodeop" in the SLEIGH specification).
    ///
    /// # Errors
    /// Returns an error if the name is not a known user-defined pcode op.
    pub fn register_pcode_op_behavior(
        &mut self,
        op_name: &str,
        behavior: Box<dyn PcodeOpBehaviorOther>,
    ) -> Result<(), String> {
        let index = self
            .find_userop_index(op_name)
            .ok_or_else(|| format!("Undefined pcodeop name: {}", op_name))?;

        self.pcode_op_map.insert(index, behavior);
        Ok(())
    }

    /// Execute a CALLOTHER op.
    ///
    /// Looks up the registered behavior for the userop index (first input of
    /// the op) and evaluates it. Returns `true` if a registered behavior was
    /// found and executed, `false` if no behavior is registered for this op.
    pub fn execute_call_other(
        &self,
        emu: &mut dyn EmulateContext,
        op: &PcodeOperation,
    ) -> bool {
        let userop_index = match op.inputs.first() {
            Some(vn) => vn.offset,
            None => return false,
        };

        let behavior = match self.pcode_op_map.get(&userop_index) {
            Some(b) => b,
            None => return false,
        };

        // Strip off the first input (userop index) before passing to behavior
        let call_other_inputs = &op.inputs[1..];
        behavior.evaluate(emu, op.output.as_ref(), call_other_inputs)
    }

    /// Callback invoked immediately before the first instruction is executed.
    ///
    /// This permits any language-specific initializations to be performed.
    /// Override in processor-specific implementations.
    pub fn initial_execute_callback(
        &mut self,
        emu: &mut dyn EmulateContext,
        current_address: &Address,
    ) {
        let _ = (emu, current_address);
        // Default: no-op
    }

    /// Callback invoked immediately following execution of an instruction.
    ///
    /// One use is to modify the flowing/future context state.
    /// Override in processor-specific implementations.
    pub fn post_execute_callback(
        &mut self,
        emu: &mut dyn EmulateContext,
        last_execute_address: &Address,
        current_address: &Address,
    ) {
        let _ = (emu, last_execute_address, current_address);
        // Default: no-op
    }

    /// Get the map of registered pcode userop behaviors (by index).
    pub fn pcode_op_map(&self) -> &HashMap<u64, Box<dyn PcodeOpBehaviorOther>> {
        &self.pcode_op_map
    }

    /// Get the number of registered pcode op behaviors.
    pub fn pcode_op_count(&self) -> usize {
        self.pcode_op_map.len()
    }

    /// Find the userop index for the given name.
    ///
    /// Returns `None` if the name is not found.
    fn find_userop_index(&self, _name: &str) -> Option<u64> {
        // In a full implementation, this would look up the language's
        // user-defined op names. For now, we use a hash-based approach.
        // Processor-specific subclasses should provide their own mapping.
        None
    }
}

/// Builder for constructing an [`EmulateInstructionStateModifier`] with
/// userop name-to-index mappings.
pub struct EmulateInstructionStateModifierBuilder {
    language: Language,
    userop_names: HashMap<String, u64>,
    behaviors: HashMap<u64, Box<dyn PcodeOpBehaviorOther>>,
}

impl EmulateInstructionStateModifierBuilder {
    /// Create a new builder.
    pub fn new(language: Language) -> Self {
        Self {
            language,
            userop_names: HashMap::new(),
            behaviors: HashMap::new(),
        }
    }

    /// Register a userop name-to-index mapping.
    pub fn with_userop_name(mut self, name: impl Into<String>, index: u64) -> Self {
        self.userop_names.insert(name.into(), index);
        self
    }

    /// Register a pcode op behavior by name.
    ///
    /// # Errors
    /// Returns an error if the name is not in the userop mapping.
    pub fn with_behavior(
        mut self,
        name: &str,
        behavior: Box<dyn PcodeOpBehaviorOther>,
    ) -> Result<Self, String> {
        let index = self
            .userop_names
            .get(name)
            .copied()
            .ok_or_else(|| format!("Undefined pcodeop name: {}", name))?;
        self.behaviors.insert(index, behavior);
        Ok(self)
    }

    /// Build the [`EmulateInstructionStateModifier`].
    pub fn build(self) -> EmulateInstructionStateModifier {
        EmulateInstructionStateModifier {
            language: self.language,
            pcode_op_map: self.behaviors,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ghidra_core::addr::{AddressFactory, AddressSpace, AddrSpaceType};
    use ghidra_core::program::lang::{Language, LanguageID};
    use ghidra_decompile::pcode::{OpCode, Varnode};

    fn test_language() -> Language {
        Language::new(
            LanguageID::new("test", "LE", 32, "default"),
            "test:LE:32:default",
            "1.0",
            0,
            "Test language",
            AddressFactory::new(),
        )
    }

    struct MockContext {
        addr: Address,
        registers: std::collections::HashMap<String, Vec<u8>>,
    }

    impl MockContext {
        fn new(addr: u64) -> Self {
            Self {
                addr: Address::new(addr),
                registers: std::collections::HashMap::new(),
            }
        }
    }

    impl EmulateContext for MockContext {
        fn execute_pcode_op(&mut self, _op: &PcodeOperation) {}
        fn get_execution_address(&self) -> Address {
            self.addr
        }
        fn get_register(&self, name: &str) -> Option<&[u8]> {
            self.registers.get(name).map(|v| v.as_slice())
        }
        fn set_register(&mut self, name: &str, value: &[u8]) {
            self.registers.insert(name.to_string(), value.to_vec());
        }
    }

    #[derive(Debug)]
    struct TestPcodeOp;

    impl PcodeOpBehaviorOther for TestPcodeOp {
        fn evaluate(
            &self,
            emu: &mut dyn EmulateContext,
            _output: Option<&Varnode>,
            _inputs: &[Varnode],
        ) -> bool {
            emu.set_register("test_result", &[1, 0, 0, 0]);
            true
        }
    }

    #[test]
    fn test_state_modifier_creation() {
        let lang = test_language();
        let modifier = EmulateInstructionStateModifier::new(lang);
        assert_eq!(modifier.pcode_op_count(), 0);
    }

    #[test]
    fn test_builder_with_userop_names() {
        let lang = test_language();
        let modifier = EmulateInstructionStateModifierBuilder::new(lang)
            .with_userop_name("my_op", 5)
            .build();

        assert_eq!(modifier.pcode_op_count(), 0); // no behaviors registered
    }

    #[test]
    fn test_builder_with_behavior() {
        let lang = test_language();
        let modifier = EmulateInstructionStateModifierBuilder::new(lang)
            .with_userop_name("my_op", 5)
            .with_behavior("my_op", Box::new(TestPcodeOp))
            .unwrap()
            .build();

        assert_eq!(modifier.pcode_op_count(), 1);
    }

    #[test]
    fn test_builder_bad_behavior_name() {
        let lang = test_language();
        let result = EmulateInstructionStateModifierBuilder::new(lang)
            .with_behavior("unknown", Box::new(TestPcodeOp));

        assert!(result.is_err());
    }

    #[test]
    fn test_execute_call_other_with_registered_behavior() {
        let lang = test_language();
        let modifier = EmulateInstructionStateModifierBuilder::new(lang)
            .with_userop_name("flag_op", 10)
            .with_behavior("flag_op", Box::new(TestPcodeOp))
            .unwrap()
            .build();

        let space = AddressSpace::new("unique", 8, false, AddrSpaceType::Unique, 0);
        let op = PcodeOperation::new_unannotated(
            OpCode::CALLOTHER,
            Some(Varnode::new(
                AddressSpace::new("register", 4, false, AddrSpaceType::Register, 2),
                0,
                4,
            )),
            vec![
                Varnode::new(space.clone(), 10, 8), // userop index
                Varnode::new(space, 42, 4),          // argument
            ],
        );

        let mut ctx = MockContext::new(0x1000);
        let handled = modifier.execute_call_other(&mut ctx, &op);
        assert!(handled);
        assert_eq!(ctx.get_register("test_result"), Some(&[1, 0, 0, 0][..]));
    }

    #[test]
    fn test_execute_call_other_unregistered() {
        let lang = test_language();
        let modifier = EmulateInstructionStateModifier::new(lang);

        let space = AddressSpace::new("unique", 8, false, AddrSpaceType::Unique, 0);
        let op = PcodeOperation::new_unannotated(
            OpCode::CALLOTHER,
            None,
            vec![Varnode::new(space, 99, 8)],
        );

        let mut ctx = MockContext::new(0x1000);
        let handled = modifier.execute_call_other(&mut ctx, &op);
        assert!(!handled);
    }

    #[test]
    fn test_initial_execute_callback_is_noop() {
        let lang = test_language();
        let mut modifier = EmulateInstructionStateModifier::new(lang);
        let mut ctx = MockContext::new(0x1000);
        // Should not panic
        modifier.initial_execute_callback(&mut ctx, &Address::new(0x1000));
    }

    #[test]
    fn test_post_execute_callback_is_noop() {
        let lang = test_language();
        let mut modifier = EmulateInstructionStateModifier::new(lang);
        let mut ctx = MockContext::new(0x2000);
        // Should not panic
        modifier.post_execute_callback(&mut ctx, &Address::new(0x1000), &Address::new(0x2000));
    }
}
