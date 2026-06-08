//! CPU register definitions and management.
//!
//! This module re-exports the [`Register`], [`RegisterManager`],
//! [`RegisterValue`], and related types from the parent `lang` module,
//! providing a dedicated access path for register functionality.
//!
//! # Correspondence to Ghidra
//!
//! This is a direct translation of:
//! - `ghidra.program.model.lang.Register` — a CPU register with hierarchy and typing
//! - `ghidra.program.model.lang.RegisterManager` — register index and lookup
//! - `ghidra.program.model.lang.RegisterValue` — register value with mask
//!
//! The Java `Register` class tracks parent/child/base relationships via
//! object references. This Rust version uses string references for the
//! register hierarchy, with `RegisterManager` providing lookup by name,
//! address, and size.

// Re-export from the parent lang module.
pub use super::lang::{
    Register, RegisterBuilder, RegisterManager, RegisterSizeKey, RegisterTree, RegisterTypeFlags,
    RegisterValue, UnknownRegister,
};

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::addr::Address;

    #[test]
    fn test_register_type_flags_default() {
        let flags = RegisterTypeFlags::default();
        assert!(!flags.is_program_counter());
        assert!(!flags.is_stack_pointer());
        assert!(!flags.is_frame_pointer());
        assert!(!flags.is_processor_context());
        assert!(!flags.is_hidden());
        assert!(!flags.is_zero());
    }

    #[test]
    fn test_register_type_flags_setters() {
        let mut flags = RegisterTypeFlags::default();
        flags.set(RegisterTypeFlags::PC);
        assert!(flags.is_program_counter());
        flags.set(RegisterTypeFlags::SP);
        assert!(flags.is_stack_pointer());
        flags.set(RegisterTypeFlags::FP);
        assert!(flags.is_frame_pointer());
        flags.set(RegisterTypeFlags::CONTEXT);
        assert!(flags.is_processor_context());
    }

    #[test]
    fn test_register_value_basic() {
        let val = RegisterValue::new("RAX", 64, 0x42, false);
        assert_eq!(val.register_name, "RAX");
        assert!(val.has_value());
    }

    #[test]
    fn test_register_value_no_value() {
        // RegisterValue with all mask bits zero = no value
        let val = RegisterValue {
            register_name: "RAX".to_string(),
            bytes: vec![0u8; 16], // 8 mask bytes + 8 value bytes
            start_bit: 0,
            end_bit: 63,
            big_endian: false,
        };
        assert!(!val.has_value());
    }

    #[test]
    fn test_register_manager_new() {
        let rm = RegisterManager::new();
        assert!(rm.get_register("RAX").is_none());
    }

    #[test]
    fn test_register_builder() {
        use crate::program::lang::Register;
        let mut builder = RegisterBuilder::new();
        let reg = Register::new("RAX", 64, "register", 0);
        builder.add_register(reg);
        let rm = builder.build();
        assert!(rm.get_register("RAX").is_some());
    }

    #[test]
    fn test_unknown_register() {
        use crate::program::lang::RegisterTypeFlags;
        let ur = UnknownRegister::new(
            "MISSING",
            "Unknown register",
            Address::new(0),
            4,
            false,
            RegisterTypeFlags::default(),
        );
        assert_eq!(ur.register.name, "MISSING");
    }
}
