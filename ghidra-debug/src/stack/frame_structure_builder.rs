//! FrameStructureBuilder - builds frame structure from unwind info.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.debug.stack.FrameStructureBuilder`.

use serde::{Deserialize, Serialize};

/// A register save location in a stack frame.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterSaveLocation {
    /// The register name.
    pub register: String,
    /// The offset from the frame pointer (or stack pointer).
    pub offset: i64,
    /// The size of the saved value in bytes.
    pub size: u32,
    /// Whether this is relative to the frame pointer (vs stack pointer).
    pub relative_to_fp: bool,
}

/// Describes the structure of a stack frame.
///
/// Ported from Ghidra's `FrameStructureBuilder`. Records where registers
/// are saved and how the frame is laid out.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrameStructure {
    /// The frame level.
    pub level: u32,
    /// Total frame size in bytes.
    pub frame_size: u64,
    /// Offset of the return address from the frame pointer.
    pub return_address_offset: Option<i64>,
    /// Where registers are saved.
    pub saved_registers: Vec<RegisterSaveLocation>,
    /// The frame pointer register name.
    pub frame_pointer_register: Option<String>,
    /// The stack pointer register name.
    pub stack_pointer_register: Option<String>,
    /// The program counter register name.
    pub pc_register: Option<String>,
    /// The link register name (for architectures that use one).
    pub link_register: Option<String>,
}

impl FrameStructure {
    /// Create a new frame structure.
    pub fn new(level: u32) -> Self {
        Self {
            level,
            frame_size: 0,
            return_address_offset: None,
            saved_registers: Vec::new(),
            frame_pointer_register: None,
            stack_pointer_register: None,
            pc_register: None,
            link_register: None,
        }
    }

    /// Set the frame size.
    pub fn with_frame_size(mut self, size: u64) -> Self {
        self.frame_size = size;
        self
    }

    /// Set the return address offset.
    pub fn with_return_address_offset(mut self, offset: i64) -> Self {
        self.return_address_offset = Some(offset);
        self
    }

    /// Add a saved register location.
    pub fn with_saved_register(
        mut self,
        register: impl Into<String>,
        offset: i64,
        size: u32,
    ) -> Self {
        self.saved_registers.push(RegisterSaveLocation {
            register: register.into(),
            offset,
            size,
            relative_to_fp: true,
        });
        self
    }

    /// Set the frame pointer register.
    pub fn with_frame_pointer(mut self, reg: impl Into<String>) -> Self {
        self.frame_pointer_register = Some(reg.into());
        self
    }

    /// Set the stack pointer register.
    pub fn with_stack_pointer(mut self, reg: impl Into<String>) -> Self {
        self.stack_pointer_register = Some(reg.into());
        self
    }

    /// Set the PC register.
    pub fn with_pc_register(mut self, reg: impl Into<String>) -> Self {
        self.pc_register = Some(reg.into());
        self
    }

    /// Set the link register.
    pub fn with_link_register(mut self, reg: impl Into<String>) -> Self {
        self.link_register = Some(reg.into());
        self
    }

    /// Find a saved register by name.
    pub fn find_saved_register(&self, name: &str) -> Option<&RegisterSaveLocation> {
        self.saved_registers.iter().find(|r| r.register == name)
    }
}

/// Builder for constructing frame structures from unwind information.
#[derive(Debug, Default)]
pub struct FrameStructureBuilder {
    level: u32,
    frame_size: Option<u64>,
    return_address_offset: Option<i64>,
    saved_registers: Vec<RegisterSaveLocation>,
    fp_reg: Option<String>,
    sp_reg: Option<String>,
    pc_reg: Option<String>,
    lr_reg: Option<String>,
}

impl FrameStructureBuilder {
    /// Create a new builder for the given frame level.
    pub fn new(level: u32) -> Self {
        Self {
            level,
            ..Default::default()
        }
    }

    /// Set the frame size.
    pub fn frame_size(&mut self, size: u64) -> &mut Self {
        self.frame_size = Some(size);
        self
    }

    /// Set the return address offset.
    pub fn return_address_offset(&mut self, offset: i64) -> &mut Self {
        self.return_address_offset = Some(offset);
        self
    }

    /// Add a saved register.
    pub fn save_register(
        &mut self,
        register: impl Into<String>,
        offset: i64,
        size: u32,
    ) -> &mut Self {
        self.saved_registers.push(RegisterSaveLocation {
            register: register.into(),
            offset,
            size,
            relative_to_fp: true,
        });
        self
    }

    /// Set register names.
    pub fn registers(
        &mut self,
        fp: Option<String>,
        sp: Option<String>,
        pc: Option<String>,
        lr: Option<String>,
    ) -> &mut Self {
        self.fp_reg = fp;
        self.sp_reg = sp;
        self.pc_reg = pc;
        self.lr_reg = lr;
        self
    }

    /// Build the frame structure.
    pub fn build(&self) -> FrameStructure {
        let mut fs = FrameStructure::new(self.level);
        if let Some(s) = self.frame_size {
            fs.frame_size = s;
        }
        fs.return_address_offset = self.return_address_offset;
        fs.saved_registers = self.saved_registers.clone();
        fs.frame_pointer_register = self.fp_reg.clone();
        fs.stack_pointer_register = self.sp_reg.clone();
        fs.pc_register = self.pc_reg.clone();
        fs.link_register = self.lr_reg.clone();
        fs
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_frame_structure_basic() {
        let fs = FrameStructure::new(0);
        assert_eq!(fs.level, 0);
        assert_eq!(fs.frame_size, 0);
        assert!(fs.saved_registers.is_empty());
    }

    #[test]
    fn test_frame_structure_builder() {
        let fs = FrameStructureBuilder::new(1)
            .frame_size(128)
            .return_address_offset(-8)
            .save_register("rbp", -16, 8)
            .save_register("rbx", -24, 8)
            .build();
        assert_eq!(fs.level, 1);
        assert_eq!(fs.frame_size, 128);
        assert_eq!(fs.return_address_offset, Some(-8));
        assert_eq!(fs.saved_registers.len(), 2);
    }

    #[test]
    fn test_frame_structure_with_registers() {
        let fs = FrameStructure::new(0)
            .with_frame_pointer("rbp")
            .with_stack_pointer("rsp")
            .with_pc_register("rip")
            .with_link_register("lr");
        assert_eq!(fs.frame_pointer_register.as_deref(), Some("rbp"));
        assert_eq!(fs.stack_pointer_register.as_deref(), Some("rsp"));
        assert_eq!(fs.pc_register.as_deref(), Some("rip"));
        assert_eq!(fs.link_register.as_deref(), Some("lr"));
    }

    #[test]
    fn test_find_saved_register() {
        let fs = FrameStructure::new(0)
            .with_saved_register("rbp", -8, 8)
            .with_saved_register("rbx", -16, 8);
        assert!(fs.find_saved_register("rbp").is_some());
        assert_eq!(fs.find_saved_register("rbp").unwrap().offset, -8);
        assert!(fs.find_saved_register("rax").is_none());
    }

    #[test]
    fn test_serde() {
        let fs = FrameStructure::new(0).with_frame_size(64);
        let json = serde_json::to_string(&fs).unwrap();
        let back: FrameStructure = serde_json::from_str(&json).unwrap();
        assert_eq!(back.frame_size, 64);
    }
}
