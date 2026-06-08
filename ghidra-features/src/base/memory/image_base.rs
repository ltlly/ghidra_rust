//! ImageBaseDialog / SetBaseCommand -- image base address management.
//!
//! Ported from `ghidra.app.plugin.core.memory.ImageBaseDialog` and `SetBaseCommand`.
//! Provides functionality to change the program's image base address.

use crate::base::analyzer::core::*;

/// Result of setting the image base.
#[derive(Debug, Clone)]
pub struct SetBaseResult {
    /// Whether the operation succeeded.
    pub success: bool,
    /// Status message (error message if failed).
    pub status_message: String,
    /// The old image base address.
    pub old_base: u64,
    /// The new image base address.
    pub new_base: u64,
}

/// Command to set the image base address of a program.
///
/// This command changes the program's image base address and
/// adjusts all memory blocks accordingly.
///
/// # Example
///
/// ```
/// use ghidra_features::base::memory::image_base::*;
/// use ghidra_features::base::analyzer::*;
///
/// let cmd = SetBaseCommand::new(Address::new(0x400000));
/// assert_eq!(cmd.target_address(), Address::new(0x400000));
/// ```
#[derive(Debug, Clone)]
pub struct SetBaseCommand {
    /// The new image base address.
    addr: Address,
    /// Status message after execution.
    status_message: Option<String>,
}

impl SetBaseCommand {
    /// Creates a new command to set the image base to the given address.
    pub fn new(addr: Address) -> Self {
        Self {
            addr,
            status_message: None,
        }
    }

    /// Returns the target address.
    pub fn target_address(&self) -> Address {
        self.addr
    }

    /// Returns the status message from the last execution.
    pub fn status_message(&self) -> Option<&str> {
        self.status_message.as_deref()
    }

    /// Executes the command on the given program.
    pub fn apply_to(&mut self, program: &mut Program) -> SetBaseResult {
        let old_base = program.image_base;

        // Validate the new base address
        if self.addr.offset == 0 {
            self.status_message = Some("Image base cannot be 0".into());
            return SetBaseResult {
                success: false,
                status_message: self.status_message.clone().unwrap_or_default(),
                old_base,
                new_base: old_base,
            };
        }

        // Check if the new base would cause memory blocks to overflow
        let delta = self.addr.offset as i64 - old_base as i64;
        for block in &program.memory_blocks {
            let new_start = block.start.offset as i64 + delta;
            if new_start < 0 {
                self.status_message = Some(format!(
                    "Image base of {} not allowed; change causes block '{}' to underflow",
                    self.addr, block.name
                ));
                return SetBaseResult {
                    success: false,
                    status_message: self.status_message.clone().unwrap_or_default(),
                    old_base,
                    new_base: old_base,
                };
            }
        }

        // Apply the change
        program.image_base = self.addr.offset;

        // Update memory block addresses
        for block in &mut program.memory_blocks {
            let new_start = (block.start.offset as i64 + delta) as u64;
            block.start = Address::new(new_start);
        }

        self.status_message = Some(format!(
            "Image base changed from {:#x} to {:#x}",
            old_base, self.addr.offset
        ));

        SetBaseResult {
            success: true,
            status_message: self.status_message.clone().unwrap_or_default(),
            old_base,
            new_base: self.addr.offset,
        }
    }
}

/// Dialog state for the image base address dialog.
///
/// Manages the state and validation of the image base dialog.
#[derive(Debug, Clone)]
pub struct ImageBaseDialogState {
    /// Current image base address.
    pub current_addr: Address,
    /// Proposed new address (from user input).
    pub proposed_addr: Option<Address>,
    /// Whether the dialog was confirmed.
    pub confirmed: bool,
    /// Status text to display.
    pub status_text: String,
    /// Whether the OK button is enabled.
    pub ok_enabled: bool,
}

impl ImageBaseDialogState {
    /// Creates a new dialog state.
    pub fn new(current_addr: Address) -> Self {
        Self {
            current_addr,
            proposed_addr: Some(current_addr),
            confirmed: false,
            status_text: String::new(),
            ok_enabled: true,
        }
    }

    /// Updates the proposed address from user input.
    ///
    /// Returns true if the input is valid.
    pub fn update_address_input(&mut self, input: &str) -> bool {
        self.status_text.clear();

        // Try to parse the address
        let addr = if input.starts_with("0x") || input.starts_with("0X") {
            u64::from_str_radix(&input[2..], 16)
        } else {
            input.parse::<u64>()
        };

        match addr {
            Ok(offset) => {
                self.proposed_addr = Some(Address::new(offset));
                self.ok_enabled = true;
                true
            }
            Err(_) => {
                self.proposed_addr = None;
                self.status_text = "Invalid Address".into();
                self.ok_enabled = false;
                false
            }
        }
    }

    /// Confirms the dialog.
    pub fn confirm(&mut self) {
        if self.proposed_addr.is_some() {
            self.confirmed = true;
        }
    }

    /// Cancels the dialog.
    pub fn cancel(&mut self) {
        self.confirmed = false;
        self.proposed_addr = None;
    }

    /// Returns whether the address was changed.
    pub fn has_changes(&self) -> bool {
        self.proposed_addr
            .map_or(false, |addr| addr != self.current_addr)
    }

    /// Returns the command to execute (if confirmed and changed).
    pub fn to_command(&self) -> Option<SetBaseCommand> {
        if self.confirmed && self.has_changes() {
            self.proposed_addr.map(SetBaseCommand::new)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_set_base_command_creation() {
        let cmd = SetBaseCommand::new(Address::new(0x400000));
        assert_eq!(cmd.target_address(), Address::new(0x400000));
        assert!(cmd.status_message().is_none());
    }

    #[test]
    fn test_set_base_command_apply() {
        let mut cmd = SetBaseCommand::new(Address::new(0x500000));
        let mut p = Program::new(
            "test",
            Language {
                processor: "x86".into(),
                variant: "LE".into(),
                size: 64,
            },
        );
        p.image_base = 0x400000;
        p.memory_blocks.push(MemoryBlock {
            name: ".text".into(),
            start: Address::new(0x401000),
            size: 0x1000,
            is_read: true,
            is_write: false,
            is_execute: true,
            is_initialized: true,
        });

        let result = cmd.apply_to(&mut p);
        assert!(result.success);
        assert_eq!(result.old_base, 0x400000);
        assert_eq!(result.new_base, 0x500000);
        assert_eq!(p.image_base, 0x500000);
        assert_eq!(p.memory_blocks[0].start, Address::new(0x501000));
    }

    #[test]
    fn test_set_base_command_zero() {
        let mut cmd = SetBaseCommand::new(Address::new(0));
        let mut p = Program::new(
            "test",
            Language {
                processor: "x86".into(),
                variant: "LE".into(),
                size: 64,
            },
        );
        p.image_base = 0x400000;

        let result = cmd.apply_to(&mut p);
        assert!(!result.success);
        assert!(result.status_message.contains("cannot be 0"));
    }

    #[test]
    fn test_image_base_dialog_state_new() {
        let state = ImageBaseDialogState::new(Address::new(0x400000));
        assert_eq!(state.current_addr, Address::new(0x400000));
        assert!(state.proposed_addr.is_some());
        assert!(!state.confirmed);
        assert!(state.ok_enabled);
    }

    #[test]
    fn test_image_base_dialog_update_valid() {
        let mut state = ImageBaseDialogState::new(Address::new(0x400000));
        assert!(state.update_address_input("0x500000"));
        assert_eq!(state.proposed_addr, Some(Address::new(0x500000)));
        assert!(state.ok_enabled);
    }

    #[test]
    fn test_image_base_dialog_update_invalid() {
        let mut state = ImageBaseDialogState::new(Address::new(0x400000));
        assert!(!state.update_address_input("not_a_number"));
        assert!(state.proposed_addr.is_none());
        assert!(!state.ok_enabled);
        assert!(state.status_text.contains("Invalid"));
    }

    #[test]
    fn test_image_base_dialog_update_decimal() {
        let mut state = ImageBaseDialogState::new(Address::new(0x400000));
        assert!(state.update_address_input("5242880")); // 0x500000 in decimal
        assert_eq!(state.proposed_addr, Some(Address::new(5242880)));
    }

    #[test]
    fn test_image_base_dialog_confirm() {
        let mut state = ImageBaseDialogState::new(Address::new(0x400000));
        state.update_address_input("0x500000");
        state.confirm();
        assert!(state.confirmed);
        assert!(state.has_changes());
    }

    #[test]
    fn test_image_base_dialog_cancel() {
        let mut state = ImageBaseDialogState::new(Address::new(0x400000));
        state.update_address_input("0x500000");
        state.cancel();
        assert!(!state.confirmed);
        assert!(state.proposed_addr.is_none());
    }

    #[test]
    fn test_image_base_dialog_no_changes() {
        let mut state = ImageBaseDialogState::new(Address::new(0x400000));
        state.update_address_input("0x400000");
        assert!(!state.has_changes());
    }

    #[test]
    fn test_image_base_dialog_to_command() {
        let mut state = ImageBaseDialogState::new(Address::new(0x400000));
        state.update_address_input("0x500000");
        state.confirm();

        let cmd = state.to_command();
        assert!(cmd.is_some());
        assert_eq!(cmd.unwrap().target_address(), Address::new(0x500000));
    }

    #[test]
    fn test_image_base_dialog_to_command_not_confirmed() {
        let mut state = ImageBaseDialogState::new(Address::new(0x400000));
        state.update_address_input("0x500000");
        // Not confirmed
        assert!(state.to_command().is_none());
    }

    #[test]
    fn test_image_base_dialog_to_command_no_changes() {
        let mut state = ImageBaseDialogState::new(Address::new(0x400000));
        state.update_address_input("0x400000");
        state.confirm();
        assert!(state.to_command().is_none());
    }

    #[test]
    fn test_set_base_underflow() {
        let mut cmd = SetBaseCommand::new(Address::new(0x100));
        let mut p = Program::new(
            "test",
            Language {
                processor: "x86".into(),
                variant: "LE".into(),
                size: 64,
            },
        );
        p.image_base = 0x400000;
        p.memory_blocks.push(MemoryBlock {
            name: ".text".into(),
            start: Address::new(0x401000),
            size: 0x1000,
            is_read: true,
            is_write: false,
            is_execute: true,
            is_initialized: true,
        });

        let result = cmd.apply_to(&mut p);
        assert!(!result.success);
        assert!(result.status_message.contains("underflow"));
    }
}
