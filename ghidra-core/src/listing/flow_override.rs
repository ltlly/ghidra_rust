//! Flow override types for Ghidra Rust.
//!
//! Direct translation of `ghidra.program.model.listing.FlowOverride`.
//!
//! Defines flow overrides that can change how an instruction's primary
//! flow operation is interpreted (e.g., changing a CALL to a JUMP).

use crate::symbol::FlowType;
use serde::{Deserialize, Serialize};

/// Flow overrides that change how an instruction's primary flow is interpreted.
///
/// Corresponds to `ghidra.program.model.listing.FlowOverride`.
///
/// Flow overrides allow changing the primary flow pcode-op of an instruction.
/// For example, a `CALL` instruction can be overridden to behave as a `JUMP`,
/// or a `BRANCH` can be overridden to behave as a `RETURN`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum FlowOverride {
    /// No flow override has been established.
    None = 0,
    /// Override the primary CALL or RETURN with a suitable JUMP operation.
    ///
    /// Pcode mapping:
    /// - `CALL -> BRANCH`
    /// - `CALLIND -> BRANCHIND`
    /// - `RETURN -> BRANCHIND`
    Branch = 1,
    /// Override the primary BRANCH or RETURN with a suitable CALL operation.
    ///
    /// Pcode mapping:
    /// - `BRANCH -> CALL`
    /// - `BRANCHIND -> CALLIND`
    /// - `CBRANCH -> (complex mapping)`
    /// - `RETURN -> CALLIND`
    Call = 2,
    /// Override the primary BRANCH, CALL, or RETURN with CALL/RETURN.
    ///
    /// Pcode mapping: similar to Call but preserves the return.
    CallReturn = 3,
    /// Override the primary BRANCH or CALL with a suitable RETURN operation.
    ///
    /// Pcode mapping:
    /// - `BRANCH -> (complex mapping with RETURN)`
    /// - `BRANCHIND -> RETURN`
    /// - `CALL -> (complex mapping with RETURN)`
    /// - `CALLIND -> RETURN`
    Return = 4,
}

impl FlowOverride {
    /// Return `FlowOverride` with the specified ordinal value.
    ///
    /// Returns [`FlowOverride::None`] for an unknown value.
    pub fn from_ordinal(ordinal: u8) -> Self {
        match ordinal {
            0 => FlowOverride::None,
            1 => FlowOverride::Branch,
            2 => FlowOverride::Call,
            3 => FlowOverride::CallReturn,
            4 => FlowOverride::Return,
            _ => FlowOverride::None,
        }
    }

    /// Returns the ordinal value.
    pub fn ordinal(self) -> u8 {
        self as u8
    }

    /// Get modified `FlowType` resulting from the application of this
    /// flow override.
    ///
    /// If the override is `None` or the original flow type is not a jump,
    /// terminal, or call, the original flow type is returned unchanged.
    pub fn get_modified_flow_type(
        original_flow_type: FlowType,
        flow_override: FlowOverride,
    ) -> FlowType {
        if flow_override == FlowOverride::None
            || (!original_flow_type.is_jump()
                && !original_flow_type.is_terminal()
                && !original_flow_type.is_call())
        {
            return original_flow_type;
        }

        // NOTE: The following flow-type overrides assume that a return will
        // always be the last flow pcode-op -- since it is the first primary
        // flow pcode-op that will get replaced.

        match flow_override {
            FlowOverride::None => original_flow_type,
            FlowOverride::Branch => {
                if original_flow_type.is_jump() {
                    return original_flow_type;
                }
                if original_flow_type.is_conditional() {
                    if original_flow_type.is_terminal() {
                        // Assume return replaced
                        return FlowType::ConditionalComputedJump;
                    }
                    return FlowType::ConditionalJump;
                }
                if original_flow_type.is_computed() {
                    return FlowType::ComputedJump;
                }
                if original_flow_type.is_terminal() {
                    // Assume return replaced
                    return FlowType::ComputedJump;
                }
                FlowType::UnconditionalJump
            }
            FlowOverride::Call => {
                if original_flow_type.is_call() {
                    return original_flow_type;
                }
                if original_flow_type.is_conditional() {
                    if original_flow_type.is_terminal()
                        && (original_flow_type.is_call() || original_flow_type.is_jump())
                    {
                        // Assume original return was preserved
                        return FlowType::ConditionalCallTerminator;
                    }
                    if original_flow_type.is_terminal() {
                        // Assume return was replaced
                        return FlowType::ConditionalComputedCall;
                    }
                    return FlowType::ConditionalCall;
                }
                if original_flow_type.is_computed() {
                    if original_flow_type.is_terminal()
                        && (original_flow_type.is_call() || original_flow_type.is_jump())
                    {
                        // Assume original return was preserved
                        return FlowType::ComputedCallTerminator;
                    }
                    return FlowType::ComputedCall;
                }
                if original_flow_type.is_terminal()
                    && (original_flow_type.is_call() || original_flow_type.is_jump())
                {
                    // Assume original return was preserved
                    return FlowType::CallTerminator;
                }
                if original_flow_type.is_terminal() {
                    // Assume return was replaced
                    return FlowType::ComputedCall;
                }
                FlowType::UnconditionalCall
            }
            FlowOverride::CallReturn => {
                if original_flow_type.is_conditional() {
                    if original_flow_type.is_computed() {
                        return FlowType::ConditionalComputedCall;
                    }
                    if original_flow_type.is_terminal() {
                        // Assume return was replaced
                        return FlowType::ComputedCallTerminator;
                    }
                    return original_flow_type; // don't replace
                }
                if original_flow_type.is_computed() {
                    return FlowType::ComputedCallTerminator;
                }
                if original_flow_type.is_terminal() {
                    // Assume return was replaced
                    return FlowType::ComputedCallTerminator;
                }
                FlowType::CallTerminator
            }
            FlowOverride::Return => {
                if original_flow_type.is_conditional() {
                    return FlowType::ConditionalTerminator;
                }
                FlowType::Terminator
            }
        }
    }
}

impl std::fmt::Display for FlowOverride {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FlowOverride::None => write!(f, "NONE"),
            FlowOverride::Branch => write!(f, "BRANCH"),
            FlowOverride::Call => write!(f, "CALL"),
            FlowOverride::CallReturn => write!(f, "CALL_RETURN"),
            FlowOverride::Return => write!(f, "RETURN"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_flow_override_from_ordinal() {
        assert_eq!(FlowOverride::from_ordinal(0), FlowOverride::None);
        assert_eq!(FlowOverride::from_ordinal(1), FlowOverride::Branch);
        assert_eq!(FlowOverride::from_ordinal(2), FlowOverride::Call);
        assert_eq!(FlowOverride::from_ordinal(3), FlowOverride::CallReturn);
        assert_eq!(FlowOverride::from_ordinal(4), FlowOverride::Return);
        assert_eq!(FlowOverride::from_ordinal(99), FlowOverride::None);
    }

    #[test]
    fn test_flow_override_display() {
        assert_eq!(format!("{}", FlowOverride::None), "NONE");
        assert_eq!(format!("{}", FlowOverride::Branch), "BRANCH");
        assert_eq!(format!("{}", FlowOverride::Return), "RETURN");
    }

    #[test]
    fn test_get_modified_flow_type_none() {
        let ft = FlowType::UnconditionalCall;
        let result = FlowOverride::get_modified_flow_type(ft, FlowOverride::None);
        assert_eq!(result, FlowType::UnconditionalCall);
    }

    #[test]
    fn test_get_modified_flow_type_branch() {
        let ft = FlowType::UnconditionalCall;
        let result = FlowOverride::get_modified_flow_type(ft, FlowOverride::Branch);
        assert_eq!(result, FlowType::UnconditionalJump);
    }

    #[test]
    fn test_get_modified_flow_type_call() {
        let ft = FlowType::UnconditionalJump;
        let result = FlowOverride::get_modified_flow_type(ft, FlowOverride::Call);
        assert_eq!(result, FlowType::UnconditionalCall);
    }

    #[test]
    fn test_get_modified_flow_type_return() {
        let ft = FlowType::UnconditionalJump;
        let result = FlowOverride::get_modified_flow_type(ft, FlowOverride::Return);
        assert_eq!(result, FlowType::Terminator);
    }

    #[test]
    fn test_get_modified_flow_type_return_conditional() {
        let ft = FlowType::ConditionalJump;
        let result = FlowOverride::get_modified_flow_type(ft, FlowOverride::Return);
        assert_eq!(result, FlowType::ConditionalTerminator);
    }
}
