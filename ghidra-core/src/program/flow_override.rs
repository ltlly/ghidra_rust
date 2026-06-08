//! Flow override definitions for Ghidra Rust.
//!
//! Direct translation of `ghidra.program.model.listing.FlowOverride`.
//!
//! Provides the [`FlowOverride`] enum and the [`get_modified_flow_type`] function
//! for overriding instruction flow semantics (e.g., converting a CALL to a JUMP).

use crate::symbol::{FlowType, RefType};
use serde::{Deserialize, Serialize};
use std::fmt;

/// Flow overrides that can be applied to an instruction's primary flow pcode-op.
///
/// Corresponds to `ghidra.program.model.listing.FlowOverride`.
///
/// Flow overrides allow the user to change the semantics of an instruction's
/// control flow. For example, a CALL instruction can be overridden to behave
/// as a JUMP (tail call) or a RETURN.
///
/// # P-code Mappings
///
/// See the variant documentation for the specific pcode op replacements.
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
    /// - `CBRANCH <addr>,<cond>` -> (complex mapping with negated condition)
    /// - `RETURN -> CALLIND`
    Call = 2,

    /// Override the primary BRANCH, CALL, or RETURN with a CALL/RETURN sequence.
    ///
    /// Pcode mapping:
    /// - `BRANCH -> CALL/RETURN`
    /// - `BRANCHIND -> CALLIND/RETURN`
    /// - `CBRANCH <addr>,<cond>` -> (complex mapping)
    /// - `CALL -> CALL/RETURN`
    /// - `CALLIND -> CALLIND/RETURN`
    /// - `RETURN -> CALLIND/RETURN`
    CallReturn = 3,

    /// Override the primary BRANCH or CALL with a suitable RETURN operation.
    ///
    /// Pcode mapping:
    /// - `BRANCH <addr>` -> `RETURN &<addr>`
    /// - `BRANCHIND -> RETURN`
    /// - `CBRANCH <addr>,<cond>` -> (complex mapping)
    /// - `CALL <addr>` -> `RETURN &<addr>`
    /// - `CALLIND -> RETURN`
    Return = 4,
}

impl FlowOverride {
    /// Returns the `FlowOverride` for the given ordinal value.
    ///
    /// Returns [`FlowOverride::None`] for unknown values.
    ///
    /// Corresponds to `FlowOverride.getFlowOverride(int)` in Java.
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

    /// Returns the ordinal value for persistent storage.
    pub fn ordinal(self) -> u8 {
        self as u8
    }

    /// Returns `true` if this is the [`None`](FlowOverride::None) override.
    pub fn is_none_override(self) -> bool {
        self == FlowOverride::None
    }

    /// Returns `true` if this override converts flow to a branch/jump.
    pub fn is_branch(self) -> bool {
        self == FlowOverride::Branch
    }

    /// Returns `true` if this override converts flow to a call.
    pub fn is_call(self) -> bool {
        self == FlowOverride::Call
    }

    /// Returns `true` if this override converts flow to a call-return sequence.
    pub fn is_call_return(self) -> bool {
        self == FlowOverride::CallReturn
    }

    /// Returns `true` if this override converts flow to a return.
    pub fn is_return(self) -> bool {
        self == FlowOverride::Return
    }

    /// Returns all flow override values.
    pub fn all() -> &'static [FlowOverride] {
        &[
            FlowOverride::None,
            FlowOverride::Branch,
            FlowOverride::Call,
            FlowOverride::CallReturn,
            FlowOverride::Return,
        ]
    }
}

impl fmt::Display for FlowOverride {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FlowOverride::None => write!(f, "None"),
            FlowOverride::Branch => write!(f, "Branch"),
            FlowOverride::Call => write!(f, "Call"),
            FlowOverride::CallReturn => write!(f, "Call Return"),
            FlowOverride::Return => write!(f, "Return"),
        }
    }
}

impl Default for FlowOverride {
    fn default() -> Self {
        FlowOverride::None
    }
}

/// Get modified FlowType resulting from the application of the specified flow override.
///
/// Corresponds to `FlowOverride.getModifiedFlowType(FlowType, FlowOverride)` in Java.
///
/// This function applies the flow override to the original flow type and returns
/// the resulting flow type. The logic handles conditional, computed, and terminal
/// flow types to produce the correct overridden flow type.
///
/// If the override is [`FlowOverride::None`], or the original flow type is not a
/// jump, call, or terminal, the original flow type is returned unchanged.
pub fn get_modified_flow_type(original: FlowType, flow_override: FlowOverride) -> FlowType {
    if flow_override == FlowOverride::None {
        return original;
    }

    if !original.is_jump() && !original.is_terminal() && !original.is_call() {
        return original;
    }

    match flow_override {
        FlowOverride::None => original,
        FlowOverride::Branch => get_branch_override(original),
        FlowOverride::Call => get_call_override(original),
        FlowOverride::CallReturn => get_call_return_override(original),
        FlowOverride::Return => get_return_override(original),
    }
}

/// Apply BRANCH override: convert CALL/RETURN to JUMP.
fn get_branch_override(flow_type: FlowType) -> FlowType {
    if flow_type.is_jump() {
        return flow_type;
    }
    if flow_type.is_conditional() {
        // Assume return replaced
        if flow_type.is_terminal() {
            return FlowType::ConditionalComputedJump;
        }
        return FlowType::ConditionalJump;
    }
    if flow_type.is_computed() {
        return FlowType::ComputedJump;
    }
    if flow_type.is_terminal() {
        // Assume return replaced
        return FlowType::ComputedJump;
    }
    FlowType::UnconditionalJump
}

/// Apply CALL override: convert BRANCH/RETURN to CALL.
fn get_call_override(flow_type: FlowType) -> FlowType {
    if flow_type.is_call() {
        return flow_type;
    }
    if flow_type.is_conditional() {
        if flow_type.is_terminal() && (flow_type.is_call() || flow_type.is_jump()) {
            // Assume original return was preserved
            return FlowType::ConditionalCallTerminator;
        }
        if flow_type.is_terminal() {
            // Assume return was replaced
            return FlowType::ConditionalComputedCall;
        }
        return FlowType::ConditionalCall;
    }
    if flow_type.is_computed() {
        if flow_type.is_terminal() && (flow_type.is_call() || flow_type.is_jump()) {
            // Assume original return was preserved
            return FlowType::ComputedCallTerminator;
        }
        return FlowType::ComputedCall;
    }
    if flow_type.is_terminal() && (flow_type.is_call() || flow_type.is_jump()) {
        // Assume original return was preserved
        return FlowType::CallTerminator;
    }
    if flow_type.is_terminal() {
        // Assume return was replaced
        return FlowType::ComputedCall;
    }
    FlowType::UnconditionalCall
}

/// Apply CALL_RETURN override: convert to CALL/RETURN sequence.
fn get_call_return_override(flow_type: FlowType) -> FlowType {
    if flow_type.is_conditional() {
        if flow_type.is_computed() {
            return FlowType::ConditionalComputedCall;
        }
        if flow_type.is_terminal() {
            // Assume return was replaced
            return FlowType::ComputedCallTerminator;
        }
        return flow_type; // don't replace
    }
    if flow_type.is_computed() {
        return FlowType::ComputedCallTerminator;
    }
    if flow_type.is_terminal() {
        // Assume return was replaced
        return FlowType::ComputedCallTerminator;
    }
    FlowType::CallTerminator
}

/// Apply RETURN override: convert BRANCH/CALL to RETURN.
fn get_return_override(flow_type: FlowType) -> FlowType {
    if flow_type.is_conditional() {
        return FlowType::ConditionalTerminator;
    }
    FlowType::Terminator
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_ordinal() {
        assert_eq!(FlowOverride::from_ordinal(0), FlowOverride::None);
        assert_eq!(FlowOverride::from_ordinal(1), FlowOverride::Branch);
        assert_eq!(FlowOverride::from_ordinal(2), FlowOverride::Call);
        assert_eq!(FlowOverride::from_ordinal(3), FlowOverride::CallReturn);
        assert_eq!(FlowOverride::from_ordinal(4), FlowOverride::Return);
        assert_eq!(FlowOverride::from_ordinal(99), FlowOverride::None);
    }

    #[test]
    fn test_ordinal() {
        assert_eq!(FlowOverride::None.ordinal(), 0);
        assert_eq!(FlowOverride::Branch.ordinal(), 1);
        assert_eq!(FlowOverride::Call.ordinal(), 2);
        assert_eq!(FlowOverride::CallReturn.ordinal(), 3);
        assert_eq!(FlowOverride::Return.ordinal(), 4);
    }

    #[test]
    fn test_display() {
        assert_eq!(format!("{}", FlowOverride::None), "None");
        assert_eq!(format!("{}", FlowOverride::Branch), "Branch");
        assert_eq!(format!("{}", FlowOverride::Call), "Call");
        assert_eq!(format!("{}", FlowOverride::CallReturn), "Call Return");
        assert_eq!(format!("{}", FlowOverride::Return), "Return");
    }

    #[test]
    fn test_default() {
        assert_eq!(FlowOverride::default(), FlowOverride::None);
    }

    #[test]
    fn test_all() {
        assert_eq!(FlowOverride::all().len(), 5);
    }

    #[test]
    fn test_modified_flow_type_none_override() {
        let original = FlowType::UnconditionalCall;
        let result = get_modified_flow_type(original, FlowOverride::None);
        assert_eq!(result, FlowType::UnconditionalCall);
    }

    #[test]
    fn test_modified_flow_type_branch_override_call() {
        // CALL -> JUMP
        let result = get_modified_flow_type(FlowType::UnconditionalCall, FlowOverride::Branch);
        assert_eq!(result, FlowType::UnconditionalJump);
    }

    #[test]
    fn test_modified_flow_type_branch_override_conditional_call() {
        // CONDITIONAL_CALL -> CONDITIONAL_JUMP
        let result = get_modified_flow_type(FlowType::ConditionalCall, FlowOverride::Branch);
        assert_eq!(result, FlowType::ConditionalJump);
    }

    #[test]
    fn test_modified_flow_type_branch_override_computed_call() {
        // COMPUTED_CALL -> COMPUTED_JUMP
        let result = get_modified_flow_type(FlowType::ComputedCall, FlowOverride::Branch);
        assert_eq!(result, FlowType::ComputedJump);
    }

    #[test]
    fn test_modified_flow_type_branch_override_terminator() {
        // TERMINATOR -> COMPUTED_JUMP (return replaced)
        let result = get_modified_flow_type(FlowType::Terminator, FlowOverride::Branch);
        assert_eq!(result, FlowType::ComputedJump);
    }

    #[test]
    fn test_modified_flow_type_branch_override_jump_passthrough() {
        // JUMP stays as JUMP
        let result = get_modified_flow_type(FlowType::UnconditionalJump, FlowOverride::Branch);
        assert_eq!(result, FlowType::UnconditionalJump);
    }

    #[test]
    fn test_modified_flow_type_call_override_jump() {
        // JUMP -> CALL
        let result = get_modified_flow_type(FlowType::UnconditionalJump, FlowOverride::Call);
        assert_eq!(result, FlowType::UnconditionalCall);
    }

    #[test]
    fn test_modified_flow_type_call_override_computed_jump() {
        // COMPUTED_JUMP -> COMPUTED_CALL
        let result = get_modified_flow_type(FlowType::ComputedJump, FlowOverride::Call);
        assert_eq!(result, FlowType::ComputedCall);
    }

    #[test]
    fn test_modified_flow_type_call_override_terminator() {
        // TERMINATOR -> COMPUTED_CALL (return replaced)
        let result = get_modified_flow_type(FlowType::Terminator, FlowOverride::Call);
        assert_eq!(result, FlowType::ComputedCall);
    }

    #[test]
    fn test_modified_flow_type_call_override_passthrough() {
        // CALL stays as CALL
        let result = get_modified_flow_type(FlowType::UnconditionalCall, FlowOverride::Call);
        assert_eq!(result, FlowType::UnconditionalCall);
    }

    #[test]
    fn test_modified_flow_type_return_override() {
        // JUMP -> TERMINATOR
        let result = get_modified_flow_type(FlowType::UnconditionalJump, FlowOverride::Return);
        assert_eq!(result, FlowType::Terminator);

        // CALL -> TERMINATOR
        let result = get_modified_flow_type(FlowType::UnconditionalCall, FlowOverride::Return);
        assert_eq!(result, FlowType::Terminator);
    }

    #[test]
    fn test_modified_flow_type_return_override_conditional() {
        // CONDITIONAL_JUMP -> CONDITIONAL_TERMINATOR
        let result = get_modified_flow_type(FlowType::ConditionalJump, FlowOverride::Return);
        assert_eq!(result, FlowType::ConditionalTerminator);
    }

    #[test]
    fn test_modified_flow_type_non_flow_passthrough() {
        // Non-flow types are not affected
        let result = get_modified_flow_type(FlowType::FallThrough, FlowOverride::Branch);
        assert_eq!(result, FlowType::FallThrough);
    }

    #[test]
    fn test_ordinal_roundtrip() {
        for fo in FlowOverride::all() {
            let ordinal = fo.ordinal();
            let parsed = FlowOverride::from_ordinal(ordinal);
            assert_eq!(*fo, parsed);
        }
    }
}
