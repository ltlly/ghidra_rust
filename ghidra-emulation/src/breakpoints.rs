//! Breakpoint management for the emulator.
//!
//! [`BreakpointManager`] tracks execution, read, write, and access
//! breakpoints. Each breakpoint has a kind, address, enabled state, hit
//! count, and an optional condition expression.
//!
//! Enhancements ported from Ghidra:
//! - Condition expression evaluation against [`EmulatorState`].
//! - Bulk enable/disable (enable all / disable all).
//! - Breakpoint callbacks (user-defined actions when a breakpoint fires).

use ghidra_core::addr::Address;
use std::collections::HashMap;

/// The kind of breakpoint trigger.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BreakpointKind {
    /// Break when execution reaches the address.
    Execution,
    /// Break when the address is read from.
    Read,
    /// Break when the address is written to.
    Write,
    /// Break on any access (read or write) to the address.
    Access,
}

impl BreakpointKind {
    /// Human-readable name of this breakpoint kind.
    pub fn name(self) -> &'static str {
        match self {
            BreakpointKind::Execution => "execution",
            BreakpointKind::Read => "read",
            BreakpointKind::Write => "write",
            BreakpointKind::Access => "access",
        }
    }
}

/// Metadata for a single breakpoint.
#[derive(Debug, Clone)]
pub struct BreakpointInfo {
    /// The type of breakpoint.
    pub kind: BreakpointKind,
    /// Whether this breakpoint is currently active.
    pub enabled: bool,
    /// Number of times this breakpoint has been hit.
    pub hit_count: u64,
    /// Optional condition expression (e.g., `"RAX == 0"`).
    ///
    /// The breakpoint only triggers when this expression evaluates to true.
    /// When `None`, the breakpoint always triggers.
    pub condition: Option<String>,
    /// Optional user-defined tag (arbitrary metadata).
    pub tag: Option<String>,
}

impl BreakpointInfo {
    /// Create a new enabled breakpoint of the given kind.
    pub fn new(kind: BreakpointKind) -> Self {
        Self {
            kind,
            enabled: true,
            hit_count: 0,
            condition: None,
            tag: None,
        }
    }

    /// Create a new enabled breakpoint with a condition expression.
    pub fn conditional(kind: BreakpointKind, condition: impl Into<String>) -> Self {
        Self {
            kind,
            enabled: true,
            hit_count: 0,
            condition: Some(condition.into()),
            tag: None,
        }
    }

    /// Create a new enabled breakpoint with a tag.
    pub fn with_tag(kind: BreakpointKind, tag: impl Into<String>) -> Self {
        Self {
            kind,
            enabled: true,
            hit_count: 0,
            condition: None,
            tag: Some(tag.into()),
        }
    }

    /// Enable this breakpoint.
    pub fn enable(&mut self) {
        self.enabled = true;
    }

    /// Disable this breakpoint.
    pub fn disable(&mut self) {
        self.enabled = false;
    }

    /// Record a hit on this breakpoint (increment the hit counter).
    pub fn record_hit(&mut self) {
        self.hit_count = self.hit_count.saturating_add(1);
    }

    /// Returns true if this breakpoint should trigger.
    ///
    /// The breakpoint triggers when it is enabled. Condition expressions
    /// are evaluated by [`BreakpointManager::check_condition`].
    pub fn should_trigger(&self) -> bool {
        self.enabled
    }

    /// Returns true if this breakpoint has a condition.
    pub fn has_condition(&self) -> bool {
        self.condition.is_some()
    }
}

// ---------------------------------------------------------------------------
// ConditionEvaluator
// ---------------------------------------------------------------------------

/// Simple condition expression evaluator for breakpoint conditions.
///
/// Supports basic expressions of the form:
/// - `"RAX == 0"` -- register equals constant
/// - `"RAX != 0"` -- register not equal to constant
/// - `"RAX < 10"` -- register less than constant
/// - `"RAX > 10"` -- register greater than constant
/// - `"RAX"` or `"ZF"` -- register/flag is non-zero
///
/// This is intentionally simple; for complex conditions, users should
/// implement the evaluation logic themselves.
#[derive(Debug)]
pub struct ConditionEvaluator;

impl ConditionEvaluator {
    /// Evaluate a condition expression against the given register map and
    /// flags map.
    ///
    /// Returns `true` if the condition is satisfied, `false` otherwise.
    /// If the expression cannot be parsed, returns `false` (safe default).
    pub fn evaluate(
        expr: &str,
        registers: &HashMap<String, Vec<u8>>,
        flags: &HashMap<String, bool>,
    ) -> bool {
        let expr = expr.trim();

        // Try binary comparisons: "REG op CONST"
        for op in &["==", "!=", "<=", ">=", "<", ">"] {
            if let Some(idx) = expr.find(op) {
                let lhs = expr[..idx].trim();
                let rhs = expr[idx + op.len()..].trim();
                let lhs_val = Self::resolve_value(lhs, registers, flags);
                let rhs_val = Self::parse_constant(rhs);
                if let (Some(a), Some(b)) = (lhs_val, rhs_val) {
                    return match *op {
                        "==" => a == b,
                        "!=" => a != b,
                        "<" => a < b,
                        ">" => a > b,
                        "<=" => a <= b,
                        ">=" => a >= b,
                        _ => false,
                    };
                }
            }
        }

        // Try simple boolean: "REG" or "FLAG"
        if let Some(val) = Self::resolve_value(expr, registers, flags) {
            return val != 0;
        }

        // Unparseable expression: safe default
        false
    }

    /// Resolve a register name or flag name to a u64 value.
    fn resolve_value(
        name: &str,
        registers: &HashMap<String, Vec<u8>>,
        flags: &HashMap<String, bool>,
    ) -> Option<u64> {
        // Check flags first
        if let Some(&val) = flags.get(name) {
            return Some(if val { 1 } else { 0 });
        }

        // Check registers
        if let Some(bytes) = registers.get(name) {
            let mut buf = [0u8; 8];
            let len = bytes.len().min(8);
            buf[..len].copy_from_slice(&bytes[..len]);
            return Some(u64::from_le_bytes(buf));
        }

        None
    }

    /// Parse a constant from a string (decimal or hex with 0x prefix).
    fn parse_constant(s: &str) -> Option<u64> {
        let s = s.trim();
        if s.starts_with("0x") || s.starts_with("0X") {
            u64::from_str_radix(&s[2..], 16).ok()
        } else {
            s.parse::<u64>().ok()
        }
    }
}

// ---------------------------------------------------------------------------
// BreakpointCallback
// ---------------------------------------------------------------------------

/// An action to take when a breakpoint fires.
///
/// Ported from Ghidra's `BreakCallBack`. The callback can optionally
/// modify emulator state or halt execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BreakpointAction {
    /// Continue execution past the breakpoint.
    Continue,
    /// Halt emulation at this breakpoint.
    Halt,
}

impl Default for BreakpointAction {
    fn default() -> Self {
        BreakpointAction::Halt
    }
}

// ---------------------------------------------------------------------------
// BreakpointManager
// ---------------------------------------------------------------------------

/// Manages a collection of breakpoints indexed by address.
#[derive(Debug, Clone, Default)]
pub struct BreakpointManager {
    /// Breakpoints keyed by address.
    pub breakpoints: HashMap<Address, BreakpointInfo>,
    /// Default action when a breakpoint fires (Halt or Continue).
    pub default_action: BreakpointAction,
}

impl BreakpointManager {
    /// Create an empty breakpoint manager.
    pub fn new() -> Self {
        Self {
            breakpoints: HashMap::new(),
            default_action: BreakpointAction::Halt,
        }
    }

    /// Set a breakpoint at the given address.
    ///
    /// If a breakpoint already exists at this address, it is replaced.
    pub fn set(&mut self, addr: Address, kind: BreakpointKind) {
        self.breakpoints.insert(addr, BreakpointInfo::new(kind));
    }

    /// Set a conditional breakpoint at the given address.
    pub fn set_conditional(
        &mut self,
        addr: Address,
        kind: BreakpointKind,
        condition: impl Into<String>,
    ) {
        self.breakpoints
            .insert(addr, BreakpointInfo::conditional(kind, condition));
    }

    /// Set a tagged breakpoint at the given address.
    pub fn set_tagged(
        &mut self,
        addr: Address,
        kind: BreakpointKind,
        tag: impl Into<String>,
    ) {
        self.breakpoints
            .insert(addr, BreakpointInfo::with_tag(kind, tag));
    }

    /// Clear (remove) the breakpoint at the given address.
    ///
    /// Returns the removed breakpoint info, or `None` if none existed.
    pub fn clear(&mut self, addr: Address) -> Option<BreakpointInfo> {
        self.breakpoints.remove(&addr)
    }

    /// Get the breakpoint info at the given address, if any.
    pub fn get(&self, addr: &Address) -> Option<&BreakpointInfo> {
        self.breakpoints.get(addr)
    }

    /// Get a mutable reference to the breakpoint at the given address.
    pub fn get_mut(&mut self, addr: &Address) -> Option<&mut BreakpointInfo> {
        self.breakpoints.get_mut(addr)
    }

    /// Check whether any enabled breakpoint exists at the given address.
    pub fn is_set(&self, addr: &Address) -> bool {
        self.breakpoints
            .get(addr)
            .map(|bp| bp.should_trigger())
            .unwrap_or(false)
    }

    /// Evaluate a breakpoint's condition expression.
    ///
    /// Returns `true` if the condition is satisfied (or no condition
    /// exists), `false` otherwise.
    pub fn check_condition(
        &self,
        bp: &BreakpointInfo,
        registers: &HashMap<String, Vec<u8>>,
        flags: &HashMap<String, bool>,
    ) -> bool {
        match &bp.condition {
            Some(expr) => ConditionEvaluator::evaluate(expr, registers, flags),
            None => true, // No condition = always triggers
        }
    }

    /// Check for and record a hit on any execution breakpoint at the given
    /// address. Returns `true` if a breakpoint was triggered.
    pub fn check_execution(&mut self, addr: &Address) -> bool {
        if let Some(bp) = self.breakpoints.get_mut(addr) {
            if bp.kind == BreakpointKind::Execution && bp.should_trigger() {
                bp.record_hit();
                return true;
            }
        }
        false
    }

    /// Check for and record a hit on any execution breakpoint at the given
    /// address, evaluating conditions. Returns `true` if a breakpoint was
    /// triggered and its condition (if any) was satisfied.
    pub fn check_execution_conditional(
        &mut self,
        addr: &Address,
        registers: &HashMap<String, Vec<u8>>,
        flags: &HashMap<String, bool>,
    ) -> bool {
        if let Some(bp) = self.breakpoints.get_mut(addr) {
            if bp.kind == BreakpointKind::Execution && bp.should_trigger() {
                let should_fire = match &bp.condition {
                    Some(expr) => ConditionEvaluator::evaluate(expr, registers, flags),
                    None => true,
                };
                if should_fire {
                    bp.record_hit();
                    return true;
                }
            }
        }
        false
    }

    /// Check for and record a hit on any read breakpoint at the given
    /// address. Returns `true` if a breakpoint was triggered.
    pub fn check_read(&mut self, addr: &Address) -> bool {
        if let Some(bp) = self.breakpoints.get_mut(addr) {
            if matches!(bp.kind, BreakpointKind::Read | BreakpointKind::Access)
                && bp.should_trigger()
            {
                bp.record_hit();
                return true;
            }
        }
        false
    }

    /// Check for and record a hit on any write breakpoint at the given
    /// address. Returns `true` if a breakpoint was triggered.
    pub fn check_write(&mut self, addr: &Address) -> bool {
        if let Some(bp) = self.breakpoints.get_mut(addr) {
            if matches!(bp.kind, BreakpointKind::Write | BreakpointKind::Access)
                && bp.should_trigger()
            {
                bp.record_hit();
                return true;
            }
        }
        false
    }

    /// Return the number of breakpoints.
    pub fn len(&self) -> usize {
        self.breakpoints.len()
    }

    /// Returns true if there are no breakpoints.
    pub fn is_empty(&self) -> bool {
        self.breakpoints.is_empty()
    }

    /// Remove all breakpoints.
    pub fn clear_all(&mut self) {
        self.breakpoints.clear();
    }

    /// Enable a disabled breakpoint at the given address.
    pub fn enable(&mut self, addr: &Address) -> bool {
        if let Some(bp) = self.breakpoints.get_mut(addr) {
            bp.enable();
            true
        } else {
            false
        }
    }

    /// Disable a breakpoint at the given address without removing it.
    pub fn disable(&mut self, addr: &Address) -> bool {
        if let Some(bp) = self.breakpoints.get_mut(addr) {
            bp.disable();
            true
        } else {
            false
        }
    }

    /// Enable all breakpoints.
    pub fn enable_all(&mut self) {
        for bp in self.breakpoints.values_mut() {
            bp.enable();
        }
    }

    /// Disable all breakpoints without removing them.
    pub fn disable_all(&mut self) {
        for bp in self.breakpoints.values_mut() {
            bp.disable();
        }
    }

    /// Return an iterator over all breakpoint entries.
    pub fn iter(&self) -> impl Iterator<Item = (&Address, &BreakpointInfo)> {
        self.breakpoints.iter()
    }

    /// Return the total number of breakpoint hits across all breakpoints.
    pub fn total_hits(&self) -> u64 {
        self.breakpoints.values().map(|bp| bp.hit_count).sum()
    }

    /// Return all breakpoints of a given kind.
    pub fn by_kind(&self, kind: BreakpointKind) -> Vec<(&Address, &BreakpointInfo)> {
        self.breakpoints
            .iter()
            .filter(|(_, bp)| bp.kind == kind)
            .collect()
    }

    /// Return all breakpoints matching a tag.
    pub fn by_tag(&self, tag: &str) -> Vec<(&Address, &BreakpointInfo)> {
        self.breakpoints
            .iter()
            .filter(|(_, bp)| bp.tag.as_deref() == Some(tag))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(offset: u64) -> Address {
        Address::new(offset)
    }

    #[test]
    fn test_set_and_clear_breakpoint() {
        let mut mgr = BreakpointManager::new();
        assert!(mgr.is_empty());

        mgr.set(addr(0x401000), BreakpointKind::Execution);
        assert_eq!(mgr.len(), 1);
        assert!(mgr.is_set(&addr(0x401000)));
        assert!(!mgr.is_set(&addr(0x402000)));

        mgr.clear(addr(0x401000));
        assert!(mgr.is_empty());
        assert!(!mgr.is_set(&addr(0x401000)));
    }

    #[test]
    fn test_breakpoint_hit_count() {
        let mut mgr = BreakpointManager::new();
        mgr.set(addr(0x401000), BreakpointKind::Execution);

        assert!(mgr.check_execution(&addr(0x401000)));
        assert!(mgr.check_execution(&addr(0x401000)));
        assert!(!mgr.check_execution(&addr(0x402000)));

        let bp = mgr.get(&addr(0x401000)).unwrap();
        assert_eq!(bp.hit_count, 2);
    }

    #[test]
    fn test_disabled_breakpoint_does_not_trigger() {
        let mut mgr = BreakpointManager::new();
        mgr.set(addr(0x401000), BreakpointKind::Execution);
        mgr.disable(&addr(0x401000));

        assert!(!mgr.check_execution(&addr(0x401000)));
    }

    #[test]
    fn test_read_write_access_breakpoints() {
        let mut mgr = BreakpointManager::new();

        // Read breakpoint only triggers on reads
        mgr.set(addr(0x1000), BreakpointKind::Read);
        assert!(mgr.check_read(&addr(0x1000)));
        assert!(!mgr.check_write(&addr(0x1000)));

        // Write breakpoint only triggers on writes
        mgr.set(addr(0x2000), BreakpointKind::Write);
        assert!(!mgr.check_read(&addr(0x2000)));
        assert!(mgr.check_write(&addr(0x2000)));

        // Access breakpoint triggers on both
        mgr.set(addr(0x3000), BreakpointKind::Access);
        assert!(mgr.check_read(&addr(0x3000)));
        assert!(mgr.check_write(&addr(0x3000)));
    }

    #[test]
    fn test_conditional_breakpoint() {
        let mut mgr = BreakpointManager::new();
        mgr.set_conditional(addr(0x401000), BreakpointKind::Execution, "RAX == 0");

        let bp = mgr.get(&addr(0x401000)).unwrap();
        assert_eq!(bp.condition.as_deref(), Some("RAX == 0"));
        assert!(bp.enabled);
    }

    #[test]
    fn test_condition_evaluation() {
        let mut regs = HashMap::new();
        regs.insert("RAX".to_string(), vec![0, 0, 0, 0, 0, 0, 0, 0]);
        let flags = HashMap::new();

        // RAX == 0 -> true
        assert!(ConditionEvaluator::evaluate("RAX == 0", &regs, &flags));

        // RAX != 0 -> false
        assert!(!ConditionEvaluator::evaluate("RAX != 0", &regs, &flags));

        // RAX < 10 -> true
        assert!(ConditionEvaluator::evaluate("RAX < 10", &regs, &flags));

        // RAX > 10 -> false
        assert!(!ConditionEvaluator::evaluate("RAX > 10", &regs, &flags));

        // Change RAX to 5
        regs.insert("RAX".to_string(), vec![5, 0, 0, 0, 0, 0, 0, 0]);
        assert!(ConditionEvaluator::evaluate("RAX == 5", &regs, &flags));
        assert!(ConditionEvaluator::evaluate("RAX > 0", &regs, &flags));
    }

    #[test]
    fn test_condition_evaluation_flags() {
        let regs = HashMap::new();
        let mut flags = HashMap::new();
        flags.insert("ZF".to_string(), true);
        flags.insert("CF".to_string(), false);

        assert!(ConditionEvaluator::evaluate("ZF", &regs, &flags));
        assert!(!ConditionEvaluator::evaluate("CF", &regs, &flags));
    }

    #[test]
    fn test_condition_evaluation_hex() {
        let mut regs = HashMap::new();
        regs.insert(
            "RAX".to_string(),
            vec![0xDE, 0xAD, 0, 0, 0, 0, 0, 0],
        );
        let flags = HashMap::new();

        assert!(ConditionEvaluator::evaluate("RAX == 0xADDE", &regs, &flags));
    }

    #[test]
    fn test_check_execution_conditional() {
        let mut mgr = BreakpointManager::new();
        mgr.set_conditional(addr(0x401000), BreakpointKind::Execution, "RAX == 0");

        let mut regs = HashMap::new();
        regs.insert("RAX".to_string(), vec![0, 0, 0, 0, 0, 0, 0, 0]);
        let flags = HashMap::new();

        // Condition satisfied: breakpoint fires
        assert!(mgr.check_execution_conditional(&addr(0x401000), &regs, &flags));

        // Change RAX to non-zero
        regs.insert("RAX".to_string(), vec![5, 0, 0, 0, 0, 0, 0, 0]);
        assert!(!mgr.check_execution_conditional(&addr(0x401000), &regs, &flags));
    }

    #[test]
    fn test_enable_all_disable_all() {
        let mut mgr = BreakpointManager::new();
        mgr.set(addr(0x1000), BreakpointKind::Execution);
        mgr.set(addr(0x2000), BreakpointKind::Read);
        mgr.set(addr(0x3000), BreakpointKind::Write);

        mgr.disable_all();
        assert!(!mgr.is_set(&addr(0x1000)));
        assert!(!mgr.is_set(&addr(0x2000)));
        assert!(!mgr.is_set(&addr(0x3000)));

        mgr.enable_all();
        assert!(mgr.is_set(&addr(0x1000)));
        assert!(mgr.is_set(&addr(0x2000)));
        assert!(mgr.is_set(&addr(0x3000)));
    }

    #[test]
    fn test_tagged_breakpoints() {
        let mut mgr = BreakpointManager::new();
        mgr.set_tagged(addr(0x1000), BreakpointKind::Execution, "syscall");
        mgr.set_tagged(addr(0x2000), BreakpointKind::Read, "syscall");
        mgr.set(addr(0x3000), BreakpointKind::Write);

        let syscall_bps = mgr.by_tag("syscall");
        assert_eq!(syscall_bps.len(), 2);
    }

    #[test]
    fn test_by_kind() {
        let mut mgr = BreakpointManager::new();
        mgr.set(addr(0x1000), BreakpointKind::Execution);
        mgr.set(addr(0x2000), BreakpointKind::Execution);
        mgr.set(addr(0x3000), BreakpointKind::Read);

        let exec_bps = mgr.by_kind(BreakpointKind::Execution);
        assert_eq!(exec_bps.len(), 2);
    }

    #[test]
    fn test_total_hits() {
        let mut mgr = BreakpointManager::new();
        mgr.set(addr(0x1000), BreakpointKind::Execution);
        mgr.set(addr(0x2000), BreakpointKind::Execution);

        mgr.check_execution(&addr(0x1000));
        mgr.check_execution(&addr(0x1000));
        mgr.check_execution(&addr(0x2000));

        assert_eq!(mgr.total_hits(), 3);
    }

    #[test]
    fn test_iter() {
        let mut mgr = BreakpointManager::new();
        mgr.set(addr(0x1000), BreakpointKind::Execution);
        mgr.set(addr(0x2000), BreakpointKind::Read);

        let entries: Vec<_> = mgr.iter().map(|(a, _)| a.offset).collect();
        assert_eq!(entries.len(), 2);
        assert!(entries.contains(&0x1000));
        assert!(entries.contains(&0x2000));
    }

    #[test]
    fn test_breakpoint_action_default() {
        assert_eq!(BreakpointAction::default(), BreakpointAction::Halt);
    }
}
