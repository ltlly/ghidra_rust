//! Context management for the SLEIGH disassembly engine.
//!
//! In SLEIGH, the **context** carries processor state across instruction
//! boundaries during disassembly. For example, on ARM the TMode context bit
//! indicates whether the processor is in Thumb or ARM mode; on MIPS the
//! processor mode bits control which register set is active.
//!
//! Context variables are declared in the `.slaspec` file and set/cleared by
//! [`ContextOp`](super::construct::ContextOp)s attached to constructors.
//!
//! # Key Types
//! - [`ContextDatabase`] - The complete context state and metadata registry
//! - [`ContextBit`] - Metadata for a single-bit context variable
//! - [`ContextField`] - Metadata for a multi-bit context variable
//! - [`TrackedContext`] - A context variable bound to a specific varnode location

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

use super::pcode::Varnode;

// ---------------------------------------------------------------------------
// ContextBit
// ---------------------------------------------------------------------------

/// Metadata for a single boolean context variable.
///
/// Each context bit has a name, a position in the context bit vector, and a
/// default value. During disassembly, the context bit vector is updated as
/// constructors match.
///
/// # Example
/// ```ignore
/// define context TMode    // ARM Thumb mode bit
///     bit  = (0,0)        // at bit position 0
///     flow = true         // follows control flow
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContextBit {
    /// Human-readable name (e.g., "TMode" for ARM Thumb mode)
    pub name: String,
    /// Bit position in the context vector
    pub position: usize,
    /// Default value when no context has been set (0 or 1)
    pub default_value: u8,
    /// If true, this bit propagates along control-flow edges
    pub flow_follow: bool,
}

impl ContextBit {
    /// Create a new context bit definition.
    pub fn new(name: impl Into<String>, position: usize, default_value: u8) -> Self {
        Self {
            name: name.into(),
            position,
            default_value: default_value.min(1),
            flow_follow: false,
        }
    }

    /// Mark this bit as following control flow.
    pub fn with_flow_follow(mut self) -> Self {
        self.flow_follow = true;
        self
    }
}

impl fmt::Display for ContextBit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} @ bit {} (default: {})",
            self.name, self.position, self.default_value
        )
    }
}

// ---------------------------------------------------------------------------
// ContextField
// ---------------------------------------------------------------------------

/// Metadata for a multi-bit context variable.
///
/// A context field spans multiple bits in the context vector and represents
/// a value that cannot be expressed as a single boolean. For example, a
/// processor mode field might use 2 or 3 bits to select among 4-8 modes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContextField {
    /// Human-readable name (e.g., "processorMode")
    pub name: String,
    /// Starting bit position (inclusive) in the context vector
    pub start_bit: usize,
    /// Ending bit position (exclusive) in the context vector
    pub end_bit: usize,
    /// Default value for the field
    pub default_value: u64,
    /// If true, this field propagates along control-flow edges
    pub flow_follow: bool,
}

impl ContextField {
    /// Create a new context field definition.
    pub fn new(
        name: impl Into<String>,
        start_bit: usize,
        end_bit: usize,
        default_value: u64,
    ) -> Self {
        Self {
            name: name.into(),
            start_bit,
            end_bit,
            default_value,
            flow_follow: false,
        }
    }

    /// Number of bits in this field.
    pub fn bit_width(&self) -> usize {
        self.end_bit.saturating_sub(self.start_bit)
    }

    /// Maximum value that fits in this field.
    pub fn max_value(&self) -> u64 {
        let width = self.bit_width();
        if width >= 64 {
            u64::MAX
        } else {
            (1u64 << width) - 1
        }
    }

    /// Extract this field's value from a context bit vector.
    pub fn extract(&self, context_bits: &[u8]) -> u64 {
        let mut value: u64 = 0;
        let byte_start = self.start_bit / 8;
        let byte_end = (self.end_bit + 7) / 8;
        for i in byte_start..byte_end.min(context_bits.len()) {
            value = (value << 8) | (context_bits[i] as u64);
        }
        let shift = (byte_end * 8).saturating_sub(self.end_bit);
        value >>= shift;
        // Mask
        let mask = self.max_value();
        value & mask
    }

    /// Encode a value into a context bit vector at this field's position.
    pub fn encode(&self, context_bits: &mut Vec<u8>, value: u64) {
        // Ensure the vector is large enough
        let required_bytes = (self.end_bit + 7) / 8;
        if context_bits.len() < required_bytes {
            context_bits.resize(required_bytes, 0);
        }

        let clamped = value & self.max_value();
        let width = self.bit_width();

        // Write the value into the bit vector
        for i in 0..width {
            let bit_idx = self.start_bit + i;
            let byte_idx = bit_idx / 8;
            let bit_off = 7 - (bit_idx % 8); // MSB-first within byte

            if (clamped >> (width - 1 - i)) & 1 != 0 {
                context_bits[byte_idx] |= 1 << bit_off;
            } else {
                context_bits[byte_idx] &= !(1 << bit_off);
            }
        }
    }

    /// Mark this field as following control flow.
    pub fn with_flow_follow(mut self) -> Self {
        self.flow_follow = true;
        self
    }
}

impl fmt::Display for ContextField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} [{}:{}] ({} bits, default: 0x{:x})",
            self.name,
            self.start_bit,
            self.end_bit,
            self.bit_width(),
            self.default_value
        )
    }
}

// ---------------------------------------------------------------------------
// TrackedContext
// ---------------------------------------------------------------------------

/// A context variable bound to a specific varnode location.
///
/// Some context variables are not purely abstract but are stored in an
/// actual register or memory location. `TrackedContext` records the mapping
/// between a context variable and its backing varnode.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrackedContext {
    /// Name of the context variable
    pub name: String,
    /// The varnode that stores this context value
    pub varnode: Varnode,
    /// Whether this tracking relationship is currently valid
    pub valid: bool,
}

impl TrackedContext {
    /// Create a new tracked context binding.
    pub fn new(name: impl Into<String>, varnode: Varnode) -> Self {
        Self {
            name: name.into(),
            varnode,
            valid: true,
        }
    }

    /// Invalidate this tracking relationship (e.g., varnode was overwritten).
    pub fn invalidate(&mut self) {
        self.valid = false;
    }

    /// Revalidate this tracking relationship.
    pub fn validate(&mut self) {
        self.valid = true;
    }
}

impl fmt::Display for TrackedContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} @ {} (valid: {})",
            self.name, self.varnode, self.valid
        )
    }
}

// ---------------------------------------------------------------------------
// ContextDatabase
// ---------------------------------------------------------------------------

/// The complete context state database.
///
/// `ContextDatabase` manages:
/// - The **definition** of all context variables (bits and fields)
/// - The **current state** as a bit vector
/// - **Tracked** context variables (bound to varnodes)
/// - **Commit/rollback** for speculative disassembly (branching)
///
/// # Architecture
///
/// The context state is stored as a flat bit vector (`Vec<u8>`). Individual
/// bits are addressed by position; multi-bit fields are extracted/encoded
/// as ranges. The `ContextDatabase` provides a high-level interface for
/// getting/setting named variables.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextDatabase {
    /// All registered context bit variables
    bits: Vec<ContextBit>,
    /// All registered multi-bit context field variables
    fields: Vec<ContextField>,
    /// Context variables tracked to specific varnodes
    tracked: Vec<TrackedContext>,
    /// Name-to-index mappings for fast lookup
    bit_index: HashMap<String, usize>,
    /// Name-to-index mappings for field lookup
    field_index: HashMap<String, usize>,
    /// Current context state as a flat bit vector
    current_state: Vec<u8>,
    /// Saved state for commit/rollback (LIFO stack)
    save_stack: Vec<Vec<u8>>,
    /// Total number of bits in the context
    total_bits: usize,
}

impl ContextDatabase {
    /// Create an empty context database.
    pub fn new() -> Self {
        Self {
            bits: Vec::new(),
            fields: Vec::new(),
            tracked: Vec::new(),
            bit_index: HashMap::new(),
            field_index: HashMap::new(),
            current_state: Vec::new(),
            save_stack: Vec::new(),
            total_bits: 0,
        }
    }

    // --- Registration ---

    /// Register a new single-bit context variable.
    ///
    /// Returns an error if a variable with the same name already exists.
    pub fn register_bit(&mut self, bit: ContextBit) -> Result<(), String> {
        if self.bit_index.contains_key(&bit.name) {
            return Err(format!("Context bit '{}' already registered", bit.name));
        }
        if self.field_index.contains_key(&bit.name) {
            return Err(format!(
                "Name '{}' already used as a context field",
                bit.name
            ));
        }
        self.total_bits = self.total_bits.max(bit.position + 1);
        let idx = self.bits.len();
        self.bit_index.insert(bit.name.clone(), idx);
        self.ensure_state_size();
        // Apply default value immediately, even if state was already large enough
        self.apply_bit_value(&bit, bit.default_value);
        self.bits.push(bit);
        Ok(())
    }

    /// Write a value to the context bit vector at the given bit's position.
    fn apply_bit_value(&mut self, bit: &ContextBit, value: u8) {
        let byte_idx = bit.position / 8;
        let bit_off = 7 - (bit.position % 8);
        if byte_idx < self.current_state.len() {
            if value != 0 {
                self.current_state[byte_idx] |= 1 << bit_off;
            } else {
                self.current_state[byte_idx] &= !(1 << bit_off);
            }
        }
    }

    /// Register a new multi-bit context field variable.
    ///
    /// Returns an error if a variable with the same name already exists.
    pub fn register_field(&mut self, field: ContextField) -> Result<(), String> {
        if self.field_index.contains_key(&field.name) {
            return Err(format!("Context field '{}' already registered", field.name));
        }
        if self.bit_index.contains_key(&field.name) {
            return Err(format!(
                "Name '{}' already used as a context bit",
                field.name
            ));
        }
        self.total_bits = self.total_bits.max(field.end_bit);
        let idx = self.fields.len();
        self.field_index.insert(field.name.clone(), idx);
        self.ensure_state_size();
        // Apply default value immediately
        let default_val = field.default_value;
        self.fields.push(field);
        // Encode default at the newly registered field's position
        if let Some(last_field) = self.fields.last() {
            last_field.encode(&mut self.current_state, default_val);
        }
        Ok(())
    }

    /// Register a tracked context variable.
    pub fn register_tracked(&mut self, tracked: TrackedContext) {
        self.tracked.push(tracked);
    }

    // --- State Management ---

    /// Ensure the current state vector is large enough to hold all bits.
    fn ensure_state_size(&mut self) {
        let required = (self.total_bits + 7) / 8;
        if self.current_state.len() < required {
            // Preserve existing bits, initialize new bytes to defaults
            let old_len = self.current_state.len();
            self.current_state.resize(required, 0);
            // Apply defaults for newly allocated bits
            for bit in &self.bits {
                if bit.default_value != 0 && bit.position / 8 >= old_len {
                    let byte_idx = bit.position / 8;
                    let bit_off = 7 - (bit.position % 8);
                    if bit.default_value != 0 {
                        self.current_state[byte_idx] |= 1 << bit_off;
                    }
                }
            }
        }
    }

    /// Clear all context state to defaults.
    pub fn reset(&mut self) {
        self.current_state.clear();
        self.save_stack.clear();
        self.ensure_state_size();
        // Apply all defaults
        for bit in &self.bits {
            let byte_idx = bit.position / 8;
            let bit_off = 7 - (bit.position % 8);
            if bit.default_value != 0 {
                if byte_idx < self.current_state.len() {
                    self.current_state[byte_idx] |= 1 << bit_off;
                }
            } else if byte_idx < self.current_state.len() {
                self.current_state[byte_idx] &= !(1 << bit_off);
            }
        }
        for field in &self.fields {
            field.encode(&mut self.current_state, field.default_value);
        }
    }

    // --- Bit Operations ---

    /// Get the value of a single-bit context variable by name.
    pub fn get_bit(&self, name: &str) -> Option<bool> {
        let idx = self.bit_index.get(name)?;
        let bit = &self.bits[*idx];
        let byte_idx = bit.position / 8;
        let bit_off = 7 - (bit.position % 8);
        if byte_idx < self.current_state.len() {
            Some((self.current_state[byte_idx] >> bit_off) & 1 != 0)
        } else {
            Some(bit.default_value != 0)
        }
    }

    /// Set the value of a single-bit context variable by name.
    pub fn set_bit(&mut self, name: &str, value: bool) -> Result<(), String> {
        let idx = self
            .bit_index
            .get(name)
            .ok_or_else(|| format!("Context bit '{}' not found", name))?;
        let bit = &self.bits[*idx];
        let byte_idx = bit.position / 8;
        let bit_off = 7 - (bit.position % 8);
        self.ensure_state_size();
        if byte_idx < self.current_state.len() {
            if value {
                self.current_state[byte_idx] |= 1 << bit_off;
            } else {
                self.current_state[byte_idx] &= !(1 << bit_off);
            }
        }
        Ok(())
    }

    /// Get the value of a named context field (multi-bit).
    pub fn get_field(&self, name: &str) -> Option<u64> {
        let idx = self.field_index.get(name)?;
        let field = &self.fields[*idx];
        Some(field.extract(&self.current_state))
    }

    /// Set the value of a named context field (multi-bit).
    pub fn set_field(&mut self, name: &str, value: u64) -> Result<(), String> {
        let idx = self
            .field_index
            .get(name)
            .ok_or_else(|| format!("Context field '{}' not found", name))?;
        let field = self.fields[*idx].clone();
        field.encode(&mut self.current_state, value);
        Ok(())
    }

    // --- Save / Restore ---

    /// Save the current context state for later rollback.
    ///
    /// This is used before speculative disassembly (e.g., following a branch)
    /// so that the state can be restored if the speculation is wrong.
    pub fn save_state(&mut self) {
        self.save_stack.push(self.current_state.clone());
    }

    /// Restore the most recently saved context state (pop from save stack).
    ///
    /// Returns `Ok(())` if a saved state was restored, or an error if the
    /// save stack is empty.
    pub fn restore_state(&mut self) -> Result<(), String> {
        if let Some(saved) = self.save_stack.pop() {
            self.current_state = saved;
            Ok(())
        } else {
            Err("No saved context state to restore".into())
        }
    }

    /// Commit (discard) the most recently saved state without restoring it.
    ///
    /// This is used after successful speculative disassembly when the new
    /// context state should be kept.
    pub fn commit_state(&mut self) -> Result<(), String> {
        if self.save_stack.pop().is_some() {
            Ok(())
        } else {
            Err("No saved context state to commit".into())
        }
    }

    /// Number of levels in the save stack.
    pub fn save_depth(&self) -> usize {
        self.save_stack.len()
    }

    // --- Query ---

    /// Returns the total number of bits in the context.
    pub fn total_bits(&self) -> usize {
        self.total_bits
    }

    /// Returns the current state as a byte slice.
    pub fn state_bytes(&self) -> &[u8] {
        &self.current_state
    }

    /// Returns an iterator over all registered bit variables.
    pub fn iter_bits(&self) -> impl Iterator<Item = &ContextBit> {
        self.bits.iter()
    }

    /// Returns an iterator over all registered field variables.
    pub fn iter_fields(&self) -> impl Iterator<Item = &ContextField> {
        self.fields.iter()
    }

    /// Returns an iterator over all tracked context variables.
    pub fn iter_tracked(&self) -> impl Iterator<Item = &TrackedContext> {
        self.tracked.iter()
    }

    /// Check if a named context variable exists (bit or field).
    pub fn contains(&self, name: &str) -> bool {
        self.bit_index.contains_key(name) || self.field_index.contains_key(name)
    }

    /// Returns the bit width of a named variable, if it exists.
    pub fn width_of(&self, name: &str) -> Option<usize> {
        if self.bit_index.contains_key(name) {
            Some(1)
        } else if let Some(idx) = self.field_index.get(name) {
            Some(self.fields[*idx].bit_width())
        } else {
            None
        }
    }
}

impl Default for ContextDatabase {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for ContextDatabase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "ContextDatabase ({} bits total):", self.total_bits)?;
        for bit in &self.bits {
            let val = self.get_bit(&bit.name).unwrap_or(false);
            writeln!(f, "  {} = {}", bit.name, val as u8)?;
        }
        for field in &self.fields {
            let val = self.get_field(&field.name).unwrap_or(0);
            writeln!(f, "  {} = 0x{:x}", field.name, val)?;
        }
        if !self.tracked.is_empty() {
            writeln!(f, "Tracked:")?;
            for t in &self.tracked {
                writeln!(f, "  {}", t)?;
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_register_and_get_bit() {
        let mut db = ContextDatabase::new();
        db.register_bit(ContextBit::new("TMode", 0, 0)).unwrap();
        db.register_bit(ContextBit::new("BigEndian", 1, 1)).unwrap();

        assert_eq!(db.total_bits(), 2);
        assert_eq!(db.get_bit("TMode"), Some(false)); // default 0
        assert_eq!(db.get_bit("BigEndian"), Some(true)); // default 1
    }

    #[test]
    fn test_set_and_get_bit() {
        let mut db = ContextDatabase::new();
        db.register_bit(ContextBit::new("TMode", 0, 0)).unwrap();

        db.set_bit("TMode", true).unwrap();
        assert_eq!(db.get_bit("TMode"), Some(true));

        db.set_bit("TMode", false).unwrap();
        assert_eq!(db.get_bit("TMode"), Some(false));
    }

    #[test]
    fn test_register_field() {
        let mut db = ContextDatabase::new();
        db.register_field(ContextField::new("Mode", 0, 2, 0))
            .unwrap();

        assert_eq!(db.total_bits(), 2);
        assert_eq!(db.get_field("Mode"), Some(0));

        db.set_field("Mode", 3).unwrap();
        assert_eq!(db.get_field("Mode"), Some(3));

        // 3 is max for 2 bits
        db.set_field("Mode", 5).unwrap();
        assert_eq!(db.get_field("Mode"), Some(1)); // 5 & 3 = 1
    }

    #[test]
    fn test_save_restore_state() {
        let mut db = ContextDatabase::new();
        db.register_bit(ContextBit::new("TMode", 0, 0)).unwrap();

        db.set_bit("TMode", true).unwrap();
        db.save_state();

        db.set_bit("TMode", false).unwrap();
        assert_eq!(db.get_bit("TMode"), Some(false));

        db.restore_state().unwrap();
        assert_eq!(db.get_bit("TMode"), Some(true));
    }

    #[test]
    fn test_commit_state() {
        let mut db = ContextDatabase::new();
        db.register_bit(ContextBit::new("TMode", 0, 0)).unwrap();

        db.set_bit("TMode", true).unwrap();
        db.save_state();

        db.set_bit("TMode", false).unwrap();
        db.commit_state().unwrap();

        assert_eq!(db.get_bit("TMode"), Some(false));
        // Restore should now fail since we committed
        assert!(db.restore_state().is_err());
    }

    #[test]
    fn test_duplicate_register_fails() {
        let mut db = ContextDatabase::new();
        db.register_bit(ContextBit::new("TMode", 0, 0)).unwrap();
        assert!(db.register_bit(ContextBit::new("TMode", 1, 0)).is_err());
        assert!(db
            .register_field(ContextField::new("TMode", 0, 2, 0))
            .is_err());
    }

    #[test]
    fn test_reset_to_defaults() {
        let mut db = ContextDatabase::new();
        db.register_bit(ContextBit::new("Flag", 0, 1)).unwrap();
        db.set_bit("Flag", false).unwrap();

        db.reset();
        assert_eq!(db.get_bit("Flag"), Some(true)); // back to default
    }

    #[test]
    fn test_field_extract_encode() {
        // 8-bit field spanning bits 4..12
        let field = ContextField::new("Mode", 4, 12, 0);
        let mut bits = vec![0u8; 2]; // 16 bits

        field.encode(&mut bits, 0xAB);
        let extracted = field.extract(&bits);
        assert_eq!(extracted, 0xAB);
    }

    #[test]
    fn test_tracked_context() {
        let vn = Varnode::register(0, 4);
        let mut tc = TrackedContext::new("PC", vn.clone());
        assert!(tc.valid);

        tc.invalidate();
        assert!(!tc.valid);

        tc.validate();
        assert!(tc.valid);
    }
}
