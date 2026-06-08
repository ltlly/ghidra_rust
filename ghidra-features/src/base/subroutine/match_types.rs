//! Subroutine match types -- ported from `SubroutineMatch.java` and
//! `SubroutineMatchSet.java`.
//!
//! - [`SubroutineMatch`] -- cheap container for a single match between
//!   addresses in program A and program B, with a match reason string.
//! - [`SubroutineMatchSet`] -- a collection of [`SubroutineMatch`]es
//!   between two programs, holding references to both programs' block
//!   models for convenient length queries.

use crate::base::analyzer::core::{Address, CancelledError};
use super::block_model::{CodeBlockModel, TaskMonitor};

// ============================================================================
// SubroutineMatch
// ============================================================================

/// A match between one or more addresses in program A and one or more
/// addresses in program B.
///
/// A match is typically produced by a correlator that identified a
/// correspondence between subroutines in two different programs (e.g.,
/// during version tracking).
///
/// # Examples
///
/// ```ignore
/// use ghidra_features::base::subroutine::*;
/// use ghidra_features::base::analyzer::core::Address;
///
/// let mut m = SubroutineMatch::new("Exact Hash Match");
/// m.add_a(Address::new(0x401000));
/// m.add_b(Address::new(0x10001000));
/// assert!(m.is_one_to_one());
/// ```
#[derive(Debug, Clone)]
pub struct SubroutineMatch {
    /// Addresses in program A.
    prog_a_addrs: Vec<Address>,
    /// Addresses in program B.
    prog_b_addrs: Vec<Address>,
    /// Why these subroutines were matched.
    reason: String,
}

impl SubroutineMatch {
    /// Create a new empty match with the given reason.
    pub fn new(reason: impl Into<String>) -> Self {
        Self {
            prog_a_addrs: Vec::new(),
            prog_b_addrs: Vec::new(),
            reason: reason.into(),
        }
    }

    /// Add an address to the appropriate program side.
    ///
    /// Returns `true` (the address was always added in the original Java).
    pub fn add(&mut self, addr: Address, is_a: bool) -> bool {
        if is_a {
            self.prog_a_addrs.push(addr);
        } else {
            self.prog_b_addrs.push(addr);
        }
        true
    }

    /// Add an address to program A.
    pub fn add_a(&mut self, addr: Address) {
        self.prog_a_addrs.push(addr);
    }

    /// Add an address to program B.
    pub fn add_b(&mut self, addr: Address) {
        self.prog_b_addrs.push(addr);
    }

    /// Remove an address from the appropriate program side.
    ///
    /// Returns `false` when the address is `None` or not found (matching
    /// the original Java behaviour).
    pub fn remove(&mut self, addr: Address, is_a: bool) -> bool {
        let addrs = if is_a {
            &mut self.prog_a_addrs
        } else {
            &mut self.prog_b_addrs
        };
        if let Some(pos) = addrs.iter().position(|a| *a == addr) {
            addrs.remove(pos);
            true
        } else {
            false
        }
    }

    /// The reason this match was created.
    pub fn reason(&self) -> &str {
        &self.reason
    }

    /// Addresses in program A.
    pub fn a_addresses(&self) -> &[Address] {
        &self.prog_a_addrs
    }

    /// Addresses in program B.
    pub fn b_addresses(&self) -> &[Address] {
        &self.prog_b_addrs
    }

    /// Returns `true` if this is a 1-to-1 match.
    pub fn is_one_to_one(&self) -> bool {
        self.prog_a_addrs.len() == 1 && self.prog_b_addrs.len() == 1
    }

    /// Number of addresses in program A.
    pub fn a_count(&self) -> usize {
        self.prog_a_addrs.len()
    }

    /// Number of addresses in program B.
    pub fn b_count(&self) -> usize {
        self.prog_b_addrs.len()
    }
}

impl std::fmt::Display for SubroutineMatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ", self.reason)?;
        for (i, addr) in self.prog_a_addrs.iter().enumerate() {
            if i > 0 {
                write!(f, ",")?;
            }
            write!(f, "{}", addr)?;
        }
        write!(f, " --- ")?;
        for (i, addr) in self.prog_b_addrs.iter().enumerate() {
            if i > 0 {
                write!(f, ",")?;
            }
            write!(f, "{}", addr)?;
        }
        Ok(())
    }
}

// ============================================================================
// SubroutineMatchSet
// ============================================================================

/// A collection of [`SubroutineMatch`]es between two programs.
///
/// The set holds references to the two programs (via their block models)
/// so that code-length queries can be answered directly.
pub struct SubroutineMatchSet {
    /// Matches collected so far.
    matches: Vec<SubroutineMatch>,
    /// Model for program A (used for length queries).
    a_model_name: String,
    /// Model for program B.
    b_model_name: String,
}

impl SubroutineMatchSet {
    /// Create a new match set.
    ///
    /// `a_model_name` and `b_model_name` are labels for the block models
    /// used to resolve subroutine lengths.
    pub fn new(a_model_name: impl Into<String>, b_model_name: impl Into<String>) -> Self {
        Self {
            matches: Vec::new(),
            a_model_name: a_model_name.into(),
            b_model_name: b_model_name.into(),
        }
    }

    /// Add a match to the set.
    pub fn push(&mut self, m: SubroutineMatch) {
        self.matches.push(m);
    }

    /// All matches.
    pub fn matches(&self) -> &[SubroutineMatch] {
        &self.matches
    }

    /// Number of matches.
    pub fn len(&self) -> usize {
        self.matches.len()
    }

    /// Whether the set is empty.
    pub fn is_empty(&self) -> bool {
        self.matches.is_empty()
    }

    /// Get the code-block length at `addr` using the provided model.
    ///
    /// Returns `0` if the block cannot be resolved.
    pub fn get_length(
        addr: &Address,
        model: &dyn CodeBlockModel,
        monitor: &dyn TaskMonitor,
    ) -> Result<u64, CancelledError> {
        match model.get_code_block_at(addr, monitor)? {
            Some(block) => Ok(block.num_addresses()),
            None => Ok(0),
        }
    }

    /// Model name for program A.
    pub fn a_model_name(&self) -> &str {
        &self.a_model_name
    }

    /// Model name for program B.
    pub fn b_model_name(&self) -> &str {
        &self.b_model_name
    }
}

impl std::fmt::Debug for SubroutineMatchSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SubroutineMatchSet")
            .field("count", &self.matches.len())
            .field("a_model", &self.a_model_name)
            .field("b_model", &self.b_model_name)
            .finish()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::base::analyzer::core::AddressRange;
    use crate::base::subroutine::CodeBlock;
    use crate::AddressSet;

    // -- SubroutineMatch tests --

    #[test]
    fn test_match_creation() {
        let m = SubroutineMatch::new("Hash Match");
        assert_eq!(m.reason(), "Hash Match");
        assert!(m.a_addresses().is_empty());
        assert!(m.b_addresses().is_empty());
    }

    #[test]
    fn test_match_add_a_and_b() {
        let mut m = SubroutineMatch::new("test");
        m.add_a(Address::new(0x401000));
        m.add_a(Address::new(0x402000));
        m.add_b(Address::new(0x10001000));
        assert_eq!(m.a_count(), 2);
        assert_eq!(m.b_count(), 1);
        assert!(!m.is_one_to_one());
    }

    #[test]
    fn test_match_add_generic() {
        let mut m = SubroutineMatch::new("test");
        m.add(Address::new(0x401000), true);  // A
        m.add(Address::new(0x10001000), false); // B
        assert!(m.is_one_to_one());
    }

    #[test]
    fn test_match_remove_existing() {
        let mut m = SubroutineMatch::new("test");
        m.add_a(Address::new(0x401000));
        m.add_a(Address::new(0x402000));
        assert!(m.remove(Address::new(0x401000), true));
        assert_eq!(m.a_count(), 1);
        assert_eq!(m.a_addresses()[0], Address::new(0x402000));
    }

    #[test]
    fn test_match_remove_nonexistent() {
        let mut m = SubroutineMatch::new("test");
        m.add_a(Address::new(0x401000));
        assert!(!m.remove(Address::new(0xDEADBEEF), true));
        assert_eq!(m.a_count(), 1);
    }

    #[test]
    fn test_match_is_one_to_one() {
        let mut m = SubroutineMatch::new("test");
        m.add_a(Address::new(0x100));
        m.add_b(Address::new(0x200));
        assert!(m.is_one_to_one());

        m.add_a(Address::new(0x300));
        assert!(!m.is_one_to_one());
    }

    #[test]
    fn test_match_display() {
        let mut m = SubroutineMatch::new("CallGraph");
        m.add_a(Address::new(0x401000));
        m.add_b(Address::new(0x10001000));
        let s = m.to_string();
        assert!(s.contains("CallGraph"));
        assert!(s.contains("---"));
    }

    // -- SubroutineMatchSet tests --

    #[test]
    fn test_match_set_creation() {
        let set = SubroutineMatchSet::new("PartitionModel", "SubroutineModel");
        assert!(set.is_empty());
        assert_eq!(set.len(), 0);
    }

    #[test]
    fn test_match_set_push() {
        let mut set = SubroutineMatchSet::new("A", "B");
        let mut m1 = SubroutineMatch::new("Hash");
        m1.add_a(Address::new(0x401000));
        m1.add_b(Address::new(0x10001000));
        set.push(m1);

        let mut m2 = SubroutineMatch::new("CallGraph");
        m2.add_a(Address::new(0x402000));
        m2.add_b(Address::new(0x10002000));
        set.push(m2);

        assert_eq!(set.len(), 2);
        assert!(!set.is_empty());
        assert_eq!(set.matches()[0].reason(), "Hash");
        assert_eq!(set.matches()[1].reason(), "CallGraph");
    }

    #[test]
    fn test_match_set_model_names() {
        let set = SubroutineMatchSet::new("ModelA", "ModelB");
        assert_eq!(set.a_model_name(), "ModelA");
        assert_eq!(set.b_model_name(), "ModelB");
    }

    #[test]
    fn test_match_set_debug() {
        let set = SubroutineMatchSet::new("A", "B");
        let dbg = format!("{:?}", set);
        assert!(dbg.contains("SubroutineMatchSet"));
        assert!(dbg.contains("0"));
    }

    // -- CodeBlock helper for length test --

    struct SingleBlockModel {
        block: Option<CodeBlock>,
    }

    impl SingleBlockModel {
        fn new(block: CodeBlock) -> Self {
            Self { block: Some(block) }
        }

        fn empty() -> Self {
            Self { block: None }
        }
    }

    impl CodeBlockModel for SingleBlockModel {
        fn name(&self) -> &str {
            "SingleBlockModel"
        }

        fn get_code_block_at(
            &self,
            _addr: &Address,
            _monitor: &dyn TaskMonitor,
        ) -> Result<Option<CodeBlock>, CancelledError> {
            Ok(self.block.clone())
        }

        fn get_code_blocks_containing(
            &self,
            _set: &AddressSet,
            _monitor: &dyn TaskMonitor,
        ) -> Result<Vec<CodeBlock>, CancelledError> {
            Ok(self.block.iter().cloned().collect())
        }

        fn get_code_blocks(
            &self,
            _monitor: &dyn TaskMonitor,
        ) -> Result<Vec<CodeBlock>, CancelledError> {
            Ok(self.block.iter().cloned().collect())
        }

        fn get_first_code_block_containing(
            &self,
            _addr: &Address,
            _monitor: &dyn TaskMonitor,
        ) -> Result<Option<CodeBlock>, CancelledError> {
            Ok(self.block.clone())
        }

        fn get_basic_block_model(&self) -> &dyn CodeBlockModel {
            self
        }

        fn allows_block_overlap(&self) -> bool {
            false
        }

        fn externals_included(&self) -> bool {
            false
        }
    }

    #[test]
    fn test_get_length_with_block() {
        let block = CodeBlock::new(
            "func",
            AddressRange::new(Address::new(0x401000), Address::new(0x4010FF)),
            "M",
        );
        let model = SingleBlockModel::new(block);
        let monitor = super::super::block_model::DummyMonitor;
        let len =
            SubroutineMatchSet::get_length(&Address::new(0x401000), &model, &monitor).unwrap();
        assert_eq!(len, 0x100); // 0x10FF - 0x401000 + 1 = 256
    }

    #[test]
    fn test_get_length_no_block() {
        let model = SingleBlockModel::empty();
        let monitor = super::super::block_model::DummyMonitor;
        let len =
            SubroutineMatchSet::get_length(&Address::new(0x401000), &model, &monitor).unwrap();
        assert_eq!(len, 0);
    }
}
