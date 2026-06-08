//! Subroutine model command -- ported from `SubroutineModelCmd.java`.
//!
//! The [`SubroutineModelCmd`] organizes a program module or fragment
//! according to a specified [`SubroutineBlockModel`], producing a
//! flat (single-layer) partitioning of the code into subroutine-
//! sized fragments.
//!
//! In Ghidra the command creates new modules/fragments in the program
//! tree.  Here the logic is modelled as a pure computation over
//! [`CodeBlock`]s so it can be reused in non-GUI contexts.

use crate::base::analyzer::core::{AddressRange, AddressSet, CancelledError};
#[allow(unused_imports)]
use super::block_model::{CodeBlockModel, SubroutineBlockModel, TaskMonitor};

/// Suffix appended to newly created module/fragment names.
pub const NEW_MODULE_SUFFIX: &str = " [Subroutines]";

// ============================================================================
// ProgramFragmentInfo
// ============================================================================

/// Represents a fragment in the program tree that would be created by
/// the subroutine model command.
///
/// In Ghidra, a `ProgramFragment` is a leaf node in the program tree
/// that contains a set of addresses.  This struct carries just the
/// information needed to create such a fragment.
#[derive(Debug, Clone)]
pub struct ProgramFragmentInfo {
    /// Name of the fragment (typically the block name).
    pub name: String,
    /// Address ranges in this fragment.
    pub address_ranges: Vec<AddressRange>,
}

impl ProgramFragmentInfo {
    /// Create a new fragment info.
    pub fn new(name: impl Into<String>, ranges: Vec<AddressRange>) -> Self {
        Self {
            name: name.into(),
            address_ranges: ranges,
        }
    }

    /// Total number of addresses in this fragment.
    pub fn num_addresses(&self) -> u64 {
        self.address_ranges.iter().map(|r| r.len()).sum()
    }
}

// ============================================================================
// SubroutineModelCmd
// ============================================================================

/// Command to organise a module or fragment according to a subroutine
/// block model.
///
/// This produces a flat partitioning where each code block from the
/// model becomes a separate [`ProgramFragmentInfo`].
///
/// # Usage
///
/// ```ignore
/// use ghidra_features::base::subroutine::*;
/// use ghidra_features::base::analyzer::core::AddressSet;
///
/// let cmd = SubroutineModelCmd::new(model_name, group_path, tree_name);
/// let fragments = cmd.execute(&model, &address_set, &monitor)?;
/// ```
#[derive(Debug, Clone)]
pub struct SubroutineModelCmd {
    /// Name of the block model to use.  `None` means "use the active
    /// subroutine model."
    model_name: Option<String>,
    /// Path to the group (module/fragment) to be reorganised.
    group_path: Vec<String>,
    /// Name of the program tree.
    tree_name: String,
}

impl SubroutineModelCmd {
    /// Create a new command.
    ///
    /// * `model_name` -- name of the subroutine block model, or `None`
    ///   for the active model.
    /// * `group_path` -- path segments to the target group in the tree
    ///   (root first).
    /// * `tree_name` -- name of the program tree (e.g., "Program Tree").
    pub fn new(
        model_name: Option<impl Into<String>>,
        group_path: Vec<impl Into<String>>,
        tree_name: impl Into<String>,
    ) -> Self {
        Self {
            model_name: model_name.map(Into::into),
            group_path: group_path.into_iter().map(Into::into).collect(),
            tree_name: tree_name.into(),
        }
    }

    /// The model name, if explicitly set.
    pub fn model_name(&self) -> Option<&str> {
        self.model_name.as_deref()
    }

    /// The group path segments.
    pub fn group_path(&self) -> &[String] {
        &self.group_path
    }

    /// The program tree name.
    pub fn tree_name(&self) -> &str {
        &self.tree_name
    }

    /// Execute the command using the given model and address set.
    ///
    /// Returns a list of [`ProgramFragmentInfo`]s that represent the
    /// new tree fragments to be created.
    pub fn execute(
        &self,
        model: &dyn SubroutineBlockModel,
        address_set: &AddressSet,
        monitor: &dyn TaskMonitor,
    ) -> Result<Vec<ProgramFragmentInfo>, CancelledError> {
        let blocks = if address_set.is_empty() {
            model.get_code_blocks(monitor)?
        } else {
            model.get_code_blocks_containing(address_set, monitor)?
        };

        let mut fragments = Vec::with_capacity(blocks.len());
        let mut seen_names = std::collections::HashMap::<String, usize>::new();

        for block in blocks {
            monitor.check_cancelled()?;
            let base_name = block.name.clone();
            let name = Self::unique_name(&base_name, &mut seen_names);
            let ranges = block.address_ranges();
            fragments.push(ProgramFragmentInfo::new(name, ranges));
        }

        Ok(fragments)
    }

    /// Generate a unique fragment name by appending `(N)` if the base
    /// name has already been used.
    fn unique_name(
        base: &String,
        seen: &mut std::collections::HashMap<String, usize>,
    ) -> String {
        let count = seen.entry(base.clone()).or_insert(0);
        if *count == 0 {
            *count += 1;
            base.clone()
        } else {
            let name = format!("{}({})", base, *count);
            *count += 1;
            name
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::block_model::DummyMonitor;
    use crate::base::subroutine::CodeBlock;
    use crate::Address;

    /// Test subroutine block model.
    struct TestSubModel {
        blocks: Vec<CodeBlock>,
    }

    impl TestSubModel {
        fn new(blocks: Vec<CodeBlock>) -> Self {
            Self { blocks }
        }
    }

    impl CodeBlockModel for TestSubModel {
        fn name(&self) -> &str {
            "TestSubModel"
        }

        fn get_code_block_at(
            &self,
            addr: &Address,
            _monitor: &dyn TaskMonitor,
        ) -> Result<Option<CodeBlock>, CancelledError> {
            Ok(self.blocks.iter().find(|b| b.contains(addr)).cloned())
        }

        fn get_code_blocks_containing(
            &self,
            set: &AddressSet,
            _monitor: &dyn TaskMonitor,
        ) -> Result<Vec<CodeBlock>, CancelledError> {
            Ok(self
                .blocks
                .iter()
                .filter(|b| set.contains(&b.min_address()))
                .cloned()
                .collect())
        }

        fn get_code_blocks(
            &self,
            _monitor: &dyn TaskMonitor,
        ) -> Result<Vec<CodeBlock>, CancelledError> {
            Ok(self.blocks.clone())
        }

        fn get_first_code_block_containing(
            &self,
            addr: &Address,
            _monitor: &dyn TaskMonitor,
        ) -> Result<Option<CodeBlock>, CancelledError> {
            Ok(self.blocks.iter().find(|b| b.contains(addr)).cloned())
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

    impl SubroutineBlockModel for TestSubModel {
        fn get_base_subroutine_model(&self) -> &dyn SubroutineBlockModel {
            self
        }
    }

    #[test]
    fn test_cmd_creation() {
        let cmd = SubroutineModelCmd::new(
            Some("SubroutineModel"),
            vec!["Root", "Module1"],
            "Program Tree",
        );
        assert_eq!(cmd.model_name(), Some("SubroutineModel"));
        assert_eq!(cmd.group_path(), &["Root", "Module1"]);
        assert_eq!(cmd.tree_name(), "Program Tree");
    }

    #[test]
    fn test_cmd_no_model_name() {
        let cmd = SubroutineModelCmd::new(None::<String>, vec!["Root"], "Tree");
        assert!(cmd.model_name().is_none());
    }

    #[test]
    fn test_execute_empty_model() {
        let model = TestSubModel::new(vec![]);
        let cmd = SubroutineModelCmd::new(Some("M"), vec!["Root"], "Tree");
        let addr_set = AddressSet::new();
        let monitor = DummyMonitor;
        let frags = cmd.execute(&model, &addr_set, &monitor).unwrap();
        assert!(frags.is_empty());
    }

    #[test]
    fn test_execute_with_blocks() {
        let blocks = vec![
            CodeBlock::new(
                "main",
                AddressRange::new(Address::new(0x401000), Address::new(0x4010FF)),
                "M",
            ),
            CodeBlock::new(
                "helper",
                AddressRange::new(Address::new(0x402000), Address::new(0x402050)),
                "M",
            ),
        ];
        let model = TestSubModel::new(blocks);
        let cmd = SubroutineModelCmd::new(Some("M"), vec!["Root"], "Tree");
        let addr_set = AddressSet::new();
        let monitor = DummyMonitor;
        let frags = cmd.execute(&model, &addr_set, &monitor).unwrap();
        assert_eq!(frags.len(), 2);
        assert_eq!(frags[0].name, "main");
        assert_eq!(frags[1].name, "helper");
    }

    #[test]
    fn test_execute_duplicate_names_get_numbered() {
        let blocks = vec![
            CodeBlock::new(
                "sub",
                AddressRange::new(Address::new(0x401000), Address::new(0x4010FF)),
                "M",
            ),
            CodeBlock::new(
                "sub",
                AddressRange::new(Address::new(0x402000), Address::new(0x402050)),
                "M",
            ),
            CodeBlock::new(
                "sub",
                AddressRange::new(Address::new(0x403000), Address::new(0x403050)),
                "M",
            ),
        ];
        let model = TestSubModel::new(blocks);
        let cmd = SubroutineModelCmd::new(Some("M"), vec!["Root"], "Tree");
        let addr_set = AddressSet::new();
        let monitor = DummyMonitor;
        let frags = cmd.execute(&model, &addr_set, &monitor).unwrap();
        assert_eq!(frags.len(), 3);
        assert_eq!(frags[0].name, "sub");
        assert_eq!(frags[1].name, "sub(1)");
        assert_eq!(frags[2].name, "sub(2)");
    }

    #[test]
    fn test_execute_with_address_filter() {
        let blocks = vec![
            CodeBlock::new(
                "a",
                AddressRange::new(Address::new(0x401000), Address::new(0x4010FF)),
                "M",
            ),
            CodeBlock::new(
                "b",
                AddressRange::new(Address::new(0x402000), Address::new(0x4020FF)),
                "M",
            ),
        ];
        let model = TestSubModel::new(blocks);
        let cmd = SubroutineModelCmd::new(Some("M"), vec!["Root"], "Tree");
        let mut addr_set = AddressSet::new();
        addr_set.add(Address::new(0x401000)); // only "a"
        let monitor = DummyMonitor;
        let frags = cmd.execute(&model, &addr_set, &monitor).unwrap();
        assert_eq!(frags.len(), 1);
        assert_eq!(frags[0].name, "a");
    }

    #[test]
    fn test_fragment_info_num_addresses() {
        let frag = ProgramFragmentInfo::new(
            "test",
            vec![
                AddressRange::new(Address::new(0x1000), Address::new(0x10FF)),
                AddressRange::new(Address::new(0x2000), Address::new(0x200F)),
            ],
        );
        assert_eq!(frag.num_addresses(), 0x100 + 0x10); // 256 + 16
    }

    #[test]
    fn test_new_module_suffix_constant() {
        assert_eq!(NEW_MODULE_SUFFIX, " [Subroutines]");
    }
}
