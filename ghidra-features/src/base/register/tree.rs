//! Register tree — hierarchical organization of registers.
//!
//! Ported from `RegisterTree` in Ghidra's `ghidra.app.plugin.core.register`.
//!
//! The register tree organizes CPU registers into a hierarchy of groups
//! and individual register nodes, supporting filtering (show only registers
//! with values) and selection.

use ghidra_core::program::lang::Register;
use ghidra_core::program::listing::ProgramContext;
use std::collections::HashMap;

// ============================================================================
// RegisterNode
// ============================================================================

/// A node representing a single register in the tree.
///
/// Ported from `RegisterTreeNode` in Java. Stores a register and its
/// child registers (sub-registers).
#[derive(Debug, Clone)]
pub struct RegisterNode {
    /// The register represented by this node.
    register: Register,
    /// Child register nodes (sub-registers).
    children: Vec<RegisterNode>,
}

impl RegisterNode {
    /// Create a new register node, recursively adding children for sub-registers.
    pub fn new(register: Register, all_registers: &[Register]) -> Self {
        let children: Vec<RegisterNode> = all_registers
            .iter()
            .filter(|r| r.parent.as_deref() == Some(&register.name))
            .map(|r| RegisterNode::new(r.clone(), all_registers))
            .collect();

        Self {
            register,
            children,
        }
    }

    /// Get the register name.
    pub fn name(&self) -> &str {
        &self.register.name
    }

    /// Get the register's bit length.
    pub fn bit_length(&self) -> u32 {
        self.register.bit_length
    }

    /// Get the display name (name + bit length + aliases).
    pub fn display_name(&self) -> String {
        let mut name = format!("{}  ({})", self.register.name, self.register.bit_length);
        if !self.register.aliases.is_empty() {
            name.push_str("; ");
            let mut alias_vec: Vec<&str> = self.register.aliases.iter().map(|s| s.as_str()).collect();
            alias_vec.sort();
            name.push_str(&alias_vec.join(", "));
        }
        name
    }

    /// Get the register's description.
    pub fn description(&self) -> &str {
        &self.register.description
    }

    /// Whether this node has child registers.
    pub fn has_children(&self) -> bool {
        !self.children.is_empty()
    }

    /// Get the child register nodes.
    pub fn children(&self) -> &[RegisterNode] {
        &self.children
    }

    /// Get the register.
    pub fn register(&self) -> &Register {
        &self.register
    }

    /// Search for a node with the given register name in this subtree.
    pub fn find_by_name(&self, name: &str) -> Option<&RegisterNode> {
        if self.register.name == name {
            return Some(self);
        }
        for child in &self.children {
            if let Some(found) = child.find_by_name(name) {
                return Some(found);
            }
        }
        None
    }
}

// ============================================================================
// RegisterGroupNode
// ============================================================================

/// A group node in the register tree (e.g., "General Purpose", "Floating Point").
///
/// Ported from `RegisterTreeGroupNode` in Java.
#[derive(Debug, Clone)]
pub struct RegisterGroupNode {
    /// Name of this group.
    name: String,
    /// Register nodes in this group.
    children: Vec<RegisterNode>,
}

impl RegisterGroupNode {
    /// Create a new group node.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            children: Vec::new(),
        }
    }

    /// Get the group name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Add a register node to this group.
    pub fn add_register(&mut self, node: RegisterNode) {
        self.children.push(node);
    }

    /// Get the register nodes in this group.
    pub fn children(&self) -> &[RegisterNode] {
        &self.children
    }

    /// Whether this group has any children.
    pub fn has_children(&self) -> bool {
        !self.children.is_empty()
    }

    /// Search for a register by name within this group.
    pub fn find_by_name(&self, name: &str) -> Option<&RegisterNode> {
        for child in &self.children {
            if let Some(found) = child.find_by_name(name) {
                return Some(found);
            }
        }
        None
    }
}

// ============================================================================
// RegisterTree
// ============================================================================

/// Top-level register tree, organizing registers by group.
///
/// Ported from `RegisterTree` in Java. This is a data structure (not a GUI
/// tree widget) that holds the hierarchical organization of registers.
///
/// Registers are organized as:
/// - Grouped registers (under `RegisterGroupNode`s, e.g., "General Purpose")
/// - Ungrouped registers (directly under the root)
#[derive(Debug, Clone)]
pub struct RegisterTree {
    /// Grouped register nodes.
    groups: Vec<RegisterGroupNode>,
    /// Ungrouped register nodes.
    ungrouped: Vec<RegisterNode>,
    /// All top-level register nodes (for quick lookup).
    all_registers: Vec<Register>,
    /// Whether the tree is filtered to show only registers with values.
    is_filtered: bool,
}

impl RegisterTree {
    /// Create a new register tree populated with the given registers.
    ///
    /// Registers are organized into groups by their `group` field.
    /// Registers that are sub-registers of another visible register
    /// (whose parent is not hidden) are added as children of their
    /// parent node, not as top-level nodes.
    pub fn new(registers: &[Register]) -> Self {
        let mut tree = Self {
            groups: Vec::new(),
            ungrouped: Vec::new(),
            all_registers: registers.to_vec(),
            is_filtered: false,
        };
        tree.build_tree(registers);
        tree
    }

    fn build_tree(&mut self, registers: &[Register]) {
        self.groups.clear();
        self.ungrouped.clear();

        let mut group_map: HashMap<String, RegisterGroupNode> = HashMap::new();

        for register in registers {
            // Skip sub-registers whose parent is visible
            if let Some(ref parent_name) = register.parent {
                if registers.iter().any(|r| &r.name == parent_name && !r.is_hidden()) {
                    continue;
                }
            }

            let node = RegisterNode::new(register.clone(), registers);

            if let Some(ref group_name) = register.group {
                let group = group_map
                    .entry(group_name.clone())
                    .or_insert_with(|| RegisterGroupNode::new(group_name.clone()));
                group.add_register(node);
            } else {
                self.ungrouped.push(node);
            }
        }

        // Sort groups by name
        let mut groups: Vec<RegisterGroupNode> = group_map.into_values().collect();
        groups.sort_by(|a, b| a.name.cmp(&b.name));
        self.groups = groups;

        // Sort ungrouped by name
        self.ungrouped.sort_by(|a, b| a.name().cmp(b.name()));
    }

    /// Get the group nodes.
    pub fn groups(&self) -> &[RegisterGroupNode] {
        &self.groups
    }

    /// Get the ungrouped register nodes.
    pub fn ungrouped(&self) -> &[RegisterNode] {
        &self.ungrouped
    }

    /// Get all registers.
    pub fn all_registers(&self) -> &[Register] {
        &self.all_registers
    }

    /// Whether the tree is filtered.
    pub fn is_filtered(&self) -> bool {
        self.is_filtered
    }

    /// Set the filter state. When filtered, only registers with non-default
    /// values are shown.
    pub fn set_filtered(&mut self, filtered: bool, context: Option<&ProgramContext>) {
        self.is_filtered = filtered;
        if filtered {
            if let Some(ctx) = context {
                // Rebuild with only registers that have values
                let registers_with_values: Vec<Register> = self
                    .all_registers
                    .iter()
                    .filter(|r| ctx.get_value(&Default::default(), &r.name).is_some())
                    .cloned()
                    .collect();
                self.build_tree(&registers_with_values);
            }
        } else {
            self.build_tree(&self.all_registers.clone());
        }
    }

    /// Search for a register by name in the entire tree.
    pub fn find_register(&self, name: &str) -> Option<&Register> {
        self.all_registers.iter().find(|r| r.name == name)
    }

    /// Search for a register node by name.
    pub fn find_node(&self, name: &str) -> Option<&RegisterNode> {
        for group in &self.groups {
            if let Some(node) = group.find_by_name(name) {
                return Some(node);
            }
        }
        for node in &self.ungrouped {
            if let Some(found) = node.find_by_name(name) {
                return Some(found);
            }
        }
        None
    }

    /// Update the tree with a new set of registers (e.g., after program change).
    pub fn update_registers(&mut self, registers: &[Register]) {
        self.all_registers = registers.to_vec();
        self.build_tree(registers);
    }
}

impl Default for RegisterTree {
    fn default() -> Self {
        Self::new(&[])
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use ghidra_core::program::lang::Register;

    fn make_register(name: &str, group: Option<&str>, parent: Option<&str>, bit_len: u32) -> Register {
        use std::collections::HashSet;
        Register {
            name: name.to_string(),
            description: String::new(),
            group: group.map(|s| s.to_string()),
            parent: parent.map(|s| s.to_string()),
            bit_length: bit_len,
            address: ghidra_core::addr::Address::new(0),
            num_bytes: (bit_len as usize + 7) / 8,
            least_significant_bit: 0,
            big_endian: false,
            type_flags: ghidra_core::program::lang::RegisterTypeFlags::default(),
            aliases: HashSet::new(),
            child_registers: Vec::new(),
            base_register: None,
            least_significant_bit_in_base: 0,
            lane_sizes: 0,
        }
    }

    #[test]
    fn test_empty_tree() {
        let tree = RegisterTree::new(&[]);
        assert!(tree.groups().is_empty());
        assert!(tree.ungrouped().is_empty());
    }

    #[test]
    fn test_registers_in_group() {
        let regs = vec![
            make_register("EAX", Some("General"), None, 32),
            make_register("EBX", Some("General"), None, 32),
            make_register("ECX", Some("General"), None, 32),
        ];
        let tree = RegisterTree::new(&regs);
        assert_eq!(tree.groups().len(), 1);
        assert_eq!(tree.groups()[0].name(), "General");
        assert_eq!(tree.groups()[0].children().len(), 3);
    }

    #[test]
    fn test_registers_in_multiple_groups() {
        let regs = vec![
            make_register("EAX", Some("General"), None, 32),
            make_register("ST0", Some("Float"), None, 80),
        ];
        let tree = RegisterTree::new(&regs);
        assert_eq!(tree.groups().len(), 2);
    }

    #[test]
    fn test_ungrouped_registers() {
        let regs = vec![
            make_register("MYREG", None, None, 16),
        ];
        let tree = RegisterTree::new(&regs);
        assert!(tree.groups().is_empty());
        assert_eq!(tree.ungrouped().len(), 1);
        assert_eq!(tree.ungrouped()[0].name(), "MYREG");
    }

    #[test]
    fn test_sub_registers_excluded_from_top_level() {
        let regs = vec![
            make_register("EAX", Some("General"), None, 32),
            make_register("AX", Some("General"), Some("EAX"), 16),
            make_register("AL", Some("General"), Some("AX"), 8),
        ];
        let tree = RegisterTree::new(&regs);
        // Only EAX should appear at top level; AX and AL are children
        let group = &tree.groups()[0];
        assert_eq!(group.children().len(), 1);
        let eax_node = &group.children()[0];
        assert_eq!(eax_node.name(), "EAX");
        assert!(eax_node.has_children());
    }

    #[test]
    fn test_find_register() {
        let regs = vec![
            make_register("EAX", Some("General"), None, 32),
            make_register("EBX", Some("General"), None, 32),
        ];
        let tree = RegisterTree::new(&regs);
        assert!(tree.find_register("EAX").is_some());
        assert!(tree.find_register("nonexistent").is_none());
    }

    #[test]
    fn test_find_node() {
        let regs = vec![
            make_register("EAX", Some("General"), None, 32),
        ];
        let tree = RegisterTree::new(&regs);
        assert!(tree.find_node("EAX").is_some());
    }

    #[test]
    fn test_node_display_name() {
        let reg = make_register("EAX", Some("General"), None, 32);
        let node = RegisterNode::new(reg, &[]);
        assert_eq!(node.display_name(), "EAX  (32)");
    }

    #[test]
    fn test_node_display_name_with_aliases() {
        use std::collections::HashSet;
        let mut reg = make_register("R0", Some("General"), None, 32);
        let mut aliases = HashSet::new();
        aliases.insert("zero".to_string());
        reg.aliases = aliases;
        let node = RegisterNode::new(reg, &[]);
        assert_eq!(node.display_name(), "R0  (32); zero");
    }

    #[test]
    fn test_update_registers() {
        let regs1 = vec![
            make_register("EAX", Some("General"), None, 32),
        ];
        let mut tree = RegisterTree::new(&regs1);
        assert_eq!(tree.all_registers().len(), 1);

        let regs2 = vec![
            make_register("EAX", Some("General"), None, 32),
            make_register("EBX", Some("General"), None, 32),
        ];
        tree.update_registers(&regs2);
        assert_eq!(tree.all_registers().len(), 2);
    }
}
