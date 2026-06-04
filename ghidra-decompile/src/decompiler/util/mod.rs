//! Decompiler utilities.
//!
//! Port of Ghidra's `ghidra.app.decompiler.util` package.

use super::clang_node::{ClangNodeArena, ClangNodeId};
use super::clang_line::ClangLine;

/// Convert a ClangNode tree into a list of ClangLines.
///
/// This is a convenience wrapper around `clang_line::to_lines`.
pub fn to_lines(arena: &ClangNodeArena, root_id: ClangNodeId) -> Vec<ClangLine> {
    super::clang_line::to_lines(arena, root_id)
}

/// Extract the plain text from a ClangNode tree.
pub fn to_plain_text(arena: &ClangNodeArena, root_id: ClangNodeId) -> String {
    let lines = to_lines(arena, root_id);
    let mut buf = String::new();
    for line in &lines {
        buf.push_str(&line.indent_string());
        for &tok_id in line.all_tokens() {
            if let Some(text) = arena.token_text(tok_id) {
                buf.push_str(&text);
            }
        }
        buf.push('\n');
    }
    buf
}

/// Find the ClangNodeId of the token at the given line and column.
pub fn find_token_at(
    arena: &ClangNodeArena,
    root_id: ClangNodeId,
    target_line: usize,
    target_column: usize,
) -> Option<ClangNodeId> {
    let lines = to_lines(arena, root_id);
    let line = lines.get(target_line)?;
    let mut column = 0usize;
    for &tok_id in line.all_tokens() {
        let text = arena.token_text(tok_id).unwrap_or_default();
        let end_column = column + text.len();
        if target_column >= column && target_column < end_column {
            return Some(tok_id);
        }
        column = end_column;
    }
    None
}

/// Calculate the display width of a line.
pub fn line_display_width(arena: &ClangNodeArena, line: &ClangLine) -> usize {
    let indent_width = line.indent();
    let text_width: usize = line
        .all_tokens()
        .iter()
        .map(|&tok_id| arena.token_text(tok_id).map_or(0, |t| t.len()))
        .sum();
    indent_width + text_width
}

// ============================================================================
// FillOutStructureHelper
// ============================================================================

/// Helper for "Fill Out Structure" functionality.
///
/// Given a decompiled function that references an undefined structure,
/// this helper analyzes memory accesses to infer field offsets and types,
/// then proposes a structure definition.
#[derive(Debug, Clone, Default)]
pub struct FillOutStructureHelper {
    /// The base address of the structure being analyzed.
    pub base_address: u64,
    /// Discovered field entries: (offset, size, name_hint).
    pub fields: Vec<StructFieldEntry>,
    /// The proposed structure size (bytes).
    pub proposed_size: usize,
}

/// A proposed structure field.
#[derive(Debug, Clone)]
pub struct StructFieldEntry {
    /// Byte offset from the structure base.
    pub offset: i64,
    /// Size of the field in bytes.
    pub size: usize,
    /// Suggested field name (from variable analysis).
    pub name_hint: Option<String>,
    /// Suggested data type name.
    pub type_hint: Option<String>,
    /// Number of times this offset was accessed.
    pub access_count: u32,
}

impl StructFieldEntry {
    /// Create a new field entry.
    pub fn new(offset: i64, size: usize) -> Self {
        Self {
            offset,
            size,
            name_hint: None,
            type_hint: None,
            access_count: 1,
        }
    }
}

impl FillOutStructureHelper {
    /// Create a new fill-out-structure helper.
    pub fn new(base_address: u64) -> Self {
        Self {
            base_address,
            fields: Vec::new(),
            proposed_size: 0,
        }
    }

    /// Add a memory access at the given offset.
    pub fn add_access(&mut self, offset: i64, size: usize) {
        if let Some(field) = self.fields.iter_mut().find(|f| f.offset == offset && f.size == size) {
            field.access_count += 1;
        } else {
            self.fields.push(StructFieldEntry::new(offset, size));
        }
        let end = offset as usize + size;
        if end > self.proposed_size {
            self.proposed_size = end;
        }
    }

    /// Sort fields by offset.
    pub fn sort_fields(&mut self) {
        self.fields.sort_by_key(|f| f.offset);
    }

    /// Get the number of discovered fields.
    pub fn field_count(&self) -> usize {
        self.fields.len()
    }
}

// ============================================================================
// DataTypeDependencyOrderer
// ============================================================================

/// Orders data types by their dependencies so that types can be
/// emitted in a valid order (dependencies before dependents).
///
/// This mirrors Ghidra's `DataTypeDependencyOrderer`. It performs
/// a topological sort of types based on their field references.
#[derive(Debug, Clone, Default)]
pub struct DataTypeDependencyOrderer {
    /// The type names in dependency order (dependencies first).
    pub ordered_types: Vec<String>,
    /// Detected cycles (types that form circular dependencies).
    pub cycles: Vec<Vec<String>>,
}

impl DataTypeDependencyOrderer {
    /// Create a new dependency orderer.
    pub fn new() -> Self {
        Self::default()
    }

    /// Order a set of types given their dependencies.
    ///
    /// `types` maps type-name to a list of type-names it depends on.
    pub fn order(&mut self, types: &std::collections::HashMap<String, Vec<String>>) {
        use std::collections::{HashSet, VecDeque};

        let mut in_degree: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
        let mut dependents: std::collections::HashMap<String, Vec<String>> = std::collections::HashMap::new();

        // Initialize all types with in-degree 0.
        for name in types.keys() {
            in_degree.entry(name.clone()).or_insert(0);
        }

        // Build the dependency graph.
        for (name, deps) in types {
            for dep in deps {
                if types.contains_key(dep) {
                    *in_degree.entry(name.clone()).or_insert(0) += 1;
                    dependents.entry(dep.clone()).or_default().push(name.clone());
                }
            }
        }

        // Kahn's algorithm for topological sort.
        let mut queue: VecDeque<String> = in_degree
            .iter()
            .filter(|(_, &deg)| deg == 0)
            .map(|(name, _)| name.clone())
            .collect();

        let mut result = Vec::new();
        let mut visited = HashSet::new();

        while let Some(current) = queue.pop_front() {
            if visited.contains(&current) {
                continue;
            }
            visited.insert(current.clone());
            result.push(current.clone());

            if let Some(deps) = dependents.get(&current) {
                for dep in deps {
                    if let Some(deg) = in_degree.get_mut(dep) {
                        *deg -= 1;
                        if *deg == 0 {
                            queue.push_back(dep.clone());
                        }
                    }
                }
            }
        }

        self.ordered_types = result;

        // Detect cycles: any type not in the result is in a cycle.
        let all_types: HashSet<String> = types.keys().cloned().collect();
        let ordered: HashSet<String> = self.ordered_types.iter().cloned().collect();
        let cycle_types: Vec<String> = all_types.difference(&ordered).cloned().collect();
        if !cycle_types.is_empty() {
            self.cycles.push(cycle_types);
        }
    }

    /// Whether there are any circular dependencies.
    pub fn has_cycles(&self) -> bool {
        !self.cycles.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::super::clang_node::*;
    use super::*;

    fn make_arena() -> (ClangNodeArena, ClangNodeId) {
        let mut arena = ClangNodeArena::new();
        let root = arena.alloc(ClangNodeKind::TokenGroup(ClangTokenGroupData::default()));

        let t1 = arena.alloc(ClangNodeKind::Token(ClangTokenData {
            text: Some("int".into()),
            ..Default::default()
        }));
        arena.add_child(root, t1);

        let t2 = arena.alloc(ClangNodeKind::Token(ClangTokenData {
            text: Some(" ".into()),
            ..Default::default()
        }));
        arena.add_child(root, t2);

        let t3 = arena.alloc(ClangNodeKind::Token(ClangTokenData {
            text: Some("x".into()),
            ..Default::default()
        }));
        arena.add_child(root, t3);

        let t4 = arena.alloc(ClangNodeKind::Token(ClangTokenData {
            text: Some(";".into()),
            ..Default::default()
        }));
        arena.add_child(root, t4);

        (arena, root)
    }

    #[test]
    fn test_to_lines() {
        let (arena, root) = make_arena();
        let lines = to_lines(&arena, root);
        assert!(!lines.is_empty());
    }

    #[test]
    fn test_to_plain_text() {
        let (arena, root) = make_arena();
        let text = to_plain_text(&arena, root);
        assert!(text.contains("int"));
        assert!(text.contains("x"));
    }

    #[test]
    fn test_find_token_at() {
        let (arena, root) = make_arena();
        // "int x;" -> column 0-2 is "int", column 3 is " ", column 4 is "x", column 5 is ";"
        let tok = find_token_at(&arena, root, 0, 4);
        assert!(tok.is_some());
    }

    #[test]
    fn fill_out_structure_helper_basic() {
        let mut helper = FillOutStructureHelper::new(0x1000);
        helper.add_access(0, 4);   // 4-byte field at offset 0
        helper.add_access(4, 8);   // 8-byte field at offset 4
        helper.add_access(0, 4);   // duplicate access
        assert_eq!(helper.field_count(), 2);
        assert_eq!(helper.proposed_size, 12);

        // The first field should have access_count 2.
        let f0 = &helper.fields[0];
        assert_eq!(f0.offset, 0);
        assert_eq!(f0.access_count, 2);
    }

    #[test]
    fn fill_out_structure_helper_sort() {
        let mut helper = FillOutStructureHelper::new(0x1000);
        helper.add_access(8, 4);
        helper.add_access(0, 4);
        helper.add_access(4, 4);
        helper.sort_fields();
        assert_eq!(helper.fields[0].offset, 0);
        assert_eq!(helper.fields[1].offset, 4);
        assert_eq!(helper.fields[2].offset, 8);
    }

    #[test]
    fn data_type_dependency_orderer_simple() {
        let mut orderer = DataTypeDependencyOrderer::new();
        let mut types = std::collections::HashMap::new();
        types.insert("A".to_string(), vec!["B".to_string()]);
        types.insert("B".to_string(), vec![]);
        orderer.order(&types);
        assert!(!orderer.has_cycles());
        // B should come before A.
        let pos_b = orderer.ordered_types.iter().position(|s| s == "B").unwrap();
        let pos_a = orderer.ordered_types.iter().position(|s| s == "A").unwrap();
        assert!(pos_b < pos_a);
    }

    #[test]
    fn data_type_dependency_orderer_cycle() {
        let mut orderer = DataTypeDependencyOrderer::new();
        let mut types = std::collections::HashMap::new();
        types.insert("A".to_string(), vec!["B".to_string()]);
        types.insert("B".to_string(), vec!["A".to_string()]);
        orderer.order(&types);
        assert!(orderer.has_cycles());
        assert_eq!(orderer.ordered_types.len(), 0);
    }

    #[test]
    fn data_type_dependency_orderer_no_deps() {
        let mut orderer = DataTypeDependencyOrderer::new();
        let mut types = std::collections::HashMap::new();
        types.insert("X".to_string(), vec![]);
        types.insert("Y".to_string(), vec![]);
        orderer.order(&types);
        assert!(!orderer.has_cycles());
        assert_eq!(orderer.ordered_types.len(), 2);
    }
}
