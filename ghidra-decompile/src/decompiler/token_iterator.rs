//! TokenIterator: walks a ClangNode tree returning successive leaf tokens.
//!
//! Port of Ghidra's `ghidra.app.decompiler.TokenIterator`.

use super::clang_node::{ClangNodeArena, ClangNodeId, ClangNodeKind};

/// Iterator over ClangToken leaf nodes in a ClangNode tree.
///
/// The iterator walks the tree of ClangNode objects using parent/child
/// relationships, returning successive leaf ClangNodeId values.
/// Can run either forward or backward.
pub struct TokenIterator<'a> {
    arena: &'a ClangNodeArena,
    /// Stack of group ancestors.
    node_stack: Vec<ClangNodeId>,
    /// Stack of child indices into each ancestor group.
    index_stack: Vec<usize>,
    /// Current token (leaf) id, or None if exhausted.
    current: Option<ClangNodeId>,
    /// +1 for forward, -1 for backward.
    direction: i32,
    /// Depth in the ancestry stack.
    depth: usize,
}

impl<'a> TokenIterator<'a> {
    /// Create an iterator starting at a specific token, walking forward or backward.
    pub fn from_token(arena: &'a ClangNodeArena, token_id: ClangNodeId, forward: bool) -> Self {
        let mut group_list = Vec::new();
        // Walk up the parent chain to find all ancestor groups.
        // Since we store parent ids in group data, we search for parents.
        let mut current_node = token_id;
        loop {
            if let Some(parent_id) = find_parent(arena, current_node) {
                group_list.push(parent_id);
                current_node = parent_id;
            } else {
                break;
            }
        }
        group_list.reverse();

        let mut node_stack = group_list.clone();
        let mut index_stack = Vec::with_capacity(node_stack.len());
        let mut node = token_id;
        // Walk back down to find indices
        for &group_id in &node_stack {
            let idx = find_child_index(arena, group_id, node);
            index_stack.push(idx);
            node = group_id;
        }

        let depth = if node_stack.is_empty() { 0 } else { node_stack.len() - 1 };
        let direction = if forward { 1 } else { -1 };

        Self {
            arena,
            node_stack,
            index_stack,
            current: Some(token_id),
            direction,
            depth,
        }
    }

    /// Create an iterator across all tokens under a group.
    pub fn from_group(arena: &'a ClangNodeArena, group_id: ClangNodeId, forward: bool) -> Self {
        let mut group_list = Vec::new();
        let mut node = group_id;

        // Walk down to find the first/last leaf
        loop {
            group_list.push(node);
            let num_children = arena.num_children(node);
            if num_children == 0 {
                break;
            }
            let child_idx = if forward { 0 } else { num_children - 1 };
            match arena.child(node, child_idx) {
                Some(child) => {
                    node = child;
                }
                None => break,
            }
        }

        let mut node_stack = group_list;
        let mut index_stack = Vec::with_capacity(node_stack.len());
        for &gid in &node_stack {
            let num = arena.num_children(gid);
            index_stack.push(if forward { 0 } else { num.saturating_sub(1) });
        }

        let direction = if forward { 1 } else { -1 };
        let depth = node_stack.len().saturating_sub(1);
        let current = if is_token_leaf(arena, node) {
            Some(node)
        } else {
            None
        };

        Self {
            arena,
            node_stack,
            index_stack,
            current,
            direction,
            depth,
        }
    }

    /// Returns true if there are more tokens.
    pub fn has_next(&self) -> bool {
        self.current.is_some()
    }

    /// Advance and return the next token id, or None.
    pub fn next_token(&mut self) -> Option<ClangNodeId> {
        let res = self.current;
        self.advance();
        res
    }

    fn advance(&mut self) {
        // Try to find the next leaf at the current depth or above
        self.current = None;

        loop {
            if self.node_stack.is_empty() {
                return;
            }
            let group_id = self.node_stack[self.depth];
            let idx = self.index_stack[self.depth] as i32 + self.direction;
            let num_children = self.arena.num_children(group_id) as i32;

            if idx >= 0 && idx < num_children {
                self.index_stack[self.depth] = idx as usize;
                // Walk down to find the leftmost/rightmost leaf
                let mut node = self.arena.child(group_id, idx as usize).unwrap();
                loop {
                    let num = self.arena.num_children(node);
                    if num == 0 {
                        break;
                    }
                    let child_idx = if self.direction > 0 { 0 } else { num - 1 };
                    match self.arena.child(node, child_idx) {
                        Some(child) => {
                            if self.depth + 1 < self.node_stack.len() {
                                self.node_stack[self.depth + 1] = node;
                                self.index_stack[self.depth + 1] = child_idx;
                            }
                            node = child;
                        }
                        None => break,
                    }
                }
                if is_token_leaf(self.arena, node) {
                    self.current = Some(node);
                }
                return;
            } else {
                // Back up one level
                self.node_stack.pop();
                self.index_stack.pop();
                if self.depth > 0 {
                    self.depth -= 1;
                }
            }
        }
    }
}

impl<'a> Iterator for TokenIterator<'a> {
    type Item = ClangNodeId;

    fn next(&mut self) -> Option<Self::Item> {
        self.next_token()
    }
}

/// Check if a node is a leaf token (not a group).
fn is_token_leaf(arena: &ClangNodeArena, id: ClangNodeId) -> bool {
    match arena.get(id) {
        Some(ClangNodeKind::TokenGroup(_))
        | Some(ClangNodeKind::Function(_))
        | Some(ClangNodeKind::FuncProto(_))
        | Some(ClangNodeKind::Statement(_))
        | Some(ClangNodeKind::VariableDecl(_))
        | Some(ClangNodeKind::ReturnType(_)) => false,
        Some(_) => true,
        None => false,
    }
}

/// Find the parent of a node by searching all groups.  O(n) but fine for typical sizes.
fn find_parent(arena: &ClangNodeArena, child_id: ClangNodeId) -> Option<ClangNodeId> {
    for (id, kind) in arena.iter() {
        match kind {
            ClangNodeKind::TokenGroup(d) => {
                if d.children.contains(&child_id) {
                    return Some(id);
                }
            }
            ClangNodeKind::Function(d) => {
                if d.group.children.contains(&child_id) {
                    return Some(id);
                }
            }
            ClangNodeKind::FuncProto(d) => {
                if d.group.children.contains(&child_id) {
                    return Some(id);
                }
            }
            ClangNodeKind::Statement(d) => {
                if d.group.children.contains(&child_id) {
                    return Some(id);
                }
            }
            ClangNodeKind::VariableDecl(d) => {
                if d.group.children.contains(&child_id) {
                    return Some(id);
                }
            }
            ClangNodeKind::ReturnType(d) => {
                if d.group.children.contains(&child_id) {
                    return Some(id);
                }
            }
            _ => {}
        }
    }
    None
}

/// Find the index of a child within a group.
fn find_child_index(arena: &ClangNodeArena, group_id: ClangNodeId, child_id: ClangNodeId) -> usize {
    match arena.get(group_id) {
        Some(ClangNodeKind::TokenGroup(d)) => d.children.iter().position(|&c| c == child_id).unwrap_or(0),
        Some(ClangNodeKind::Function(d)) => d.group.children.iter().position(|&c| c == child_id).unwrap_or(0),
        Some(ClangNodeKind::FuncProto(d)) => d.group.children.iter().position(|&c| c == child_id).unwrap_or(0),
        Some(ClangNodeKind::Statement(d)) => d.group.children.iter().position(|&c| c == child_id).unwrap_or(0),
        Some(ClangNodeKind::VariableDecl(d)) => d.group.children.iter().position(|&c| c == child_id).unwrap_or(0),
        Some(ClangNodeKind::ReturnType(d)) => d.group.children.iter().position(|&c| c == child_id).unwrap_or(0),
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::super::clang_node::*;
    use super::*;

    fn make_arena_with_tokens() -> (ClangNodeArena, ClangNodeId, Vec<ClangNodeId>) {
        let mut arena = ClangNodeArena::new();
        let root = arena.alloc(ClangNodeKind::TokenGroup(ClangTokenGroupData::default()));
        let mut tok_ids = Vec::new();
        for i in 0..5 {
            let tok = arena.alloc(ClangNodeKind::Token(ClangTokenData {
                text: Some(format!("tok{}", i)),
                ..Default::default()
            }));
            arena.add_child(root, tok);
            tok_ids.push(tok);
        }
        (arena, root, tok_ids)
    }

    #[test]
    fn test_forward_iterator() {
        let (arena, root, expected) = make_arena_with_tokens();
        let collected: Vec<ClangNodeId> = TokenIterator::from_group(&arena, root, true).collect();
        assert_eq!(collected, expected);
    }

    #[test]
    fn test_backward_iterator() {
        let (arena, root, expected) = make_arena_with_tokens();
        let mut rev_expected = expected.clone();
        rev_expected.reverse();
        let collected: Vec<ClangNodeId> = TokenIterator::from_group(&arena, root, false).collect();
        assert_eq!(collected, rev_expected);
    }

    #[test]
    fn test_from_token_iterator() {
        let (arena, root, expected) = make_arena_with_tokens();
        // Start from token 2 (middle), go forward
        let start = expected[2];
        let collected: Vec<ClangNodeId> = TokenIterator::from_token(&arena, start, true).collect();
        assert_eq!(collected, vec![expected[2], expected[3], expected[4]]);
    }

    #[test]
    fn test_empty_group() {
        let mut arena = ClangNodeArena::new();
        let root = arena.alloc(ClangNodeKind::TokenGroup(ClangTokenGroupData::default()));
        let collected: Vec<ClangNodeId> = TokenIterator::from_group(&arena, root, true).collect();
        assert!(collected.is_empty());
    }
}
