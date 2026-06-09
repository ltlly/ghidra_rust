//! ClangTokenGroup: a group of tokens representing a C code construct.
//!
//! Port of Ghidra's `ghidra.app.decompiler.ClangTokenGroup`.
//!
//! A `ClangTokenGroup` is a sequence of tokens that form a meaningful group
//! in source code.  This group may break up into subgroups and may be part of
//! a larger group.  Groups are the interior nodes of the Clang AST; tokens
//! are the leaves.
//!
//! In the Rust implementation, the actual data lives in `ClangTokenGroupData`
//! (defined in `clang_node.rs`), stored in a `ClangNodeArena`.  This module
//! provides convenience functions for constructing and manipulating groups.

use super::clang_node::{
    ClangNodeArena, ClangNodeId, ClangNodeKind, ClangTokenGroupData,
};

/// Create an empty token group.
pub fn empty_group() -> ClangTokenGroupData {
    ClangTokenGroupData::default()
}

/// Create a token group with a given parent id.
pub fn group_with_parent(parent: ClangNodeId) -> ClangTokenGroupData {
    ClangTokenGroupData {
        parent,
        ..Default::default()
    }
}

/// A helper struct for building and manipulating a token group within an arena.
///
/// This provides an API closer to the Java `ClangTokenGroup` class, operating
/// on arena-allocated nodes.
pub struct ClangTokenGroupBuilder<'a> {
    arena: &'a mut ClangNodeArena,
    group_id: ClangNodeId,
}

impl<'a> ClangTokenGroupBuilder<'a> {
    /// Create a new builder for an existing group node.
    pub fn new(arena: &'a mut ClangNodeArena, group_id: ClangNodeId) -> Self {
        Self { arena, group_id }
    }

    /// Allocate a new empty token group in the arena and return a builder.
    pub fn alloc(arena: &'a mut ClangNodeArena) -> Self {
        let group_id = arena.alloc(ClangNodeKind::TokenGroup(ClangTokenGroupData::default()));
        Self { arena, group_id }
    }

    /// Allocate a new empty token group with a parent.
    pub fn alloc_with_parent(arena: &'a mut ClangNodeArena, parent: ClangNodeId) -> Self {
        let group_id = arena.alloc(ClangNodeKind::TokenGroup(ClangTokenGroupData {
            parent,
            ..Default::default()
        }));
        Self { arena, group_id }
    }

    /// Get the group's node id.
    pub fn id(&self) -> ClangNodeId {
        self.group_id
    }

    /// Get a reference to the arena.
    pub fn arena(&self) -> &ClangNodeArena {
        self.arena
    }

    /// Get a mutable reference to the arena.
    pub fn arena_mut(&mut self) -> &mut ClangNodeArena {
        self.arena
    }

    /// Add a child token or group to this group.
    ///
    /// Updates min/max address tracking.  Corresponds to Java's `AddTokenGroup`.
    pub fn add_token_group(&mut self, child_id: ClangNodeId) {
        self.arena.add_child(self.group_id, child_id);
    }

    /// Get the number of children.
    pub fn num_children(&self) -> usize {
        self.arena.num_children(self.group_id)
    }

    /// Get the i-th child.
    pub fn child(&self, i: usize) -> Option<ClangNodeId> {
        self.arena.child(self.group_id, i)
    }

    /// Get the min address of this group.
    pub fn min_address(&self) -> Option<ghidra_core::addr::Address> {
        self.arena.min_address(self.group_id)
    }

    /// Get the max address of this group.
    pub fn max_address(&self) -> Option<ghidra_core::addr::Address> {
        self.arena.max_address(self.group_id)
    }

    /// Flatten all leaf tokens into a list.
    ///
    /// Corresponds to Java's `flatten()`.
    pub fn flatten(&self) -> Vec<ClangNodeId> {
        self.arena.flatten(self.group_id)
    }

    /// Get the text representation by concatenating all leaf tokens.
    ///
    /// Corresponds to Java's `toString()`.
    pub fn to_string(&self) -> String {
        self.arena.to_string(self.group_id)
    }

    /// Create an iterator over all leaf tokens in display order.
    ///
    /// Corresponds to Java's `tokenIterator(true)`.
    pub fn token_iter(&self) -> ClangTokenGroupIter<'_> {
        ClangTokenGroupIter {
            arena: self.arena,
            stack: vec![ChildIterState {
                parent: self.group_id,
                index: 0,
            }],
        }
    }

    /// Create an iterator over direct children (not leaf tokens).
    ///
    /// Corresponds to Java's `iterator()`.
    pub fn children_iter(&self) -> ClangChildrenIter<'_> {
        ClangChildrenIter {
            arena: self.arena,
            parent: self.group_id,
            index: 0,
        }
    }

    /// Convert to a stream of children ids (convenience).
    pub fn children_vec(&self) -> Vec<ClangNodeId> {
        (0..self.num_children())
            .filter_map(|i| self.child(i))
            .collect()
    }
}

/// State for the depth-first leaf token iterator.
struct ChildIterState {
    parent: ClangNodeId,
    index: usize,
}

/// Iterator over all leaf tokens in a group (depth-first, display order).
///
/// This is the Rust equivalent of Java's `TokenIterator` applied to a group.
pub struct ClangTokenGroupIter<'a> {
    arena: &'a ClangNodeArena,
    stack: Vec<ChildIterState>,
}

impl<'a> Iterator for ClangTokenGroupIter<'a> {
    type Item = ClangNodeId;

    fn next(&mut self) -> Option<Self::Item> {
        while let Some(state) = self.stack.last_mut() {
            if let Some(child_id) = self.arena.child(state.parent, state.index) {
                state.index += 1;
                let num_children = self.arena.num_children(child_id);
                if num_children > 0 {
                    // This is a group -- descend into it
                    self.stack.push(ChildIterState {
                        parent: child_id,
                        index: 0,
                    });
                } else {
                    // This is a leaf token
                    return Some(child_id);
                }
            } else {
                self.stack.pop();
            }
        }
        None
    }
}

/// Iterator over direct children of a group.
pub struct ClangChildrenIter<'a> {
    arena: &'a ClangNodeArena,
    parent: ClangNodeId,
    index: usize,
}

impl<'a> Iterator for ClangChildrenIter<'a> {
    type Item = ClangNodeId;

    fn next(&mut self) -> Option<Self::Item> {
        let child = self.arena.child(self.parent, self.index);
        if child.is_some() {
            self.index += 1;
        }
        child
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::clang_node::{ClangTokenData, SyntaxType, ClangNodeKind, ClangTokenGroupData};

    #[test]
    fn test_empty_group() {
        let g = empty_group();
        assert!(g.children.is_empty());
        assert!(g.min_address.is_none());
        assert!(g.max_address.is_none());
    }

    #[test]
    fn test_group_with_parent() {
        let g = group_with_parent(42);
        assert_eq!(g.parent, 42);
    }

    #[test]
    fn test_builder_alloc() {
        let mut arena = ClangNodeArena::new();
        let builder = ClangTokenGroupBuilder::alloc(&mut arena);
        assert_eq!(builder.num_children(), 0);
    }

    #[test]
    fn test_builder_add_children() {
        let mut arena = ClangNodeArena::new();
        let tok1 = arena.alloc(ClangNodeKind::Token(ClangTokenData {
            text: Some("int".to_string()),
            syntax_type: SyntaxType::Keyword,
            ..Default::default()
        }));
        let tok2 = arena.alloc(ClangNodeKind::Token(ClangTokenData {
            text: Some("x".to_string()),
            syntax_type: SyntaxType::Variable,
            ..Default::default()
        }));
        let mut builder = ClangTokenGroupBuilder::alloc(&mut arena);
        builder.add_token_group(tok1);
        builder.add_token_group(tok2);
        assert_eq!(builder.num_children(), 2);
        assert_eq!(builder.child(0), Some(tok1));
        assert_eq!(builder.child(1), Some(tok2));
    }

    #[test]
    fn test_builder_flatten() {
        let mut arena = ClangNodeArena::new();
        // Create a nested structure: group -> [group -> [tok1, tok2], tok3]
        let tok1 = arena.alloc(ClangNodeKind::Token(ClangTokenData {
            text: Some("a".to_string()),
            ..Default::default()
        }));
        let tok2 = arena.alloc(ClangNodeKind::Token(ClangTokenData {
            text: Some("b".to_string()),
            ..Default::default()
        }));
        let mut inner = ClangTokenGroupBuilder::alloc(&mut arena);
        inner.add_token_group(tok1);
        inner.add_token_group(tok2);
        let inner_id = inner.id();

        let tok3 = arena.alloc(ClangNodeKind::Token(ClangTokenData {
            text: Some("c".to_string()),
            ..Default::default()
        }));
        let mut outer = ClangTokenGroupBuilder::alloc(&mut arena);
        outer.add_token_group(inner_id);
        outer.add_token_group(tok3);

        let flat = outer.flatten();
        assert_eq!(flat, vec![tok1, tok2, tok3]);
    }

    #[test]
    fn test_builder_to_string() {
        let mut arena = ClangNodeArena::new();
        let tok1 = arena.alloc(ClangNodeKind::Token(ClangTokenData {
            text: Some("int".to_string()),
            ..Default::default()
        }));
        let tok2 = arena.alloc(ClangNodeKind::Token(ClangTokenData {
            text: Some(" ".to_string()),
            ..Default::default()
        }));
        let tok3 = arena.alloc(ClangNodeKind::Token(ClangTokenData {
            text: Some("x".to_string()),
            ..Default::default()
        }));
        let mut builder = ClangTokenGroupBuilder::alloc(&mut arena);
        builder.add_token_group(tok1);
        builder.add_token_group(tok2);
        builder.add_token_group(tok3);
        assert_eq!(builder.to_string(), "int x");
    }

    #[test]
    fn test_token_iter() {
        let mut arena = ClangNodeArena::new();
        let tok1 = arena.alloc(ClangNodeKind::Token(ClangTokenData {
            text: Some("a".to_string()),
            ..Default::default()
        }));
        let tok2 = arena.alloc(ClangNodeKind::Token(ClangTokenData {
            text: Some("b".to_string()),
            ..Default::default()
        }));
        let mut builder = ClangTokenGroupBuilder::alloc(&mut arena);
        builder.add_token_group(tok1);
        builder.add_token_group(tok2);

        let tokens: Vec<_> = builder.token_iter().collect();
        assert_eq!(tokens, vec![tok1, tok2]);
    }

    #[test]
    fn test_token_iter_nested() {
        let mut arena = ClangNodeArena::new();
        let tok1 = arena.alloc(ClangNodeKind::Token(ClangTokenData {
            text: Some("a".to_string()),
            ..Default::default()
        }));
        let tok2 = arena.alloc(ClangNodeKind::Token(ClangTokenData {
            text: Some("b".to_string()),
            ..Default::default()
        }));
        let inner = arena.alloc(ClangNodeKind::TokenGroup(ClangTokenGroupData::default()));
        // Manually add children to inner
        arena.add_child(inner, tok1);
        arena.add_child(inner, tok2);

        let tok3 = arena.alloc(ClangNodeKind::Token(ClangTokenData {
            text: Some("c".to_string()),
            ..Default::default()
        }));
        let outer = arena.alloc(ClangNodeKind::TokenGroup(ClangTokenGroupData::default()));
        arena.add_child(outer, inner);
        arena.add_child(outer, tok3);

        let builder = ClangTokenGroupBuilder::new(&mut arena, outer);
        let tokens: Vec<_> = builder.token_iter().collect();
        assert_eq!(tokens, vec![tok1, tok2, tok3]);
    }

    #[test]
    fn test_children_iter() {
        let mut arena = ClangNodeArena::new();
        let tok1 = arena.alloc(ClangNodeKind::Token(ClangTokenData {
            text: Some("x".to_string()),
            ..Default::default()
        }));
        let tok2 = arena.alloc(ClangNodeKind::Token(ClangTokenData {
            text: Some("y".to_string()),
            ..Default::default()
        }));
        let mut builder = ClangTokenGroupBuilder::alloc(&mut arena);
        builder.add_token_group(tok1);
        builder.add_token_group(tok2);

        let children: Vec<_> = builder.children_iter().collect();
        assert_eq!(children, vec![tok1, tok2]);
    }

    #[test]
    fn test_children_vec() {
        let mut arena = ClangNodeArena::new();
        let tok1 = arena.alloc(ClangNodeKind::Token(ClangTokenData::default()));
        let tok2 = arena.alloc(ClangNodeKind::Token(ClangTokenData::default()));
        let mut builder = ClangTokenGroupBuilder::alloc(&mut arena);
        builder.add_token_group(tok1);
        builder.add_token_group(tok2);
        assert_eq!(builder.children_vec(), vec![tok1, tok2]);
    }

    #[test]
    fn test_alloc_with_parent() {
        let mut arena = ClangNodeArena::new();
        let parent_id = arena.alloc(ClangNodeKind::TokenGroup(ClangTokenGroupData::default()));
        let builder = ClangTokenGroupBuilder::alloc_with_parent(&mut arena, parent_id);
        let child_id = builder.id();
        drop(builder);
        let node = arena.get(child_id).unwrap();
        match node {
            ClangNodeKind::TokenGroup(d) => assert_eq!(d.parent, parent_id),
            _ => panic!("Expected TokenGroup"),
        }
    }

    #[test]
    fn test_empty_iter() {
        let mut arena = ClangNodeArena::new();
        let builder = ClangTokenGroupBuilder::alloc(&mut arena);
        let tokens: Vec<_> = builder.token_iter().collect();
        assert!(tokens.is_empty());
        let children: Vec<_> = builder.children_iter().collect();
        assert!(children.is_empty());
    }
}
