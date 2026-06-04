//! STL-like container types for Ghidra Rust.
//!
//! Ports Ghidra's `generic.stl` package: `Pair`, `Quad`, `DominantPair`,
//! `RedBlackTree`, `MapSTL`, `SetSTL`, `VectorSTL`, `ListSTL`, and
//! the `IteratorSTL` trait.

use std::cmp::Ordering;
use std::collections::VecDeque;
use std::fmt;

// ============================================================================
// Pair
// ============================================================================

/// A simple two-element tuple.
///
/// Corresponds to Ghidra's `generic.stl.Pair`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Pair<T1, T2> {
    pub first: T1,
    pub second: T2,
}

impl<T1, T2> Pair<T1, T2> {
    pub fn new(first: T1, second: T2) -> Self {
        Self { first, second }
    }
}

impl<T1: fmt::Display, T2: fmt::Display> fmt::Display for Pair<T1, T2> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "<{},{}>", self.first, self.second)
    }
}

// ============================================================================
// Quad
// ============================================================================

/// A four-element tuple.
///
/// Corresponds to Ghidra's `generic.stl.Quad`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Quad<T1, T2, T3, T4> {
    pub first: T1,
    pub second: T2,
    pub third: T3,
    pub fourth: T4,
}

impl<T1, T2, T3, T4> Quad<T1, T2, T3, T4> {
    pub fn new(first: T1, second: T2, third: T3, fourth: T4) -> Self {
        Self {
            first,
            second,
            third,
            fourth,
        }
    }
}

// ============================================================================
// DominantPair — equality/hash based only on the key (first)
// ============================================================================

/// A pair where equality and hash depend only on the first (key) element.
///
/// Corresponds to Ghidra's `generic.stl.DominantPair`.
#[derive(Debug, Clone)]
pub struct DominantPair<K, V> {
    pub first: K,
    pub second: V,
}

impl<K, V> DominantPair<K, V> {
    pub fn new(first: K, second: V) -> Self {
        Self { first, second }
    }
}

impl<K: PartialEq, V> PartialEq for DominantPair<K, V> {
    fn eq(&self, other: &Self) -> bool {
        self.first == other.first
    }
}

impl<K: Eq, V> Eq for DominantPair<K, V> {}

impl<K: std::hash::Hash, V> std::hash::Hash for DominantPair<K, V> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.first.hash(state);
    }
}

impl<K: fmt::Display, V: fmt::Display> fmt::Display for DominantPair<K, V> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "({},{})", self.first, self.second)
    }
}

// ============================================================================
// RedBlackTree — a complete red-black tree implementation
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NodeColor {
    Red,
    Black,
}

struct RbNode<K, V> {
    key: K,
    value: Option<V>,
    color: NodeColor,
    left: Option<usize>,
    right: Option<usize>,
    parent: Option<usize>,
}

/// A red-black tree with configurable comparator and optional duplicate keys.
///
/// Corresponds to Ghidra's `generic.stl.RedBlackTree`.
pub struct RedBlackTree<K, V> {
    nodes: Vec<RbNode<K, V>>,
    root: Option<usize>,
    size: usize,
    allow_duplicates: bool,
    comparator: Box<dyn Fn(&K, &K) -> Ordering>,
}

impl<K: fmt::Debug, V: fmt::Debug> fmt::Debug for RedBlackTree<K, V> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RedBlackTree")
            .field("size", &self.size)
            .field("root", &self.root)
            .finish()
    }
}

impl<K, V> RedBlackTree<K, V> {
    pub fn new(comparator: impl Fn(&K, &K) -> Ordering + 'static, allow_duplicates: bool) -> Self {
        Self {
            nodes: Vec::new(),
            root: None,
            size: 0,
            allow_duplicates,
            comparator: Box::new(comparator),
        }
    }

    pub fn size(&self) -> usize {
        self.size
    }

    pub fn is_empty(&self) -> bool {
        self.size == 0
    }

    pub fn contains_key(&self, key: &K) -> bool {
        self.find_node(key).is_some()
    }

    fn find_node(&self, key: &K) -> Option<usize> {
        let mut node = self.root;
        while let Some(idx) = node {
            let cmp = (self.comparator)(key, &self.nodes[idx].key);
            match cmp {
                Ordering::Equal => return Some(idx),
                Ordering::Less => node = self.nodes[idx].left,
                Ordering::Greater => node = self.nodes[idx].right,
            }
        }
        None
    }

    pub fn get_first(&self) -> Option<usize> {
        let mut node = self.root;
        while let Some(idx) = node {
            if self.nodes[idx].left.is_none() {
                return Some(idx);
            }
            node = self.nodes[idx].left;
        }
        None
    }

    pub fn get_last(&self) -> Option<usize> {
        let mut node = self.root;
        while let Some(idx) = node {
            if self.nodes[idx].right.is_none() {
                return Some(idx);
            }
            node = self.nodes[idx].right;
        }
        None
    }

    pub fn lower_bound(&self, key: &K) -> Option<usize> {
        let mut best = None;
        let mut node = self.root;
        while let Some(idx) = node {
            let cmp = (self.comparator)(key, &self.nodes[idx].key);
            if cmp != Ordering::Greater {
                best = Some(idx);
                node = self.nodes[idx].left;
            } else {
                node = self.nodes[idx].right;
            }
        }
        best
    }

    pub fn upper_bound(&self, key: &K) -> Option<usize> {
        let mut best = None;
        let mut node = self.root;
        while let Some(idx) = node {
            let cmp = (self.comparator)(key, &self.nodes[idx].key);
            if cmp == Ordering::Less {
                best = Some(idx);
                node = self.nodes[idx].left;
            } else {
                node = self.nodes[idx].right;
            }
        }
        best
    }

    pub fn get(&self, idx: usize) -> Option<(&K, &V)> {
        self.nodes.get(idx).and_then(|n| n.value.as_ref().map(|v| (&n.key, v)))
    }

    pub fn get_key(&self, idx: usize) -> Option<&K> {
        self.nodes.get(idx).map(|n| &n.key)
    }

    pub fn get_value(&self, idx: usize) -> Option<&V> {
        self.nodes.get(idx).and_then(|n| n.value.as_ref())
    }

    pub fn get_successor(&self, idx: usize) -> Option<usize> {
        let node = &self.nodes[idx];
        if let Some(right) = node.right {
            let mut current = right;
            while let Some(left) = self.nodes[current].left {
                current = left;
            }
            return Some(current);
        }
        let mut current = idx;
        while let Some(parent) = self.nodes[current].parent {
            if self.nodes[parent].left == Some(current) {
                return Some(parent);
            }
            current = parent;
        }
        None
    }

    pub fn get_predecessor(&self, idx: usize) -> Option<usize> {
        let node = &self.nodes[idx];
        if let Some(left) = node.left {
            let mut current = left;
            while let Some(right) = self.nodes[current].right {
                current = right;
            }
            return Some(current);
        }
        let mut current = idx;
        while let Some(parent) = self.nodes[current].parent {
            if self.nodes[parent].right == Some(current) {
                return Some(parent);
            }
            current = parent;
        }
        None
    }

    pub fn put(&mut self, key: K, value: V) -> (usize, bool) {
        if self.root.is_none() {
            let idx = self.alloc_node(key, value, None);
            self.nodes[idx].color = NodeColor::Black;
            self.root = Some(idx);
            self.size += 1;
            return (idx, true);
        }

        let mut current = self.root.unwrap();
        loop {
            let cmp = (self.comparator)(&key, &self.nodes[current].key);
            if cmp == Ordering::Equal && !self.allow_duplicates {
                let idx = current;
                self.nodes[idx].value = Some(value);
                return (idx, false);
            } else if cmp == Ordering::Less {
                if let Some(left) = self.nodes[current].left {
                    current = left;
                } else {
                    let idx = self.alloc_node(key, value, Some(current));
                    self.nodes[current].left = Some(idx);
                    self.fix_after_insertion(idx);
                    self.size += 1;
                    return (idx, true);
                }
            } else {
                if let Some(right) = self.nodes[current].right {
                    current = right;
                } else {
                    let idx = self.alloc_node(key, value, Some(current));
                    self.nodes[current].right = Some(idx);
                    self.fix_after_insertion(idx);
                    self.size += 1;
                    return (idx, true);
                }
            }
        }
    }

    pub fn find_first_node(&self, key: &K) -> Option<usize> {
        let mut node = self.root;
        let mut best = None;
        while let Some(idx) = node {
            let cmp = (self.comparator)(key, &self.nodes[idx].key);
            if cmp == Ordering::Equal {
                best = Some(idx);
            }
            if cmp != Ordering::Greater {
                node = self.nodes[idx].left;
            } else {
                node = self.nodes[idx].right;
            }
        }
        best
    }

    pub fn remove(&mut self, key: &K) -> Option<V> {
        let node = self.find_first_node(key)?;
        let value = self.nodes[node].value.take();
        self.delete_entry(node);
        value
    }

    pub fn delete_entry(&mut self, idx: usize) {
        self.size -= 1;

        // If internal node, swap with successor
        if self.nodes[idx].left.is_some() && self.nodes[idx].right.is_some() {
            let successor = self.get_successor(idx).unwrap();
            self.swap_position(successor, idx);
        }

        let replacement = if self.nodes[idx].left.is_some() {
            self.nodes[idx].left
        } else {
            self.nodes[idx].right
        };

        if let Some(repl) = replacement {
            self.nodes[repl].parent = self.nodes[idx].parent;
            if self.nodes[idx].parent.is_none() {
                self.root = Some(repl);
            } else if self.is_left_child(idx) {
                let parent = self.nodes[idx].parent.unwrap();
                self.nodes[parent].left = Some(repl);
            } else {
                let parent = self.nodes[idx].parent.unwrap();
                self.nodes[parent].right = Some(repl);
            }
            self.nodes[idx].left = None;
            self.nodes[idx].right = None;
            self.nodes[idx].parent = None;
            if self.nodes[idx].color == NodeColor::Black {
                self.fix_after_deletion(repl);
            }
        } else if self.nodes[idx].parent.is_none() {
            self.root = None;
        } else {
            if self.nodes[idx].color == NodeColor::Black {
                self.fix_after_deletion(idx);
            }
            if let Some(parent) = self.nodes[idx].parent {
                if self.is_left_child(idx) {
                    self.nodes[parent].left = None;
                } else {
                    self.nodes[parent].right = None;
                }
            }
            self.nodes[idx].parent = None;
        }
    }

    pub fn clear(&mut self) {
        self.nodes.clear();
        self.root = None;
        self.size = 0;
    }

    // ---- Private helpers ----

    fn alloc_node(&mut self, key: K, value: V, parent: Option<usize>) -> usize {
        let idx = self.nodes.len();
        self.nodes.push(RbNode {
            key,
            value: Some(value),
            color: NodeColor::Red,
            left: None,
            right: None,
            parent,
        });
        idx
    }

    fn is_left_child(&self, idx: usize) -> bool {
        if let Some(parent) = self.nodes[idx].parent {
            self.nodes[parent].left == Some(idx)
        } else {
            false
        }
    }

    fn rotate_left(&mut self, idx: usize) {
        let r = self.nodes[idx].right.unwrap();
        self.nodes[idx].right = self.nodes[r].left;
        if let Some(left) = self.nodes[r].left {
            self.nodes[left].parent = Some(idx);
        }
        self.nodes[r].parent = self.nodes[idx].parent;
        if self.nodes[idx].parent.is_none() {
            self.root = Some(r);
        } else {
            let parent = self.nodes[idx].parent.unwrap();
            if self.nodes[parent].left == Some(idx) {
                self.nodes[parent].left = Some(r);
            } else {
                self.nodes[parent].right = Some(r);
            }
        }
        self.nodes[r].left = Some(idx);
        self.nodes[idx].parent = Some(r);
    }

    fn rotate_right(&mut self, idx: usize) {
        let l = self.nodes[idx].left.unwrap();
        self.nodes[idx].left = self.nodes[l].right;
        if let Some(right) = self.nodes[l].right {
            self.nodes[right].parent = Some(idx);
        }
        self.nodes[l].parent = self.nodes[idx].parent;
        if self.nodes[idx].parent.is_none() {
            self.root = Some(l);
        } else {
            let parent = self.nodes[idx].parent.unwrap();
            if self.nodes[parent].right == Some(idx) {
                self.nodes[parent].right = Some(l);
            } else {
                self.nodes[parent].left = Some(l);
            }
        }
        self.nodes[l].right = Some(idx);
        self.nodes[idx].parent = Some(l);
    }

    fn color_of(&self, idx: Option<usize>) -> NodeColor {
        match idx {
            Some(i) => self.nodes[i].color,
            None => NodeColor::Black,
        }
    }

    fn fix_after_insertion(&mut self, mut x: usize) {
        self.nodes[x].color = NodeColor::Red;
        while x != self.root.unwrap()
            && self.nodes[self.nodes[x].parent.unwrap()].color == NodeColor::Red
        {
            let parent = self.nodes[x].parent.unwrap();
            let grandparent = self.nodes[parent].parent.unwrap();
            let is_left = self.nodes[parent].left == Some(x);
            let parent_is_left = self.nodes[grandparent].left == Some(parent);
            if is_left == parent_is_left {
                // Same side
                if is_left {
                    // Left-left
                    let uncle = self.nodes[grandparent].right;
                    if self.color_of(uncle) == NodeColor::Red {
                        self.nodes[parent].color = NodeColor::Black;
                        if let Some(u) = uncle {
                            self.nodes[u].color = NodeColor::Black;
                        }
                        self.nodes[grandparent].color = NodeColor::Red;
                        x = grandparent;
                    } else {
                        if self.nodes[parent].right == Some(x) {
                            x = parent;
                            self.rotate_left(x);
                        }
                        let parent = self.nodes[x].parent.unwrap();
                        let grandparent = self.nodes[parent].parent.unwrap();
                        self.nodes[parent].color = NodeColor::Black;
                        self.nodes[grandparent].color = NodeColor::Red;
                        self.rotate_right(grandparent);
                    }
                } else {
                    // Right-right
                    let uncle = self.nodes[grandparent].left;
                    if self.color_of(uncle) == NodeColor::Red {
                        self.nodes[parent].color = NodeColor::Black;
                        if let Some(u) = uncle {
                            self.nodes[u].color = NodeColor::Black;
                        }
                        self.nodes[grandparent].color = NodeColor::Red;
                        x = grandparent;
                    } else {
                        if self.nodes[parent].left == Some(x) {
                            x = parent;
                            self.rotate_right(x);
                        }
                        let parent = self.nodes[x].parent.unwrap();
                        let grandparent = self.nodes[parent].parent.unwrap();
                        self.nodes[parent].color = NodeColor::Black;
                        self.nodes[grandparent].color = NodeColor::Red;
                        self.rotate_left(grandparent);
                    }
                }
            } else {
                // Different sides
                if self.nodes[grandparent].left == Some(parent) {
                    let uncle = self.nodes[grandparent].left;
                    if self.color_of(uncle) == NodeColor::Red {
                        self.nodes[parent].color = NodeColor::Black;
                        if let Some(u) = uncle {
                            self.nodes[u].color = NodeColor::Black;
                        }
                        self.nodes[grandparent].color = NodeColor::Red;
                        x = grandparent;
                    } else {
                        if self.nodes[parent].left == Some(x) {
                            x = parent;
                            self.rotate_right(x);
                        }
                        let parent = self.nodes[x].parent.unwrap();
                        let grandparent = self.nodes[parent].parent.unwrap();
                        self.nodes[parent].color = NodeColor::Black;
                        self.nodes[grandparent].color = NodeColor::Red;
                        self.rotate_left(grandparent);
                    }
                } else {
                    let uncle = self.nodes[grandparent].right;
                    if self.color_of(uncle) == NodeColor::Red {
                        self.nodes[parent].color = NodeColor::Black;
                        if let Some(u) = uncle {
                            self.nodes[u].color = NodeColor::Black;
                        }
                        self.nodes[grandparent].color = NodeColor::Red;
                        x = grandparent;
                    } else {
                        if self.nodes[parent].right == Some(x) {
                            x = parent;
                            self.rotate_left(x);
                        }
                        let parent = self.nodes[x].parent.unwrap();
                        let grandparent = self.nodes[parent].parent.unwrap();
                        self.nodes[parent].color = NodeColor::Black;
                        self.nodes[grandparent].color = NodeColor::Red;
                        self.rotate_right(grandparent);
                    }
                }
            }
        }
        if let Some(root) = self.root {
            self.nodes[root].color = NodeColor::Black;
        }
    }

    fn fix_after_deletion(&mut self, mut x: usize) {
        while Some(x) != self.root && self.color_of(Some(x)) == NodeColor::Black {
            let parent = self.nodes[x].parent.unwrap();
            if self.nodes[parent].left == Some(x) {
                let mut sibling = self.nodes[parent].right.unwrap();
                if self.color_of(Some(sibling)) == NodeColor::Red {
                    self.nodes[sibling].color = NodeColor::Black;
                    self.nodes[parent].color = NodeColor::Red;
                    self.rotate_left(parent);
                    sibling = self.nodes[parent].right.unwrap();
                }
                if self.color_of(self.nodes[sibling].left) == NodeColor::Black
                    && self.color_of(self.nodes[sibling].right) == NodeColor::Black
                {
                    self.nodes[sibling].color = NodeColor::Red;
                    x = parent;
                } else {
                    if self.color_of(self.nodes[sibling].right) == NodeColor::Black {
                        if let Some(left) = self.nodes[sibling].left {
                            self.nodes[left].color = NodeColor::Black;
                        }
                        self.nodes[sibling].color = NodeColor::Red;
                        self.rotate_right(sibling);
                        sibling = self.nodes[parent].right.unwrap();
                    }
                    self.nodes[sibling].color = self.nodes[parent].color;
                    self.nodes[parent].color = NodeColor::Black;
                    if let Some(right) = self.nodes[sibling].right {
                        self.nodes[right].color = NodeColor::Black;
                    }
                    self.rotate_left(parent);
                    x = self.root.unwrap();
                }
            } else {
                let mut sibling = self.nodes[parent].left.unwrap();
                if self.color_of(Some(sibling)) == NodeColor::Red {
                    self.nodes[sibling].color = NodeColor::Black;
                    self.nodes[parent].color = NodeColor::Red;
                    self.rotate_right(parent);
                    sibling = self.nodes[parent].left.unwrap();
                }
                if self.color_of(self.nodes[sibling].right) == NodeColor::Black
                    && self.color_of(self.nodes[sibling].left) == NodeColor::Black
                {
                    self.nodes[sibling].color = NodeColor::Red;
                    x = parent;
                } else {
                    if self.color_of(self.nodes[sibling].left) == NodeColor::Black {
                        if let Some(right) = self.nodes[sibling].right {
                            self.nodes[right].color = NodeColor::Black;
                        }
                        self.nodes[sibling].color = NodeColor::Red;
                        self.rotate_left(sibling);
                        sibling = self.nodes[parent].left.unwrap();
                    }
                    self.nodes[sibling].color = self.nodes[parent].color;
                    self.nodes[parent].color = NodeColor::Black;
                    if let Some(left) = self.nodes[sibling].left {
                        self.nodes[left].color = NodeColor::Black;
                    }
                    self.rotate_right(parent);
                    x = self.root.unwrap();
                }
            }
        }
        self.nodes[x].color = NodeColor::Black;
    }

    fn swap_position(&mut self, x: usize, y: usize) {
        // Swap keys and values using split_at_mut to satisfy the borrow checker
        let (left, right) = if x < y {
            let (l, r) = self.nodes.split_at_mut(y);
            (&mut l[x], &mut r[0])
        } else {
            let (l, r) = self.nodes.split_at_mut(x);
            (&mut r[0], &mut l[y])
        };
        std::mem::swap(&mut left.key, &mut right.key);
        std::mem::swap(&mut left.value, &mut right.value);
    }
}

// ============================================================================
// MapSTL
// ============================================================================

/// An ordered map backed by a red-black tree.
///
/// Corresponds to Ghidra's `generic.stl.MapSTL`.
pub struct MapSTL<K, V> {
    tree: RedBlackTree<K, V>,
}

impl<K: Ord, V> MapSTL<K, V> {
    pub fn new() -> Self {
        Self {
            tree: RedBlackTree::new(|a: &K, b: &K| a.cmp(b), false),
        }
    }
}

impl<K, V> MapSTL<K, V> {
    pub fn with_comparator(comparator: impl Fn(&K, &K) -> Ordering + 'static) -> Self {
        Self {
            tree: RedBlackTree::new(comparator, false),
        }
    }

    pub fn put(&mut self, key: K, value: V) {
        self.tree.put(key, value);
    }

    pub fn get(&self, key: &K) -> Option<&V> {
        let node = self.tree.find_first_node(key)?;
        self.tree.get_value(node)
    }

    pub fn contains(&self, key: &K) -> bool {
        self.tree.contains_key(key)
    }

    pub fn remove(&mut self, key: &K) -> Option<V> {
        self.tree.remove(key)
    }

    pub fn size(&self) -> usize {
        self.tree.size()
    }

    pub fn is_empty(&self) -> bool {
        self.tree.is_empty()
    }

    pub fn clear(&mut self) {
        self.tree.clear();
    }

    pub fn find(&self, key: &K) -> Option<usize> {
        self.tree.find_first_node(key)
    }

    pub fn lower_bound(&self, key: &K) -> Option<usize> {
        self.tree.lower_bound(key)
    }

    pub fn upper_bound(&self, key: &K) -> Option<usize> {
        self.tree.upper_bound(key)
    }

    pub fn get_entry(&self, idx: usize) -> Option<(&K, &V)> {
        self.tree.get(idx)
    }

    pub fn get_first(&self) -> Option<usize> {
        self.tree.get_first()
    }

    pub fn get_last(&self) -> Option<usize> {
        self.tree.get_last()
    }

    pub fn get_successor(&self, idx: usize) -> Option<usize> {
        self.tree.get_successor(idx)
    }

    pub fn delete_entry(&mut self, idx: usize) {
        self.tree.delete_entry(idx);
    }
}

impl<K: Ord, V> Default for MapSTL<K, V> {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// SetSTL
// ============================================================================

/// An ordered set backed by a red-black tree.
///
/// Corresponds to Ghidra's `generic.stl.SetSTL`.
pub struct SetSTL<K> {
    tree: RedBlackTree<K, ()>,
}

impl<K: Ord> SetSTL<K> {
    pub fn new() -> Self {
        Self {
            tree: RedBlackTree::new(|a: &K, b: &K| a.cmp(b), false),
        }
    }
}

impl<K> SetSTL<K> {
    pub fn with_comparator(comparator: impl Fn(&K, &K) -> Ordering + 'static) -> Self {
        Self {
            tree: RedBlackTree::new(comparator, false),
        }
    }

    pub fn insert(&mut self, key: K) -> (usize, bool) {
        self.tree.put(key, ())
    }

    pub fn contains(&self, key: &K) -> bool {
        self.tree.contains_key(key)
    }

    pub fn remove(&mut self, key: &K) -> bool {
        self.tree.remove(key).is_some()
    }

    pub fn size(&self) -> usize {
        self.tree.size()
    }

    pub fn is_empty(&self) -> bool {
        self.tree.is_empty()
    }

    pub fn clear(&mut self) {
        self.tree.clear();
    }

    pub fn find(&self, key: &K) -> Option<usize> {
        self.tree.find_first_node(key)
    }

    pub fn lower_bound(&self, key: &K) -> Option<usize> {
        self.tree.lower_bound(key)
    }

    pub fn upper_bound(&self, key: &K) -> Option<usize> {
        self.tree.upper_bound(key)
    }

    pub fn get_key(&self, idx: usize) -> Option<&K> {
        self.tree.get_key(idx)
    }

    pub fn get_first(&self) -> Option<usize> {
        self.tree.get_first()
    }

    pub fn get_last(&self) -> Option<usize> {
        self.tree.get_last()
    }

    pub fn get_successor(&self, idx: usize) -> Option<usize> {
        self.tree.get_successor(idx)
    }

    pub fn delete_entry(&mut self, idx: usize) {
        self.tree.delete_entry(idx);
    }
}

impl<K: Ord> Default for SetSTL<K> {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// VectorSTL — Vec-backed container with STL-like API
// ============================================================================

/// A `Vec` wrapper that provides an STL-style interface.
///
/// Corresponds to Ghidra's `generic.stl.VectorSTL`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VectorSTL<T> {
    data: Vec<T>,
}

impl<T> Default for VectorSTL<T> {
    fn default() -> Self {
        Self { data: Vec::new() }
    }
}

impl<T> VectorSTL<T> {
    pub fn new() -> Self {
        Self { data: Vec::new() }
    }

    pub fn with_capacity(cap: usize) -> Self {
        Self {
            data: Vec::with_capacity(cap),
        }
    }

    pub fn reserve(&mut self, additional: usize) {
        self.data.reserve(additional);
    }

    pub fn size(&self) -> usize {
        self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    pub fn get(&self, index: usize) -> &T {
        &self.data[index]
    }

    pub fn front(&self) -> &T {
        &self.data[0]
    }

    pub fn back(&self) -> &T {
        &self.data[self.data.len() - 1]
    }

    pub fn push_back(&mut self, value: T) {
        self.data.push(value);
    }

    pub fn pop_back(&mut self) -> T {
        self.data.pop().expect("VectorSTL::pop_back on empty vector")
    }

    pub fn insert_at(&mut self, index: usize, value: T) {
        self.data.insert(index, value);
    }

    pub fn set(&mut self, index: usize, value: T) {
        self.data[index] = value;
    }

    pub fn clear(&mut self) {
        self.data.clear();
    }

    pub fn erase(&mut self, index: usize) -> T {
        self.data.remove(index)
    }

    pub fn erase_range(&mut self, start: usize, end: usize) {
        self.data.drain(start..end);
    }

    pub fn append_all(&mut self, other: &mut Vec<T>) {
        self.data.append(other);
    }

    pub fn resize(&mut self, new_size: usize, value: T)
    where
        T: Clone,
    {
        self.data.resize(new_size, value);
    }

    pub fn as_slice(&self) -> &[T] {
        &self.data
    }

    pub fn as_mut_slice(&mut self) -> &mut [T] {
        &mut self.data
    }

    pub fn sort(&mut self)
    where
        T: Ord,
    {
        self.data.sort();
    }

    pub fn sort_by(&mut self, cmp: impl FnMut(&T, &T) -> Ordering) {
        self.data.sort_by(cmp);
    }

    pub fn assign(&mut self, other: &Self)
    where
        T: Clone,
    {
        self.data.clone_from(&other.data);
    }

    pub fn lower_bound(&self, key: &T) -> usize
    where
        T: Ord,
    {
        self.data.partition_point(|x| x < key)
    }

    pub fn upper_bound(&self, key: &T) -> usize
    where
        T: Ord,
    {
        self.data.partition_point(|x| x <= key)
    }

    pub fn iter(&self) -> std::slice::Iter<'_, T> {
        self.data.iter()
    }

    pub fn iter_mut(&mut self) -> std::slice::IterMut<'_, T> {
        self.data.iter_mut()
    }
}

impl<T> From<Vec<T>> for VectorSTL<T> {
    fn from(v: Vec<T>) -> Self {
        Self { data: v }
    }
}

impl<T> IntoIterator for VectorSTL<T> {
    type Item = T;
    type IntoIter = std::vec::IntoIter<T>;
    fn into_iter(self) -> Self::IntoIter {
        self.data.into_iter()
    }
}

// ============================================================================
// ListSTL — doubly-linked list
// ============================================================================

/// A doubly-linked list with STL-style API.
///
/// Corresponds to Ghidra's `generic.stl.ListSTL`.
#[derive(Debug, Clone)]
pub struct ListSTL<T> {
    data: VecDeque<T>,
}

impl<T> Default for ListSTL<T> {
    fn default() -> Self {
        Self {
            data: VecDeque::new(),
        }
    }
}

impl<T> ListSTL<T> {
    pub fn new() -> Self {
        Self {
            data: VecDeque::new(),
        }
    }

    pub fn size(&self) -> usize {
        self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    pub fn push_back(&mut self, value: T) {
        self.data.push_back(value);
    }

    pub fn push_front(&mut self, value: T) {
        self.data.push_front(value);
    }

    pub fn pop_back(&mut self) -> Option<T> {
        self.data.pop_back()
    }

    pub fn pop_front(&mut self) -> Option<T> {
        self.data.pop_front()
    }

    pub fn front(&self) -> Option<&T> {
        self.data.front()
    }

    pub fn back(&self) -> Option<&T> {
        self.data.back()
    }

    pub fn clear(&mut self) {
        self.data.clear();
    }

    pub fn sort(&mut self)
    where
        T: Ord,
    {
        self.data.make_contiguous().sort();
    }

    pub fn sort_by(&mut self, cmp: impl FnMut(&T, &T) -> Ordering) {
        self.data.make_contiguous().sort_by(cmp);
    }

    pub fn iter(&self) -> std::collections::vec_deque::Iter<'_, T> {
        self.data.iter()
    }

    pub fn iter_mut(&mut self) -> std::collections::vec_deque::IterMut<'_, T> {
        self.data.iter_mut()
    }
}

impl<T> From<Vec<T>> for ListSTL<T> {
    fn from(v: Vec<T>) -> Self {
        Self {
            data: VecDeque::from(v),
        }
    }
}

impl<T> IntoIterator for ListSTL<T> {
    type Item = T;
    type IntoIter = std::collections::vec_deque::IntoIter<T>;
    fn into_iter(self) -> Self::IntoIter {
        self.data.into_iter()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pair() {
        let p = Pair::new(1, "hello");
        assert_eq!(p.first, 1);
        assert_eq!(p.second, "hello");
        assert_eq!(format!("{}", p), "<1,hello>");
    }

    #[test]
    fn test_quad() {
        let q = Quad::new(1, 2, 3, 4);
        assert_eq!(q.first, 1);
        assert_eq!(q.fourth, 4);
    }

    #[test]
    fn test_dominant_pair() {
        let p1 = DominantPair::new(1, "a");
        let p2 = DominantPair::new(1, "b");
        assert_eq!(p1, p2); // same key => equal

        let p3 = DominantPair::new(2, "a");
        assert_ne!(p1, p3);
    }

    #[test]
    fn test_red_black_tree_basic() {
        let mut tree = RedBlackTree::new(|a: &i32, b: &i32| a.cmp(b), false);
        tree.put(5, "five");
        tree.put(3, "three");
        tree.put(7, "seven");
        assert_eq!(tree.size(), 3);
        assert!(tree.contains_key(&5));
        assert!(!tree.contains_key(&4));
    }

    #[test]
    fn test_red_black_tree_ordering() {
        let mut tree = RedBlackTree::new(|a: &i32, b: &i32| a.cmp(b), false);
        for i in [5, 3, 7, 1, 4, 6, 8] {
            tree.put(i, i);
        }
        // First should be 1, last should be 8
        let first = tree.get_first().unwrap();
        assert_eq!(*tree.get_key(first).unwrap(), 1);
        let last = tree.get_last().unwrap();
        assert_eq!(*tree.get_key(last).unwrap(), 8);
    }

    #[test]
    fn test_red_black_tree_remove() {
        let mut tree = RedBlackTree::new(|a: &i32, b: &i32| a.cmp(b), false);
        tree.put(5, "five");
        tree.put(3, "three");
        tree.put(7, "seven");
        assert_eq!(tree.remove(&3), Some("three"));
        assert_eq!(tree.size(), 2);
        assert!(!tree.contains_key(&3));
        assert_eq!(tree.remove(&10), None);
    }

    #[test]
    fn test_red_black_tree_bounds() {
        let mut tree = RedBlackTree::new(|a: &i32, b: &i32| a.cmp(b), false);
        for i in [10, 20, 30, 40, 50] {
            tree.put(i, i);
        }
        // lower_bound(25) should be 30
        let lb = tree.lower_bound(&25).unwrap();
        assert_eq!(*tree.get_key(lb).unwrap(), 30);
        // upper_bound(30) should be 40
        let ub = tree.upper_bound(&30).unwrap();
        assert_eq!(*tree.get_key(ub).unwrap(), 40);
    }

    #[test]
    fn test_map_stl() {
        let mut map = MapSTL::new();
        map.put(1, "one");
        map.put(2, "two");
        map.put(3, "three");
        assert_eq!(map.size(), 3);
        assert_eq!(map.get(&2), Some(&"two"));
        assert!(map.contains(&1));
        assert!(!map.contains(&5));
        assert_eq!(map.remove(&2), Some("two"));
        assert_eq!(map.size(), 2);
    }

    #[test]
    fn test_set_stl() {
        let mut set = SetSTL::new();
        assert_eq!(set.insert(5).1, true);
        assert_eq!(set.insert(5).1, false); // already present
        assert_eq!(set.insert(3).1, true);
        assert!(set.contains(&5));
        assert!(!set.contains(&4));
        assert_eq!(set.size(), 2);
        assert!(set.remove(&5));
        assert_eq!(set.size(), 1);
    }

    #[test]
    fn test_vector_stl() {
        let mut v = VectorSTL::new();
        v.push_back(1);
        v.push_back(2);
        v.push_back(3);
        assert_eq!(v.size(), 3);
        assert_eq!(*v.front(), 1);
        assert_eq!(*v.back(), 3);
        assert_eq!(v.erase(1), 2);
        assert_eq!(v.size(), 2);
        v.sort();
        assert_eq!(*v.get(0), 1);
        assert_eq!(*v.get(1), 3);
    }

    #[test]
    fn test_vector_stl_binary_search() {
        let v = VectorSTL::from(vec![10, 20, 30, 40, 50]);
        assert_eq!(v.lower_bound(&25), 2);
        assert_eq!(v.upper_bound(&30), 3);
        assert_eq!(v.lower_bound(&10), 0);
        assert_eq!(v.upper_bound(&50), 5);
    }

    #[test]
    fn test_list_stl() {
        let mut list = ListSTL::new();
        list.push_back(1);
        list.push_back(2);
        list.push_front(0);
        assert_eq!(list.size(), 3);
        assert_eq!(list.front(), Some(&0));
        assert_eq!(list.back(), Some(&2));
        assert_eq!(list.pop_front(), Some(0));
        assert_eq!(list.pop_back(), Some(2));
        assert_eq!(list.size(), 1);
    }

    #[test]
    fn test_list_stl_sort() {
        let mut list = ListSTL::from(vec![5, 3, 1, 4, 2]);
        list.sort();
        let sorted: Vec<i32> = list.into_iter().collect();
        assert_eq!(sorted, vec![1, 2, 3, 4, 5]);
    }
}
