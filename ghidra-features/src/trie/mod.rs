//! Byte-based trie with Aho-Corasick multi-pattern search.
//!
//! Ported from `ghidra.util.search.trie`.
//!
//! The [`ByteTrie`] is a trie data structure specifically designed for the
//! Aho-Corasick string search algorithm, supporting both byte-array and
//! memory-mapped searches.

use std::collections::{HashMap, VecDeque};
use std::fmt::Debug;

// ---------------------------------------------------------------------------
// SearchResult
// ---------------------------------------------------------------------------

/// A single match result from a trie search.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchResult<P, T> {
    /// The matched item stored at the terminal node.
    pub item: T,
    /// The position where the match starts (byte offset or address).
    pub position: P,
    /// The length of the matched sequence.
    pub length: usize,
}

impl<P: Debug, T: Debug> SearchResult<P, T> {
    /// Create a new search result.
    pub fn new(item: T, position: P, length: usize) -> Self {
        Self {
            item,
            position,
            length,
        }
    }
}

// ---------------------------------------------------------------------------
// ByteTrieNode
// ---------------------------------------------------------------------------

/// A node in the byte trie.
#[derive(Debug)]
pub struct ByteTrieNode<T> {
    /// The byte value this node represents.
    id: u8,
    /// Whether this node is the end of a sequence.
    terminal: bool,
    /// The user item stored at terminal nodes.
    item: Option<T>,
    /// Length of the path from root to this node.
    length: usize,
    /// Children indexed by byte value.
    children: HashMap<u8, usize>,
    /// Suffix (failure) pointer index.
    suffix: usize,
    /// Output link for Aho-Corasick.
    output_link: usize,
}

impl<T> ByteTrieNode<T> {
    fn new(id: u8, length: usize) -> Self {
        Self {
            id,
            terminal: false,
            item: None,
            length,
            children: HashMap::new(),
            suffix: 0,
            output_link: 0,
        }
    }

    /// Whether this node is terminal (end of a sequence).
    pub fn is_terminal(&self) -> bool {
        self.terminal
    }

    /// The stored item (only valid for terminal nodes).
    pub fn item(&self) -> Option<&T> {
        self.item.as_ref()
    }

    /// The length of the path from root to this node.
    pub fn length(&self) -> usize {
        self.length
    }

    /// The byte value at this node.
    pub fn id(&self) -> u8 {
        self.id
    }
}

// ---------------------------------------------------------------------------
// ByteTrie
// ---------------------------------------------------------------------------

/// A byte-based trie implementing the Aho-Corasick multiple string search algorithm.
///
/// # Example
///
/// ```
/// use ghidra_features::trie::ByteTrie;
///
/// let mut trie = ByteTrie::new();
/// trie.add(b"he", 1);
/// trie.add(b"she", 2);
/// trie.add(b"his", 3);
/// trie.add(b"hers", 4);
///
/// let results = trie.search(b"ahishers").unwrap();
/// assert!(results.iter().any(|r| r.item == 3)); // "his" at offset 1
/// assert!(results.iter().any(|r| r.item == 2)); // "she" at offset 3
/// ```
#[derive(Debug)]
pub struct ByteTrie<T> {
    nodes: Vec<ByteTrieNode<T>>,
    size: usize,
    /// Whether suffix pointers have been computed.
    suffixes_fixed: bool,
}

impl<T: Clone + Debug> ByteTrie<T> {
    /// Create a new empty trie.
    pub fn new() -> Self {
        let root = ByteTrieNode::new(0, 0);
        Self {
            nodes: vec![root],
            size: 0,
            suffixes_fixed: false,
        }
    }

    /// Whether the trie is empty.
    pub fn is_empty(&self) -> bool {
        self.size == 0
    }

    /// Number of byte sequences in the trie.
    pub fn size(&self) -> usize {
        self.size
    }

    /// Number of nodes in the trie.
    pub fn number_of_nodes(&self) -> usize {
        self.nodes.len()
    }

    /// Add a byte sequence with an associated user item.
    ///
    /// Returns `true` if a new sequence was added, `false` if it was a replacement.
    pub fn add(&mut self, value: &[u8], item: T) -> bool {
        self.suffixes_fixed = false;
        let mut current = 0; // root index

        for &byte in value {
            let next = if let Some(&child_idx) = self.nodes[current].children.get(&byte) {
                child_idx
            } else {
                let new_len = self.nodes[current].length + 1;
                let new_idx = self.nodes.len();
                self.nodes.push(ByteTrieNode::new(byte, new_len));
                self.nodes[current].children.insert(byte, new_idx);
                new_idx
            };
            current = next;
        }

        let absent = !self.nodes[current].terminal;
        self.nodes[current].terminal = true;
        self.nodes[current].item = Some(item);
        if absent {
            self.size += 1;
        }
        absent
    }

    /// Find a node corresponding to the given byte sequence.
    pub fn find(&self, value: &[u8]) -> Option<usize> {
        let mut current = 0;
        for &byte in value {
            current = *self.nodes[current].children.get(&byte)?;
        }
        if self.nodes[current].terminal {
            Some(current)
        } else {
            None
        }
    }

    /// Search a byte array using the Aho-Corasick algorithm.
    ///
    /// Returns all matches found in the text.
    pub fn search(&mut self, text: &[u8]) -> Result<Vec<SearchResult<usize, T>>, String> {
        self.fixup_suffix_pointers();

        let mut results = Vec::new();
        let mut state = 0usize; // root

        for (index, &byte) in text.iter().enumerate() {
            loop {
                if let Some(&child) = self.nodes[state].children.get(&byte) {
                    state = child;
                    break;
                }
                if state == 0 {
                    break;
                }
                state = self.nodes[state].suffix;
            }

            // Follow output links
            let mut tmp = state;
            while tmp != 0 {
                if self.nodes[tmp].terminal {
                    if let Some(item) = self.nodes[tmp].item.clone() {
                        let match_len = self.nodes[tmp].length;
                        results.push(SearchResult::new(
                            item,
                            index + 1 - match_len,
                            match_len,
                        ));
                    }
                }
                tmp = self.nodes[tmp].output_link;
            }
        }

        Ok(results)
    }

    /// Visit all terminal nodes in order, calling the provided closure.
    pub fn for_each_terminal(&self, mut f: impl FnMut(&T)) {
        for node in &self.nodes {
            if node.terminal {
                if let Some(item) = &node.item {
                    f(item);
                }
            }
        }
    }

    // -- Aho-Corasick suffix pointer fixup --

    fn fixup_suffix_pointers(&mut self) {
        if self.suffixes_fixed {
            return;
        }

        // Initialize: root's suffix points to itself, children of root point to root
        self.nodes[0].suffix = 0;
        self.nodes[0].output_link = 0;

        let mut queue = VecDeque::new();

        // Set root's children suffixes to root
        let root_children: Vec<usize> = self.nodes[0].children.values().copied().collect();
        for &child_idx in &root_children {
            self.nodes[child_idx].suffix = 0;
            self.nodes[child_idx].output_link = 0;
            queue.push_back(child_idx);
        }

        // BFS to compute suffix and output links
        while let Some(node_idx) = queue.pop_front() {
            let children: Vec<(u8, usize)> = self.nodes[node_idx]
                .children
                .iter()
                .map(|(&b, &idx)| (b, idx))
                .collect();

            for (byte, child_idx) in children {
                // Compute suffix: follow parent's suffix chain
                let mut s = self.nodes[node_idx].suffix;
                loop {
                    if let Some(&next) = self.nodes[s].children.get(&byte) {
                        self.nodes[child_idx].suffix = next;
                        break;
                    }
                    if s == 0 {
                        self.nodes[child_idx].suffix = 0;
                        break;
                    }
                    s = self.nodes[s].suffix;
                }

                // Compute output link
                let suffix = self.nodes[child_idx].suffix;
                if self.nodes[suffix].terminal {
                    self.nodes[child_idx].output_link = suffix;
                } else {
                    self.nodes[child_idx].output_link = self.nodes[suffix].output_link;
                }

                queue.push_back(child_idx);
            }
        }

        self.suffixes_fixed = true;
    }
}

impl<T: Clone + Debug> Default for ByteTrie<T> {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// CaseInsensitiveByteTrie
// ---------------------------------------------------------------------------

/// A case-insensitive variant of [`ByteTrie`].
///
/// All byte values are lowercased before insertion and search.
#[derive(Debug)]
pub struct CaseInsensitiveByteTrie<T> {
    inner: ByteTrie<T>,
}

impl<T: Clone + Debug> CaseInsensitiveByteTrie<T> {
    /// Create a new case-insensitive trie.
    pub fn new() -> Self {
        Self {
            inner: ByteTrie::new(),
        }
    }

    /// Add a case-insensitive byte sequence.
    pub fn add(&mut self, value: &[u8], item: T) -> bool {
        let lowered: Vec<u8> = value.iter().map(|b| b.to_ascii_lowercase()).collect();
        self.inner.add(&lowered, item)
    }

    /// Search case-insensitively.
    pub fn search(&mut self, text: &[u8]) -> Result<Vec<SearchResult<usize, T>>, String> {
        let lowered: Vec<u8> = text.iter().map(|b| b.to_ascii_lowercase()).collect();
        self.inner.search(&lowered)
    }

    /// Whether the trie is empty.
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Number of entries.
    pub fn size(&self) -> usize {
        self.inner.size()
    }
}

impl<T: Clone + Debug> Default for CaseInsensitiveByteTrie<T> {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trie_basic() {
        let mut trie = ByteTrie::new();
        assert!(trie.is_empty());
        trie.add(b"hello", 1);
        trie.add(b"world", 2);
        assert_eq!(trie.size(), 2);
        assert!(!trie.is_empty());
    }

    #[test]
    fn test_trie_duplicate_add() {
        let mut trie = ByteTrie::new();
        assert!(trie.add(b"hello", 1));
        assert!(!trie.add(b"hello", 2)); // replacement
        assert_eq!(trie.size(), 1);
    }

    #[test]
    fn test_trie_find() {
        let mut trie = ByteTrie::new();
        trie.add(b"abc", 42);
        assert!(trie.find(b"abc").is_some());
        assert!(trie.find(b"ab").is_none());
        assert!(trie.find(b"abcd").is_none());
    }

    #[test]
    fn test_aho_corasick_search() {
        let mut trie = ByteTrie::new();
        trie.add(b"he", 1);
        trie.add(b"she", 2);
        trie.add(b"his", 3);
        trie.add(b"hers", 4);

        let results = trie.search(b"ahishers").unwrap();
        // "his" at position 1
        assert!(results.iter().any(|r| r.item == 3 && r.position == 1));
        // "she" at position 3
        assert!(results.iter().any(|r| r.item == 2 && r.position == 3));
        // "he" at position 4
        assert!(results.iter().any(|r| r.item == 1 && r.position == 4));
        // "hers" at position 4
        assert!(results.iter().any(|r| r.item == 4 && r.position == 4));
    }

    #[test]
    fn test_aho_corasick_overlapping() {
        let mut trie = ByteTrie::new();
        trie.add(b"a", 1);
        trie.add(b"aa", 2);
        trie.add(b"aaa", 3);

        let results = trie.search(b"aaaa").unwrap();
        // Should find: "a" at 0,1,2,3; "aa" at 0,1,2; "aaa" at 0,1
        assert!(results.len() >= 9);
    }

    #[test]
    fn test_empty_search() {
        let mut trie: ByteTrie<i32> = ByteTrie::new();
        let results = trie.search(b"anything").unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn test_case_insensitive_trie() {
        let mut trie = CaseInsensitiveByteTrie::new();
        trie.add(b"Hello", 1);
        trie.add(b"WORLD", 2);

        let results = trie.search(b"hello world").unwrap();
        assert!(results.iter().any(|r| r.item == 1));
        assert!(results.iter().any(|r| r.item == 2));
    }

    #[test]
    fn test_for_each_terminal() {
        let mut trie = ByteTrie::new();
        trie.add(b"abc", 10);
        trie.add(b"def", 20);

        let mut items = Vec::new();
        trie.for_each_terminal(|item| items.push(item.clone()));
        assert!(items.contains(&10));
        assert!(items.contains(&20));
    }

    #[test]
    fn test_search_result() {
        let result = SearchResult::new(42usize, 10usize, 5);
        assert_eq!(result.item, 42);
        assert_eq!(result.position, 10);
        assert_eq!(result.length, 5);
    }
}
