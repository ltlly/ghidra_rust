//! Closed Sequence Mining (BIDE algorithm).
//!
//! Ported from Ghidra's `ghidra.closedpatternmining` package.
//!
//! Implements the BIDE (BIdirectional Extension) algorithm for mining closed
//! sequential patterns.  In the Ghidra context this is used to discover
//! frequent byte sequences in function prologues and epilogues so they can
//! be used as function-start identification patterns.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};

// ---------------------------------------------------------------------------
// SequenceItem -- a single item in a sequence
// ---------------------------------------------------------------------------

/// A single item in a sequence.
///
/// In Ghidra, a `SequenceItem` typically represents a byte value at a
/// particular offset or a register value for context-aware patterns.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SequenceItem {
    /// The index (offset) of this item within its sequence.
    pub index: usize,
    /// The value of this item.
    pub value: u32,
}

impl SequenceItem {
    /// Create a new sequence item.
    pub fn new(index: usize, value: u32) -> Self {
        Self { index, value }
    }
}

// ---------------------------------------------------------------------------
// Sequence -- an ordered collection of SequenceItems
// ---------------------------------------------------------------------------

/// An ordered collection of [`SequenceItem`]s forming a subsequence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sequence {
    /// Items in this sequence, sorted by index.
    pub items: Vec<SequenceItem>,
}

impl Sequence {
    /// Create a new sequence from items (will be sorted by index).
    pub fn new(mut items: Vec<SequenceItem>) -> Self {
        items.sort_by_key(|i| i.index);
        Self { items }
    }

    /// Create a sequence from a raw byte slice, where each byte becomes
    /// an item at its offset.
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let items: Vec<SequenceItem> = bytes
            .iter()
            .enumerate()
            .map(|(i, &v)| SequenceItem::new(i, v as u32))
            .collect();
        Self { items }
    }

    /// The length of this sequence (number of items).
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// Whether this sequence is empty.
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// Check whether `self` is a subsequence of `other`.
    ///
    /// A sequence S is a subsequence of T if every item in S appears in T
    /// at the same index.
    pub fn is_subsequence_of(&self, other: &Sequence) -> bool {
        let mut self_iter = self.items.iter().peekable();
        for item in &other.items {
            if let Some(s_item) = self_iter.peek() {
                if s_item.index == item.index && s_item.value == item.value {
                    self_iter.next();
                }
            } else {
                return true;
            }
        }
        self_iter.peek().is_none()
    }

    /// Get the item at a given index, if present.
    pub fn item_at(&self, index: usize) -> Option<&SequenceItem> {
        self.items.iter().find(|i| i.index == index)
    }

    /// Check whether this sequence can be bidirectionally extended backward.
    ///
    /// `support_indices` should be the indices of database sequences that
    /// contain this pattern (used for BIDE closure check).
    pub fn has_backward_extension(
        &self,
        database: &SequenceDatabase,
        support_indices: &[usize],
    ) -> bool {
        if self.items.is_empty() {
            return false;
        }
        let first = &self.items[0];
        if first.index == 0 {
            return false; // Cannot extend backward
        }
        let prev_index = first.index - 1;

        for &sid in support_indices {
            if sid >= database.sequences.len() {
                continue;
            }
            let seq = &database.sequences[sid];
            if let Some(item) = seq.item_at(prev_index) {
                // Check if ALL supporting sequences share this item at prev_index
                if support_indices.iter().all(|&i| {
                    if i < database.sequences.len() {
                        database.sequences[i]
                            .item_at(prev_index)
                            .map_or(false, |si| si.value == item.value)
                    } else {
                        true
                    }
                }) {
                    return true;
                }
            }
        }
        false
    }

    /// Forward extension check (analogous to backward).
    pub fn has_forward_extension(
        &self,
        database: &SequenceDatabase,
        support_indices: &[usize],
    ) -> bool {
        if self.items.is_empty() {
            return false;
        }
        let last = self.items.last().unwrap();
        let next_index = last.index + 1;

        for &sid in support_indices {
            if sid >= database.sequences.len() {
                continue;
            }
            let seq = &database.sequences[sid];
            if let Some(item) = seq.item_at(next_index) {
                if support_indices.iter().all(|&i| {
                    if i < database.sequences.len() {
                        database.sequences[i]
                            .item_at(next_index)
                            .map_or(false, |si| si.value == item.value)
                    } else {
                        true
                    }
                }) {
                    return true;
                }
            }
        }
        false
    }
}

// ---------------------------------------------------------------------------
// FrequentSequence -- a Sequence with support information
// ---------------------------------------------------------------------------

/// A sequence together with its support set (the set of database sequences
/// that contain it).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrequentSequence {
    /// The pattern sequence.
    pub sequence: Sequence,
    /// The support (number of database sequences containing this pattern).
    pub support: usize,
    /// Whether this is a closed pattern (no super-sequence with the same support).
    pub is_closed: bool,
}

impl FrequentSequence {
    /// Create a new frequent sequence.
    pub fn new(sequence: Sequence, support: usize) -> Self {
        Self {
            sequence,
            support,
            is_closed: false,
        }
    }
}

// ---------------------------------------------------------------------------
// SequenceDatabase -- the collection of input sequences
// ---------------------------------------------------------------------------

/// A database of sequences used as input to the mining algorithm.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SequenceDatabase {
    /// The sequences in the database.
    pub sequences: Vec<Sequence>,
    /// Metadata for each sequence (e.g., function address).
    pub metadata: Vec<Option<String>>,
    /// Minimum support threshold.
    pub min_support: usize,
}

impl SequenceDatabase {
    /// Create a new sequence database.
    pub fn new(min_support: usize) -> Self {
        Self {
            sequences: Vec::new(),
            metadata: Vec::new(),
            min_support,
        }
    }

    /// Add a sequence to the database.
    pub fn add_sequence(&mut self, seq: Sequence, meta: Option<String>) {
        self.sequences.push(seq);
        self.metadata.push(meta);
    }

    /// Number of sequences in the database.
    pub fn len(&self) -> usize {
        self.sequences.len()
    }

    /// Whether the database is empty.
    pub fn is_empty(&self) -> bool {
        self.sequences.is_empty()
    }

    /// Count the support of a given item across all sequences.
    pub fn count_item_support(&self, item: &SequenceItem) -> usize {
        self.sequences
            .iter()
            .filter(|seq| seq.items.iter().any(|i| i.index == item.index && i.value == item.value))
            .count()
    }

    /// Get all unique items that meet the minimum support threshold.
    pub fn frequent_items(&self) -> Vec<SequenceItem> {
        let mut item_counts: HashMap<(usize, u32), usize> = HashMap::new();
        for seq in &self.sequences {
            for item in &seq.items {
                *item_counts
                    .entry((item.index, item.value))
                    .or_insert(0) += 1;
            }
        }
        let mut items: Vec<SequenceItem> = item_counts
            .into_iter()
            .filter(|(_, count)| *count >= self.min_support)
            .map(|((index, value), _)| SequenceItem::new(index, value))
            .collect();
        items.sort();
        items
    }
}

// ---------------------------------------------------------------------------
// ProjectedDatabase -- prefix-projected database for BIDE
// ---------------------------------------------------------------------------

/// A projected database used internally by the BIDE algorithm.
///
/// Each entry pairs a suffix sequence (the projection) with the index of the
/// original database sequence it came from.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectedDatabase {
    /// Suffix sequences and the database index they came from.
    pub entries: Vec<ProjectedSequenceInfo>,
    /// The prefix pattern this projection is relative to.
    pub prefix: Sequence,
}

/// Information about a single projected sequence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectedSequenceInfo {
    /// Index of the original sequence in the database.
    pub database_index: usize,
    /// The suffix sequence after the prefix match.
    pub suffix: Sequence,
}

impl ProjectedDatabase {
    /// Create a new projected database.
    pub fn new(prefix: Sequence) -> Self {
        Self {
            entries: Vec::new(),
            prefix,
        }
    }

    /// The support of this projected database (= number of entries).
    pub fn support(&self) -> usize {
        self.entries.len()
    }

    /// Get all frequent items in the projected database.
    pub fn frequent_items(&self, min_support: usize) -> Vec<SequenceItem> {
        let mut counts: BTreeMap<(usize, u32), usize> = BTreeMap::new();
        for entry in &self.entries {
            for item in &entry.suffix.items {
                *counts
                    .entry((item.index, item.value))
                    .or_insert(0) += 1;
            }
        }
        counts
            .into_iter()
            .filter(|(_, c)| *c >= min_support)
            .map(|((index, value), _)| SequenceItem::new(index, value))
            .collect()
    }
}

// ---------------------------------------------------------------------------
// ClosedSequenceMiner -- the BIDE algorithm
// ---------------------------------------------------------------------------

/// Closed sequence pattern miner (BIDE algorithm).
///
/// Mines the [`SequenceDatabase`] for all closed sequential patterns that
/// meet the minimum support threshold.
///
/// # Usage
///
/// ```rust
/// use ghidra_features::byte_patterns::*;
///
/// let mut db = SequenceDatabase::new(2);
/// db.add_sequence(Sequence::from_bytes(&[0x55, 0x89, 0xE5]), None);
/// db.add_sequence(Sequence::from_bytes(&[0x55, 0x89, 0xEC]), None);
/// db.add_sequence(Sequence::from_bytes(&[0x55, 0x89, 0xE5]), None);
///
/// let mut miner = ClosedSequenceMiner::new(2);
/// let results = miner.mine(&db);
/// assert!(results.iter().any(|p| p.sequence.len() >= 2));
/// ```
#[derive(Debug)]
pub struct ClosedSequenceMiner {
    /// Minimum support threshold.
    pub min_support: usize,
    /// Maximum pattern length to discover.
    pub max_pattern_length: usize,
}

impl ClosedSequenceMiner {
    /// Create a new miner with the given minimum support.
    pub fn new(min_support: usize) -> Self {
        Self {
            min_support,
            max_pattern_length: 100,
        }
    }

    /// Set the maximum pattern length.
    pub fn with_max_pattern_length(mut self, len: usize) -> Self {
        self.max_pattern_length = len;
        self
    }

    /// Mine the database for closed sequential patterns.
    pub fn mine(&mut self, db: &SequenceDatabase) -> Vec<FrequentSequence> {
        let mut results = Vec::new();
        let frequent_items = db.frequent_items();

        for item in &frequent_items {
            let seq = Sequence::new(vec![item.clone()]);
            let projected = self.project(db, &seq);
            if projected.support() >= self.min_support {
                self.bide_extend(db, &seq, &projected, &mut results);
            }
        }

        results
    }

    /// Project the database onto the given prefix.
    fn project(&self, db: &SequenceDatabase, prefix: &Sequence) -> ProjectedDatabase {
        let mut projected = ProjectedDatabase::new(prefix.clone());

        for (idx, seq) in db.sequences.iter().enumerate() {
            if let Some(suffix) = self.extract_suffix(seq, prefix) {
                projected.entries.push(ProjectedSequenceInfo {
                    database_index: idx,
                    suffix,
                });
            }
        }

        projected
    }

    /// Extract the suffix of `seq` after matching `prefix`.
    fn extract_suffix(&self, seq: &Sequence, prefix: &Sequence) -> Option<Sequence> {
        if prefix.is_empty() {
            return Some(seq.clone());
        }

        // Find the last index in the prefix
        let last_prefix_index = prefix.items.last()?.index;
        let suffix_items: Vec<SequenceItem> = seq
            .items
            .iter()
            .filter(|item| item.index > last_prefix_index)
            .cloned()
            .collect();

        if prefix.is_subsequence_of(seq) {
            Some(Sequence::new(suffix_items))
        } else {
            None
        }
    }

    /// Recursive BIDE extension.
    fn bide_extend(
        &self,
        db: &SequenceDatabase,
        prefix: &Sequence,
        projected: &ProjectedDatabase,
        results: &mut Vec<FrequentSequence>,
    ) {
        if prefix.len() >= self.max_pattern_length {
            return;
        }

        let frequent_items = projected.frequent_items(self.min_support);
        let support_indices: Vec<usize> = projected.entries.iter().map(|e| e.database_index).collect();
        if frequent_items.is_empty() {
            // No more extensions possible. This is a closed pattern if
            // it has no backward or forward extensions.
            if !prefix.has_backward_extension(db, &support_indices)
                && !prefix.has_forward_extension(db, &support_indices)
            {
                results.push(FrequentSequence::new(prefix.clone(), projected.support()));
            }
            return;
        }

        let mut extended = false;
        for item in &frequent_items {
            let mut new_prefix = prefix.clone();
            new_prefix.items.push(item.clone());
            new_prefix.items.sort_by_key(|i| i.index);

            let new_projected = self.project(db, &new_prefix);
            if new_projected.support() >= self.min_support {
                extended = true;
                self.bide_extend(db, &new_prefix, &new_projected, results);
            }
        }

        // If no extensions met the support threshold, this prefix itself is
        // a closed pattern.
        if !extended && !prefix.is_empty() {
            let fs = FrequentSequence::new(prefix.clone(), projected.support());
            results.push(fs);
        }
    }
}

// ---------------------------------------------------------------------------
// SequenceMiningParams
// ---------------------------------------------------------------------------

/// Parameters controlling the sequence mining process.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SequenceMiningParams {
    /// Minimum support (absolute count or ratio, depending on `support_is_ratio`).
    pub min_support: u32,
    /// Whether `min_support` is a ratio (0.0 - 1.0) rather than an absolute count.
    pub support_is_ratio: bool,
    /// Minimum pattern length.
    pub min_pattern_length: usize,
    /// Maximum pattern length.
    pub max_pattern_length: usize,
    /// Only consider byte values that appear at fixed offsets.
    pub fixed_offset_only: bool,
}

impl Default for SequenceMiningParams {
    fn default() -> Self {
        Self {
            min_support: 2,
            support_is_ratio: false,
            min_pattern_length: 1,
            max_pattern_length: 100,
            fixed_offset_only: true,
        }
    }
}

impl SequenceMiningParams {
    /// Compute the effective minimum support given a database size.
    pub fn effective_min_support(&self, db_size: usize) -> usize {
        if self.support_is_ratio {
            ((self.min_support as f64 / 100.0) * db_size as f64).ceil() as usize
        } else {
            self.min_support as usize
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sequence_from_bytes() {
        let seq = Sequence::from_bytes(&[0x55, 0x89, 0xE5]);
        assert_eq!(seq.len(), 3);
        assert_eq!(seq.items[0].value, 0x55);
        assert_eq!(seq.items[0].index, 0);
        assert_eq!(seq.items[2].value, 0xE5);
        assert_eq!(seq.items[2].index, 2);
    }

    #[test]
    fn test_is_subsequence_of() {
        let a = Sequence::new(vec![
            SequenceItem::new(0, 0x55),
            SequenceItem::new(2, 0xE5),
        ]);
        let b = Sequence::from_bytes(&[0x55, 0x89, 0xE5]);
        assert!(a.is_subsequence_of(&b));
        assert!(!b.is_subsequence_of(&a));
    }

    #[test]
    fn test_closed_sequence_miner_basic() {
        let mut db = SequenceDatabase::new(2);
        // Three sequences sharing [0x55 at index 0, 0x89 at index 1]
        db.add_sequence(Sequence::from_bytes(&[0x55, 0x89, 0xE5]), None);
        db.add_sequence(Sequence::from_bytes(&[0x55, 0x89, 0xEC]), None);
        db.add_sequence(Sequence::from_bytes(&[0x55, 0x89, 0xE5]), None);

        let mut miner = ClosedSequenceMiner::new(2);
        let results = miner.mine(&db);

        // Should find at least one pattern containing (index 0 = 0x55)
        assert!(!results.is_empty());
        let has_55 = results.iter().any(|p| {
            p.sequence.items.iter().any(|i| i.index == 0 && i.value == 0x55)
        });
        assert!(has_55, "Should find pattern with byte 0x55 at index 0");
    }

    #[test]
    fn test_closed_sequence_miner_no_frequent_pattern() {
        let mut db = SequenceDatabase::new(10); // very high threshold
        db.add_sequence(Sequence::from_bytes(&[0x01]), None);
        db.add_sequence(Sequence::from_bytes(&[0x02]), None);

        let mut miner = ClosedSequenceMiner::new(10);
        let results = miner.mine(&db);
        assert!(results.is_empty());
    }

    #[test]
    fn test_projected_database_frequent_items() {
        let mut proj = ProjectedDatabase::new(Sequence::new(vec![]));
        proj.entries.push(ProjectedSequenceInfo {
            database_index: 0,
            suffix: Sequence::from_bytes(&[0xAA, 0xBB]),
        });
        proj.entries.push(ProjectedSequenceInfo {
            database_index: 1,
            suffix: Sequence::from_bytes(&[0xAA, 0xCC]),
        });

        let frequent = proj.frequent_items(2);
        // 0xAA appears at index 0 in both entries
        assert!(frequent.iter().any(|i| i.index == 0 && i.value == 0xAA));
        // 0xBB and 0xCC each appear only once
        assert!(!frequent.iter().any(|i| i.value == 0xBB));
        assert!(!frequent.iter().any(|i| i.value == 0xCC));
    }

    #[test]
    fn test_sequence_database_frequent_items() {
        let mut db = SequenceDatabase::new(2);
        db.add_sequence(Sequence::from_bytes(&[0xFF, 0x00]), None);
        db.add_sequence(Sequence::from_bytes(&[0xFF, 0x01]), None);
        db.add_sequence(Sequence::from_bytes(&[0xFE, 0x00]), None);

        let freq = db.frequent_items();
        // 0xFF at index 0 appears in 2 sequences (>= min_support 2)
        assert!(freq.iter().any(|i| i.index == 0 && i.value == 0xFF));
        // 0x00 at index 1 appears in 2 sequences
        assert!(freq.iter().any(|i| i.index == 1 && i.value == 0x00));
        // 0xFE at index 0 appears only once
        assert!(!freq.iter().any(|i| i.index == 0 && i.value == 0xFE));
    }

    #[test]
    fn test_mining_params_effective_support() {
        let params = SequenceMiningParams {
            min_support: 50,
            support_is_ratio: true,
            ..Default::default()
        };
        assert_eq!(params.effective_min_support(100), 50);
        assert_eq!(params.effective_min_support(3), 2); // ceil(1.5) = 2

        let params2 = SequenceMiningParams {
            min_support: 3,
            support_is_ratio: false,
            ..Default::default()
        };
        assert_eq!(params2.effective_min_support(100), 3);
    }

    #[test]
    fn test_sequence_item_at() {
        let seq = Sequence::from_bytes(&[0x10, 0x20, 0x30]);
        assert_eq!(seq.item_at(1).map(|i| i.value), Some(0x20));
        assert!(seq.item_at(5).is_none());
    }

    #[test]
    fn test_sequence_is_empty() {
        let seq = Sequence::new(vec![]);
        assert!(seq.is_empty());
        let seq2 = Sequence::from_bytes(&[0x01]);
        assert!(!seq2.is_empty());
    }
}
