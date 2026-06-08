//! Maps addresses to arbitrary objects using range-based markers.
//!
//! Direct translation of `ghidra.program.model.address.AddressObjectMap`.
//!
//! Provides [`AddressObjectMap`] -- a mapping between addresses in a program
//! and objects that have been discovered. Uses a marker-based scheme where
//! range starts are marked with the object ID and range ends are marked with
//! the negated ID.
//!
//! # Design
//!
//! The map uses a `BTreeMap<u64, Mark>` internally. Each [`Mark`] tracks
//! which object(s) are associated at a given key position. The mark types are:
//! - `Start`: beginning of a range for the object
//! - `End`: end of a range for the object
//! - `Single`: a single-address range for the object
//!
//! Adjacent ranges with the same object are coalesced automatically.

use crate::addr::Address;
use crate::addr::address_map_impl::AddressMapImpl;
use std::collections::BTreeMap;
use std::collections::btree_map::Entry;

// ---------------------------------------------------------------------------
// Mark — internal marker type
// ---------------------------------------------------------------------------

/// Type of mark at a given position.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MarkType {
    /// Beginning of a range.
    Start,
    /// End of a range.
    End,
    /// A single-address range (both start and end).
    Single,
}

/// A marker that associates one or more object IDs with a position.
///
/// Objects are stored as a vector of `usize` IDs. When only one object is
/// present, the `objects` vector has length 1.
#[derive(Debug, Clone)]
struct Mark {
    mark_type: MarkType,
    objects: Vec<usize>,
}

impl Mark {
    /// Create a new mark with a single object.
    fn new(obj_id: usize, mark_type: MarkType) -> Self {
        Self {
            mark_type,
            objects: vec![obj_id],
        }
    }

    /// Add an object to this mark if not already present.
    fn add(&mut self, obj_id: usize) {
        if !self.objects.contains(&obj_id) {
            self.objects.push(obj_id);
        }
    }

    /// Remove an object from this mark.
    fn remove(&mut self, obj_id: usize) {
        self.objects.retain(|&id| id != obj_id);
    }

    /// Returns true if this mark contains the given object.
    fn contains(&self, obj_id: usize) -> bool {
        self.objects.contains(&obj_id)
    }

    /// Returns true if this mark has no objects.
    fn is_empty(&self) -> bool {
        self.objects.is_empty()
    }

    /// Returns true if this mark contains exactly the same objects as another.
    fn contains_same_objects(&self, other: &Mark) -> bool {
        if self.objects.len() != other.objects.len() {
            return false;
        }
        for id in &self.objects {
            if !other.objects.contains(id) {
                return false;
            }
        }
        true
    }
}

// ---------------------------------------------------------------------------
// AddressObjectMap
// ---------------------------------------------------------------------------

/// Maps addresses to objects using range-based markers.
///
/// Corresponds to `ghidra.program.model.address.AddressObjectMap`.
///
/// An address can belong to multiple objects. The map uses an
/// [`AddressMapImpl`] internally to encode addresses as keys, and a
/// `BTreeMap` of markers to track range boundaries.
///
/// # Examples
///
/// ```
/// use ghidra_core::addr::Address;
/// use ghidra_core::addr::address_object_map::AddressObjectMap;
///
/// let mut map = AddressObjectMap::new();
/// let obj_id = 42;
/// map.add_object(obj_id, Address::new(0x100), Address::new(0x200));
///
/// let objects = map.get_objects(Address::new(0x150));
/// assert!(objects.contains(&obj_id));
///
/// let objects = map.get_objects(Address::new(0x300));
/// assert!(objects.is_empty());
/// ```
#[derive(Debug)]
pub struct AddressObjectMap {
    /// Internal address map for encoding/decoding.
    addr_map: AddressMapImpl,
    /// Marker storage: key -> mark.
    markers: BTreeMap<u64, Mark>,
    /// Registry of objects by ID.
    objects: Vec<Box<dyn std::any::Any>>,
}

impl Default for AddressObjectMap {
    fn default() -> Self {
        Self::new()
    }
}

impl AddressObjectMap {
    /// Creates a new empty `AddressObjectMap`.
    pub fn new() -> Self {
        Self {
            addr_map: AddressMapImpl::new(),
            markers: BTreeMap::new(),
            objects: Vec::new(),
        }
    }

    /// Register an object and return its ID.
    pub fn register_object(&mut self, obj: impl std::any::Any + 'static) -> usize {
        let id = self.objects.len();
        self.objects.push(Box::new(obj));
        id
    }

    /// Get the list of object IDs associated with the given address.
    pub fn get_objects(&self, addr: Address) -> Vec<usize> {
        let key = self.encode_key_readonly(addr);
        self.get_obj_ids(key)
    }

    /// Check if a specific object is associated with the given address.
    pub fn has_object(&self, addr: Address, obj_id: usize) -> bool {
        let key = self.encode_key_readonly(addr);
        self.get_obj_ids(key).contains(&obj_id)
    }

    /// Associate the given object ID with the given address range.
    pub fn add_object(&mut self, obj_id: usize, start: Address, end: Address) {
        let start_key = self.encode_key(start);
        let end_key = self.encode_key(end);
        self.add_range(obj_id, start_key, end_key);
        self.coalesce_range(start_key, end_key);
    }

    /// Remove the association of the given object from the given address range.
    pub fn remove_object(&mut self, obj_id: usize, start: Address, end: Address) {
        let start_key = self.encode_key(start);
        let end_key = self.encode_key(end);
        self.remove_range(obj_id, start_key, end_key);
        self.coalesce_range(start_key, end_key);
    }

    /// Returns true if the map has any entries.
    pub fn is_empty(&self) -> bool {
        self.markers.is_empty()
    }

    /// Returns the number of marker entries.
    pub fn len(&self) -> usize {
        self.markers.len()
    }

    // -- Internal helpers --

    /// Encode an address to a key using the internal address map.
    fn encode_key(&mut self, addr: Address) -> u64 {
        self.addr_map.get_key(addr)
    }

    /// Encode an address to a key for read-only operations.
    ///
    /// Uses the same encoding as `encode_key` but does not create new base entries.
    /// Returns the raw offset if no base has been registered for this address.
    fn encode_key_readonly(&self, addr: Address) -> u64 {
        self.addr_map.get_key_readonly(addr).unwrap_or(addr.offset)
    }

    /// Get object IDs at a given key position.
    fn get_obj_ids(&self, key: u64) -> Vec<usize> {
        use std::collections::HashSet;

        // Check if there's a mark at this exact key
        if let Some(mark) = self.markers.get(&key) {
            match mark.mark_type {
                MarkType::Start | MarkType::Single => {
                    return mark.objects.clone();
                }
                MarkType::End => {
                    // The address is at the end of a range; still part of it
                    return mark.objects.clone();
                }
            }
        }

        // No mark at this key; scan all preceding marks to find active ranges.
        // Track which objects have been "opened" (Start) and not yet "closed" (End).
        let mut active: HashSet<usize> = HashSet::new();
        for (_, mark) in self.markers.range(..key) {
            match mark.mark_type {
                MarkType::Start => {
                    for &obj in &mark.objects {
                        active.insert(obj);
                    }
                }
                MarkType::End => {
                    for &obj in &mark.objects {
                        active.remove(&obj);
                    }
                }
                MarkType::Single => {
                    // Single-address range; not active at a later key
                }
            }
        }

        active.into_iter().collect()
    }

    /// Add a range [start_key, end_key] for the given object.
    fn add_range(&mut self, obj_id: usize, start_key: u64, end_key: u64) {
        if start_key == end_key {
            // Single address
            match self.markers.entry(start_key) {
                Entry::Occupied(mut e) => {
                    let mark = e.get_mut();
                    mark.add(obj_id);
                    if mark.mark_type == MarkType::End {
                        mark.mark_type = MarkType::Single;
                    }
                }
                Entry::Vacant(e) => {
                    e.insert(Mark::new(obj_id, MarkType::Single));
                }
            }
        } else {
            // Start mark
            match self.markers.entry(start_key) {
                Entry::Occupied(mut e) => {
                    let mark = e.get_mut();
                    mark.add(obj_id);
                    if mark.mark_type == MarkType::End {
                        mark.mark_type = MarkType::Single;
                    } else if mark.mark_type == MarkType::Single {
                        mark.mark_type = MarkType::Start;
                    }
                }
                Entry::Vacant(e) => {
                    e.insert(Mark::new(obj_id, MarkType::Start));
                }
            }

            // End mark
            match self.markers.entry(end_key) {
                Entry::Occupied(mut e) => {
                    let mark = e.get_mut();
                    mark.add(obj_id);
                    if mark.mark_type == MarkType::Start {
                        mark.mark_type = MarkType::Single;
                    } else if mark.mark_type == MarkType::Single {
                        mark.mark_type = MarkType::End;
                    }
                }
                Entry::Vacant(e) => {
                    e.insert(Mark::new(obj_id, MarkType::End));
                }
            }
        }
    }

    /// Remove an object from range [start_key, end_key].
    ///
    /// This properly handles partial range removal by splitting existing ranges.
    fn remove_range(&mut self, obj_id: usize, start_key: u64, end_key: u64) {
        // Find all existing ranges for this object that overlap [start_key, end_key].
        // We need to handle: full containment, partial overlap from left/right, and split.
        let overlapping: Vec<(u64, MarkType)> = self
            .markers
            .iter()
            .filter(|(_, mark)| mark.contains(obj_id))
            .map(|(&k, mark)| (k, mark.mark_type))
            .collect();

        // Build a list of (range_start, range_end) for all ranges of this object
        let mut ranges: Vec<(u64, u64)> = Vec::new();
        let mut i = 0;
        while i < overlapping.len() {
            match overlapping[i].1 {
                MarkType::Start => {
                    let rs = overlapping[i].0;
                    // Find matching End
                    let mut depth = 1;
                    let mut j = i + 1;
                    while j < overlapping.len() && depth > 0 {
                        match overlapping[j].1 {
                            MarkType::Start => depth += 1,
                            MarkType::End => depth -= 1,
                            MarkType::Single => {}
                        }
                        j += 1;
                    }
                    if depth == 0 {
                        ranges.push((rs, overlapping[j - 1].0));
                    }
                    i = j;
                }
                MarkType::Single => {
                    ranges.push((overlapping[i].0, overlapping[i].0));
                    i += 1;
                }
                MarkType::End => {
                    i += 1;
                }
            }
        }

        // For each overlapping range, remove the original and re-add the non-removed parts
        for (rs, re) in ranges {
            // Check if this range overlaps [start_key, end_key]
            if re < start_key || rs > end_key {
                continue;
            }

            // Remove the original range's marks for this object
            self.remove_marks_for_object(obj_id, rs, re);

            // Re-add the left part (before the removal range)
            if rs < start_key {
                self.add_range(obj_id, rs, start_key - 1);
            }

            // Re-add the right part (after the removal range)
            if re > end_key {
                self.add_range(obj_id, end_key + 1, re);
            }
        }
    }

    /// Remove all marks for a specific object in a given key range.
    fn remove_marks_for_object(&mut self, obj_id: usize, start_key: u64, end_key: u64) {
        let keys: Vec<u64> = self
            .markers
            .range(start_key..=end_key)
            .filter(|(_, mark)| mark.contains(obj_id))
            .map(|(&k, _)| k)
            .collect();

        for key in keys {
            if let Some(mark) = self.markers.get_mut(&key) {
                mark.remove(obj_id);
                if mark.is_empty() {
                    self.markers.remove(&key);
                }
            }
        }
    }

    /// Coalesce adjacent markers with the same objects.
    fn coalesce_range(&mut self, start_key: u64, end_key: u64) {
        // Collect keys to check for coalescing
        let keys: Vec<u64> = self
            .markers
            .range(start_key..=end_key)
            .map(|(&k, _)| k)
            .collect();

        for key in keys {
            self.coalesce_at(key);
        }
    }

    /// Try to coalesce the mark at `key` with its neighbors.
    fn coalesce_at(&mut self, key: u64) {
        // Check with predecessor
        let prev_key = key.checked_sub(1);
        if let Some(pk) = prev_key {
            if self.markers.contains_key(&pk) && self.markers.contains_key(&key) {
                let same_objects = {
                    let a = &self.markers[&pk];
                    let b = &self.markers[&key];
                    a.contains_same_objects(b)
                };
                if same_objects {
                    let f_type = self.markers[&pk].mark_type;
                    let s_type = self.markers[&key].mark_type;
                    match (f_type, s_type) {
                        (MarkType::End, MarkType::Start) => {
                            self.markers.remove(&pk);
                            self.markers.remove(&key);
                            // Need to re-add as a combined range
                            // The Start and End cancel out; nothing to do
                        }
                        (MarkType::End, MarkType::Single) => {
                            self.markers.remove(&pk);
                            if let Some(mark) = self.markers.get_mut(&key) {
                                mark.mark_type = MarkType::End;
                            }
                        }
                        (MarkType::Single, MarkType::Single) => {
                            if let Some(mark) = self.markers.get_mut(&pk) {
                                mark.mark_type = MarkType::Start;
                            }
                            if let Some(mark) = self.markers.get_mut(&key) {
                                mark.mark_type = MarkType::End;
                            }
                        }
                        (MarkType::Single, MarkType::Start) => {
                            self.markers.remove(&key);
                            if let Some(mark) = self.markers.get_mut(&pk) {
                                mark.mark_type = MarkType::Start;
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_and_get_single_address() {
        let mut map = AddressObjectMap::new();
        map.add_object(1, Address::new(0x100), Address::new(0x100));
        let objs = map.get_objects(Address::new(0x100));
        assert_eq!(objs, vec![1]);
    }

    #[test]
    fn test_add_range() {
        let mut map = AddressObjectMap::new();
        map.add_object(42, Address::new(0x100), Address::new(0x200));

        // Inside range
        let objs = map.get_objects(Address::new(0x150));
        assert_eq!(objs, vec![42]);

        // At start
        let objs = map.get_objects(Address::new(0x100));
        assert_eq!(objs, vec![42]);

        // At end
        let objs = map.get_objects(Address::new(0x200));
        assert_eq!(objs, vec![42]);

        // Outside range
        let objs = map.get_objects(Address::new(0x300));
        assert!(objs.is_empty());
    }

    #[test]
    fn test_remove_object() {
        let mut map = AddressObjectMap::new();
        map.add_object(1, Address::new(0x100), Address::new(0x200));
        map.remove_object(1, Address::new(0x100), Address::new(0x200));

        let objs = map.get_objects(Address::new(0x150));
        assert!(objs.is_empty());
    }

    #[test]
    fn test_multiple_objects_at_same_range() {
        let mut map = AddressObjectMap::new();
        map.add_object(1, Address::new(0x100), Address::new(0x200));
        map.add_object(2, Address::new(0x100), Address::new(0x200));

        let objs = map.get_objects(Address::new(0x150));
        assert!(objs.contains(&1));
        assert!(objs.contains(&2));
    }

    #[test]
    fn test_overlapping_ranges() {
        let mut map = AddressObjectMap::new();
        map.add_object(1, Address::new(0x100), Address::new(0x300));
        map.add_object(2, Address::new(0x200), Address::new(0x400));

        // Only object 1
        let objs = map.get_objects(Address::new(0x150));
        assert_eq!(objs, vec![1]);

        // Both objects
        let objs = map.get_objects(Address::new(0x250));
        assert!(objs.contains(&1));
        assert!(objs.contains(&2));

        // Only object 2
        let objs = map.get_objects(Address::new(0x350));
        assert_eq!(objs, vec![2]);
    }

    #[test]
    fn test_is_empty_and_len() {
        let mut map = AddressObjectMap::new();
        assert!(map.is_empty());
        map.add_object(1, Address::new(0x100), Address::new(0x200));
        assert!(!map.is_empty());
        assert!(map.len() > 0);
    }

    #[test]
    fn test_has_object() {
        let mut map = AddressObjectMap::new();
        map.add_object(1, Address::new(0x100), Address::new(0x200));
        assert!(map.has_object(Address::new(0x150), 1));
        assert!(!map.has_object(Address::new(0x150), 2));
        assert!(!map.has_object(Address::new(0x300), 1));
    }

    #[test]
    fn test_remove_partial_range() {
        let mut map = AddressObjectMap::new();
        map.add_object(1, Address::new(0x100), Address::new(0x400));
        map.remove_object(1, Address::new(0x200), Address::new(0x300));

        // Still present at start
        let objs = map.get_objects(Address::new(0x150));
        assert_eq!(objs, vec![1]);

        // Removed in middle
        let objs = map.get_objects(Address::new(0x250));
        assert!(objs.is_empty());

        // Still present at end
        let objs = map.get_objects(Address::new(0x350));
        assert_eq!(objs, vec![1]);
    }

    #[test]
    fn test_default_is_empty() {
        let map = AddressObjectMap::default();
        assert!(map.is_empty());
    }

    #[test]
    fn test_sequential_single_addresses() {
        let mut map = AddressObjectMap::new();
        map.add_object(1, Address::new(0x100), Address::new(0x100));
        map.add_object(1, Address::new(0x101), Address::new(0x101));
        map.add_object(1, Address::new(0x102), Address::new(0x102));

        assert!(map.has_object(Address::new(0x100), 1));
        assert!(map.has_object(Address::new(0x101), 1));
        assert!(map.has_object(Address::new(0x102), 1));
    }
}
