//! ChangeMap — bitmap tracking which buffers have been modified.
//!
//! Port of Java `db.buffers.ChangeMap`. Facilitates the decoding of
//! change-data to determine if a specific buffer was modified by the
//! corresponding buffer file version.

// ============================================================================
// ChangeMap
// ============================================================================

/// A bitmap that tracks which buffers have been modified between versions.
///
/// Port of Java `db.buffers.ChangeMap`. Each bit in the map corresponds
/// to a buffer index. A set bit indicates the buffer was modified.
#[derive(Debug, Clone)]
pub struct ChangeMap {
    /// Raw bitmap data.
    map_data: Vec<u8>,
    /// Maximum valid index (derived from map_data length).
    max_index: i32,
}

impl ChangeMap {
    /// Create a new ChangeMap from raw map data.
    ///
    /// Port of Java `ChangeMap(byte[] mapData)`.
    pub fn new(map_data: Vec<u8>) -> Self {
        let max_index = (map_data.len() as i32 * 8) - 1;
        Self { map_data, max_index }
    }

    /// Create a new ChangeMap with the given capacity (in bits).
    pub fn with_capacity(num_bits: usize) -> Self {
        let num_bytes = (num_bits + 7) / 8;
        let max_index = (num_bytes as i32 * 8) - 1;
        Self {
            map_data: vec![0u8; num_bytes],
            max_index,
        }
    }

    /// Get the underlying change map data as a byte slice.
    ///
    /// Port of Java `ChangeMap.getData()`.
    pub fn get_data(&self) -> &[u8] {
        &self.map_data
    }

    /// Get the underlying change map data as a mutable byte slice.
    pub fn get_data_mut(&mut self) -> &mut [u8] {
        &mut self.map_data
    }

    /// Add the specified map data to this map (bitwise OR) within the
    /// size constraints of this map.
    ///
    /// Port of Java `ChangeMap.addChangeMapData(byte[])`.
    pub fn add_change_map_data(&mut self, other_map_data: &[u8]) {
        let limit = self.map_data.len().min(other_map_data.len());
        for byte_offset in 0..limit {
            self.map_data[byte_offset] |= other_map_data[byte_offset];
        }
    }

    /// Flag all specified indexes as changed within this change map.
    /// Index values outside the size constraints of this map are ignored.
    ///
    /// Port of Java `ChangeMap.setChangedIndexes(int[])`.
    pub fn set_changed_indexes(&mut self, indexes: &[i32]) {
        for &index in indexes {
            if index > self.max_index {
                continue;
            }
            let byte_offset = (index / 8) as usize;
            let bit_mask = 1u8 << (index % 8);
            self.map_data[byte_offset] |= bit_mask;
        }
    }

    /// Flag all specified indexes as unchanged within this change map.
    /// Index values outside the size constraints of this map are ignored.
    ///
    /// Port of Java `ChangeMap.setUnchangedIndexes(int[])`.
    pub fn set_unchanged_indexes(&mut self, indexes: &[i32]) {
        for &index in indexes {
            if index > self.max_index {
                continue;
            }
            let byte_offset = (index / 8) as usize;
            let bit_mask = !(1u8 << (index % 8));
            self.map_data[byte_offset] &= bit_mask;
        }
    }

    /// Returns true if the change map data indicates that the specified
    /// buffer has been modified.
    ///
    /// Port of Java `ChangeMap.hasChanged(int)`.
    /// If the map data is null or the index is out of bounds, returns true
    /// (must be a new buffer index).
    pub fn has_changed(&self, index: i32) -> bool {
        if index > self.max_index {
            return true; // must be a new buffer index
        }
        let byte_offset = (index / 8) as usize;
        let bit_mask = 1u8 << (index % 8);
        (self.map_data[byte_offset] & bit_mask) != 0
    }

    /// Returns true if the specified index is within the bounds of this map.
    ///
    /// Port of Java `ChangeMap.containsIndex(int)`.
    pub fn contains_index(&self, index: i32) -> bool {
        index <= self.max_index
    }

    /// Get the capacity of this map in bits.
    pub fn capacity(&self) -> usize {
        self.map_data.len() * 8
    }

    /// Count the number of changed bits in this map.
    pub fn count_changed(&self) -> u32 {
        self.map_data.iter().map(|b| b.count_ones()).sum()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_change_map() {
        let map = ChangeMap::new(vec![0u8; 4]);
        assert_eq!(map.capacity(), 32);
        assert!(map.contains_index(0));
        assert!(map.contains_index(31));
        assert!(!map.contains_index(32));
    }

    #[test]
    fn test_with_capacity() {
        let map = ChangeMap::with_capacity(10);
        assert_eq!(map.capacity(), 16); // 2 bytes = 16 bits
        assert!(map.contains_index(9));
        assert!(!map.contains_index(16));
    }

    #[test]
    fn test_set_and_check_changed() {
        let mut map = ChangeMap::with_capacity(32);
        assert!(!map.has_changed(0));
        assert!(!map.has_changed(15));

        map.set_changed_indexes(&[0, 5, 15, 31]);
        assert!(map.has_changed(0));
        assert!(map.has_changed(5));
        assert!(map.has_changed(15));
        assert!(map.has_changed(31));
        assert!(!map.has_changed(1));
        assert!(!map.has_changed(16));
    }

    #[test]
    fn test_set_unchanged() {
        let mut map = ChangeMap::with_capacity(32);
        map.set_changed_indexes(&[0, 5, 15]);
        assert!(map.has_changed(5));

        map.set_unchanged_indexes(&[5]);
        assert!(!map.has_changed(5));
        assert!(map.has_changed(0));
        assert!(map.has_changed(15));
    }

    #[test]
    fn test_out_of_bounds_is_changed() {
        let map = ChangeMap::with_capacity(16);
        assert!(map.has_changed(100)); // out of bounds => true
        assert!(!map.contains_index(100));
    }

    #[test]
    fn test_add_change_map_data() {
        let mut map1 = ChangeMap::with_capacity(16);
        let mut map2 = ChangeMap::with_capacity(16);

        map1.set_changed_indexes(&[0, 1]);
        map2.set_changed_indexes(&[1, 2]);

        map1.add_change_map_data(map2.get_data());
        assert!(map1.has_changed(0));
        assert!(map1.has_changed(1));
        assert!(map1.has_changed(2));
        assert!(!map1.has_changed(3));
    }

    #[test]
    fn test_add_change_map_data_different_sizes() {
        let mut map1 = ChangeMap::with_capacity(8);
        let mut map2 = ChangeMap::with_capacity(16);

        map2.set_changed_indexes(&[0, 5, 12]);
        map1.add_change_map_data(map2.get_data());

        // Only first byte is merged
        assert!(map1.has_changed(0));
        assert!(map1.has_changed(5));
        assert!(!map1.has_changed(12)); // out of range for map1
    }

    #[test]
    fn test_count_changed() {
        let mut map = ChangeMap::with_capacity(16);
        assert_eq!(map.count_changed(), 0);

        map.set_changed_indexes(&[0, 3, 7, 8, 15]);
        assert_eq!(map.count_changed(), 5);
    }

    #[test]
    fn test_get_data() {
        let mut map = ChangeMap::with_capacity(8);
        map.set_changed_indexes(&[0, 7]);
        assert_eq!(map.get_data(), &[0x81]); // bits 0 and 7
    }

    #[test]
    fn test_complex_scenario() {
        let mut map = ChangeMap::with_capacity(64);

        // Simulate buffer modifications
        for i in 0..64 {
            if i % 3 == 0 {
                map.set_changed_indexes(&[i]);
            }
        }

        for i in 0..64 {
            if i % 3 == 0 {
                assert!(map.has_changed(i), "Expected index {} to be changed", i);
            } else {
                assert!(!map.has_changed(i), "Expected index {} to be unchanged", i);
            }
        }

        // Clear some
        map.set_unchanged_indexes(&[0, 3, 6]);
        assert!(!map.has_changed(0));
        assert!(!map.has_changed(3));
        assert!(!map.has_changed(6));
        assert!(map.has_changed(9));
    }
}
