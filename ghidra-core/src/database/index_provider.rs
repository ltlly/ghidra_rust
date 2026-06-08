//! IndexProvider — free index management for BufferFile.
//!
//! Port of Java `db.buffers.IndexProvider`. Maintains the free index list
//! associated with a BufferFile. Exhausts the free index list before
//! allocating new indexes.

// ============================================================================
// IndexProvider
// ============================================================================

/// Maintains the free index list associated with a BufferFile.
///
/// Port of Java `db.buffers.IndexProvider`. This provider will exhaust the
/// free index list before allocating new indexes. It relies on the BufferFile
/// growing automatically when buffers having indexes beyond the end-of-file
/// are written.
#[derive(Debug, Clone)]
pub struct IndexProvider {
    /// Next index to allocate when free list is empty.
    next_index: i32,
    /// Stack of free indexes available for reuse.
    free_index_stack: Vec<i32>,
}

impl IndexProvider {
    /// Constructor for an empty BufferFile.
    ///
    /// Port of Java `IndexProvider()`.
    pub fn new() -> Self {
        Self {
            next_index: 0,
            free_index_stack: Vec::new(),
        }
    }

    /// Constructor with initial state.
    ///
    /// Port of Java `IndexProvider(int indexCount, int[] freeIndexes)`.
    pub fn with_state(index_count: i32, free_indexes: &[i32]) -> Self {
        let mut stack = Vec::with_capacity(free_indexes.len());
        for &idx in free_indexes {
            stack.push(idx);
        }
        Self {
            next_index: index_count,
            free_index_stack: stack,
        }
    }

    /// Return the total number of buffer indexes which have been allocated.
    ///
    /// Port of Java `IndexProvider.getIndexCount()`.
    pub fn get_index_count(&self) -> i32 {
        self.next_index
    }

    /// Returns the number of free indexes within the allocated index space.
    ///
    /// Port of Java `IndexProvider.getFreeIndexCount()`.
    pub fn get_free_index_count(&self) -> usize {
        self.free_index_stack.len()
    }

    /// Allocate a new buffer index. Exhaust free list before increasing
    /// total index count.
    ///
    /// Port of Java `IndexProvider.allocateIndex()`.
    /// Returns the assigned index.
    pub fn allocate_index(&mut self) -> i32 {
        match self.free_index_stack.pop() {
            Some(idx) => idx,
            None => {
                let idx = self.next_index;
                self.next_index += 1;
                idx
            }
        }
    }

    /// Allocate a specific index. Current index count will be adjusted if
    /// the specified index exceeds current index count.
    ///
    /// Port of Java `IndexProvider.allocateIndex(int)`.
    /// Returns true if index was successfully allocated.
    pub fn allocate_specific_index(&mut self, index: i32) -> bool {
        if index >= self.next_index {
            // Increase index count, pushing intermediate indexes onto free stack
            for i in self.next_index..index {
                self.free_index_stack.push(i);
            }
            self.next_index = index + 1;
            return true;
        }

        // Try to remove from free list
        if let Some(pos) = self.free_index_stack.iter().position(|&x| x == index) {
            self.free_index_stack.swap_remove(pos);
            return true;
        }
        false
    }

    /// Check if a specific index is free.
    ///
    /// Port of Java `IndexProvider.isFree(int)`.
    pub fn is_free(&self, index: i32) -> bool {
        self.free_index_stack.contains(&index)
    }

    /// Free the specified buffer index.
    ///
    /// Port of Java `IndexProvider.freeIndex(int)`.
    pub fn free_index(&mut self, index: i32) {
        self.free_index_stack.push(index);
    }

    /// Truncate this buffer file. Has no effect if the specified new index
    /// count is greater than the current index count.
    ///
    /// Port of Java `IndexProvider.truncate(int)`.
    /// Returns true if successful, false if newIndexCnt is larger than current count.
    pub fn truncate(&mut self, new_index_cnt: i32) -> bool {
        if new_index_cnt >= self.next_index {
            return false;
        }
        self.next_index = new_index_cnt;

        // Remove free indexes which have been lost
        self.free_index_stack.retain(|&idx| idx < new_index_cnt);
        true
    }

    /// Returns the current list of free indexes.
    ///
    /// Port of Java `IndexProvider.getFreeIndexes()`.
    pub fn get_free_indexes(&self) -> Vec<i32> {
        self.free_index_stack.clone()
    }
}

impl Default for IndexProvider {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_provider() {
        let mut provider = IndexProvider::new();
        assert_eq!(provider.get_index_count(), 0);
        assert_eq!(provider.get_free_index_count(), 0);

        let idx = provider.allocate_index();
        assert_eq!(idx, 0);
        assert_eq!(provider.get_index_count(), 1);

        let idx = provider.allocate_index();
        assert_eq!(idx, 1);
        assert_eq!(provider.get_index_count(), 2);
    }

    #[test]
    fn test_with_state() {
        let provider = IndexProvider::with_state(5, &[1, 3]);
        assert_eq!(provider.get_index_count(), 5);
        assert_eq!(provider.get_free_index_count(), 2);
        assert!(provider.is_free(1));
        assert!(provider.is_free(3));
        assert!(!provider.is_free(0));
        assert!(!provider.is_free(2));
    }

    #[test]
    fn test_allocate_from_free_list() {
        let mut provider = IndexProvider::with_state(5, &[1, 3]);
        let idx = provider.allocate_index();
        // Should pop from free list (LIFO: 3)
        assert_eq!(idx, 3);
        assert_eq!(provider.get_free_index_count(), 1);
    }

    #[test]
    fn test_allocate_specific_index() {
        let mut provider = IndexProvider::new();
        assert!(provider.allocate_specific_index(5));
        assert_eq!(provider.get_index_count(), 6);
        // Indexes 0-4 should be in free list
        assert_eq!(provider.get_free_index_count(), 5);
        assert!(provider.is_free(0));
        assert!(provider.is_free(4));
        assert!(!provider.is_free(5));
    }

    #[test]
    fn test_allocate_specific_already_allocated() {
        let mut provider = IndexProvider::with_state(5, &[2]);
        assert!(provider.allocate_specific_index(2));
        assert_eq!(provider.get_free_index_count(), 0);
    }

    #[test]
    fn test_allocate_specific_not_free() {
        let mut provider = IndexProvider::with_state(5, &[]);
        assert!(!provider.allocate_specific_index(3));
    }

    #[test]
    fn test_free_index() {
        let mut provider = IndexProvider::with_state(5, &[]);
        provider.free_index(2);
        assert_eq!(provider.get_free_index_count(), 1);
        assert!(provider.is_free(2));
    }

    #[test]
    fn test_truncate() {
        let mut provider = IndexProvider::with_state(10, &[3, 7, 9]);
        assert!(provider.truncate(8));
        assert_eq!(provider.get_index_count(), 8);
        assert_eq!(provider.get_free_index_count(), 2); // 9 removed
        assert!(provider.is_free(3));
        assert!(provider.is_free(7));
        assert!(!provider.is_free(9));
    }

    #[test]
    fn test_truncate_no_effect() {
        let mut provider = IndexProvider::with_state(5, &[]);
        assert!(!provider.truncate(10));
        assert_eq!(provider.get_index_count(), 5);
    }

    #[test]
    fn test_get_free_indexes() {
        let provider = IndexProvider::with_state(5, &[1, 3]);
        let free = provider.get_free_indexes();
        assert_eq!(free.len(), 2);
        assert!(free.contains(&1));
        assert!(free.contains(&3));
    }

    #[test]
    fn test_sequential_allocation() {
        let mut provider = IndexProvider::new();
        for i in 0..100 {
            assert_eq!(provider.allocate_index(), i);
        }
        assert_eq!(provider.get_index_count(), 100);
    }

    #[test]
    fn test_free_and_reallocate() {
        let mut provider = IndexProvider::new();
        let idx0 = provider.allocate_index();
        let idx1 = provider.allocate_index();
        assert_eq!(idx0, 0);
        assert_eq!(idx1, 1);

        provider.free_index(0);
        assert!(provider.is_free(0));

        let idx2 = provider.allocate_index();
        assert_eq!(idx2, 0); // reuses freed index
    }
}
