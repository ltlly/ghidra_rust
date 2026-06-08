//! BufferNode — cache management node for BufferMgr.
//!
//! Port of Java `db.buffers.BufferNode`. A `DataBuffer` wrapper that
//! facilitates linking nodes into various doubly-linked lists and tracking
//! status. Linked lists supported include:
//! - Buffer cache
//! - Buffer versions
//! - Checkpoint list

// ============================================================================
// BufferNode
// ============================================================================

/// A `DataBuffer` wrapper for cache management within the buffer manager.
///
/// Port of Java `db.buffers.BufferNode`. Supports doubly-linked list
/// operations for cache management, version tracking, and checkpoint
/// lists. Each node holds a buffer ID, checkpoint number, and a
/// reference to the associated [`DataBuffer`](super::data_buffer::DataBuffer).
#[derive(Debug)]
pub struct BufferNode {
    // ---- Cache list pointers ----
    /// Next node in the cache linked list.
    pub next_cached: Option<usize>,
    /// Previous node in the cache linked list.
    pub prev_cached: Option<usize>,

    // ---- Version list pointers ----
    /// Next node in the version linked list.
    pub next_version: Option<usize>,
    /// Previous node in the version linked list.
    pub prev_version: Option<usize>,

    // ---- Checkpoint list pointers ----
    /// Next node in the checkpoint linked list.
    pub next_in_checkpoint: Option<usize>,
    /// Previous node in the checkpoint linked list.
    pub prev_in_checkpoint: Option<usize>,

    // ---- Identity ----
    /// Buffer ID.
    pub id: i32,
    /// Checkpoint number this node is associated with.
    pub checkpoint: i32,

    // ---- Status ----
    /// DataBuffer index within disk cache.
    /// A value of -1 indicates that buffer has not yet been written to disk cache.
    pub disk_cache_index: i32,
    /// True when the associated buffer has been given out for update.
    pub locked: bool,
    /// True when a buffer has been deleted and is available for re-use.
    pub empty: bool,
    /// True the first time the buffer is modified relative to the source file.
    pub modified: bool,
    /// True when the buffer has been modified since last written to disk cache.
    pub is_dirty: bool,
    /// Snapshot tracking flags for RecoveryMgr.
    pub snapshot_taken: [bool; 2],
}

impl BufferNode {
    /// Construct a new buffer node with the given ID and checkpoint.
    ///
    /// Port of Java `BufferNode(int id, int checkpoint)`.
    pub fn new(id: i32, checkpoint: i32) -> Self {
        Self {
            next_cached: None,
            prev_cached: None,
            next_version: None,
            prev_version: None,
            next_in_checkpoint: None,
            prev_in_checkpoint: None,
            id,
            checkpoint,
            disk_cache_index: -1,
            locked: false,
            empty: false,
            modified: false,
            is_dirty: false,
            snapshot_taken: [false, false],
        }
    }

    /// Clear snapshotTaken flags so that node will be properly retained
    /// by the next recovery snapshot if necessary.
    ///
    /// Port of Java `BufferNode.clearSnapshotTaken()`.
    pub fn clear_snapshot_taken(&mut self) {
        self.snapshot_taken[0] = false;
        self.snapshot_taken[1] = false;
    }
}

// ============================================================================
// Linked list operations (index-based, for use with Vec<BufferNode>)
// ============================================================================

/// Operations for managing a BufferNode within a cache doubly-linked list.
///
/// These functions operate on a `Vec<BufferNode>` pool using indices.
/// The `cache_head` is index 0 (sentinel node).
pub mod cache_list {
    use super::BufferNode;

    /// Unlink this node from the cache list.
    ///
    /// Port of Java `BufferNode.removeFromCache()`.
    /// `nodes` is the pool of all BufferNodes; `idx` is the index of this node.
    pub fn remove_from_cache(nodes: &mut [BufferNode], idx: usize) {
        let prev = nodes[idx].prev_cached;
        let next = nodes[idx].next_cached;
        if let Some(p) = prev {
            nodes[p].next_cached = next;
        }
        if let Some(n) = next {
            nodes[n].prev_cached = prev;
        }
        nodes[idx].next_cached = None;
        nodes[idx].prev_cached = None;
    }

    /// Link this node to the top of the cache list.
    ///
    /// Port of Java `BufferNode.addToCache(BufferNode cacheHead)`.
    /// `cache_head` is the sentinel node index.
    pub fn add_to_cache(nodes: &mut [BufferNode], idx: usize, cache_head: usize) {
        let old_next = nodes[cache_head].next_cached;
        nodes[idx].prev_cached = Some(cache_head);
        nodes[idx].next_cached = old_next;
        if let Some(n) = old_next {
            nodes[n].prev_cached = Some(idx);
        }
        nodes[cache_head].next_cached = Some(idx);
    }
}

/// Operations for managing a BufferNode within a checkpoint doubly-linked list.
pub mod checkpoint_list {
    use super::BufferNode;

    /// Unlink this node from the checkpoint list.
    ///
    /// Port of Java `BufferNode.removeFromCheckpoint()`.
    pub fn remove_from_checkpoint(nodes: &mut [BufferNode], idx: usize) {
        let prev = nodes[idx].prev_in_checkpoint;
        let next = nodes[idx].next_in_checkpoint;
        if let Some(p) = prev {
            nodes[p].next_in_checkpoint = next;
        }
        if let Some(n) = next {
            nodes[n].prev_in_checkpoint = prev;
        }
        nodes[idx].next_in_checkpoint = None;
        nodes[idx].prev_in_checkpoint = None;
    }

    /// Link this node to the top of the checkpoint list.
    ///
    /// Port of Java `BufferNode.addToCheckpoint(BufferNode checkpointHead)`.
    pub fn add_to_checkpoint(nodes: &mut [BufferNode], idx: usize, checkpoint_head: usize) {
        let old_next = nodes[checkpoint_head].next_in_checkpoint;
        nodes[idx].prev_in_checkpoint = Some(checkpoint_head);
        nodes[idx].next_in_checkpoint = old_next;
        if let Some(n) = old_next {
            nodes[n].prev_in_checkpoint = Some(idx);
        }
        nodes[checkpoint_head].next_in_checkpoint = Some(idx);
    }
}

/// Operations for managing a BufferNode within a version doubly-linked list.
pub mod version_list {
    use super::BufferNode;

    /// Unlink this node from the version list.
    ///
    /// Port of Java `BufferNode.removeFromVersion()`.
    pub fn remove_from_version(nodes: &mut [BufferNode], idx: usize) {
        let prev = nodes[idx].prev_version;
        let next = nodes[idx].next_version;
        if let Some(p) = prev {
            nodes[p].next_version = next;
        }
        if let Some(n) = next {
            nodes[n].prev_version = prev;
        }
        nodes[idx].next_version = None;
        nodes[idx].prev_version = None;
    }

    /// Link this node to the top of the version list.
    ///
    /// Port of Java `BufferNode.addToVersion(BufferNode versionHead)`.
    pub fn add_to_version(nodes: &mut [BufferNode], idx: usize, version_head: usize) {
        let old_next = nodes[version_head].next_version;
        nodes[idx].prev_version = Some(version_head);
        nodes[idx].next_version = old_next;
        if let Some(n) = old_next {
            nodes[n].prev_version = Some(idx);
        }
        nodes[version_head].next_version = Some(idx);
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_buffer_node_new() {
        let node = BufferNode::new(42, 3);
        assert_eq!(node.id, 42);
        assert_eq!(node.checkpoint, 3);
        assert_eq!(node.disk_cache_index, -1);
        assert!(!node.locked);
        assert!(!node.empty);
        assert!(!node.modified);
        assert!(!node.is_dirty);
        assert_eq!(node.snapshot_taken, [false, false]);
    }

    #[test]
    fn test_clear_snapshot_taken() {
        let mut node = BufferNode::new(1, 0);
        node.snapshot_taken = [true, true];
        node.clear_snapshot_taken();
        assert_eq!(node.snapshot_taken, [false, false]);
    }

    #[test]
    fn test_cache_list_add_and_remove() {
        // Create a pool: index 0 = sentinel, indices 1..3 = data nodes
        let mut nodes = vec![
            BufferNode::new(-1, 0), // sentinel (cache head)
            BufferNode::new(1, 0),
            BufferNode::new(2, 0),
            BufferNode::new(3, 0),
        ];

        // Add node 1 and 2 to cache
        cache_list::add_to_cache(&mut nodes, 1, 0);
        cache_list::add_to_cache(&mut nodes, 2, 0);

        // Sentinel -> node2 -> node1 -> back to sentinel
        assert_eq!(nodes[0].next_cached, Some(2));
        assert_eq!(nodes[2].next_cached, Some(1));
        assert_eq!(nodes[1].prev_cached, Some(2));

        // Remove node 2
        cache_list::remove_from_cache(&mut nodes, 2);
        assert_eq!(nodes[0].next_cached, Some(1));
        assert_eq!(nodes[1].prev_cached, Some(0));
        assert!(nodes[2].next_cached.is_none());
        assert!(nodes[2].prev_cached.is_none());
    }

    #[test]
    fn test_checkpoint_list_add_and_remove() {
        let mut nodes = vec![
            BufferNode::new(-1, 0), // sentinel
            BufferNode::new(1, 0),
            BufferNode::new(2, 0),
        ];

        checkpoint_list::add_to_checkpoint(&mut nodes, 1, 0);
        checkpoint_list::add_to_checkpoint(&mut nodes, 2, 0);

        assert_eq!(nodes[0].next_in_checkpoint, Some(2));
        assert_eq!(nodes[2].next_in_checkpoint, Some(1));

        checkpoint_list::remove_from_checkpoint(&mut nodes, 2);
        assert_eq!(nodes[0].next_in_checkpoint, Some(1));
        assert!(nodes[2].next_in_checkpoint.is_none());
    }

    #[test]
    fn test_version_list_add_and_remove() {
        let mut nodes = vec![
            BufferNode::new(-1, 0), // sentinel
            BufferNode::new(1, 0),
            BufferNode::new(2, 0),
        ];

        version_list::add_to_version(&mut nodes, 1, 0);
        version_list::add_to_version(&mut nodes, 2, 0);

        assert_eq!(nodes[0].next_version, Some(2));
        assert_eq!(nodes[2].next_version, Some(1));

        version_list::remove_from_version(&mut nodes, 1);
        assert_eq!(nodes[0].next_version, Some(2));
        assert_eq!(nodes[2].next_version, Some(0)); // points back to sentinel
    }
}
