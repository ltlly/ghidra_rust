//! ProgramCache -- time-based LRU caching for programs.
//!
//! Ported from `ghidra.app.plugin.core.progmgr.ProgramCache`.
//!
//! Programs are expensive to open.  When a program is closed by the
//! user, it is placed in a time-based cache so that reopening it is
//! fast.  Entries expire after a configurable duration and the cache
//! has a maximum capacity.

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

use super::ProgramLocator;

/// A cached program entry.
#[derive(Debug)]
struct CacheEntry<P> {
    /// The cached program.
    program: P,
    /// The locator key.
    locator: ProgramLocator,
    /// When this entry was last accessed.
    last_accessed: Instant,
    /// Consumer count (the cache itself counts as one consumer).
    consumer_count: usize,
}

/// Time-based LRU cache for programs.
///
/// Programs are keyed by [`ProgramLocator`].  The cache automatically
/// evicts entries that have not been accessed within the configured
/// duration, and also evicts the least-recently-used entry when the
/// cache exceeds its capacity.
///
/// The generic parameter `P` represents the program type (e.g.,
/// `Arc<ProgramDB>` in the full implementation).
///
/// # Examples
///
/// ```rust
/// use std::time::Duration;
/// use ghidra_features::progmgr::{ProgramCache, ProgramLocator};
///
/// let mut cache: ProgramCache<String> = ProgramCache::new(
///     Duration::from_secs(300), // 5 minutes
///     10,                       // max 10 entries
/// );
///
/// let loc = ProgramLocator::from_path("/test/program.gzf");
/// cache.put(loc.clone(), "program_data".to_string());
/// assert!(cache.get(&loc));
/// ```
#[derive(Debug)]
pub struct ProgramCache<P> {
    /// Maximum number of cached programs.
    capacity: usize,
    /// Duration before an entry expires without access.
    duration: Duration,
    /// The cache entries, keyed by ProgramLocator.
    entries: HashMap<ProgramLocator, CacheEntry<P>>,
    /// LRU ordering: most recently used at the back.
    lru_order: VecDeque<ProgramLocator>,
}

impl<P> ProgramCache<P> {
    /// Create a new ProgramCache with the given duration and capacity.
    pub fn new(duration: Duration, capacity: usize) -> Self {
        Self {
            capacity,
            duration,
            entries: HashMap::new(),
            lru_order: VecDeque::new(),
        }
    }

    /// Set the cache capacity.
    pub fn set_capacity(&mut self, capacity: usize) {
        self.capacity = capacity;
        self.evict_to_capacity();
    }

    /// Returns the cache capacity.
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Set the cache duration.
    pub fn set_duration(&mut self, duration: Duration) {
        self.duration = duration;
        self.evict_expired();
    }

    /// Returns the cache duration.
    pub fn duration(&self) -> Duration {
        self.duration
    }

    /// Returns the number of entries in the cache.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` if the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Check if the cache contains an entry for the given locator.
    pub fn contains(&self, locator: &ProgramLocator) -> bool {
        self.entries.contains_key(locator)
    }

    /// Get a program from the cache.
    ///
    /// Returns `true` if the entry exists and has not expired.
    /// Accessing the entry resets its expiration timer.
    pub fn get(&mut self, locator: &ProgramLocator) -> bool {
        self.evict_expired();

        if let Some(entry) = self.entries.get_mut(locator) {
            entry.last_accessed = Instant::now();
            self.touch_lru(locator.clone());
            true
        } else {
            false
        }
    }

    /// Get a reference to a cached program.
    ///
    /// Returns the program reference if it exists and has not expired.
    pub fn get_ref(&self, locator: &ProgramLocator) -> Option<&P> {
        self.entries.get(locator).map(|e| &e.program)
    }

    /// Put a program into the cache.
    ///
    /// If the cache is full, the least-recently-used entry is evicted.
    pub fn put(&mut self, locator: ProgramLocator, program: P) {
        self.evict_expired();

        // If already exists, just update
        if self.entries.contains_key(&locator) {
            if let Some(entry) = self.entries.get_mut(&locator) {
                entry.program = program;
                entry.last_accessed = Instant::now();
                self.touch_lru(locator);
                return;
            }
        }

        // Evict if at capacity
        while self.entries.len() >= self.capacity {
            self.evict_lru();
        }

        let entry = CacheEntry {
            program,
            locator: locator.clone(),
            last_accessed: Instant::now(),
            consumer_count: 1, // cache itself is a consumer
        };
        self.entries.insert(locator.clone(), entry);
        self.lru_order.push_back(locator);
    }

    /// Remove an entry from the cache.
    pub fn remove(&mut self, locator: &ProgramLocator) -> Option<P> {
        self.lru_order.retain(|l| l != locator);
        self.entries.remove(locator).map(|e| e.program)
    }

    /// Clear all entries from the cache.
    pub fn clear(&mut self) {
        self.entries.clear();
        self.lru_order.clear();
    }

    /// Returns all cached locator keys.
    pub fn keys(&self) -> Vec<&ProgramLocator> {
        self.entries.keys().collect()
    }

    /// Returns the consumer count for the given locator.
    pub fn consumer_count(&self, locator: &ProgramLocator) -> usize {
        self.entries
            .get(locator)
            .map(|e| e.consumer_count)
            .unwrap_or(0)
    }

    /// Increment the consumer count for a cached program.
    pub fn add_consumer(&mut self, locator: &ProgramLocator) {
        if let Some(entry) = self.entries.get_mut(locator) {
            entry.consumer_count += 1;
        }
    }

    /// Decrement the consumer count.  If it reaches zero, the entry
    /// should be removed by the caller (the program would be closed).
    pub fn release_consumer(&mut self, locator: &ProgramLocator) -> usize {
        if let Some(entry) = self.entries.get_mut(locator) {
            if entry.consumer_count > 0 {
                entry.consumer_count -= 1;
            }
            entry.consumer_count
        } else {
            0
        }
    }

    // ------------------------------------------------------------------
    // Internal
    // ------------------------------------------------------------------

    /// Evict entries that have expired.
    fn evict_expired(&mut self) {
        let now = Instant::now();
        let expired: Vec<ProgramLocator> = self
            .entries
            .iter()
            .filter(|(_, entry)| now.duration_since(entry.last_accessed) > self.duration)
            .map(|(loc, _)| loc.clone())
            .collect();

        for loc in expired {
            self.entries.remove(&loc);
            self.lru_order.retain(|l| l != &loc);
        }
    }

    /// Evict the least recently used entry.
    fn evict_lru(&mut self) {
        if let Some(oldest) = self.lru_order.pop_front() {
            self.entries.remove(&oldest);
        }
    }

    /// Evict entries until we are at or below capacity.
    fn evict_to_capacity(&mut self) {
        while self.entries.len() > self.capacity {
            self.evict_lru();
        }
    }

    /// Move a locator to the back of the LRU order (most recently used).
    fn touch_lru(&mut self, locator: ProgramLocator) {
        self.lru_order.retain(|l| l != &locator);
        self.lru_order.push_back(locator);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn test_basic_put_get() {
        let mut cache = ProgramCache::new(Duration::from_secs(60), 10);
        let loc = ProgramLocator::from_path("/test");

        cache.put(loc.clone(), "data".to_string());
        assert!(cache.get(&loc));
        assert_eq!(cache.get_ref(&loc), Some(&"data".to_string()));
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn test_not_found() {
        let mut cache: ProgramCache<i32> = ProgramCache::new(Duration::from_secs(60), 10);
        let loc = ProgramLocator::from_path("/missing");
        assert!(!cache.get(&loc));
        assert!(cache.get_ref(&loc).is_none());
    }

    #[test]
    fn test_remove() {
        let mut cache = ProgramCache::new(Duration::from_secs(60), 10);
        let loc = ProgramLocator::from_path("/test");
        cache.put(loc.clone(), 42);
        assert!(cache.contains(&loc));

        cache.remove(&loc);
        assert!(!cache.contains(&loc));
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn test_capacity_eviction() {
        let mut cache = ProgramCache::new(Duration::from_secs(60), 2);

        let loc1 = ProgramLocator::from_path("/a");
        let loc2 = ProgramLocator::from_path("/b");
        let loc3 = ProgramLocator::from_path("/c");

        cache.put(loc1.clone(), 1);
        cache.put(loc2.clone(), 2);
        assert_eq!(cache.len(), 2);

        // This should evict loc1 (LRU)
        cache.put(loc3.clone(), 3);
        assert_eq!(cache.len(), 2);
        assert!(!cache.contains(&loc1));
        assert!(cache.contains(&loc2));
        assert!(cache.contains(&loc3));
    }

    #[test]
    fn test_expiration() {
        let mut cache = ProgramCache::new(Duration::from_millis(50), 10);
        let loc = ProgramLocator::from_path("/test");
        cache.put(loc.clone(), 42);

        assert!(cache.get(&loc));

        thread::sleep(Duration::from_millis(100));

        assert!(!cache.get(&loc));
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn test_lru_touch() {
        let mut cache = ProgramCache::new(Duration::from_secs(60), 2);

        let loc1 = ProgramLocator::from_path("/a");
        let loc2 = ProgramLocator::from_path("/b");

        cache.put(loc1.clone(), 1);
        cache.put(loc2.clone(), 2);

        // Touch loc1 to make it most recently used
        cache.get(&loc1);

        // This should evict loc2 (now LRU)
        let loc3 = ProgramLocator::from_path("/c");
        cache.put(loc3.clone(), 3);

        assert!(cache.contains(&loc1));
        assert!(!cache.contains(&loc2));
        assert!(cache.contains(&loc3));
    }

    #[test]
    fn test_consumer_count() {
        let mut cache = ProgramCache::new(Duration::from_secs(60), 10);
        let loc = ProgramLocator::from_path("/test");
        cache.put(loc.clone(), 42);

        assert_eq!(cache.consumer_count(&loc), 1); // cache itself
        cache.add_consumer(&loc);
        assert_eq!(cache.consumer_count(&loc), 2);

        let remaining = cache.release_consumer(&loc);
        assert_eq!(remaining, 1);
    }

    #[test]
    fn test_update_existing() {
        let mut cache = ProgramCache::new(Duration::from_secs(60), 10);
        let loc = ProgramLocator::from_path("/test");

        cache.put(loc.clone(), "old".to_string());
        cache.put(loc.clone(), "new".to_string());
        assert_eq!(cache.len(), 1);
        assert_eq!(cache.get_ref(&loc), Some(&"new".to_string()));
    }

    #[test]
    fn test_clear() {
        let mut cache = ProgramCache::new(Duration::from_secs(60), 10);
        cache.put(ProgramLocator::from_path("/a"), 1);
        cache.put(ProgramLocator::from_path("/b"), 2);

        cache.clear();
        assert!(cache.is_empty());
    }

    #[test]
    fn test_set_capacity() {
        let mut cache = ProgramCache::new(Duration::from_secs(60), 10);
        cache.put(ProgramLocator::from_path("/a"), 1);
        cache.put(ProgramLocator::from_path("/b"), 2);
        cache.put(ProgramLocator::from_path("/c"), 3);

        cache.set_capacity(2);
        assert_eq!(cache.capacity(), 2);
        assert!(cache.len() <= 2);
    }
}
