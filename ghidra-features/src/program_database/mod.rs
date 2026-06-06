//! Program database abstractions.
//!
//! Ported from `ghidra.program.database`.
//!
//! Provides database-level program abstractions including property management
//! and change tracking for the program object.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};

// ---------------------------------------------------------------------------
// DatabaseObject
// ---------------------------------------------------------------------------

/// Trait for objects stored in a Ghidra program database.
pub trait DatabaseObject {
    /// The unique key of this object in the database.
    fn key(&self) -> u64;

    /// Called when the object is deleted from the database.
    fn deleted(&mut self) {}

    /// Called when the object is refreshed from the database.
    fn refresh(&mut self) {}
}

// ---------------------------------------------------------------------------
// ProgramProperties
// ---------------------------------------------------------------------------

/// A set of named properties associated with a program.
///
/// Supports string, int, long, and boolean property types.
#[derive(Debug, Clone, Default)]
pub struct ProgramProperties {
    strings: HashMap<String, String>,
    ints: HashMap<String, i32>,
    longs: HashMap<String, i64>,
    bools: HashMap<String, bool>,
}

impl ProgramProperties {
    /// Create empty properties.
    pub fn new() -> Self {
        Self::default()
    }

    /// Get a string property.
    pub fn get_string(&self, key: &str, default: Option<&str>) -> Option<String> {
        self.strings
            .get(key)
            .cloned()
            .or_else(|| default.map(|s| s.to_string()))
    }

    /// Set a string property.
    pub fn set_string(&mut self, key: &str, value: &str) {
        self.strings.insert(key.to_string(), value.to_string());
    }

    /// Get an int property.
    pub fn get_int(&self, key: &str, default: i32) -> i32 {
        self.ints.get(key).copied().unwrap_or(default)
    }

    /// Set an int property.
    pub fn set_int(&mut self, key: &str, value: i32) {
        self.ints.insert(key.to_string(), value);
    }

    /// Get a long property.
    pub fn get_long(&self, key: &str, default: i64) -> i64 {
        self.longs.get(key).copied().unwrap_or(default)
    }

    /// Set a long property.
    pub fn set_long(&mut self, key: &str, value: i64) {
        self.longs.insert(key.to_string(), value);
    }

    /// Get a boolean property.
    pub fn get_bool(&self, key: &str, default: bool) -> bool {
        self.bools.get(key).copied().unwrap_or(default)
    }

    /// Set a boolean property.
    pub fn set_bool(&mut self, key: &str, value: bool) {
        self.bools.insert(key.to_string(), value);
    }

    /// Remove a property by key (from all type maps).
    pub fn remove(&mut self, key: &str) {
        self.strings.remove(key);
        self.ints.remove(key);
        self.longs.remove(key);
        self.bools.remove(key);
    }

    /// Whether a property exists with the given key (any type).
    pub fn has(&self, key: &str) -> bool {
        self.strings.contains_key(key)
            || self.ints.contains_key(key)
            || self.longs.contains_key(key)
            || self.bools.contains_key(key)
    }

    /// Number of properties.
    pub fn len(&self) -> usize {
        let mut keys = std::collections::HashSet::new();
        keys.extend(self.strings.keys());
        keys.extend(self.ints.keys());
        keys.extend(self.longs.keys());
        keys.extend(self.bools.keys());
        keys.len()
    }

    /// Whether there are no properties.
    pub fn is_empty(&self) -> bool {
        self.strings.is_empty()
            && self.ints.is_empty()
            && self.longs.is_empty()
            && self.bools.is_empty()
    }
}

// ---------------------------------------------------------------------------
// ModificationTracker
// ---------------------------------------------------------------------------

/// Tracks modification events on a program database.
///
/// Maintains a monotonically increasing modification number that is
/// incremented on each change. Consumers can compare the number to detect
/// whether the program has been modified since a prior snapshot.
#[derive(Debug)]
pub struct ModificationTracker {
    modification_number: AtomicU64,
}

impl ModificationTracker {
    /// Create a new tracker starting at 0.
    pub fn new() -> Self {
        Self {
            modification_number: AtomicU64::new(0),
        }
    }

    /// Get the current modification number.
    pub fn modification_number(&self) -> u64 {
        self.modification_number.load(Ordering::Relaxed)
    }

    /// Increment the modification number (called on each program change).
    pub fn increment(&self) -> u64 {
        self.modification_number.fetch_add(1, Ordering::Relaxed) + 1
    }

    /// Check whether the program has been modified since the given number.
    pub fn is_modified_since(&self, since: u64) -> bool {
        self.modification_number() > since
    }

    /// Reset the modification number to 0.
    pub fn reset(&self) {
        self.modification_number.store(0, Ordering::Relaxed);
    }
}

impl Default for ModificationTracker {
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
    fn test_program_properties_string() {
        let mut props = ProgramProperties::new();
        props.set_string("name", "test_program");
        assert_eq!(props.get_string("name", None), Some("test_program".into()));
        assert_eq!(props.get_string("missing", Some("default")), Some("default".into()));
    }

    #[test]
    fn test_program_properties_int() {
        let mut props = ProgramProperties::new();
        props.set_int("version", 42);
        assert_eq!(props.get_int("version", 0), 42);
        assert_eq!(props.get_int("missing", -1), -1);
    }

    #[test]
    fn test_program_properties_long() {
        let mut props = ProgramProperties::new();
        props.set_long("size", 0x100000);
        assert_eq!(props.get_long("size", 0), 0x100000);
    }

    #[test]
    fn test_program_properties_bool() {
        let mut props = ProgramProperties::new();
        props.set_bool("analyzed", true);
        assert!(props.get_bool("analyzed", false));
        assert!(!props.get_bool("missing", false));
    }

    #[test]
    fn test_program_properties_remove() {
        let mut props = ProgramProperties::new();
        props.set_string("key", "value");
        assert!(props.has("key"));
        props.remove("key");
        assert!(!props.has("key"));
    }

    #[test]
    fn test_program_properties_len() {
        let mut props = ProgramProperties::new();
        assert!(props.is_empty());
        props.set_string("a", "1");
        props.set_int("b", 2);
        props.set_long("c", 3);
        props.set_bool("d", true);
        assert_eq!(props.len(), 4);
    }

    #[test]
    fn test_modification_tracker() {
        let tracker = ModificationTracker::new();
        assert_eq!(tracker.modification_number(), 0);
        assert!(!tracker.is_modified_since(0));

        tracker.increment();
        assert_eq!(tracker.modification_number(), 1);
        assert!(tracker.is_modified_since(0));
        assert!(!tracker.is_modified_since(1));
    }

    #[test]
    fn test_modification_tracker_reset() {
        let tracker = ModificationTracker::new();
        tracker.increment();
        tracker.increment();
        assert_eq!(tracker.modification_number(), 2);
        tracker.reset();
        assert_eq!(tracker.modification_number(), 0);
    }

    #[test]
    fn test_modification_tracker_concurrent() {
        use std::sync::Arc;
        use std::thread;

        let tracker = Arc::new(ModificationTracker::new());
        let mut handles = vec![];

        for _ in 0..10 {
            let tracker = Arc::clone(&tracker);
            handles.push(thread::spawn(move || {
                for _ in 0..100 {
                    tracker.increment();
                }
            }));
        }

        for handle in handles {
            handle.join().unwrap();
        }

        assert_eq!(tracker.modification_number(), 1000);
    }
}
