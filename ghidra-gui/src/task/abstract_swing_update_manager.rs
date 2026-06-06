//! Port of `AbstractSwingUpdateManager` from `ghidra.util.task`.
//!
//! Manages coalesced UI update operations. When multiple rapid updates are
//! requested (e.g., from a stream of data changes), this manager debounces
//! them into a single update operation, reducing UI flicker and improving
//! performance.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Default minimum delay between updates (milliseconds).
pub const DEFAULT_MIN_DELAY_MS: u64 = 200;

/// Default maximum delay before forcing an update (milliseconds).
pub const DEFAULT_MAX_DELAY_MS: u64 = 1000;

/// Minimum delay floor (milliseconds).
pub const MIN_DELAY_FLOOR_MS: u64 = 10;

/// Abstract Swing update manager for coalescing rapid UI updates.
///
/// Ports `ghidra.util.task.AbstractSwingUpdateManager`. Provides debounced
/// update scheduling to avoid excessive UI repaints.
#[derive(Debug)]
pub struct AbstractSwingUpdateManager {
    /// Name for debugging.
    name: String,
    /// Minimum delay between updates.
    min_delay: Duration,
    /// Maximum delay before forcing an update.
    max_delay: Duration,
    /// Whether an update is pending.
    pending: AtomicBool,
    /// Whether an update is currently executing.
    running: AtomicBool,
    /// Number of updates requested.
    request_count: AtomicU64,
    /// Number of updates actually executed.
    execute_count: AtomicU64,
    /// Timestamp of last update execution.
    last_update: Mutex<Option<Instant>>,
    /// Timestamp of last update request.
    last_request: Mutex<Option<Instant>>,
}

impl AbstractSwingUpdateManager {
    /// Create a new update manager with default delays.
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            min_delay: Duration::from_millis(DEFAULT_MIN_DELAY_MS),
            max_delay: Duration::from_millis(DEFAULT_MAX_DELAY_MS),
            pending: AtomicBool::new(false),
            running: AtomicBool::new(false),
            request_count: AtomicU64::new(0),
            execute_count: AtomicU64::new(0),
            last_update: Mutex::new(None),
            last_request: Mutex::new(None),
        }
    }

    /// Create with custom delays.
    pub fn with_delays(name: &str, min_delay_ms: u64, max_delay_ms: u64) -> Self {
        Self {
            min_delay: Duration::from_millis(min_delay_ms.max(MIN_DELAY_FLOOR_MS)),
            max_delay: Duration::from_millis(max_delay_ms),
            ..Self::new(name)
        }
    }

    /// Request an update. The actual update may be coalesced with other
    /// pending requests.
    pub fn update(&self) {
        self.request_count.fetch_add(1, Ordering::Relaxed);
        self.pending.store(true, Ordering::SeqCst);
        if let Ok(mut last) = self.last_request.lock() {
            *last = Some(Instant::now());
        }
    }

    /// Check if an update should be executed now.
    pub fn should_update(&self) -> bool {
        if !self.pending.load(Ordering::SeqCst) {
            return false;
        }

        let last = self.last_request.lock().ok()?;
        let request_time = last?;
        let elapsed = request_time.elapsed();

        if elapsed >= self.max_delay {
            return true; // force update after max delay
        }

        elapsed >= self.min_delay
    }

    /// Execute the pending update (to be called from the UI thread).
    pub fn execute_update(&self) {
        if !self.pending.swap(false, Ordering::SeqCst) {
            return;
        }
        self.running.store(true, Ordering::SeqCst);
        self.execute_count.fetch_add(1, Ordering::Relaxed);
        if let Ok(mut last) = self.last_update.lock() {
            *last = Some(Instant::now());
        }
        self.running.store(false, Ordering::SeqCst);
    }

    /// Check if an update is pending.
    pub fn is_pending(&self) -> bool {
        self.pending.load(Ordering::SeqCst)
    }

    /// Check if an update is currently running.
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    /// Get the name of this manager.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get the minimum delay.
    pub fn min_delay(&self) -> Duration {
        self.min_delay
    }

    /// Get the maximum delay.
    pub fn max_delay(&self) -> Duration {
        self.max_delay
    }

    /// Get the number of update requests.
    pub fn request_count(&self) -> u64 {
        self.request_count.load(Ordering::Relaxed)
    }

    /// Get the number of executed updates.
    pub fn execute_count(&self) -> u64 {
        self.execute_count.load(Ordering::Relaxed)
    }

    /// Reset the manager state.
    pub fn reset(&self) {
        self.pending.store(false, Ordering::SeqCst);
        self.running.store(false, Ordering::SeqCst);
    }
}

impl Default for AbstractSwingUpdateManager {
    fn default() -> Self {
        Self::new("DefaultUpdateManager")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_update_manager_default() {
        let mgr = AbstractSwingUpdateManager::default();
        assert!(!mgr.is_pending());
        assert!(!mgr.is_running());
        assert_eq!(mgr.request_count(), 0);
        assert_eq!(mgr.execute_count(), 0);
    }

    #[test]
    fn test_update_manager_request() {
        let mgr = AbstractSwingUpdateManager::new("test");
        mgr.update();
        assert!(mgr.is_pending());
        assert_eq!(mgr.request_count(), 1);

        mgr.update();
        assert_eq!(mgr.request_count(), 2);
    }

    #[test]
    fn test_update_manager_execute() {
        let mgr = AbstractSwingUpdateManager::new("test");
        mgr.update();
        assert!(mgr.is_pending());

        mgr.execute_update();
        assert!(!mgr.is_pending());
        assert_eq!(mgr.execute_count(), 1);
    }

    #[test]
    fn test_update_manager_execute_no_pending() {
        let mgr = AbstractSwingUpdateManager::new("test");
        mgr.execute_update(); // no-op when nothing pending
        assert_eq!(mgr.execute_count(), 0);
    }

    #[test]
    fn test_update_manager_with_delays() {
        let mgr = AbstractSwingUpdateManager::with_delays("fast", 50, 500);
        assert_eq!(mgr.min_delay(), Duration::from_millis(50));
        assert_eq!(mgr.max_delay(), Duration::from_millis(500));
    }

    #[test]
    fn test_update_manager_min_delay_floor() {
        let mgr = AbstractSwingUpdateManager::with_delays("tiny", 1, 100);
        assert_eq!(mgr.min_delay(), Duration::from_millis(MIN_DELAY_FLOOR_MS));
    }

    #[test]
    fn test_update_manager_reset() {
        let mgr = AbstractSwingUpdateManager::new("test");
        mgr.update();
        assert!(mgr.is_pending());
        mgr.reset();
        assert!(!mgr.is_pending());
    }
}
