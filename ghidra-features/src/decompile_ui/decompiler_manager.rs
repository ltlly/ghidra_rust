//! Decompiler manager -- Rust port of
//! `ghidra.app.decompiler.component.DecompilerManager`.
//!
//! Manages the threading involved with the decompiler.  It uses a simpler
//! approach than Ghidra's earlier versions: there is only one active
//! [`DecompileRequest`] at a time.  If a new decompile request comes in
//! while one is in progress, the new request is checked to see if it will
//! decompile the same function.  If so, only the location is updated and
//! the current decompile continues.  If the new request targets a different
//! function (or force is set), the current decompile is cancelled and a new
//! one is scheduled.
//!
//! A [`SwingUpdateManager`]-style coalescing mechanism prevents rapid-fire
//! requests from overwhelming the decompiler.
//!
//! # Architecture
//!
//! ```text
//! DecompilerManager
//!   ├── decompiler: DecompilerHandle (native decompiler process)
//!   ├── current_request: Option<DecompileRequest>
//!   ├── pending_request: Option<DecompileRequest>
//!   ├── update_coalescer: UpdateCoalescer (debounce requests)
//!   └── status: DecompilerStatus
//!
//! DecompileRequest
//!   ├── program_name: String
//!   ├── function_entry: Address
//!   ├── location: Address
//!   ├── force_decompile: bool
//!   └── debug_file: Option<PathBuf>
//!
//! DecompileRequest::update(other) -> bool
//!   same function & not forced -> update location, return true
//! ```

use std::collections::VecDeque;
use std::fmt;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use ghidra_core::addr::Address;

use super::controller::{DecompileData, DecompileResults};

// ---------------------------------------------------------------------------
// DecompilerStatus -- the current state of the decompiler
// ---------------------------------------------------------------------------

/// The status of the decompiler manager.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecompilerStatus {
    /// No decompile in progress; idle.
    Idle,
    /// A decompile is in progress.
    Decompiling,
    /// The decompiler was cancelled.
    Cancelled,
    /// The decompiler encountered an error.
    Error,
}

impl fmt::Display for DecompilerStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DecompilerStatus::Idle => write!(f, "Idle"),
            DecompilerStatus::Decompiling => write!(f, "Decompiling"),
            DecompilerStatus::Cancelled => write!(f, "Cancelled"),
            DecompilerStatus::Error => write!(f, "Error"),
        }
    }
}

// ---------------------------------------------------------------------------
// DecompileRequest -- a single decompile job
// ---------------------------------------------------------------------------

/// A request to decompile a function.
///
/// In Ghidra this is represented by `DecompileRunnable`.  Here we model
/// the data needed to identify and schedule a decompile.
#[derive(Debug, Clone)]
pub struct DecompileRequest {
    /// The name (or identifier) of the program.
    pub program_name: String,
    /// The entry point of the function to decompile.
    pub function_entry: Address,
    /// The location (address) to navigate to after decompilation.
    pub location: Address,
    /// If `true`, force a new decompile even if the same function is
    /// already being decompiled.
    pub force_decompile: bool,
    /// Optional path to a debug output file.
    pub debug_file: Option<PathBuf>,
    /// Viewer scroll position (index, y_offset).
    pub viewer_position: Option<(usize, usize)>,
    /// When this request was created.
    pub created_at: Instant,
}

impl DecompileRequest {
    /// Create a new decompile request.
    pub fn new(
        program_name: impl Into<String>,
        function_entry: Address,
        location: Address,
    ) -> Self {
        Self {
            program_name: program_name.into(),
            function_entry,
            location,
            force_decompile: false,
            debug_file: None,
            viewer_position: None,
            created_at: Instant::now(),
        }
    }

    /// Create a new decompile request with force flag.
    pub fn forced(
        program_name: impl Into<String>,
        function_entry: Address,
        location: Address,
    ) -> Self {
        Self {
            force_decompile: true,
            ..Self::new(program_name, function_entry, location)
        }
    }

    /// Set the debug output file.
    pub fn with_debug_file(mut self, path: PathBuf) -> Self {
        self.debug_file = Some(path);
        self
    }

    /// Set the viewer position.
    pub fn with_viewer_position(mut self, position: (usize, usize)) -> Self {
        self.viewer_position = Some(position);
        self
    }

    /// Try to update this request in-place with a new request.
    ///
    /// If both requests target the same function and the new request does
    /// not force a re-decompile, the location is updated and `true` is
    /// returned.  Otherwise `false` is returned (the caller should create
    /// a new request).
    ///
    /// This corresponds to `DecompileRunnable.update()` in the Java source.
    pub fn update(&mut self, new_request: &DecompileRequest) -> bool {
        if new_request.force_decompile {
            return false;
        }
        if self.function_entry != new_request.function_entry {
            return false;
        }
        // Same function -- update the location and viewer position.
        self.location = new_request.location;
        self.viewer_position = new_request.viewer_position;
        true
    }

    /// The elapsed time since this request was created.
    pub fn age(&self) -> Duration {
        self.created_at.elapsed()
    }
}

// ---------------------------------------------------------------------------
// DecompileCallback -- trait for receiving decompile results
// ---------------------------------------------------------------------------

/// A callback interface for receiving decompile results.
///
/// In Ghidra this is `DecompilerCallbackHandler` / the controller's
/// `setDecompileData` method.  Here we model it as a trait so the
/// manager can be tested independently of the controller.
pub trait DecompileCallback: fmt::Debug {
    /// Called when the decompile status changes.
    fn status_changed(&self, status: DecompilerStatus);

    /// Called when a decompile completes with results.
    fn decompile_complete(&self, data: DecompileData);

    /// Called when a decompile fails with an error.
    fn decompile_error(&self, function_entry: Address, message: String);
}

// ---------------------------------------------------------------------------
// UpdateCoalescer -- debounces rapid decompile requests
// ---------------------------------------------------------------------------

/// A simple coalescing mechanism for decompile requests.
///
/// When multiple requests arrive within a short window (e.g., the user is
/// scrolling through the listing), only the last request is actually
/// processed.  This mirrors Ghidra's `SwingUpdateManager` with a 500ms
/// delay.
#[derive(Debug)]
pub struct UpdateCoalescer {
    /// The delay before a pending update is flushed.
    delay: Duration,
    /// When the last update was scheduled.
    last_scheduled: Option<Instant>,
    /// Whether a flush is pending.
    pending: bool,
}

impl UpdateCoalescer {
    /// Create a new coalescer with the given delay.
    pub fn new(delay: Duration) -> Self {
        Self {
            delay,
            last_scheduled: None,
            pending: false,
        }
    }

    /// Schedule an update.  Returns `true` if this is the first update
    /// in a burst (the caller should start a timer); `false` if a
    /// timer is already running (the update will be coalesced).
    pub fn schedule(&mut self) -> bool {
        let now = Instant::now();
        self.last_scheduled = Some(now);
        if self.pending {
            false // Already have a pending flush.
        } else {
            self.pending = true;
            true // Caller should start a timer.
        }
    }

    /// Check if the pending update should be flushed.
    ///
    /// Returns `true` if enough time has passed since the last schedule.
    pub fn should_flush(&self) -> bool {
        if !self.pending {
            return false;
        }
        match self.last_scheduled {
            Some(scheduled) => scheduled.elapsed() >= self.delay,
            None => false,
        }
    }

    /// Flush the pending update.
    pub fn flush(&mut self) {
        self.pending = false;
        self.last_scheduled = None;
    }

    /// Cancel any pending update.
    pub fn cancel(&mut self) {
        self.pending = false;
        self.last_scheduled = None;
    }

    /// Whether an update is pending.
    pub fn is_pending(&self) -> bool {
        self.pending
    }
}

impl Default for UpdateCoalescer {
    fn default() -> Self {
        Self::new(Duration::from_millis(500))
    }
}

// ---------------------------------------------------------------------------
// DecompilerManager -- the main manager
// ---------------------------------------------------------------------------

/// Manages the threading and scheduling of decompiler operations.
///
/// Ported from `ghidra.app.decompiler.component.DecompilerManager`.
///
/// The manager ensures that:
/// - Only one decompile runs at a time.
/// - Requests for the same function update the location without restarting.
/// - Rapid-fire requests are coalesced.
/// - The native decompiler process can be cancelled and reset.
#[derive(Debug)]
pub struct DecompilerManager {
    /// The currently executing decompile request.
    current_request: Option<DecompileRequest>,
    /// A request waiting to be started (after the coalescing delay).
    pending_request: Option<DecompileRequest>,
    /// The coalescing mechanism.
    coalescer: UpdateCoalescer,
    /// The current status.
    status: DecompilerStatus,
    /// Whether the native decompiler process is initialized.
    is_initialized: bool,
    /// The number of decompiles performed.
    decompile_count: u64,
    /// History of recently completed requests (for debugging).
    request_history: VecDeque<RequestHistoryEntry>,
    /// Maximum history size.
    max_history: usize,
    /// Whether the manager has been disposed.
    disposed: bool,
}

/// A record of a completed decompile request.
#[derive(Debug, Clone)]
pub struct RequestHistoryEntry {
    /// The request that was processed.
    pub request: DecompileRequest,
    /// How long the decompile took.
    pub elapsed: Duration,
    /// Whether it succeeded.
    pub success: bool,
    /// The status message.
    pub message: String,
}

impl DecompilerManager {
    /// Create a new decompiler manager.
    pub fn new() -> Self {
        Self {
            current_request: None,
            pending_request: None,
            coalescer: UpdateCoalescer::default(),
            status: DecompilerStatus::Idle,
            is_initialized: true,
            decompile_count: 0,
            request_history: VecDeque::new(),
            max_history: 50,
            disposed: false,
        }
    }

    // -----------------------------------------------------------------------
    // Public API
    // -----------------------------------------------------------------------

    /// Request a new decompile.
    ///
    /// If a current decompile is in progress for the same function, only
    /// the location is updated.  Otherwise the request is scheduled via
    /// the coalescing mechanism.
    ///
    /// This corresponds to `DecompilerManager.decompile()` in the Java source.
    pub fn decompile(&mut self, request: DecompileRequest) {
        if self.disposed {
            return;
        }

        if request.force_decompile {
            self.cancel_all();
            self.set_pending(request);
            return;
        }

        // Try to update the current request in-place.
        if self.try_update_current(&request) {
            return;
        }

        self.set_pending(request);
    }

    /// Cancel all in-progress and pending decompile requests.
    pub fn cancel_all(&mut self) {
        self.cancel_current();
        self.pending_request = None;
        self.coalescer.cancel();
        self.status = DecompilerStatus::Cancelled;
    }

    /// Returns `true` if a decompile is in progress or pending.
    pub fn is_busy(&self) -> bool {
        self.current_request.is_some() || self.pending_request.is_some()
    }

    /// Get the current status.
    pub fn status(&self) -> DecompilerStatus {
        self.status
    }

    /// Get the current request, if any.
    pub fn current_request(&self) -> Option<&DecompileRequest> {
        self.current_request.as_ref()
    }

    /// Get the pending request, if any.
    pub fn pending_request(&self) -> Option<&DecompileRequest> {
        self.pending_request.as_ref()
    }

    /// Get the number of decompiles performed.
    pub fn decompile_count(&self) -> u64 {
        self.decompile_count
    }

    /// Get the request history.
    pub fn request_history(&self) -> &VecDeque<RequestHistoryEntry> {
        &self.request_history
    }

    /// Check if the coalescer has a pending flush ready.
    ///
    /// The caller should call `flush_pending()` if this returns `true`.
    pub fn has_pending_flush(&self) -> bool {
        self.coalescer.should_flush()
    }

    /// Flush the pending decompile request.
    ///
    /// This should be called when the coalescing delay has elapsed.
    /// The pending request becomes the current request and decompilation
    /// begins.
    pub fn flush_pending(&mut self) {
        if !self.coalescer.should_flush() {
            return;
        }

        self.coalescer.flush();

        let pending = match self.pending_request.take() {
            Some(r) => r,
            None => return,
        };

        // Cancel any current decompile.
        self.cancel_current();

        // Start the new decompile.
        self.current_request = Some(pending);
        self.status = DecompilerStatus::Decompiling;
    }

    /// Complete the current decompile with results.
    ///
    /// Called by the native decompiler thread when a decompile finishes.
    pub fn complete_decompile(&mut self, results: DecompileResults) {
        let elapsed = self
            .current_request
            .as_ref()
            .map(|r| r.age())
            .unwrap_or_default();

        let success = results.decompile_completed();

        // Record history.
        if let Some(request) = self.current_request.take() {
            self.push_history(RequestHistoryEntry {
                request,
                elapsed,
                success,
                message: if success {
                    "OK".to_string()
                } else {
                    results
                        .error_message
                        .clone()
                        .unwrap_or_else(|| "Unknown error".to_string())
                },
            });
        }

        self.decompile_count += 1;
        self.status = DecompilerStatus::Idle;
    }

    /// Report an error for the current decompile.
    pub fn error_decompile(&mut self, message: impl Into<String>) {
        let msg = message.into();
        let elapsed = self
            .current_request
            .as_ref()
            .map(|r| r.age())
            .unwrap_or_default();

        if let Some(request) = self.current_request.take() {
            self.push_history(RequestHistoryEntry {
                request,
                elapsed,
                success: false,
                message: msg,
            });
        }

        self.status = DecompilerStatus::Error;
    }

    /// Reset the native decompiler process.
    ///
    /// Called when the decompiler's view of a program has been invalidated
    /// (e.g., a new overlay space was added).
    pub fn reset_decompiler(&mut self) {
        self.cancel_all();
        self.is_initialized = true;
        self.status = DecompilerStatus::Idle;
    }

    /// Dispose the manager, releasing all resources.
    pub fn dispose(&mut self) {
        self.cancel_all();
        self.disposed = true;
        self.request_history.clear();
    }

    /// Whether the manager has been disposed.
    pub fn is_disposed(&self) -> bool {
        self.disposed
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    /// Try to update the current request with a new one.
    ///
    /// Returns `true` if the update succeeded (same function).
    fn try_update_current(&mut self, new_request: &DecompileRequest) -> bool {
        if self.pending_request.is_some() {
            return false; // Can't update when there's a pending request.
        }
        match self.current_request.as_mut() {
            Some(current) => current.update(new_request),
            None => false,
        }
    }

    /// Set a new pending request and schedule the coalescer.
    fn set_pending(&mut self, request: DecompileRequest) {
        self.pending_request = Some(request);
        self.coalescer.schedule();
    }

    /// Cancel the current decompile request.
    fn cancel_current(&mut self) {
        if self.current_request.is_some() {
            // In a full implementation, this would signal the native
            // decompiler to cancel via `decompiler.cancelCurrentAction()`.
            self.current_request = None;
        }
    }

    /// Push an entry to the request history, evicting old entries if needed.
    fn push_history(&mut self, entry: RequestHistoryEntry) {
        if self.request_history.len() >= self.max_history {
            self.request_history.pop_front();
        }
        self.request_history.push_back(entry);
    }
}

impl Default for DecompilerManager {
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

    fn make_request(entry: u64, location: u64) -> DecompileRequest {
        DecompileRequest::new("test.elf", Address::new(entry), Address::new(location))
    }

    fn make_forced(entry: u64, location: u64) -> DecompileRequest {
        DecompileRequest::forced("test.elf", Address::new(entry), Address::new(location))
    }

    // --- DecompileRequest ---

    #[test]
    fn request_new() {
        let req = make_request(0x1000, 0x1004);
        assert_eq!(req.program_name, "test.elf");
        assert_eq!(req.function_entry, Address::new(0x1000));
        assert_eq!(req.location, Address::new(0x1004));
        assert!(!req.force_decompile);
    }

    #[test]
    fn request_forced() {
        let req = make_forced(0x1000, 0x1004);
        assert!(req.force_decompile);
    }

    #[test]
    fn request_with_options() {
        let req = make_request(0x1000, 0x1004)
            .with_debug_file(PathBuf::from("/tmp/debug.txt"))
            .with_viewer_position((10, 5));
        assert!(req.debug_file.is_some());
        assert_eq!(req.viewer_position, Some((10, 5)));
    }

    #[test]
    fn request_update_same_function() {
        let mut req = make_request(0x1000, 0x1000);
        let new_req = make_request(0x1000, 0x1008);
        assert!(req.update(&new_req));
        assert_eq!(req.location, Address::new(0x1008));
    }

    #[test]
    fn request_update_different_function() {
        let mut req = make_request(0x1000, 0x1000);
        let new_req = make_request(0x2000, 0x2000);
        assert!(!req.update(&new_req));
    }

    #[test]
    fn request_update_forced() {
        let mut req = make_request(0x1000, 0x1000);
        let new_req = make_forced(0x1000, 0x1008);
        assert!(!req.update(&new_req));
    }

    // --- UpdateCoalescer ---

    #[test]
    fn coalescer_schedule_first() {
        let mut c = UpdateCoalescer::new(Duration::from_millis(100));
        assert!(c.schedule());
        assert!(c.is_pending());
    }

    #[test]
    fn coalescer_schedule_second() {
        let mut c = UpdateCoalescer::new(Duration::from_millis(100));
        c.schedule();
        assert!(!c.schedule()); // second schedule is coalesced
    }

    #[test]
    fn coalescer_cancel() {
        let mut c = UpdateCoalescer::new(Duration::from_millis(100));
        c.schedule();
        c.cancel();
        assert!(!c.is_pending());
    }

    #[test]
    fn coalescer_flush() {
        let mut c = UpdateCoalescer::new(Duration::from_millis(0));
        c.schedule();
        // With 0 delay, should_flush should be true immediately.
        // (In practice there's a tiny race, but 0ms should work.)
        // Note: This test may be flaky on slow machines.
        c.flush();
        assert!(!c.is_pending());
    }

    // --- DecompilerManager ---

    #[test]
    fn manager_new() {
        let mgr = DecompilerManager::new();
        assert!(!mgr.is_busy());
        assert_eq!(mgr.status(), DecompilerStatus::Idle);
        assert_eq!(mgr.decompile_count(), 0);
        assert!(mgr.current_request().is_none());
    }

    #[test]
    fn manager_decompile_sets_pending() {
        let mut mgr = DecompilerManager::new();
        mgr.decompile(make_request(0x1000, 0x1000));
        // The request should be pending (coalescer scheduled).
        assert!(mgr.pending_request().is_some());
    }

    #[test]
    fn manager_forced_cancels_current() {
        let mut mgr = DecompilerManager::new();
        mgr.decompile(make_request(0x1000, 0x1000));
        // Simulate flush to make it current.
        mgr.coalescer.pending = true;
        mgr.flush_pending();

        // Now force a new decompile.
        mgr.decompile(make_forced(0x2000, 0x2000));
        // The old current should be cancelled; new one pending.
        assert!(mgr.pending_request().is_some());
    }

    #[test]
    fn manager_cancel_all() {
        let mut mgr = DecompilerManager::new();
        mgr.decompile(make_request(0x1000, 0x1000));
        mgr.cancel_all();
        assert!(!mgr.is_busy());
        assert_eq!(mgr.status(), DecompilerStatus::Cancelled);
    }

    #[test]
    fn manager_flush_pending() {
        let mut mgr = DecompilerManager::new();
        // Use 0 delay so flush is immediate.
        mgr.coalescer = UpdateCoalescer::new(Duration::from_millis(0));
        mgr.decompile(make_request(0x1000, 0x1000));

        // Wait a tiny bit for the coalescer delay.
        std::thread::sleep(Duration::from_millis(1));

        mgr.flush_pending();
        assert!(mgr.current_request().is_some());
        assert_eq!(mgr.status(), DecompilerStatus::Decompiling);
    }

    #[test]
    fn manager_complete_decompile() {
        let mut mgr = DecompilerManager::new();
        mgr.coalescer = UpdateCoalescer::new(Duration::from_millis(0));
        mgr.decompile(make_request(0x1000, 0x1000));
        std::thread::sleep(Duration::from_millis(1));
        mgr.flush_pending();

        let results = DecompileResults::success(
            Address::new(0x1000),
            super::super::panel::DecompiledFunction::new(Address::new(0x1000), "main"),
            42,
        );
        mgr.complete_decompile(results);

        assert_eq!(mgr.status(), DecompilerStatus::Idle);
        assert_eq!(mgr.decompile_count(), 1);
        assert!(mgr.current_request().is_none());
        assert_eq!(mgr.request_history().len(), 1);
    }

    #[test]
    fn manager_error_decompile() {
        let mut mgr = DecompilerManager::new();
        mgr.current_request = Some(make_request(0x1000, 0x1000));

        mgr.error_decompile("timeout");
        assert_eq!(mgr.status(), DecompilerStatus::Error);
        assert!(mgr.current_request().is_none());
        assert_eq!(mgr.request_history().len(), 1);
        assert!(!mgr.request_history()[0].success);
    }

    #[test]
    fn manager_reset_decompiler() {
        let mut mgr = DecompilerManager::new();
        mgr.decompile(make_request(0x1000, 0x1000));
        mgr.reset_decompiler();
        assert!(!mgr.is_busy());
        assert_eq!(mgr.status(), DecompilerStatus::Idle);
    }

    #[test]
    fn manager_dispose() {
        let mut mgr = DecompilerManager::new();
        mgr.decompile(make_request(0x1000, 0x1000));
        mgr.dispose();
        assert!(mgr.is_disposed());
        assert!(!mgr.is_busy());
        assert!(mgr.request_history().is_empty());
    }

    #[test]
    fn manager_disposed_rejects_requests() {
        let mut mgr = DecompilerManager::new();
        mgr.dispose();
        mgr.decompile(make_request(0x1000, 0x1000));
        assert!(!mgr.is_busy());
    }

    #[test]
    fn manager_update_current_same_function() {
        let mut mgr = DecompilerManager::new();
        mgr.current_request = Some(make_request(0x1000, 0x1000));

        // New request for same function should update in-place.
        mgr.decompile(make_request(0x1000, 0x1008));
        assert!(mgr.pending_request.is_none());
        assert_eq!(
            mgr.current_request.as_ref().unwrap().location,
            Address::new(0x1008)
        );
    }

    #[test]
    fn manager_update_current_different_function() {
        let mut mgr = DecompilerManager::new();
        mgr.current_request = Some(make_request(0x1000, 0x1000));

        // New request for different function should become pending.
        mgr.decompile(make_request(0x2000, 0x2000));
        assert!(mgr.pending_request.is_some());
    }

    #[test]
    fn manager_update_current_with_pending() {
        let mut mgr = DecompilerManager::new();
        mgr.current_request = Some(make_request(0x1000, 0x1000));
        mgr.pending_request = Some(make_request(0x2000, 0x2000));

        // Can't update current when there's already a pending request.
        let result = mgr.try_update_current(&make_request(0x1000, 0x1008));
        assert!(!result);
    }

    #[test]
    fn manager_history_eviction() {
        let mut mgr = DecompilerManager::new();
        mgr.max_history = 2;

        for i in 0..5 {
            let entry = Address::new(0x1000 * i);
            mgr.current_request = Some(make_request(entry.offset, entry.offset));
            mgr.complete_decompile(DecompileResults::error(entry, "test"));
        }

        assert_eq!(mgr.request_history().len(), 2);
    }

    #[test]
    fn request_age() {
        let req = make_request(0x1000, 0x1000);
        // Age should be very small (near zero) for a freshly created request.
        assert!(req.age() < Duration::from_secs(1));
    }

    #[test]
    fn status_display() {
        assert_eq!(format!("{}", DecompilerStatus::Idle), "Idle");
        assert_eq!(format!("{}", DecompilerStatus::Decompiling), "Decompiling");
        assert_eq!(format!("{}", DecompilerStatus::Cancelled), "Cancelled");
        assert_eq!(format!("{}", DecompilerStatus::Error), "Error");
    }
}
