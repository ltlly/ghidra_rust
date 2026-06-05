//! RemoteAsyncResult - async result from remote debugger operations.
//!
//! Ported from Ghidra's `ghidra.debug.api.RemoteAsyncResult`.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

/// The state of a remote async operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AsyncState {
    /// The operation is pending.
    Pending,
    /// The operation completed successfully.
    Completed,
    /// The operation failed with an error.
    Error,
    /// The operation was cancelled.
    Cancelled,
    /// The operation timed out.
    TimedOut,
}

/// An asynchronous result from a remote debugger operation.
///
/// Ported from Ghidra's `RemoteAsyncResult`. Represents a pending or
/// completed result from a remote method invocation.
#[derive(Debug)]
pub struct RemoteAsyncResult<T> {
    inner: Arc<Mutex<AsyncResultInner<T>>>,
}

#[derive(Debug)]
struct AsyncResultInner<T> {
    state: AsyncState,
    value: Option<T>,
    error: Option<String>,
    started_at: Instant,
}

impl<T: Clone> RemoteAsyncResult<T> {
    /// Create a pending async result.
    pub fn new_pending() -> Self {
        Self {
            inner: Arc::new(Mutex::new(AsyncResultInner {
                state: AsyncState::Pending,
                value: None,
                error: None,
                started_at: Instant::now(),
            })),
        }
    }

    /// Create a completed async result.
    pub fn new_completed(value: T) -> Self {
        Self {
            inner: Arc::new(Mutex::new(AsyncResultInner {
                state: AsyncState::Completed,
                value: Some(value),
                error: None,
                started_at: Instant::now(),
            })),
        }
    }

    /// Create an error async result.
    pub fn new_error(error: impl Into<String>) -> Self {
        Self {
            inner: Arc::new(Mutex::new(AsyncResultInner {
                state: AsyncState::Error,
                value: None,
                error: Some(error.into()),
                started_at: Instant::now(),
            })),
        }
    }

    /// Complete this result with a value.
    pub fn complete(&self, value: T) {
        let mut inner = self.inner.lock().unwrap();
        inner.state = AsyncState::Completed;
        inner.value = Some(value);
    }

    /// Fail this result with an error.
    pub fn fail(&self, error: impl Into<String>) {
        let mut inner = self.inner.lock().unwrap();
        inner.state = AsyncState::Error;
        inner.error = Some(error.into());
    }

    /// Cancel this result.
    pub fn cancel(&self) {
        let mut inner = self.inner.lock().unwrap();
        if inner.state == AsyncState::Pending {
            inner.state = AsyncState::Cancelled;
        }
    }

    /// Get the current state.
    pub fn state(&self) -> AsyncState {
        self.inner.lock().unwrap().state
    }

    /// Whether the operation is still pending.
    pub fn is_pending(&self) -> bool {
        self.state() == AsyncState::Pending
    }

    /// Whether the operation completed (success or failure).
    pub fn is_done(&self) -> bool {
        !matches!(self.state(), AsyncState::Pending)
    }

    /// Get the value if completed.
    pub fn value(&self) -> Option<T> {
        let inner = self.inner.lock().unwrap();
        if inner.state == AsyncState::Completed {
            inner.value.clone()
        } else {
            None
        }
    }

    /// Get the error message if failed.
    pub fn error(&self) -> Option<String> {
        let inner = self.inner.lock().unwrap();
        inner.error.clone()
    }

    /// Get the elapsed time since creation.
    pub fn elapsed(&self) -> Duration {
        self.inner.lock().unwrap().started_at.elapsed()
    }

    /// Mark as timed out if still pending.
    pub fn check_timeout(&self, timeout: Duration) -> bool {
        let mut inner = self.inner.lock().unwrap();
        if inner.state == AsyncState::Pending && inner.started_at.elapsed() >= timeout {
            inner.state = AsyncState::TimedOut;
            return true;
        }
        false
    }
}

impl<T: Clone> Clone for RemoteAsyncResult<T> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pending_result() {
        let r = RemoteAsyncResult::<i32>::new_pending();
        assert!(r.is_pending());
        assert!(!r.is_done());
        assert!(r.value().is_none());
    }

    #[test]
    fn test_completed_result() {
        let r = RemoteAsyncResult::new_completed(42);
        assert_eq!(r.state(), AsyncState::Completed);
        assert_eq!(r.value(), Some(42));
        assert!(r.error().is_none());
    }

    #[test]
    fn test_error_result() {
        let r = RemoteAsyncResult::<i32>::new_error("connection lost");
        assert_eq!(r.state(), AsyncState::Error);
        assert_eq!(r.error(), Some("connection lost".into()));
    }

    #[test]
    fn test_complete_pending() {
        let r = RemoteAsyncResult::<String>::new_pending();
        r.complete("done".into());
        assert_eq!(r.state(), AsyncState::Completed);
        assert_eq!(r.value(), Some("done".into()));
    }

    #[test]
    fn test_fail_pending() {
        let r = RemoteAsyncResult::<i32>::new_pending();
        r.fail("oops");
        assert_eq!(r.state(), AsyncState::Error);
        assert_eq!(r.error(), Some("oops".into()));
    }

    #[test]
    fn test_cancel() {
        let r = RemoteAsyncResult::<i32>::new_pending();
        r.cancel();
        assert_eq!(r.state(), AsyncState::Cancelled);
    }

    #[test]
    fn test_cancel_completed() {
        let r = RemoteAsyncResult::new_completed(1);
        r.cancel();
        assert_eq!(r.state(), AsyncState::Completed); // can't cancel completed
    }

    #[test]
    fn test_timeout() {
        let r = RemoteAsyncResult::<i32>::new_pending();
        assert!(!r.check_timeout(Duration::from_secs(60)));
        // Instant elapsed is very small, so timeout check should fail
    }

    #[test]
    fn test_clone_shares_state() {
        let r1 = RemoteAsyncResult::<i32>::new_pending();
        let r2 = r1.clone();
        r1.complete(99);
        assert_eq!(r2.value(), Some(99));
    }

    #[test]
    fn test_elapsed() {
        let r = RemoteAsyncResult::<i32>::new_pending();
        let e = r.elapsed();
        assert!(e.as_millis() < 100);
    }
}
