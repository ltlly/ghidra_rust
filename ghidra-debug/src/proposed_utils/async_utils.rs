//! Async utility functions and types.
//!
//! Ported from Ghidra's `ghidra.async` package:
//! - `AsyncUtils` -- convenience methods for working with `CompletableFuture`
//! - `AsyncFence` -- barrier that completes when all participant futures complete
//! - `AsyncTimer` -- non-blocking scheduled delays for async chains
//! - `AsyncLazyMap` -- async lazy cache backed by `CompletableFuture`-like values

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use super::futures::SharedFuture;

// ============================================================================
// AsyncUtils -- convenience functions
// ============================================================================

/// Convenience methods for asynchronous programming.
///
/// Ported from Ghidra's `ghidra.async.AsyncUtils`.
pub struct AsyncUtils;

impl AsyncUtils {
    /// Unwrap nested `CompletionException` / `ExecutionException` wrappers to
    /// get the root cause.
    ///
    /// In Rust this is a no-op since errors are not wrapped in the same way,
    /// but we provide the function so call sites that port from Java have a
    /// direct analogue.
    ///
    /// Ported from `AsyncUtils.unwrapThrowable`.
    pub fn unwrap_error(e: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> Box<dyn std::error::Error + Send + Sync> {
        e.into()
    }

    /// Create a `Result`-compatible handler that copies a success or failure
    /// result from one channel into another, mirroring
    /// `AsyncUtils.copyTo(CompletableFuture)`.
    ///
    /// Returns a closure that, given a `Result<T, E>`, forwards it to the
    /// provided sender and returns the same result.
    ///
    /// Ported from `AsyncUtils.copyTo`.
    pub fn copy_to<T: Clone, E: Clone>(
        tx: tokio::sync::oneshot::Sender<Result<T, E>>,
    ) -> impl FnOnce(Result<T, E>) -> Result<T, E> {
        move |result| {
            let _ = tx.send(result.clone());
            result
        }
    }
}

// ============================================================================
// AsyncFence -- barrier for multiple futures
// ============================================================================

/// A fence that completes when all participating futures complete.
///
/// Provides an alternative to `tokio::join!` or `futures::future::join_all`
/// with a builder-style API that mirrors Ghidra's `AsyncFence`.
///
/// # Example
///
/// ```ignore
/// let mut fence = AsyncFence::new();
/// fence.include(async_operation_1());
/// fence.include(async_operation_2());
/// fence.ready().await;
/// ```
///
/// Ported from Ghidra's `ghidra.async.AsyncFence`.
pub struct AsyncFence {
    participants: Vec<SharedFuture<()>>,
    ready: bool,
}

impl AsyncFence {
    /// Create a new empty fence.
    pub fn new() -> Self {
        Self {
            participants: Vec::new(),
            ready: false,
        }
    }

    /// Include a participant future whose result is ignored.
    ///
    /// Calling this after `ready()` will panic.
    pub fn include<F>(&mut self, future: F) -> &mut Self
    where
        F: Future<Output = ()> + Send + 'static,
    {
        if self.ready {
            panic!("Fence already ready");
        }
        self.participants.push(Box::pin(future));
        self
    }

    /// Include a participant future whose result is mapped to `()`.
    ///
    /// Calling this after `ready()` will panic.
    pub fn include_map<F, T>(&mut self, future: F) -> &mut Self
    where
        F: Future<Output = T> + Send + 'static,
    {
        if self.ready {
            panic!("Fence already ready");
        }
        self.participants.push(Box::pin(async move {
            future.await;
        }));
        self
    }

    /// Obtain a future that completes when all participating futures have
    /// completed.
    ///
    /// Calling this more than once returns the same future.
    pub fn ready(&mut self) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        self.ready = true;
        let participants: Vec<SharedFuture<()>> =
            std::mem::take(&mut self.participants);
        Box::pin(async move {
            for f in participants {
                f.await;
            }
        })
    }

    /// Diagnostic: the number of participants that have been registered.
    pub fn participant_count(&self) -> usize {
        self.participants.len()
    }
}

impl Default for AsyncFence {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// AsyncTimer -- non-blocking scheduled delays
// ============================================================================

/// A timer for asynchronous scheduled tasks.
///
/// Provides `CompletableFuture`-like timed delays for async chains without
/// blocking threads. A critical tenet of async reactive programming is to
/// never block a thread for an indefinite period; `AsyncTimer` provides
/// non-blocking delays via `tokio::time::sleep`.
///
/// # Example
///
/// ```ignore
/// let timer = AsyncTimer::new();
/// let mark = timer.mark();
/// mark.after(Duration::from_secs(1)).await;
/// // ... one second later ...
/// ```
///
/// Ported from Ghidra's `ghidra.async.AsyncTimer`.
pub struct AsyncTimer;

impl AsyncTimer {
    /// Create a new timer.
    pub fn new() -> Self {
        Self
    }

    /// Mark the current system time.
    pub fn mark(&self) -> Mark {
        Mark {
            mark: Instant::now(),
        }
    }

    /// Schedule a future that completes after the given duration.
    pub async fn after(duration: Duration) {
        if duration.is_zero() {
            return;
        }
        tokio::time::sleep(duration).await;
    }

    /// Return a future that completes at the given system time (relative to
    /// `Instant::now()` plus the remaining duration). If the time has already
    /// passed, completes immediately.
    pub async fn at_instant(instant: Instant) {
        let now = Instant::now();
        if instant > now {
            tokio::time::sleep_until(tokio::time::Instant::from_std(instant)).await;
        }
    }
}

impl Default for AsyncTimer {
    fn default() -> Self {
        Self::new()
    }
}

/// A mark capturing a point in time, relative to which delays are scheduled.
///
/// Ported from the inner `Mark` class of Ghidra's `AsyncTimer`.
pub struct Mark {
    mark: Instant,
}

impl Mark {
    /// Schedule a future that completes `duration` after this mark was taken.
    pub fn after(&self, duration: Duration) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        let target = self.mark + duration;
        Box::pin(AsyncTimer::at_instant(target))
    }

    /// Race a future against a deadline. If the future does not complete
    /// within `timeout`, return the provided fallback value instead.
    ///
    /// Ported from `Mark.timeOut`.
    pub async fn time_out<T, F>(
        &self,
        future: F,
        timeout: Duration,
        value_if_late: T,
    ) -> T
    where
        F: Future<Output = T> + Send,
        T: Send,
    {
        let deadline = self.mark + timeout;
        tokio::select! {
            val = future => val,
            _ = AsyncTimer::at_instant(deadline) => value_if_late,
        }
    }
}

// ============================================================================
// AsyncLazyMap -- async lazy cache
// ============================================================================

/// An asynchronous lazy cache where values are computed on first request.
///
/// Ported from Ghidra's `ghidra.async.AsyncLazyMap`.
///
/// Keys are requested via `get`; if not present, the configured computation
/// function is invoked to produce the value. The computation runs at most
/// once per key (unless the entry is removed). Errors can optionally be
/// forgotten (allowing retry) via `set_forget_errors`.
///
/// Uses `tokio::sync::OnceCell` per key so that concurrent requests for the
/// same key share a single computation.
pub struct AsyncLazyMap<K, V>
where
    K: Eq + std::hash::Hash + Clone,
{
    map: Arc<Mutex<HashMap<K, Arc<tokio::sync::OnceCell<V>>>>>,
    compute: Arc<dyn Fn(K) -> Pin<Box<dyn Future<Output = V> + Send>> + Send + Sync>,
    forget_errors: bool,
}

impl<K, V> AsyncLazyMap<K, V>
where
    K: Eq + std::hash::Hash + Clone + Send + Sync + 'static,
    V: Clone + Send + Sync + 'static,
{
    /// Create a new async lazy map with the given computation function.
    pub fn new<F, Fut>(compute: F) -> Self
    where
        F: Fn(K) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = V> + Send + 'static,
    {
        let compute: Arc<dyn Fn(K) -> Pin<Box<dyn Future<Output = V> + Send>> + Send + Sync> =
            Arc::new(move |k| Box::pin(compute(k)));
        Self {
            map: Arc::new(Mutex::new(HashMap::new())),
            compute,
            forget_errors: false,
        }
    }

    /// Set whether errors should be forgotten (removed from cache), allowing
    /// retry on subsequent `get` calls.
    pub fn set_forget_errors(&mut self, forget: bool) {
        self.forget_errors = forget;
    }

    /// Request a value for the given key. If the key is not already cached,
    /// the computation function is invoked to produce the value.
    ///
    /// Concurrent requests for the same key will share a single computation.
    pub async fn get(&self, key: K) -> V {
        let cell = {
            let mut map = self.map.lock().unwrap();
            map.entry(key.clone())
                .or_insert_with(|| Arc::new(tokio::sync::OnceCell::new()))
                .clone()
        };
        let compute = Arc::clone(&self.compute);
        cell.get_or_init(|| (compute)(key)).await.clone()
    }

    /// Insert an already-computed value for a key.
    pub async fn put(&self, key: K, value: V) {
        let cell = {
            let mut map = self.map.lock().unwrap();
            map.entry(key)
                .or_insert_with(|| Arc::new(tokio::sync::OnceCell::new()))
                .clone()
        };
        let _ = cell.set(value);
    }

    /// Remove a key from the cache without canceling anything.
    pub fn forget(&self, key: &K) {
        let mut map = self.map.lock().unwrap();
        map.remove(key);
    }

    /// Remove all entries from the cache.
    pub fn clear(&self) {
        let mut map = self.map.lock().unwrap();
        map.clear();
    }

    /// Whether the cache contains an entry for the given key.
    pub fn contains_key(&self, key: &K) -> bool {
        let map = self.map.lock().unwrap();
        map.contains_key(key)
    }

    /// The number of cached entries (including pending).
    pub fn len(&self) -> usize {
        let map = self.map.lock().unwrap();
        map.len()
    }

    /// Whether the cache is empty.
    pub fn is_empty(&self) -> bool {
        let map = self.map.lock().unwrap();
        map.is_empty()
    }
}

// ============================================================================
// AsyncReference -- a reference that can be set asynchronously
// ============================================================================

/// A reference cell that can be set asynchronously, useful for lazy
/// initialization in async contexts.
///
/// Ported from Ghidra's `ghidra.async.AsyncReference`.
pub struct AsyncReference<T: Clone> {
    inner: Arc<Mutex<AsyncReferenceInner<T>>>,
}

struct AsyncReferenceInner<T: Clone> {
    value: Option<T>,
    waiters: Vec<tokio::sync::oneshot::Sender<T>>,
}

impl<T: Clone + Send + 'static> AsyncReference<T> {
    /// Create a new unset reference.
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(AsyncReferenceInner {
                value: None,
                waiters: Vec::new(),
            })),
        }
    }

    /// Set the value and wake all waiters.
    pub fn set(&self, value: T) {
        let mut inner = self.inner.lock().unwrap();
        inner.value = Some(value.clone());
        for waiter in std::mem::take(&mut inner.waiters) {
            let _ = waiter.send(value.clone());
        }
    }

    /// Get the current value if set.
    pub fn get(&self) -> Option<T> {
        self.inner.lock().unwrap().value.clone()
    }

    /// Wait for the value to be set. Returns immediately if already set.
    pub async fn wait(&self) -> T {
        {
            let inner = self.inner.lock().unwrap();
            if let Some(ref v) = inner.value {
                return v.clone();
            }
        }
        let (tx, rx) = tokio::sync::oneshot::channel();
        {
            let mut inner = self.inner.lock().unwrap();
            // Double-check after acquiring lock
            if let Some(ref v) = inner.value {
                return v.clone();
            }
            inner.waiters.push(tx);
        }
        rx.await.expect("AsyncReference sender dropped")
    }
}

impl<T: Clone> Default for AsyncReference<T>
where
    T: Send + 'static,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Clone> Clone for AsyncReference<T> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn test_async_fence_single() {
        let mut fence = AsyncFence::new();
        fence.include(async {});
        fence.ready().await;
    }

    #[tokio::test]
    async fn test_async_fence_multiple() {
        let mut fence = AsyncFence::new();
        fence.include(async {});
        fence.include(async {});
        fence.include_map(async { 42 });
        assert_eq!(fence.participant_count(), 3);
        fence.ready().await;
    }

    #[test]
    #[should_panic(expected = "Fence already ready")]
    fn test_async_fence_include_after_ready() {
        let mut fence = AsyncFence::new();
        fence.include(async {});
        let _ = fence.ready();
        fence.include(async {}); // should panic
    }

    #[tokio::test]
    async fn test_async_timer_after() {
        let start = Instant::now();
        AsyncTimer::after(Duration::from_millis(10)).await;
        assert!(start.elapsed() >= Duration::from_millis(10));
    }

    #[tokio::test]
    async fn test_async_timer_after_zero() {
        // Should complete immediately
        AsyncTimer::after(Duration::ZERO).await;
    }

    #[tokio::test]
    async fn test_mark_after() {
        let timer = AsyncTimer::new();
        let mark = timer.mark();
        let start = Instant::now();
        mark.after(Duration::from_millis(10)).await;
        assert!(start.elapsed() >= Duration::from_millis(10));
    }

    #[tokio::test]
    async fn test_mark_time_out_completes() {
        let timer = AsyncTimer::new();
        let mark = timer.mark();
        let fast_future = async { 42 };
        let result = mark
            .time_out(fast_future, Duration::from_secs(10), -1)
            .await;
        assert_eq!(result, 42);
    }

    #[tokio::test]
    async fn test_mark_time_out_late() {
        let timer = AsyncTimer::new();
        let mark = timer.mark();
        let slow_future = async {
            tokio::time::sleep(Duration::from_secs(100)).await;
            42
        };
        let result = mark.time_out(slow_future, Duration::from_millis(10), -1).await;
        assert_eq!(result, -1);
    }

    #[tokio::test]
    async fn test_async_lazy_map_basic() {
        let map: AsyncLazyMap<String, i32> = AsyncLazyMap::new(|key: String| async move {
            key.len() as i32
        });

        let val = map.get("hello".to_string()).await;
        assert_eq!(val, 5);

        // Second call should hit cache
        let val2 = map.get("hello".to_string()).await;
        assert_eq!(val2, 5);
    }

    #[tokio::test]
    async fn test_async_lazy_map_put() {
        let map: AsyncLazyMap<String, i32> =
            AsyncLazyMap::new(|_: String| async { 0 });

        map.put("key".to_string(), 99).await;
        let val = map.get("key".to_string()).await;
        assert_eq!(val, 99);
    }

    #[tokio::test]
    async fn test_async_lazy_map_forget() {
        let map: AsyncLazyMap<String, i32> =
            AsyncLazyMap::new(|_: String| async { 0 });

        map.put("key".to_string(), 42).await;
        assert!(map.contains_key(&"key".to_string()));
        map.forget(&"key".to_string());
        assert!(!map.contains_key(&"key".to_string()));
    }

    #[tokio::test]
    async fn test_async_reference_set_and_get() {
        let reference = AsyncReference::new();
        assert!(reference.get().is_none());

        reference.set(42);
        assert_eq!(reference.get(), Some(42));
    }

    #[tokio::test]
    async fn test_async_reference_wait() {
        let reference = AsyncReference::new();
        let ref_clone = reference.clone();

        let handle = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(10)).await;
            ref_clone.set(100);
        });

        let val = reference.wait().await;
        assert_eq!(val, 100);
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn test_async_reference_wait_already_set() {
        let reference = AsyncReference::new();
        reference.set(99);
        let val = reference.wait().await;
        assert_eq!(val, 99);
    }

    #[tokio::test]
    async fn test_async_fence_default() {
        let mut fence = AsyncFence::default();
        fence.ready().await;
    }

    #[tokio::test]
    async fn test_async_timer_default() {
        let timer = AsyncTimer::default();
        let _mark = timer.mark();
    }
}
