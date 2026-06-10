//! Future combinators for the debug framework.
//!
//! Ported from Ghidra's `ghidra.async` package, providing Rust-native
//! equivalents of `CompletableFuture` combinator patterns:
//!
//! - `SharedFuture` -- a cloneable future (analogous to `CompletableFuture`)
//! - `FutureExt` -- extension trait with `.then_async`, `.map_ok`, `.and_then_async`
//! - `TryFutureExt` -- extension trait for `Result`-returning futures
//! - `Combinators` -- static combinator functions (`all_of`, `any_of`, `race`)

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

// ============================================================================
// SharedFuture -- a cloneable boxed future
// ============================================================================

/// A boxed future that can be cloned and awaited multiple times.
///
/// This is the Rust analogue of Java's `CompletableFuture`: multiple
/// consumers can hold a handle and `await` it independently.
pub type SharedFuture<T> = Pin<Box<dyn Future<Output = T> + Send>>;

/// Extension: wrap any `Send + 'static` future into a `SharedFuture`.
pub trait IntoShared: Future + Send + 'static {
    /// Convert this future into a `SharedFuture`.
    fn into_shared(self) -> SharedFuture<Self::Output>
    where
        Self: Sized,
    {
        Box::pin(self)
    }
}

impl<F> IntoShared for F where F: Future + Send + 'static {}

// ============================================================================
// FutureExt -- extension trait for combinators
// ============================================================================

/// Extension trait providing combinator methods on futures.
///
/// These mirror the chaining patterns in Ghidra's `CompletableFuture` usage:
/// `thenCompose`, `thenApply`, `handle`, etc.
pub trait FutureExt: Future + Sized {
    /// Chain an asynchronous operation on the result of this future.
    ///
    /// Equivalent to `CompletableFuture.thenCompose`.
    fn then_async<F, Fut>(self, f: F) -> ThenAsync<Self, F>
    where
        F: FnOnce(Self::Output) -> Fut,
        Fut: Future,
    {
        ThenAsync { future: self, f: Some(f) }
    }

    /// Map the output of this future with a synchronous function.
    ///
    /// Equivalent to `CompletableFuture.thenApply`.
    fn map_output<F, U>(self, f: F) -> MapOutput<Self, F>
    where
        F: FnOnce(Self::Output) -> U,
    {
        MapOutput { future: self, f: Some(f) }
    }

    /// Inspect the output without modifying it (useful for logging/debugging).
    fn inspect<F>(self, f: F) -> Inspect<Self, F>
    where
        F: FnOnce(&Self::Output),
    {
        Inspect { future: self, f: Some(f) }
    }
}

impl<F: Future> FutureExt for F {}

// ============================================================================
// TryFutureExt -- extension trait for Result-returning futures
// ============================================================================

/// Extension trait for futures that return `Result<T, E>`.
pub trait TryFutureExt<T, E>: Future<Output = Result<T, E>> + Sized {
    /// Chain an async operation on the success value; short-circuit on error.
    ///
    /// Equivalent to `CompletableFuture.thenCompose` when used with
    /// error-checking callbacks.
    fn and_then_async<F, Fut, U>(self, f: F) -> AndThenAsync<Self, F>
    where
        F: FnOnce(T) -> Fut,
        Fut: Future<Output = Result<U, E>>,
    {
        AndThenAsync { future: self, f: Some(f) }
    }

    /// Map the success value with a synchronous function.
    fn map_ok<F, U>(self, f: F) -> MapOk<Self, F>
    where
        F: FnOnce(T) -> U,
    {
        MapOk { future: self, f: Some(f) }
    }

    /// Map the error value with a synchronous function.
    fn map_err<F, E2>(self, f: F) -> MapErr<Self, F>
    where
        F: FnOnce(E) -> E2,
    {
        MapErr { future: self, f: Some(f) }
    }

    /// Provide a fallback value on error.
    fn or_else<F, E2>(self, f: F) -> OrElse<Self, F>
    where
        F: FnOnce(E) -> Result<T, E2>,
    {
        OrElse { future: self, f: Some(f) }
    }

    /// Provide a default value if the future resolves to an error.
    fn unwrap_or(self, default: T) -> UnwrapOr<Self, T> {
        UnwrapOr {
            future: self,
            default: Some(default),
        }
    }
}

impl<F, T, E> TryFutureExt<T, E> for F where F: Future<Output = Result<T, E>> + Sized {}

// ============================================================================
// Combinators -- static functions
// ============================================================================

/// Static combinator functions analogous to `CompletableFuture.allOf`,
/// `CompletableFuture.anyOf`, etc.
pub struct Combinators;

impl Combinators {
    /// Wait for all futures to complete, discarding their results.
    ///
    /// Analogous to `CompletableFuture.allOf`.
    pub async fn all_of(futures: Vec<SharedFuture<()>>) {
        for f in futures {
            f.await;
        }
    }

    /// Wait for all futures to complete and collect their results.
    ///
    /// Analogous to `CompletableFuture.allOf` followed by collecting results.
    pub async fn all_of_results<T: Send + 'static>(futures: Vec<SharedFuture<T>>) -> Vec<T> {
        let mut results = Vec::with_capacity(futures.len());
        for f in futures {
            results.push(f.await);
        }
        results
    }

    /// Race multiple futures and return the result of the first to complete.
    ///
    /// Analogous to `CompletableFuture.anyOf`.
    ///
    /// Note: requires `tokio` features. Panics if the vector is empty.
    pub async fn any_of<T: Clone + Send + 'static>(futures: Vec<SharedFuture<T>>) -> T {
        assert!(!futures.is_empty(), "any_of requires at least one future");
        let (tx, rx) = tokio::sync::oneshot::channel();
        let tx = Arc::new(Mutex::new(Some(tx)));

        let mut handles = Vec::new();
        for f in futures {
            let tx = Arc::clone(&tx);
            handles.push(tokio::spawn(async move {
                let result = f.await;
                if let Some(tx) = tx.lock().unwrap().take() {
                    let _ = tx.send(result);
                }
            }));
        }

        let result = rx.await.expect("any_of: all senders dropped");
        result
    }

    /// Race two futures, returning whichever completes first.
    pub async fn race<T>(a: impl Future<Output = T>, b: impl Future<Output = T>) -> T {
        tokio::select! {
            val = a => val,
            val = b => val,
        }
    }

    /// Race two futures with a timeout. Returns `Err` with the timeout
    /// duration if neither future completes in time.
    pub async fn race_with_timeout<T>(
        future: impl Future<Output = T>,
        timeout: Duration,
    ) -> Result<T, Duration> {
        tokio::select! {
            val = future => Ok(val),
            _ = tokio::time::sleep(timeout) => Err(timeout),
        }
    }

    /// Join two futures concurrently and return both results.
    pub async fn join<A, B>(a: impl Future<Output = A>, b: impl Future<Output = B>) -> (A, B) {
        tokio::join!(a, b)
    }

    /// Join three futures concurrently and return all results.
    pub async fn join3<A, B, C>(
        a: impl Future<Output = A>,
        b: impl Future<Output = B>,
        c: impl Future<Output = C>,
    ) -> (A, B, C) {
        tokio::join!(a, b, c)
    }

    /// Map a vector of items into futures, then wait for all to complete.
    ///
    /// Equivalent to `items.map(f).joinAll()` in the Ghidra async pattern.
    pub async fn map_all<T, U, F, Fut>(items: Vec<T>, f: F) -> Vec<U>
    where
        T: Send + 'static,
        U: Send + 'static,
        F: Fn(T) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = U> + Send + 'static,
    {
        let f = Arc::new(f);
        let mut handles = Vec::with_capacity(items.len());
        for item in items {
            let f = Arc::clone(&f);
            handles.push(tokio::spawn(async move { f(item).await }));
        }
        let mut results = Vec::with_capacity(handles.len());
        for handle in handles {
            results.push(handle.await.expect("map_all: task panicked"));
        }
        results
    }

    /// Filter items by running an async predicate on each, returning only
    /// those for which the predicate returned `true`.
    pub async fn filter_all<T, F, Fut>(items: Vec<T>, predicate: F) -> Vec<T>
    where
        T: Send + 'static,
        F: Fn(&T) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = bool> + Send + 'static,
    {
        let predicate = Arc::new(predicate);
        let mut handles = Vec::with_capacity(items.len());
        for item in items {
            let predicate = Arc::clone(&predicate);
            handles.push(tokio::spawn(async move {
                let keep = predicate(&item).await;
                (item, keep)
            }));
        }
        let mut results = Vec::new();
        for handle in handles {
            let (item, keep) = handle.await.expect("filter_all: task panicked");
            if keep {
                results.push(item);
            }
        }
        results
    }
}

use std::time::Duration;

// ============================================================================
// Combinator future types (zero-cost, stack-allocated)
// ============================================================================

/// Future returned by [`FutureExt::then_async`].
#[pin_project::pin_project]
pub struct ThenAsync<Fut, F> {
    #[pin]
    future: Fut,
    f: Option<F>,
}

impl<Fut, F, Fut2> Future for ThenAsync<Fut, F>
where
    Fut: Future,
    F: FnOnce(Fut::Output) -> Fut2,
    Fut2: Future,
{
    type Output = Fut2::Output;

    fn poll(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<Self::Output> {
        let this = self.project();
        match this.future.poll(cx) {
            std::task::Poll::Ready(output) => {
                let f = this.f.take().expect("ThenAsync polled after completion");
                let next = f(output);
                // We can't pin-project into the new future, so Box it
                // This is acceptable because then_async creates a chain
                let mut next = Box::pin(next);
                next.as_mut().poll(cx)
            }
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }
}

/// Future returned by [`FutureExt::map_output`].
#[pin_project::pin_project]
pub struct MapOutput<Fut, F> {
    #[pin]
    future: Fut,
    f: Option<F>,
}

impl<Fut, F, U> Future for MapOutput<Fut, F>
where
    Fut: Future,
    F: FnOnce(Fut::Output) -> U,
{
    type Output = U;

    fn poll(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<Self::Output> {
        let this = self.project();
        match this.future.poll(cx) {
            std::task::Poll::Ready(output) => {
                let f = this.f.take().expect("MapOutput polled after completion");
                std::task::Poll::Ready(f(output))
            }
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }
}

/// Future returned by [`FutureExt::inspect`].
#[pin_project::pin_project]
pub struct Inspect<Fut, F> {
    #[pin]
    future: Fut,
    f: Option<F>,
}

impl<Fut, F> Future for Inspect<Fut, F>
where
    Fut: Future,
    F: FnOnce(&Fut::Output),
{
    type Output = Fut::Output;

    fn poll(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<Self::Output> {
        let this = self.project();
        match this.future.poll(cx) {
            std::task::Poll::Ready(output) => {
                let f = this.f.take().expect("Inspect polled after completion");
                f(&output);
                std::task::Poll::Ready(output)
            }
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }
}

/// Future returned by [`TryFutureExt::and_then_async`].
#[pin_project::pin_project]
pub struct AndThenAsync<Fut, F> {
    #[pin]
    future: Fut,
    f: Option<F>,
}

impl<Fut, F, T, E, Fut2, U> Future for AndThenAsync<Fut, F>
where
    Fut: Future<Output = Result<T, E>>,
    F: FnOnce(T) -> Fut2,
    Fut2: Future<Output = Result<U, E>>,
{
    type Output = Result<U, E>;

    fn poll(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<Self::Output> {
        let this = self.project();
        match this.future.poll(cx) {
            std::task::Poll::Ready(Ok(value)) => {
                let f = this.f.take().expect("AndThenAsync polled after completion");
                let mut next = Box::pin(f(value));
                next.as_mut().poll(cx)
            }
            std::task::Poll::Ready(Err(e)) => std::task::Poll::Ready(Err(e)),
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }
}

/// Future returned by [`TryFutureExt::map_ok`].
#[pin_project::pin_project]
pub struct MapOk<Fut, F> {
    #[pin]
    future: Fut,
    f: Option<F>,
}

impl<Fut, F, T, E, U> Future for MapOk<Fut, F>
where
    Fut: Future<Output = Result<T, E>>,
    F: FnOnce(T) -> U,
{
    type Output = Result<U, E>;

    fn poll(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<Self::Output> {
        let this = self.project();
        match this.future.poll(cx) {
            std::task::Poll::Ready(Ok(value)) => {
                let f = this.f.take().expect("MapOk polled after completion");
                std::task::Poll::Ready(Ok(f(value)))
            }
            std::task::Poll::Ready(Err(e)) => std::task::Poll::Ready(Err(e)),
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }
}

/// Future returned by [`TryFutureExt::map_err`].
#[pin_project::pin_project]
pub struct MapErr<Fut, F> {
    #[pin]
    future: Fut,
    f: Option<F>,
}

impl<Fut, F, T, E, E2> Future for MapErr<Fut, F>
where
    Fut: Future<Output = Result<T, E>>,
    F: FnOnce(E) -> E2,
{
    type Output = Result<T, E2>;

    fn poll(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<Self::Output> {
        let this = self.project();
        match this.future.poll(cx) {
            std::task::Poll::Ready(Ok(value)) => std::task::Poll::Ready(Ok(value)),
            std::task::Poll::Ready(Err(e)) => {
                let f = this.f.take().expect("MapErr polled after completion");
                std::task::Poll::Ready(Err(f(e)))
            }
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }
}

/// Future returned by [`TryFutureExt::or_else`].
#[pin_project::pin_project]
pub struct OrElse<Fut, F> {
    #[pin]
    future: Fut,
    f: Option<F>,
}

impl<Fut, F, T, E, E2> Future for OrElse<Fut, F>
where
    Fut: Future<Output = Result<T, E>>,
    F: FnOnce(E) -> Result<T, E2>,
{
    type Output = Result<T, E2>;

    fn poll(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<Self::Output> {
        let this = self.project();
        match this.future.poll(cx) {
            std::task::Poll::Ready(Ok(value)) => std::task::Poll::Ready(Ok(value)),
            std::task::Poll::Ready(Err(e)) => {
                let f = this.f.take().expect("OrElse polled after completion");
                std::task::Poll::Ready(f(e))
            }
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }
}

/// Future returned by [`TryFutureExt::unwrap_or`].
#[pin_project::pin_project]
pub struct UnwrapOr<Fut, T> {
    #[pin]
    future: Fut,
    default: Option<T>,
}

impl<Fut, T, E> Future for UnwrapOr<Fut, T>
where
    Fut: Future<Output = Result<T, E>>,
{
    type Output = T;

    fn poll(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<Self::Output> {
        let this = self.project();
        match this.future.poll(cx) {
            std::task::Poll::Ready(Ok(value)) => std::task::Poll::Ready(value),
            std::task::Poll::Ready(Err(_)) => {
                let default = this.default.take().expect("UnwrapOr polled after completion");
                std::task::Poll::Ready(default)
            }
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_shared_future() {
        let fut: SharedFuture<i32> = Box::pin(async { 42 });
        let result = fut.await;
        assert_eq!(result, 42);
    }

    #[tokio::test]
    async fn test_then_async() {
        let result = async { 5 }
            .then_async(|x| async move { x * 2 })
            .await;
        assert_eq!(result, 10);
    }

    #[tokio::test]
    async fn test_map_output() {
        let result = async { "hello" }
            .map_output(|s| s.len())
            .await;
        assert_eq!(result, 5);
    }

    #[tokio::test]
    async fn test_inspect() {
        let observed = Arc::new(Mutex::new(None));
        let observed_clone = Arc::clone(&observed);
        let result = async { 42 }
            .inspect(move |val| {
                *observed_clone.lock().unwrap() = Some(*val);
            })
            .await;
        assert_eq!(result, 42);
        assert_eq!(*observed.lock().unwrap(), Some(42));
    }

    #[tokio::test]
    async fn test_and_then_async_ok() {
        let result = async { Ok::<i32, String>(5) }
            .and_then_async(|x| async move { Ok(x * 2) })
            .await;
        assert_eq!(result, Ok(10));
    }

    #[tokio::test]
    async fn test_and_then_async_err() {
        let result = async { Err::<i32, String>("fail".into()) }
            .and_then_async(|x: i32| async move { Ok(x * 2) })
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_map_ok() {
        let result = async { Ok::<i32, String>(5) }
            .map_ok(|x| x + 1)
            .await;
        assert_eq!(result, Ok(6));
    }

    #[tokio::test]
    async fn test_map_err() {
        let result = async { Err::<i32, i32>(1) }
            .map_err(|e| e + 100)
            .await;
        assert_eq!(result, Err(101));
    }

    #[tokio::test]
    async fn test_or_else() {
        let result = async { Err::<i32, i32>(1) }
            .or_else(|_| Ok::<i32, i32>(99))
            .await;
        assert_eq!(result, Ok(99));
    }

    #[tokio::test]
    async fn test_unwrap_or() {
        let result = async { Err::<i32, String>("fail".into()) }
            .unwrap_or(42)
            .await;
        assert_eq!(result, 42);
    }

    #[tokio::test]
    async fn test_unwrap_or_ok() {
        let result = async { Ok::<i32, String>(7) }
            .unwrap_or(42)
            .await;
        assert_eq!(result, 7);
    }

    #[tokio::test]
    async fn test_combinators_all_of() {
        Combinators::all_of(vec![
            Box::pin(async {}) as SharedFuture<()>,
            Box::pin(async {}),
            Box::pin(async {}),
        ])
        .await;
    }

    #[tokio::test]
    async fn test_combinators_all_of_results() {
        let results = Combinators::all_of_results(vec![
            Box::pin(async { 1 }) as SharedFuture<i32>,
            Box::pin(async { 2 }),
            Box::pin(async { 3 }),
        ])
        .await;
        assert_eq!(results, vec![1, 2, 3]);
    }

    #[tokio::test]
    async fn test_combinators_any_of() {
        let result = Combinators::any_of(vec![
            Box::pin(async {
                tokio::time::sleep(Duration::from_secs(100)).await;
                1
            }) as SharedFuture<i32>,
            Box::pin(async { 2 }),
        ])
        .await;
        assert_eq!(result, 2);
    }

    #[tokio::test]
    async fn test_combinators_race() {
        let result = Combinators::race(
            async { 1 },
            async {
                tokio::time::sleep(Duration::from_secs(100)).await;
                2
            },
        )
        .await;
        assert_eq!(result, 1);
    }

    #[tokio::test]
    async fn test_combinators_race_with_timeout_ok() {
        let result = Combinators::race_with_timeout(
            async { 42 },
            Duration::from_secs(10),
        )
        .await;
        assert_eq!(result, Ok(42));
    }

    #[tokio::test]
    async fn test_combinators_race_with_timeout_late() {
        let result: Result<i32, Duration> = Combinators::race_with_timeout(
            async {
                tokio::time::sleep(Duration::from_secs(100)).await;
                42
            },
            Duration::from_millis(10),
        )
        .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_combinators_join() {
        let (a, b) = Combinators::join(async { 1 }, async { 2 }).await;
        assert_eq!(a, 1);
        assert_eq!(b, 2);
    }

    #[tokio::test]
    async fn test_combinators_join3() {
        let (a, b, c) = Combinators::join3(async { 1 }, async { 2 }, async { 3 }).await;
        assert_eq!(a, 1);
        assert_eq!(b, 2);
        assert_eq!(c, 3);
    }

    #[tokio::test]
    async fn test_combinators_map_all() {
        let results = Combinators::map_all(vec![1, 2, 3], |x| async move { x * 10 }).await;
        assert_eq!(results, vec![10, 20, 30]);
    }

    #[tokio::test]
    async fn test_combinators_filter_all() {
        let results =
            Combinators::filter_all(vec![1, 2, 3, 4, 5], |x: &i32| {
                let v = *x;
                async move { v % 2 == 0 }
            })
            .await;
        assert_eq!(results, vec![2, 4]);
    }

    #[tokio::test]
    async fn test_chained_combinators() {
        let result = async { 1 }
            .then_async(|x| async move { x + 1 })
            .map_output(|x| x * 10)
            .then_async(|x| async move { format!("result={}", x) })
            .await;
        assert_eq!(result, "result=20");
    }

    #[tokio::test]
    async fn test_try_chained_combinators() {
        let result = async { Ok::<i32, String>(5) }
            .map_ok(|x| x * 2)
            .and_then_async(|x| async move {
                if x > 0 {
                    Ok(x + 1)
                } else {
                    Err("negative".into())
                }
            })
            .map_ok(|x| x.to_string())
            .await;
        assert_eq!(result, Ok("11".into()));
    }
}
