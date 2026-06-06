//! Functional interfaces and callback types.
//!
//! Port of `utility.function`: Callback, ExceptionalCallback,
//! ExceptionalConsumer, ExceptionalFunction, ExceptionalSupplier,
//! TerminatingConsumer.

use std::sync::Arc;

/// A generic callback that takes no arguments and returns nothing.
///
/// Port of `utility.function.Callback`.
pub type Callback = Arc<dyn Fn() + Send + Sync>;

/// Create a no-op callback.
pub fn dummy_callback() -> Callback {
    Arc::new(|| {})
}

/// Return the given callback or a dummy if it is None.
pub fn dummy_if_none(c: Option<Callback>) -> Callback {
    c.unwrap_or_else(dummy_callback)
}

/// A callback that may return an error.
///
/// Port of `utility.function.ExceptionalCallback`.
pub trait ExceptionalCallback: Send + Sync {
    /// The error type produced by this callback.
    type Error: std::fmt::Display + std::fmt::Debug;

    /// Call the callback.
    fn call(&self) -> Result<(), Self::Error>;
}

/// A consumer that may return an error.
///
/// Port of `utility.function.ExceptionalConsumer`.
pub trait ExceptionalConsumer<T>: Send + Sync {
    /// The error type produced by this consumer.
    type Error: std::fmt::Display + std::fmt::Debug;

    /// Consume the given value.
    fn accept(&self, value: T) -> Result<(), Self::Error>;
}

/// A function that may return an error.
///
/// Port of `utility.function.ExceptionalFunction`.
pub trait ExceptionalFunction<T>: Send + Sync {
    /// The output type.
    type Output;
    /// The error type produced by this function.
    type Error: std::fmt::Display + std::fmt::Debug;

    /// Apply the function.
    fn apply(&self, value: T) -> Result<Self::Output, Self::Error>;
}

/// A supplier that may return an error.
///
/// Port of `utility.function.ExceptionalSupplier`.
pub trait ExceptionalSupplier<T>: Send + Sync {
    /// The error type produced by this supplier.
    type Error: std::fmt::Display + std::fmt::Debug;

    /// Supply a value.
    fn get(&self) -> Result<T, Self::Error>;
}

/// A consumer that can terminate the processing stream.
///
/// Port of `utility.function.TerminatingConsumer`.
pub trait TerminatingConsumer<T>: Send + Sync {
    /// Accept a value. Returns true if processing should continue.
    fn accept(&self, value: T) -> bool;
}

/// A dummy placeholder type.
///
/// Port of `utility.function.Dummy`.
#[derive(Debug, Clone, Copy, Default)]
pub struct Dummy;

impl Dummy {
    /// Create a new Dummy instance.
    pub fn new() -> Self {
        Self
    }
}

/// Wrap a closure as an ExceptionalCallback.
pub struct FnCallback<F: Fn() + Send + Sync>(pub F);

impl<F: Fn() + Send + Sync> ExceptionalCallback for FnCallback<F> {
    type Error = std::io::Error;

    fn call(&self) -> Result<(), Self::Error> {
        (self.0)();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dummy_callback() {
        let cb = dummy_callback();
        cb(); // Should not panic
    }

    #[test]
    fn test_dummy_if_none() {
        let cb = dummy_if_none(None);
        cb();

        let real: Callback = Arc::new(|| {});
        let cb = dummy_if_none(Some(real));
        cb();
    }

    #[test]
    fn test_fn_callback() {
        let called = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let c = called.clone();
        let cb = FnCallback(move || {
            c.store(true, std::sync::atomic::Ordering::Relaxed);
        });
        assert!(cb.call().is_ok());
        assert!(called.load(std::sync::atomic::Ordering::Relaxed));
    }

    #[test]
    fn test_dummy_type() {
        let d = Dummy::new();
        assert_eq!(format!("{:?}", d), "Dummy");
    }
}
