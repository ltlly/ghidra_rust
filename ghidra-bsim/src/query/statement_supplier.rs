//! Port of `StatementSupplier` from `ghidra.features.bsim.query.client.tables`.
//!
//! A functional trait for supplying SQL statement instances. Used by
//! `CachedStatement` to lazily create prepared statements.

/// Trait for supplying SQL statement instances on demand.
///
/// Ports `StatementSupplier<T>` from Ghidra's Java source. In Java this is
/// a `@FunctionalInterface`; in Rust we use a trait with a single method.
pub trait StatementSupplier: Send + Sync {
    /// The type of statement produced.
    type Statement;

    /// Create and return a new statement instance.
    fn supply(&self) -> Self::Statement;
}

/// A closure-based statement supplier.
#[derive(Debug)]
pub struct ClosureSupplier<F> {
    closure: F,
}

impl<F> ClosureSupplier<F> {
    /// Create a new closure-based supplier.
    pub fn new(closure: F) -> Self {
        Self { closure }
    }
}

impl<F, T> StatementSupplier for ClosureSupplier<F>
where
    F: Fn() -> T + Send + Sync,
{
    type Statement = T;

    fn supply(&self) -> T {
        (self.closure)()
    }
}

/// Create a `StatementSupplier` from a closure.
pub fn statement_supplier<F, T>(f: F) -> ClosureSupplier<F>
where
    F: Fn() -> T + Send + Sync,
{
    ClosureSupplier::new(f)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_closure_supplier() {
        let supplier = statement_supplier(|| 42);
        assert_eq!(supplier.supply(), 42);
        assert_eq!(supplier.supply(), 42); // can be called multiple times
    }

    #[test]
    fn test_closure_supplier_string() {
        let supplier = statement_supplier(|| "test_statement".to_string());
        assert_eq!(supplier.supply(), "test_statement");
    }
}
