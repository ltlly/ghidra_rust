//! Port of `SFResultsUpdateListener` interface.
//!
//! Ports `ghidra.features.bsim.query.facade.SFResultsUpdateListener`.
//!
//! Provides a callback interface for receiving incremental query results from
//! BSim database queries. Implementations are called as partial results arrive
//! and again with the final accumulated result.

use super::protocol::QueryResponseRecord;

/// A listener that is called as incremental results arrive from database queries.
///
/// The results given to this listener are always a subset of the complete results.
/// Implementations can safely downcast the response based on the query type being performed.
///
/// Port of `ghidra.features.bsim.query.facade.SFResultsUpdateListener<R>`.
#[allow(dead_code)]
pub trait SFResultsUpdateListener: Send + Sync {
    /// The final result type produced by this listener.
    type FinalResult;

    /// Called as incremental results arrive from database queries.
    ///
    /// The results given to this listener are always a subset of the complete
    /// results -- they are not comprehensive. Consumer should be able to safely
    /// cast the response based upon the type of query being performed.
    ///
    /// # Arguments
    /// * `partial_response` - A partial result record with the recently received results.
    fn result_added(&mut self, partial_response: &QueryResponseRecord);

    /// Callback to supply the final accumulated result.
    ///
    /// # Arguments
    /// * `result` - The accumulated query result, or `None` if a failure occurred
    ///   which prevented results from being returned.
    fn set_final_result(&mut self, result: Option<Self::FinalResult>);

    /// Returns `true` if this listener has received its final result.
    fn is_complete(&self) -> bool {
        false
    }
}

/// A simple collector that accumulates all partial results into a `Vec`.
///
/// This is a convenience implementation of [`SFResultsUpdateListener`] that
/// collects all partial response records and the final result.
#[derive(Debug, Clone)]
pub struct CollectingResultsListener<R> {
    /// All partial response records received so far.
    pub partial_results: Vec<QueryResponseRecord>,
    /// The final accumulated result, if received.
    pub final_result: Option<R>,
    /// Whether the final result has been set.
    complete: bool,
}

impl<R> CollectingResultsListener<R> {
    /// Create a new empty collecting listener.
    pub fn new() -> Self {
        Self {
            partial_results: Vec::new(),
            final_result: None,
            complete: false,
        }
    }

    /// Get all collected partial results.
    pub fn partial_results(&self) -> &[QueryResponseRecord] {
        &self.partial_results
    }

    /// Get the final result, if available.
    pub fn final_result(&self) -> Option<&R> {
        self.final_result.as_ref()
    }

    /// Consume the listener and return the final result.
    pub fn into_final_result(self) -> Option<R> {
        self.final_result
    }

    /// Number of partial results received.
    pub fn partial_count(&self) -> usize {
        self.partial_results.len()
    }
}

impl<R: Send + Sync> SFResultsUpdateListener for CollectingResultsListener<R> {
    type FinalResult = R;

    fn result_added(&mut self, partial_response: &QueryResponseRecord) {
        self.partial_results.push(partial_response.clone());
    }

    fn set_final_result(&mut self, result: Option<Self::FinalResult>) {
        self.final_result = result;
        self.complete = true;
    }

    fn is_complete(&self) -> bool {
        self.complete
    }
}

impl<R> Default for CollectingResultsListener<R> {
    fn default() -> Self {
        Self::new()
    }
}

/// A no-op listener that discards all results.
///
/// Useful when only the final result is needed or when results are
/// streamed to an external system via side effects.
#[derive(Debug, Clone, Default)]
pub struct NoOpResultsListener<R> {
    /// The final result, if received.
    pub final_result: Option<R>,
    complete: bool,
}

impl<R> NoOpResultsListener<R> {
    /// Create a new no-op listener.
    pub fn new() -> Self {
        Self {
            final_result: None,
            complete: false,
        }
    }
}

impl<R: Send + Sync> SFResultsUpdateListener for NoOpResultsListener<R> {
    type FinalResult = R;

    fn result_added(&mut self, _partial_response: &QueryResponseRecord) {
        // Intentionally discard partial results.
    }

    fn set_final_result(&mut self, result: Option<Self::FinalResult>) {
        self.final_result = result;
        self.complete = true;
    }

    fn is_complete(&self) -> bool {
        self.complete
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_collecting_listener_basic() {
        let mut listener = CollectingResultsListener::<String>::new();
        assert!(!listener.is_complete());
        assert_eq!(listener.partial_count(), 0);

        let record = QueryResponseRecord::new("test_query");
        listener.result_added(&record);
        assert_eq!(listener.partial_count(), 1);

        listener.set_final_result(Some("done".to_string()));
        assert!(listener.is_complete());
        assert_eq!(listener.final_result(), Some(&"done".to_string()));
    }

    #[test]
    fn test_collecting_listener_none_result() {
        let mut listener = CollectingResultsListener::<String>::new();
        listener.set_final_result(None);
        assert!(listener.is_complete());
        assert!(listener.final_result().is_none());
    }

    #[test]
    fn test_collecting_listener_into_final() {
        let mut listener = CollectingResultsListener::<i32>::new();
        listener.set_final_result(Some(42));
        let result = listener.into_final_result();
        assert_eq!(result, Some(42));
    }

    #[test]
    fn test_noop_listener_discards_partial() {
        let mut listener = NoOpResultsListener::<String>::new();
        let record = QueryResponseRecord::new("test_query");
        listener.result_added(&record);
        listener.result_added(&record);
        assert!(!listener.is_complete());
        assert!(listener.final_result.is_none());

        listener.set_final_result(Some("final".to_string()));
        assert!(listener.is_complete());
        assert_eq!(listener.final_result.as_deref(), Some("final"));
    }

    #[test]
    fn test_collecting_listener_default() {
        let listener = CollectingResultsListener::<i32>::default();
        assert!(listener.partial_results.is_empty());
        assert!(listener.final_result.is_none());
    }
}
