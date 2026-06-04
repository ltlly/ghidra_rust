//! TraceThread - a thread in a trace.

use serde::{Deserialize, Serialize};

use super::Lifespan;
use super::execution_state::TraceExecutionState;

/// A thread entry in a trace database.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceThread {
    /// Unique key identifying this thread across all time.
    pub key: i64,
    /// Path name of the thread (e.g. "Threads[1234]").
    pub path: String,
    /// TID as assigned by the target's platform.
    pub tid: Option<i64>,
    /// Current name.
    pub name: String,
    /// User comment.
    pub comment: Option<String>,
    /// The lifespan during which this thread exists.
    pub lifespan: Lifespan,
    /// Execution state of the thread.
    pub execution_state: TraceExecutionState,
}

impl TraceThread {
    /// Create a new thread entry.
    pub fn new(key: i64, path: impl Into<String>, name: impl Into<String>, snap: i64) -> Self {
        Self {
            key,
            path: path.into(),
            tid: None,
            name: name.into(),
            comment: None,
            lifespan: Lifespan::now_on(snap),
            execution_state: TraceExecutionState::Unknown,
        }
    }

    /// Set the TID.
    pub fn with_tid(mut self, tid: i64) -> Self {
        self.tid = Some(tid);
        self
    }

    /// Whether this thread is valid at the given snap.
    pub fn is_valid(&self, snap: i64) -> bool {
        self.lifespan.contains(snap)
    }

    /// Whether the thread is alive for any part of the given span.
    pub fn is_alive(&self, span: &Lifespan) -> bool {
        self.lifespan.intersects(span)
    }

    /// End the thread's life at the given snap.
    pub fn remove(&mut self, snap: i64) {
        self.lifespan = self.lifespan.with_max(snap);
    }
}

/// A process entry in a trace database.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceProcess {
    /// Unique key identifying this process.
    pub key: i64,
    /// Path name of the process.
    pub path: String,
    /// PID as assigned by the target's platform.
    pub pid: Option<i64>,
    /// Current name.
    pub name: String,
    /// The lifespan during which this process exists.
    pub lifespan: Lifespan,
}

impl TraceProcess {
    /// Create a new process entry.
    pub fn new(key: i64, path: impl Into<String>, name: impl Into<String>, snap: i64) -> Self {
        Self {
            key,
            path: path.into(),
            pid: None,
            name: name.into(),
            lifespan: Lifespan::now_on(snap),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_thread_validity() {
        let t = TraceThread::new(1, "Threads[100]", "main", 0);
        assert!(t.is_valid(0));
        assert!(t.is_valid(5));
        assert!(!t.is_valid(-1));
    }

    #[test]
    fn test_thread_remove() {
        let mut t = TraceThread::new(1, "Threads[100]", "main", 0);
        t.remove(5);
        assert!(t.is_valid(5));
        assert!(!t.is_valid(6));
    }

    #[test]
    fn test_thread_is_alive() {
        let mut t = TraceThread::new(1, "Threads[100]", "main", 0);
        assert!(t.is_alive(&Lifespan::span(0, 10)));
        t.remove(50);
        assert!(t.is_alive(&Lifespan::span(0, 10)));
        assert!(!t.is_alive(&Lifespan::span(100, 200)));
    }

    #[test]
    fn test_process() {
        let p = TraceProcess::new(1, "Processes[789]", "myapp", 0);
        assert_eq!(p.key, 1);
        assert!(p.lifespan.contains(0));
    }
}
