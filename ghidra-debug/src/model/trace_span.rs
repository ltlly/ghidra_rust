//! TraceSpan - a trace reference paired with a lifespan.

use super::Lifespan;

/// Trait for objects that are associated with a trace and have a temporal span.
pub trait TraceSpan {
    /// Get the lifespan (temporal range) of this object.
    fn span(&self) -> Lifespan;

    /// Whether this span contains the given snap.
    fn contains_snap(&self, snap: i64) -> bool {
        self.span().contains(snap)
    }

    /// Whether this span intersects the given lifespan.
    fn intersects(&self, other: &Lifespan) -> bool {
        self.span().intersects(other)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestSpan {
        lifespan: Lifespan,
    }

    impl TraceSpan for TestSpan {
        fn span(&self) -> Lifespan {
            self.lifespan
        }
    }

    #[test]
    fn test_trace_span() {
        let ts = TestSpan {
            lifespan: Lifespan::span(0, 10),
        };
        assert!(ts.contains_snap(5));
        assert!(!ts.contains_snap(15));
        assert!(ts.intersects(&Lifespan::span(5, 20)));
    }
}
