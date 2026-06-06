//! QueryPair -- query for comparing a pair of functions.
//!
//! Ports `ghidra.features.bsim.query.protocol.QueryPair`.

pub use super::core::QueryPair;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::query::protocol::{ExeSpecifier, FunctionEntryData, PairInputData};

    #[test]
    fn test_query_pair_new() {
        let pair = PairInputData::new(
            ExeSpecifier::new("a.exe"),
            FunctionEntryData::new("funcA", 0x100),
            ExeSpecifier::new("b.exe"),
            FunctionEntryData::new("funcB", 0x200),
        );
        let qp = QueryPair::new(pair);
        assert_eq!(qp.pair.exec_a.exe_name, "a.exe");
        assert_eq!(qp.pair.func_b.func_name, "funcB");
    }

    #[test]
    fn test_query_pair_clone() {
        let pair = PairInputData::new(
            ExeSpecifier::new("a.exe"),
            FunctionEntryData::new("f1", 0x100),
            ExeSpecifier::new("b.exe"),
            FunctionEntryData::new("f2", 0x200),
        );
        let qp = QueryPair::new(pair);
        let cloned = qp.clone();
        assert_eq!(cloned.pair.exec_a.exe_name, "a.exe");
    }

    #[test]
    fn test_query_pair_debug() {
        let pair = PairInputData::new(
            ExeSpecifier::new("a.exe"),
            FunctionEntryData::new("f1", 0x100),
            ExeSpecifier::new("b.exe"),
            FunctionEntryData::new("f2", 0x200),
        );
        let qp = QueryPair::new(pair);
        let debug = format!("{:?}", qp);
        assert!(debug.contains("a.exe"));
    }

    #[test]
    fn test_query_pair_same_exe() {
        let pair = PairInputData::new(
            ExeSpecifier::new("same.exe"),
            FunctionEntryData::new("func_a", 0x100),
            ExeSpecifier::new("same.exe"),
            FunctionEntryData::new("func_b", 0x200),
        );
        let qp = QueryPair::new(pair);
        assert_eq!(qp.pair.exec_a, qp.pair.exec_b);
    }
}
