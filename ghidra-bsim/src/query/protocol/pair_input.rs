//! PairInput -- identifiers for a pair of functions for comparison.
//!
//! Ports `ghidra.features.bsim.query.protocol.PairInput`.

pub use super::core::PairInputData as PairInput;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::query::protocol::{ExeSpecifier, FunctionEntryData};

    #[test]
    fn test_pair_input_new() {
        let pair = PairInput::new(
            ExeSpecifier::new("a.exe"),
            FunctionEntryData::new("funcA", 0x100),
            ExeSpecifier::new("b.exe"),
            FunctionEntryData::new("funcB", 0x200),
        );
        assert_eq!(pair.exec_a.exe_name, "a.exe");
        assert_eq!(pair.func_a.func_name, "funcA");
        assert_eq!(pair.exec_b.exe_name, "b.exe");
        assert_eq!(pair.func_b.func_name, "funcB");
    }

    #[test]
    fn test_pair_input_serialization() {
        let pair = PairInput::new(
            ExeSpecifier::new("x.exe"),
            FunctionEntryData::new("main", 0x1000),
            ExeSpecifier::new("y.exe"),
            FunctionEntryData::new("main", 0x2000),
        );
        let json = serde_json::to_string(&pair).unwrap();
        assert!(json.contains("x.exe"));
        assert!(json.contains("y.exe"));
        let back: PairInput = serde_json::from_str(&json).unwrap();
        assert_eq!(back.exec_a.exe_name, "x.exe");
        assert_eq!(back.func_b.func_name, "main");
    }

    #[test]
    fn test_pair_input_clone() {
        let pair = PairInput::new(
            ExeSpecifier::new("a.exe"),
            FunctionEntryData::new("f1", 0x100),
            ExeSpecifier::new("b.exe"),
            FunctionEntryData::new("f2", 0x200),
        );
        let cloned = pair.clone();
        assert_eq!(cloned.exec_a.exe_name, "a.exe");
    }

    #[test]
    fn test_pair_input_with_md5() {
        let pair = PairInput::new(
            ExeSpecifier::from_md5("aaa"),
            FunctionEntryData::new("f1", 0x100),
            ExeSpecifier::from_md5("bbb"),
            FunctionEntryData::new("f2", 0x200),
        );
        assert_eq!(pair.exec_a.md5, "aaa");
        assert_eq!(pair.exec_b.md5, "bbb");
    }

    #[test]
    fn test_pair_input_same_exe() {
        let pair = PairInput::new(
            ExeSpecifier::new("same.exe"),
            FunctionEntryData::new("func_a", 0x100),
            ExeSpecifier::new("same.exe"),
            FunctionEntryData::new("func_b", 0x200),
        );
        assert_eq!(pair.exec_a, pair.exec_b);
    }
}
