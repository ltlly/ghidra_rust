//! FunctionEntry -- identifies a function within an executable.
//!
//! Ports `ghidra.features.bsim.query.protocol.FunctionEntry`.

pub use super::core::FunctionEntryData as FunctionEntry;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_function_entry_new() {
        let entry = FunctionEntry::new("main", 0x1000);
        assert_eq!(entry.func_name, "main");
        assert_eq!(entry.address, 0x1000);
    }

    #[test]
    fn test_function_entry_serialization() {
        let entry = FunctionEntry::new("printf", 0x4000);
        let json = serde_json::to_string(&entry).unwrap();
        assert!(json.contains("printf"));
        assert!(json.contains("16384")); // 0x4000 in decimal
        let back: FunctionEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(back.func_name, "printf");
        assert_eq!(back.address, 0x4000);
    }

    #[test]
    fn test_function_entry_clone() {
        let entry = FunctionEntry::new("malloc", 0x8000);
        let cloned = entry.clone();
        assert_eq!(cloned.func_name, "malloc");
        assert_eq!(cloned.address, 0x8000);
    }

    #[test]
    fn test_function_entry_debug() {
        let entry = FunctionEntry::new("free", 0x2000);
        let debug = format!("{:?}", entry);
        assert!(debug.contains("free"));
        assert!(debug.contains("8192")); // 0x2000 in decimal
    }

    #[test]
    fn test_function_entry_empty_name() {
        let entry = FunctionEntry::new("", 0);
        assert!(entry.func_name.is_empty());
        assert_eq!(entry.address, 0);
    }

    #[test]
    fn test_function_entry_max_address() {
        let entry = FunctionEntry::new("func", u64::MAX);
        assert_eq!(entry.address, u64::MAX);
    }
}
