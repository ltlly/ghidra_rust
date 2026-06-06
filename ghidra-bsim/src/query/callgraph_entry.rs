//! A callgraph entry representing a single call relationship.
//!
//! Ports Ghidra's `ghidra.features.bsim.query.description.CallgraphEntry`.

/// Represents a single entry in a function's callgraph: a destination function
/// and the location hash of the callsite.
#[derive(Debug, Clone)]
pub struct CallgraphEntry {
    /// The function being called (destination).
    pub dest_function_name: String,
    /// The address of the destination function.
    pub dest_address: u64,
    /// The MD5 of the executable containing the destination function.
    pub dest_exe_md5: String,
    /// Location hash of the callsite.
    pub lochash: i32,
}

impl CallgraphEntry {
    /// Create a new callgraph entry.
    pub fn new(dest_function_name: String, dest_address: u64, lochash: i32) -> Self {
        Self {
            dest_function_name,
            dest_address,
            dest_exe_md5: String::new(),
            lochash,
        }
    }

    /// Create a callgraph entry with executable info.
    pub fn with_exe(
        dest_function_name: String,
        dest_address: u64,
        dest_exe_md5: String,
        lochash: i32,
    ) -> Self {
        Self {
            dest_function_name,
            dest_address,
            dest_exe_md5,
            lochash,
        }
    }

    /// Get the destination function name.
    pub fn function_name(&self) -> &str {
        &self.dest_function_name
    }

    /// Get the destination function address.
    pub fn address(&self) -> u64 {
        self.dest_address
    }

    /// Get the location hash of the callsite.
    pub fn local_hash(&self) -> i32 {
        self.lochash
    }

    /// Get the destination executable MD5.
    pub fn exe_md5(&self) -> &str {
        &self.dest_exe_md5
    }
}

impl Default for CallgraphEntry {
    fn default() -> Self {
        Self::new(String::new(), 0, 0)
    }
}

impl PartialEq for CallgraphEntry {
    fn eq(&self, other: &Self) -> bool {
        self.dest_function_name == other.dest_function_name
            && self.dest_address == other.dest_address
            && self.lochash == other.lochash
    }
}

impl Eq for CallgraphEntry {}

impl PartialOrd for CallgraphEntry {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for CallgraphEntry {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.dest_function_name
            .cmp(&other.dest_function_name)
            .then_with(|| self.dest_address.cmp(&other.dest_address))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new() {
        let e = CallgraphEntry::new("callee".to_string(), 0x2000, 0xABCD);
        assert_eq!(e.function_name(), "callee");
        assert_eq!(e.address(), 0x2000);
        assert_eq!(e.local_hash(), 0xABCD);
    }

    #[test]
    fn test_with_exe() {
        let e = CallgraphEntry::with_exe(
            "func_b".to_string(),
            0x3000,
            "md5hash".to_string(),
            0x1234,
        );
        assert_eq!(e.exe_md5(), "md5hash");
    }

    #[test]
    fn test_ordering() {
        let a = CallgraphEntry::new("aaa".to_string(), 0x1000, 0);
        let b = CallgraphEntry::new("bbb".to_string(), 0x1000, 0);
        assert!(a < b);
    }

    #[test]
    fn test_equality() {
        let a = CallgraphEntry::new("f".to_string(), 0x1000, 42);
        let b = CallgraphEntry::new("f".to_string(), 0x1000, 42);
        assert_eq!(a, b);
    }
}
