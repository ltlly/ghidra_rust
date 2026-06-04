//! Z3 library utilities.
//!
//! Provides Z3 expression printing, memory witness handling, and
//! other utilities for the symbolic Z3 extension.

// ---------------------------------------------------------------------------
// Z3InfixPrinter
// ---------------------------------------------------------------------------

/// Pretty-prints Z3 expressions in infix notation.
///
/// Ported from `Z3InfixPrinter.java`. Converts SMT-LIB2 prefix
/// expressions to human-readable infix form for display in the GUI.
pub struct Z3InfixPrinter;

impl Z3InfixPrinter {
    /// Convert an SMT-LIB2 expression to infix notation.
    ///
    /// Transforms expressions like `(bvadd RAX RBX)` into `RAX + RBX`.
    pub fn infix(expr: &str) -> String {
        let expr = expr.trim();

        // Handle common patterns
        if expr.starts_with("(bvadd ") {
            Self::infix_binary(expr, "bvadd", "+")
        } else if expr.starts_with("(bvsub ") {
            Self::infix_binary(expr, "bvsub", "-")
        } else if expr.starts_with("(bvmul ") {
            Self::infix_binary(expr, "bvmul", "*")
        } else if expr.starts_with("(bvudiv ") {
            Self::infix_binary(expr, "bvudiv", "/")
        } else if expr.starts_with("(bvand ") {
            Self::infix_binary(expr, "bvand", "&")
        } else if expr.starts_with("(bvor ") {
            Self::infix_binary(expr, "bvor", "|")
        } else if expr.starts_with("(bvxor ") {
            Self::infix_binary(expr, "bvxor", "^")
        } else if expr.starts_with("(bvshl ") {
            Self::infix_binary(expr, "bvshl", "<<")
        } else if expr.starts_with("(bvlshr ") {
            Self::infix_binary(expr, "bvlshr", ">>")
        } else if expr.starts_with("(bvashr ") {
            Self::infix_binary(expr, "bvashr", "a>>")
        } else if expr.starts_with("(bvnot ") {
            Self::infix_unary(expr, "bvnot", "~")
        } else if expr.starts_with("(bvneg ") {
            Self::infix_unary(expr, "bvneg", "-")
        } else if expr.starts_with("(not ") {
            Self::infix_unary(expr, "not", "!")
        } else if expr.starts_with("(concat ") {
            Self::infix_binary(expr, "concat", "++")
        } else if expr.starts_with("(ite ") {
            Self::infix_ite(expr)
        } else if expr.starts_with("(= ") {
            Self::infix_binary(expr, "=", "==")
        } else if expr.starts_with("(bvult ") {
            Self::infix_binary(expr, "bvult", "<")
        } else if expr.starts_with("(bvslt ") {
            Self::infix_binary(expr, "bvslt", "s<")
        } else {
            expr.to_string()
        }
    }

    fn infix_binary(expr: &str, _op: &str, symbol: &str) -> String {
        // Find two top-level arguments
        let inner = expr.trim_start_matches('(').trim_end_matches(')');
        let parts: Vec<&str> = inner.splitn(3, ' ').collect();
        if parts.len() >= 3 {
            format!("({} {} {})", Self::infix(parts[1]), symbol, Self::infix(parts[2]))
        } else {
            expr.to_string()
        }
    }

    fn infix_unary(expr: &str, _op: &str, symbol: &str) -> String {
        let inner = expr.trim_start_matches('(').trim_end_matches(')');
        let parts: Vec<&str> = inner.splitn(2, ' ').collect();
        if parts.len() >= 2 {
            format!("({}{})", symbol, Self::infix(parts[1]))
        } else {
            expr.to_string()
        }
    }

    fn infix_ite(expr: &str) -> String {
        // Simplified ITE handling
        let inner = expr.trim_start_matches('(').trim_end_matches(')');
        let parts: Vec<&str> = inner.splitn(4, ' ').collect();
        if parts.len() >= 4 {
            format!(
                "(if {} then {} else {})",
                Self::infix(parts[1]),
                Self::infix(parts[2]),
                Self::infix(parts[3])
            )
        } else {
            expr.to_string()
        }
    }
}

// ---------------------------------------------------------------------------
// Z3MemoryWitness
// ---------------------------------------------------------------------------

/// Memory witness for symbolic execution.
///
/// Ported from `Z3MemoryWitness.java`. Tracks which memory locations
/// were read or written during symbolic execution, and the
/// concrete/symbolic values involved.
#[derive(Debug, Clone)]
pub struct Z3MemoryWitness {
    /// Memory reads: (address_expr, value_expr, size).
    reads: Vec<(String, String, u32)>,
    /// Memory writes: (address_expr, value_expr, size).
    writes: Vec<(String, String, u32)>,
}

impl Z3MemoryWitness {
    /// Create a new empty witness.
    pub fn new() -> Self {
        Self {
            reads: Vec::new(),
            writes: Vec::new(),
        }
    }

    /// Record a memory read.
    pub fn record_read(
        &mut self,
        addr_expr: impl Into<String>,
        value_expr: impl Into<String>,
        size: u32,
    ) {
        self.reads
            .push((addr_expr.into(), value_expr.into(), size));
    }

    /// Record a memory write.
    pub fn record_write(
        &mut self,
        addr_expr: impl Into<String>,
        value_expr: impl Into<String>,
        size: u32,
    ) {
        self.writes
            .push((addr_expr.into(), value_expr.into(), size));
    }

    /// Get all recorded reads.
    pub fn reads(&self) -> &[(String, String, u32)] {
        &self.reads
    }

    /// Get all recorded writes.
    pub fn writes(&self) -> &[(String, String, u32)] {
        &self.writes
    }

    /// Get the number of reads.
    pub fn read_count(&self) -> usize {
        self.reads.len()
    }

    /// Get the number of writes.
    pub fn write_count(&self) -> usize {
        self.writes.len()
    }

    /// Get a printable summary of the witness.
    pub fn printable_summary(&self) -> String {
        let mut out = String::new();
        if !self.reads.is_empty() {
            out.push_str("=== Memory Reads ===\n");
            for (addr, val, size) in &self.reads {
                out.push_str(&format!("  [{addr}] ({size}b) = {val}\n"));
            }
        }
        if !self.writes.is_empty() {
            out.push_str("=== Memory Writes ===\n");
            for (addr, val, size) in &self.writes {
                out.push_str(&format!("  [{addr}] ({size}b) = {val}\n"));
            }
        }
        out
    }

    /// Clear all recorded operations.
    pub fn clear(&mut self) {
        self.reads.clear();
        self.writes.clear();
    }
}

impl Default for Z3MemoryWitness {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// EmuUnixFileSystem (stub)
// ---------------------------------------------------------------------------

/// Symbolic Unix file system for emulation.
///
/// Ported from `SymZ3EmuUnixFileSystem.java`. Provides symbolic
/// representations of file system operations during emulation.
#[derive(Debug, Clone)]
pub struct SymZ3EmuUnixFileSystem {
    /// Open file descriptors mapping to symbolic file handles.
    file_descriptors: Vec<String>,
}

impl SymZ3EmuUnixFileSystem {
    /// Create a new symbolic file system.
    pub fn new() -> Self {
        Self {
            file_descriptors: Vec::new(),
        }
    }

    /// Open a symbolic file.
    pub fn open(&mut self, path: &str) -> i32 {
        self.file_descriptors.push(path.to_string());
        (self.file_descriptors.len() as i32) - 1
    }

    /// Close a file descriptor.
    pub fn close(&mut self, fd: i32) -> bool {
        if fd >= 0 && (fd as usize) < self.file_descriptors.len() {
            self.file_descriptors[fd as usize] = String::new();
            true
        } else {
            false
        }
    }

    /// Get the number of open file descriptors.
    pub fn open_count(&self) -> usize {
        self.file_descriptors.iter().filter(|s| !s.is_empty()).count()
    }
}

impl Default for SymZ3EmuUnixFileSystem {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// LinuxAmd64SyscallLibrary (stub)
// ---------------------------------------------------------------------------

/// Symbolic syscall library for Linux x86-64.
///
/// Ported from `SymZ3LinuxAmd64SyscallLibrary.java`. Provides
/// symbolic handlers for common Linux system calls.
pub struct SymZ3LinuxAmd64SyscallLibrary {
    /// Whether syscall handling is enabled.
    enabled: bool,
}

impl SymZ3LinuxAmd64SyscallLibrary {
    /// Create a new syscall library.
    pub fn new() -> Self {
        Self { enabled: true }
    }

    /// Whether the library is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Enable or disable the library.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    /// Get the symbolic result for a syscall.
    ///
    /// Returns a symbolic value representing the return value of the
    /// syscall. In the full implementation, each syscall number would
    /// have its own handler.
    pub fn handle_syscall(&self, syscall_number: u64) -> Option<super::SymValueZ3> {
        if !self.enabled {
            return None;
        }
        // Common syscall numbers for Linux x86-64
        match syscall_number {
            0 => Some(super::SymValueZ3::from_constant(0, 64)),   // read
            1 => Some(super::SymValueZ3::from_constant(0, 64)),   // write
            60 => Some(super::SymValueZ3::from_constant(0, 64)),  // exit
            _ => None,
        }
    }
}

impl Default for SymZ3LinuxAmd64SyscallLibrary {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_infix_bvadd() {
        let result = Z3InfixPrinter::infix("(bvadd RAX RBX)");
        assert!(result.contains("+"));
    }

    #[test]
    fn test_infix_bvsub() {
        let result = Z3InfixPrinter::infix("(bvsub RAX RBX)");
        assert!(result.contains("-"));
    }

    #[test]
    fn test_infix_bvand() {
        let result = Z3InfixPrinter::infix("(bvand RAX RBX)");
        assert!(result.contains("&"));
    }

    #[test]
    fn test_infix_bvor() {
        let result = Z3InfixPrinter::infix("(bvor RAX RBX)");
        assert!(result.contains("|"));
    }

    #[test]
    fn test_infix_bvxor() {
        let result = Z3InfixPrinter::infix("(bvxor RAX RBX)");
        assert!(result.contains("^"));
    }

    #[test]
    fn test_infix_ite() {
        let result = Z3InfixPrinter::infix("(ite (= RAX #x00) #x01 #x00)");
        assert!(result.contains("if"));
        assert!(result.contains("then"));
        assert!(result.contains("else"));
    }

    #[test]
    fn test_infix_unknown() {
        let result = Z3InfixPrinter::infix("unknown_expr");
        assert_eq!(result, "unknown_expr");
    }

    #[test]
    fn test_memory_witness() {
        let mut witness = Z3MemoryWitness::new();
        assert_eq!(witness.read_count(), 0);
        assert_eq!(witness.write_count(), 0);

        witness.record_read("0x1000", "#xDEAD", 4);
        witness.record_write("0x2000", "#xBEEF", 8);

        assert_eq!(witness.read_count(), 1);
        assert_eq!(witness.write_count(), 1);

        let summary = witness.printable_summary();
        assert!(summary.contains("Memory Reads"));
        assert!(summary.contains("Memory Writes"));
        assert!(summary.contains("0x1000"));
    }

    #[test]
    fn test_memory_witness_clear() {
        let mut witness = Z3MemoryWitness::new();
        witness.record_read("0x1000", "#xFF", 1);
        witness.clear();
        assert_eq!(witness.read_count(), 0);
    }

    #[test]
    fn test_unix_fs() {
        let mut fs = SymZ3EmuUnixFileSystem::new();
        let fd = fs.open("/tmp/test.txt");
        assert_eq!(fd, 0);
        assert_eq!(fs.open_count(), 1);

        let fd2 = fs.open("/tmp/test2.txt");
        assert_eq!(fd2, 1);
        assert_eq!(fs.open_count(), 2);

        assert!(fs.close(0));
        assert_eq!(fs.open_count(), 1);
        assert!(!fs.close(99));
    }

    #[test]
    fn test_syscall_library() {
        let lib = SymZ3LinuxAmd64SyscallLibrary::new();
        assert!(lib.is_enabled());

        let result = lib.handle_syscall(0); // read
        assert!(result.is_some());

        let result = lib.handle_syscall(999);
        assert!(result.is_none());
    }

    #[test]
    fn test_syscall_library_disabled() {
        let mut lib = SymZ3LinuxAmd64SyscallLibrary::new();
        lib.set_enabled(false);
        assert!(!lib.is_enabled());
        assert!(lib.handle_syscall(0).is_none());
    }
}
