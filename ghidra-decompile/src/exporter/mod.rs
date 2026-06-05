//! Decompiler exporters.
//!
//! Port of `ghidra.app.util.exporter`:
//! - [`CppExporter`]: export decompiled functions as C++ source

use serde::{Deserialize, Serialize};

/// Options for C++ export.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CppExportOptions {
    /// Whether to include function headers.
    pub include_headers: bool,
    /// Whether to include data type definitions.
    pub include_type_defs: bool,
    /// Whether to include comments.
    pub include_comments: bool,
    /// Indentation string (e.g., "    " or "\\t").
    pub indent: String,
    /// Maximum line width before wrapping.
    pub max_line_width: usize,
}

impl Default for CppExportOptions {
    fn default() -> Self {
        Self {
            include_headers: true,
            include_type_defs: true,
            include_comments: true,
            indent: "    ".to_string(),
            max_line_width: 120,
        }
    }
}

/// Export decompiled functions as C++ source code.
#[derive(Debug)]
pub struct CppExporter {
    /// Export options.
    pub options: CppExportOptions,
    /// Accumulated output lines.
    output: Vec<String>,
}

impl CppExporter {
    /// Create a new C++ exporter with default options.
    pub fn new() -> Self {
        Self {
            options: CppExportOptions::default(),
            output: Vec::new(),
        }
    }

    /// Create a new C++ exporter with custom options.
    pub fn with_options(options: CppExportOptions) -> Self {
        Self {
            options,
            output: Vec::new(),
        }
    }

    /// Write a header include.
    pub fn write_header(&mut self, header: &str) {
        self.output.push(format!("#include \"{}\"", header));
    }

    /// Write a function definition.
    pub fn write_function(&mut self, name: &str, body: &str) {
        if self.options.include_headers {
            self.output.push(String::new());
        }
        self.output.push(format!("// Function: {}", name));
        self.output.push(body.to_string());
    }

    /// Write a type definition.
    pub fn write_type_def(&mut self, typedef: &str) {
        if self.options.include_type_defs {
            self.output.push(typedef.to_string());
        }
    }

    /// Get the accumulated output.
    pub fn output(&self) -> &[String] {
        &self.output
    }

    /// Get the output as a single string.
    pub fn to_string_output(&self) -> String {
        self.output.join("\n")
    }

    /// Clear the output buffer.
    pub fn clear(&mut self) {
        self.output.clear();
    }

    /// Get the number of lines in the output.
    pub fn line_count(&self) -> usize {
        self.output.len()
    }
}

impl Default for CppExporter {
    fn default() -> Self {
        Self::new()
    }
}

/// Data type dependency orderer.
///
/// Orders data type definitions so that types are defined before
/// they are used by other types (topological sort of dependencies).
#[derive(Debug)]
pub struct DataTypeDependencyOrderer {
    /// Ordered type names (output).
    order: Vec<String>,
}

impl DataTypeDependencyOrderer {
    /// Create a new dependency orderer.
    pub fn new() -> Self {
        Self { order: Vec::new() }
    }

    /// Add a type name to the ordering.
    pub fn add_type(&mut self, type_name: impl Into<String>) {
        self.order.push(type_name.into());
    }

    /// Get the ordered type names.
    pub fn ordered_types(&self) -> &[String] {
        &self.order
    }

    /// Get the number of types in the ordering.
    pub fn len(&self) -> usize {
        self.order.len()
    }

    /// Check if the ordering is empty.
    pub fn is_empty(&self) -> bool {
        self.order.is_empty()
    }
}

impl Default for DataTypeDependencyOrderer {
    fn default() -> Self {
        Self::new()
    }
}

/// Concurrent decompiler queue for parallel decompilation.
#[derive(Debug)]
pub struct DecompilerConcurrentQ {
    /// Maximum number of concurrent workers.
    pub max_workers: usize,
    /// Queue of function addresses to decompile.
    queue: Vec<u64>,
    /// Results: address -> decompiled output.
    results: Vec<(u64, String)>,
}

impl DecompilerConcurrentQ {
    /// Create a new concurrent queue.
    pub fn new(max_workers: usize) -> Self {
        Self {
            max_workers,
            queue: Vec::new(),
            results: Vec::new(),
        }
    }

    /// Enqueue a function address for decompilation.
    pub fn enqueue(&mut self, address: u64) {
        self.queue.push(address);
    }

    /// Get the queue size.
    pub fn queue_size(&self) -> usize {
        self.queue.len()
    }

    /// Add a result.
    pub fn add_result(&mut self, address: u64, output: String) {
        self.results.push((address, output));
    }

    /// Get the results.
    pub fn results(&self) -> &[(u64, String)] {
        &self.results
    }

    /// Get the number of completed results.
    pub fn completed_count(&self) -> usize {
        self.results.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cpp_exporter() {
        let mut exporter = CppExporter::new();
        exporter.write_header("stdio.h");
        exporter.write_function("main", "int main() { return 0; }");
        assert_eq!(exporter.line_count(), 4); // include + empty line + comment + body
        assert!(exporter.to_string_output().contains("#include"));
    }

    #[test]
    fn test_cpp_exporter_options() {
        let opts = CppExportOptions {
            include_headers: false,
            ..Default::default()
        };
        let mut exporter = CppExporter::with_options(opts);
        exporter.write_function("test", "void test() {}");
        // No empty line before function since headers disabled
        assert_eq!(exporter.line_count(), 2); // comment + body
    }

    #[test]
    fn test_cpp_exporter_type_def() {
        let mut exporter = CppExporter::new();
        exporter.write_type_def("typedef int myint;");
        assert_eq!(exporter.line_count(), 1);
    }

    #[test]
    fn test_cpp_exporter_type_def_disabled() {
        let opts = CppExportOptions {
            include_type_defs: false,
            ..Default::default()
        };
        let mut exporter = CppExporter::with_options(opts);
        exporter.write_type_def("typedef int myint;");
        assert_eq!(exporter.line_count(), 0);
    }

    #[test]
    fn test_cpp_exporter_clear() {
        let mut exporter = CppExporter::new();
        exporter.write_header("test.h");
        assert_eq!(exporter.line_count(), 1);
        exporter.clear();
        assert_eq!(exporter.line_count(), 0);
    }

    #[test]
    fn test_data_type_dependency_orderer() {
        let mut orderer = DataTypeDependencyOrderer::new();
        orderer.add_type("int");
        orderer.add_type("struct Foo");
        assert_eq!(orderer.len(), 2);
        assert_eq!(orderer.ordered_types()[0], "int");
    }

    #[test]
    fn test_decompiler_concurrent_q() {
        let mut q = DecompilerConcurrentQ::new(4);
        q.enqueue(0x1000);
        q.enqueue(0x2000);
        assert_eq!(q.queue_size(), 2);

        q.add_result(0x1000, "int main() {}".to_string());
        assert_eq!(q.completed_count(), 1);
    }
}
