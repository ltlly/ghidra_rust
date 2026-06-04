//! C/C++ export functionality for the decompiler.
//!
//! Ported from Ghidra's `ghidra.app.util.exporter.CppExporter`.
//! Exports decompiled functions as compilable C/C++ source code,
//! including type definitions, function prototypes, and function bodies.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;

use super::clang_node::{ClangNodeArena, ClangNodeId, ClangNodeKind};
use super::decompiled_function::DecompiledFunction;
use super::pretty_printer::PrettyPrinter;
use super::util::DataTypeDependencyOrderer;

// ============================================================================
// CppExportOptions
// ============================================================================

/// Options controlling C/C++ code export.
#[derive(Debug, Clone)]
pub struct CppExportOptions {
    /// Include type definitions (structs, enums, typedefs).
    pub include_types: bool,
    /// Include function prototypes.
    pub include_prototypes: bool,
    /// Include function bodies.
    pub include_bodies: bool,
    /// Include address comments.
    pub include_addresses: bool,
    /// Sort functions by address.
    pub sort_by_address: bool,
    /// Emit `#pragma once` guard.
    pub emit_pragma_once: bool,
    /// Emit header include directives.
    pub emit_includes: bool,
    /// Indent size in spaces.
    pub indent_size: usize,
    /// Use C++ style (namespaces, references) vs C style.
    pub cpp_style: bool,
}

impl Default for CppExportOptions {
    fn default() -> Self {
        Self {
            include_types: true,
            include_prototypes: true,
            include_bodies: true,
            include_addresses: false,
            sort_by_address: true,
            emit_pragma_once: true,
            emit_includes: true,
            indent_size: 4,
            cpp_style: false,
        }
    }
}

// ============================================================================
// CppExporter
// ============================================================================

/// Exports decompiled functions as C/C++ source code.
///
/// Ported from `ghidra.app.util.exporter.CppExporter`.
///
/// # Example
///
/// ```
/// use ghidra_decompile::decompiler::cpp_exporter::*;
///
/// let mut exporter = CppExporter::new();
/// exporter.add_function(DecompiledFunctionExport {
///     name: "main".into(),
///     address: 0x1000,
///     prototype: "int main(int argc, char **argv)".into(),
///     body: "{\n    return 0;\n}".into(),
///     return_type: Some("int".into()),
///     parameter_types: vec!["int".into(), "char **".into()],
/// });
/// let source = exporter.export();
/// assert!(source.contains("int main"));
/// ```
pub struct CppExporter {
    /// Export options.
    options: CppExportOptions,
    /// Type definitions to emit (name -> definition).
    types: BTreeMap<String, String>,
    /// Functions to export.
    functions: Vec<DecompiledFunctionExport>,
    /// Custom header includes.
    includes: Vec<String>,
    /// User-defined preamble text.
    preamble: String,
    /// Postamble text (after all functions).
    postamble: String,
}

/// A single function to be exported.
#[derive(Debug, Clone)]
pub struct DecompiledFunctionExport {
    /// Function name.
    pub name: String,
    /// Entry-point address.
    pub address: u64,
    /// Full function prototype string.
    pub prototype: String,
    /// Function body (including braces).
    pub body: String,
    /// Return type.
    pub return_type: Option<String>,
    /// Parameter types.
    pub parameter_types: Vec<String>,
    /// Whether this is a static function.
    pub is_static: bool,
    /// Whether this is an extern function.
    pub is_extern: bool,
}

impl DecompiledFunctionExport {
    /// Create a new function export.
    pub fn new(
        name: impl Into<String>,
        address: u64,
        prototype: impl Into<String>,
        body: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            address,
            prototype: prototype.into(),
            body: body.into(),
            return_type: None,
            parameter_types: Vec::new(),
            is_static: false,
            is_extern: false,
        }
    }
}

impl CppExporter {
    /// Create a new exporter with default options.
    pub fn new() -> Self {
        Self {
            options: CppExportOptions::default(),
            types: BTreeMap::new(),
            functions: Vec::new(),
            includes: Vec::new(),
            preamble: String::new(),
            postamble: String::new(),
        }
    }

    /// Create an exporter with custom options.
    pub fn with_options(options: CppExportOptions) -> Self {
        Self {
            options,
            ..Self::new()
        }
    }

    /// Set the export options.
    pub fn set_options(&mut self, options: CppExportOptions) {
        self.options = options;
    }

    /// Get the current options.
    pub fn options(&self) -> &CppExportOptions {
        &self.options
    }

    /// Add a type definition.
    pub fn add_type(&mut self, name: impl Into<String>, definition: impl Into<String>) {
        self.types.insert(name.into(), definition.into());
    }

    /// Add a function to export.
    pub fn add_function(&mut self, func: DecompiledFunctionExport) {
        self.functions.push(func);
    }

    /// Add a header include directive.
    pub fn add_include(&mut self, include: impl Into<String>) {
        self.includes.push(include.into());
    }

    /// Set the preamble text.
    pub fn set_preamble(&mut self, text: impl Into<String>) {
        self.preamble = text.into();
    }

    /// Set the postamble text.
    pub fn set_postamble(&mut self, text: impl Into<String>) {
        self.postamble = text.into();
    }

    /// Get the number of functions to export.
    pub fn function_count(&self) -> usize {
        self.functions.len()
    }

    /// Get the number of type definitions.
    pub fn type_count(&self) -> usize {
        self.types.len()
    }

    /// Generate the complete C/C++ source.
    pub fn export(&self) -> String {
        let mut out = String::new();

        // Pragma once guard.
        if self.options.emit_pragma_once {
            out.push_str("#pragma once\n\n");
        }

        // Include directives.
        if self.options.emit_includes {
            if self.includes.is_empty() {
                out.push_str("#include <stdint.h>\n");
                out.push_str("#include <stdbool.h>\n");
            } else {
                for inc in &self.includes {
                    if inc.starts_with('<') || inc.starts_with('"') {
                        out.push_str(&format!("#include {}\n", inc));
                    } else {
                        out.push_str(&format!("#include \"{}\"\n", inc));
                    }
                }
            }
            out.push('\n');
        }

        // Preamble.
        if !self.preamble.is_empty() {
            out.push_str(&self.preamble);
            if !self.preamble.ends_with('\n') {
                out.push('\n');
            }
            out.push('\n');
        }

        // Type definitions.
        if self.options.include_types && !self.types.is_empty() {
            out.push_str("// ---------------------------------------------------------------------------\n");
            out.push_str("// Type definitions\n");
            out.push_str("// ---------------------------------------------------------------------------\n\n");

            // Order types by dependency.
            let mut orderer = DataTypeDependencyOrderer::new();
            let mut dep_map = HashMap::new();
            for name in self.types.keys() {
                dep_map.insert(name.clone(), Vec::new());
            }
            orderer.order(&dep_map);

            for name in &orderer.ordered_types {
                if let Some(def) = self.types.get(name) {
                    out.push_str(def);
                    if !def.ends_with('\n') {
                        out.push('\n');
                    }
                    out.push('\n');
                }
            }
        }

        // Function prototypes.
        if self.options.include_prototypes && !self.functions.is_empty() {
            out.push_str("// ---------------------------------------------------------------------------\n");
            out.push_str("// Function prototypes\n");
            out.push_str("// ---------------------------------------------------------------------------\n\n");
            for func in &self.functions {
                if func.is_extern {
                    out.push_str("extern ");
                }
                if func.is_static {
                    out.push_str("static ");
                }
                out.push_str(&func.prototype);
                out.push_str(";\n");
            }
            out.push('\n');
        }

        // Function bodies.
        if self.options.include_bodies {
            if !self.functions.is_empty() {
                out.push_str("// ---------------------------------------------------------------------------\n");
                out.push_str("// Function implementations\n");
                out.push_str("// ---------------------------------------------------------------------------\n\n");
            }

            let sorted_funcs = if self.options.sort_by_address {
                let mut v = self.functions.clone();
                v.sort_by_key(|f| f.address);
                v
            } else {
                self.functions.clone()
            };

            for func in &sorted_funcs {
                if self.options.include_addresses {
                    out.push_str(&format!("/* address: 0x{:x} */\n", func.address));
                }
                if func.is_static {
                    out.push_str("static ");
                }
                out.push_str(&func.prototype);
                out.push('\n');
                out.push_str(&func.body);
                out.push_str("\n\n");
            }
        }

        // Postamble.
        if !self.postamble.is_empty() {
            out.push_str(&self.postamble);
            if !self.postamble.ends_with('\n') {
                out.push('\n');
            }
        }

        out
    }

    /// Export a single decompiled function to its source representation.
    pub fn export_function(decompiled: &DecompiledFunction) -> DecompiledFunctionExport {
        let body = decompiled.c_code().to_string();

        let prototype = decompiled
            .signature()
            .map(|s| {
                // Extract prototype from the signature or c_code up to the first brace.
                let sig = if body.contains('{') {
                    body.split('{')
                        .next()
                        .unwrap_or("")
                        .trim()
                        .to_string()
                } else {
                    s.to_string()
                };
                sig
            })
            .unwrap_or_else(|| {
                if body.contains('{') {
                    body.split('{')
                        .next()
                        .unwrap_or("")
                        .trim()
                        .to_string()
                } else {
                    "void decompiled_fn()".to_string()
                }
            });

        // Extract a name from the prototype.
        let name = prototype
            .split('(')
            .next()
            .unwrap_or("decompiled_fn")
            .split_whitespace()
            .last()
            .unwrap_or("decompiled_fn")
            .to_string();

        DecompiledFunctionExport::new(name, 0, &prototype, &body)
    }
}

impl Default for CppExporter {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cpp_exporter_empty_export() {
        let exporter = CppExporter::new();
        let source = exporter.export();
        assert!(source.contains("#pragma once"));
        assert!(source.contains("#include <stdint.h>"));
    }

    #[test]
    fn cpp_exporter_with_function() {
        let mut exporter = CppExporter::new();
        exporter.add_function(DecompiledFunctionExport::new(
            "main",
            0x1000,
            "int main(int argc, char **argv)",
            "{\n    return 0;\n}",
        ));
        let source = exporter.export();
        assert!(source.contains("int main"));
        assert!(source.contains("return 0"));
        assert!(source.contains("Function implementations"));
    }

    #[test]
    fn cpp_exporter_with_types() {
        let mut exporter = CppExporter::new();
        exporter.add_type("my_struct", "typedef struct {\n    int x;\n    int y;\n} my_struct;");
        exporter.add_function(DecompiledFunctionExport::new(
            "use_struct",
            0x2000,
            "void use_struct(my_struct *s)",
            "{\n    s->x = 1;\n}",
        ));
        let source = exporter.export();
        assert!(source.contains("my_struct"));
        assert!(source.contains("Type definitions"));
    }

    #[test]
    fn cpp_exporter_no_types_option() {
        let mut exporter = CppExporter::with_options(CppExportOptions {
            include_types: false,
            ..Default::default()
        });
        exporter.add_type("hidden", "typedef int hidden;");
        exporter.add_function(DecompiledFunctionExport::new("f", 0, "void f()", "{}"));
        let source = exporter.export();
        assert!(!source.contains("hidden"));
    }

    #[test]
    fn cpp_exporter_sort_by_address() {
        let mut exporter = CppExporter::new();
        exporter.add_function(DecompiledFunctionExport::new("b", 0x3000, "void b()", "{}"));
        exporter.add_function(DecompiledFunctionExport::new("a", 0x1000, "void a()", "{}"));
        let source = exporter.export();
        let pos_a = source.find("void a()").unwrap();
        let pos_b = source.find("void b()").unwrap();
        assert!(pos_a < pos_b);
    }

    #[test]
    fn cpp_exporter_preamble_postamble() {
        let mut exporter = CppExporter::new();
        exporter.set_preamble("// My custom header\n// Do not edit");
        exporter.set_postamble("// End of file");
        exporter.add_function(DecompiledFunctionExport::new("f", 0, "void f()", "{}"));
        let source = exporter.export();
        assert!(source.starts_with("#pragma once"));
        assert!(source.contains("My custom header"));
        assert!(source.contains("End of file"));
    }

    #[test]
    fn cpp_exporter_address_comments() {
        let mut exporter = CppExporter::with_options(CppExportOptions {
            include_addresses: true,
            ..Default::default()
        });
        exporter.add_function(DecompiledFunctionExport::new("f", 0xDEAD, "void f()", "{}"));
        let source = exporter.export();
        assert!(source.contains("0xdead"));
    }

    #[test]
    fn cpp_exporter_custom_includes() {
        let mut exporter = CppExporter::new();
        exporter.add_include("<stdio.h>");
        exporter.add_include("\"my_header.h\"");
        let source = exporter.export();
        assert!(source.contains("#include <stdio.h>"));
        assert!(source.contains("#include \"my_header.h\""));
    }

    #[test]
    fn cpp_exporter_function_export_helper() {
        let func = DecompiledFunctionExport::new("test", 0x1000, "int test()", "{ return 0; }")
            .with_static();
        assert!(func.is_static);
        assert_eq!(func.name, "test");
    }

    // Helper extension for tests.
    impl DecompiledFunctionExport {
        fn with_static(mut self) -> Self {
            self.is_static = true;
            self
        }
    }
}
