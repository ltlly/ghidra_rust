//! C/C++ export functionality for decompiled functions.
//!
//! Ports Ghidra's `ghidra.app.util.exporter.CppExporter` and the C++ output
//! pipeline.  This module handles:
//!
//! - Generating C header/source files from decompilation results
//! - Type definitions (struct, union, enum, typedef)
//! - Function prototypes and definitions
//! - Preprocessor directive management
//! - Include-file dependency tracking

use std::collections::BTreeSet;
use std::fmt;

/// Represents a C/C++ type declaration that needs to be emitted.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum TypeDeclaration {
    /// A struct definition.
    Struct {
        /// Name of the struct.
        name: String,
        /// Field names and types as `(name, type_str)` pairs.
        fields: Vec<(String, String)>,
    },
    /// A union definition.
    Union {
        /// Name of the union.
        name: String,
        /// Field names and types.
        fields: Vec<(String, String)>,
    },
    /// An enum definition.
    Enum {
        /// Name of the enum.
        name: String,
        /// Enumerator names and optional values.
        variants: Vec<(String, Option<i64>)>,
    },
    /// A typedef.
    Typedef {
        /// The existing type.
        existing_type: String,
        /// The new name.
        new_name: String,
    },
}

impl fmt::Display for TypeDeclaration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TypeDeclaration::Struct { name, fields } => {
                writeln!(f, "struct {} {{", name)?;
                for (fname, ftype) in fields {
                    writeln!(f, "    {} {};", ftype, fname)?;
                }
                write!(f, "}};")
            }
            TypeDeclaration::Union { name, fields } => {
                writeln!(f, "union {} {{", name)?;
                for (fname, ftype) in fields {
                    writeln!(f, "    {} {};", ftype, fname)?;
                }
                write!(f, "}};")
            }
            TypeDeclaration::Enum { name, variants } => {
                writeln!(f, "enum {} {{", name)?;
                for (vname, val) in variants {
                    match val {
                        Some(v) => writeln!(f, "    {} = {},", vname, v)?,
                        None => writeln!(f, "    {},", vname)?,
                    }
                }
                write!(f, "}};")
            }
            TypeDeclaration::Typedef {
                existing_type,
                new_name,
            } => {
                write!(f, "typedef {} {};", existing_type, new_name)
            }
        }
    }
}

/// Represents a C function prototype or definition.
#[derive(Debug, Clone)]
pub struct CFunctionSignature {
    /// Return type.
    pub return_type: String,
    /// Function name.
    pub name: String,
    /// Parameters as `(type, name)` pairs.
    pub parameters: Vec<(String, String)>,
    /// Whether the function is `static`.
    pub is_static: bool,
    /// Whether the function is `extern`.
    pub is_extern: bool,
    /// Whether the function is `inline`.
    pub is_inline: bool,
}

impl CFunctionSignature {
    /// Create a new function signature.
    pub fn new(return_type: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            return_type: return_type.into(),
            name: name.into(),
            parameters: Vec::new(),
            is_static: false,
            is_extern: false,
            is_inline: false,
        }
    }

    /// Add a parameter.
    pub fn param(mut self, ptype: impl Into<String>, pname: impl Into<String>) -> Self {
        self.parameters.push((ptype.into(), pname.into()));
        self
    }

    /// Render as a prototype (with `;` terminator).
    pub fn to_prototype(&self) -> String {
        let mut s = String::new();
        if self.is_static {
            s.push_str("static ");
        }
        if self.is_inline {
            s.push_str("inline ");
        }
        if self.is_extern {
            s.push_str("extern ");
        }
        s.push_str(&self.return_type);
        s.push(' ');
        s.push_str(&self.name);
        s.push('(');
        for (i, (ptype, pname)) in self.parameters.iter().enumerate() {
            if i > 0 {
                s.push_str(", ");
            }
            s.push_str(ptype);
            if !pname.is_empty() {
                s.push(' ');
                s.push_str(pname);
            }
        }
        s.push_str(");");
        s
    }

    /// Render as a function definition header (no body).
    pub fn to_definition_header(&self) -> String {
        let proto = self.to_prototype();
        // Remove the trailing `;` and replace with ` {`.
        proto.trim_end_matches(';').to_string()
    }
}

impl fmt::Display for CFunctionSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_prototype())
    }
}

/// A complete C source file being built for export.
#[derive(Debug, Clone)]
pub struct CppExportUnit {
    /// Include directives (angle-bracket includes).
    pub includes: BTreeSet<String>,
    /// Quoted include directives.
    pub local_includes: BTreeSet<String>,
    /// Preprocessor defines.
    pub defines: Vec<(String, Option<String>)>,
    /// Type declarations (structs, enums, typedefs).
    pub type_declarations: Vec<TypeDeclaration>,
    /// Function prototypes.
    pub prototypes: Vec<CFunctionSignature>,
    /// Function bodies (name -> body text).
    pub function_bodies: Vec<(CFunctionSignature, String)>,
    /// Global variable declarations.
    pub globals: Vec<(String, String, Option<String>)>,
}

impl CppExportUnit {
    /// Create a new empty export unit.
    pub fn new() -> Self {
        Self {
            includes: BTreeSet::new(),
            local_includes: BTreeSet::new(),
            defines: Vec::new(),
            type_declarations: Vec::new(),
            prototypes: Vec::new(),
            function_bodies: Vec::new(),
            globals: Vec::new(),
        }
    }

    /// Add a system include (e.g., `<stdint.h>`).
    pub fn add_include(&mut self, header: impl Into<String>) {
        self.includes.insert(header.into());
    }

    /// Add a local include (e.g., `"myheader.h"`).
    pub fn add_local_include(&mut self, header: impl Into<String>) {
        self.local_includes.insert(header.into());
    }

    /// Add a `#define` directive.
    pub fn add_define(&mut self, name: impl Into<String>, value: Option<impl Into<String>>) {
        self.defines.push((name.into(), value.map(|v| v.into())));
    }

    /// Add a type declaration.
    pub fn add_type(&mut self, decl: TypeDeclaration) {
        self.type_declarations.push(decl);
    }

    /// Add a function prototype.
    pub fn add_prototype(&mut self, sig: CFunctionSignature) {
        self.prototypes.push(sig);
    }

    /// Add a function definition (prototype + body).
    pub fn add_function(&mut self, sig: CFunctionSignature, body: impl Into<String>) {
        self.function_bodies.push((sig, body.into()));
    }

    /// Add a global variable declaration.
    pub fn add_global(
        &mut self,
        vtype: impl Into<String>,
        name: impl Into<String>,
        init: Option<impl Into<String>>,
    ) {
        self.globals.push((vtype.into(), name.into(), init.map(|v| v.into())));
    }

    /// Render the complete C source file.
    pub fn render(&self) -> String {
        let mut out = String::new();

        // Includes
        for inc in &self.includes {
            out.push_str(&format!("#include <{}>\n", inc));
        }
        if !self.includes.is_empty() {
            out.push('\n');
        }
        for inc in &self.local_includes {
            out.push_str(&format!("#include \"{}\"\n", inc));
        }
        if !self.local_includes.is_empty() {
            out.push('\n');
        }

        // Defines
        for (name, value) in &self.defines {
            match value {
                Some(v) => out.push_str(&format!("#define {} {}\n", name, v)),
                None => out.push_str(&format!("#define {}\n", name)),
            }
        }
        if !self.defines.is_empty() {
            out.push('\n');
        }

        // Type declarations
        for decl in &self.type_declarations {
            out.push_str(&format!("{}\n\n", decl));
        }

        // Global variables
        for (vtype, name, init) in &self.globals {
            match init {
                Some(v) => out.push_str(&format!("{} {} = {};\n", vtype, name, v)),
                None => out.push_str(&format!("{} {};\n", vtype, name)),
            }
        }
        if !self.globals.is_empty() {
            out.push('\n');
        }

        // Prototypes
        for sig in &self.prototypes {
            out.push_str(&format!("{}\n", sig.to_prototype()));
        }
        if !self.prototypes.is_empty() {
            out.push('\n');
        }

        // Function definitions
        for (sig, body) in &self.function_bodies {
            out.push_str(&format!("{}\n", sig.to_definition_header()));
            out.push_str("{\n");
            for line in body.lines() {
                out.push_str(&format!("    {}\n", line));
            }
            out.push_str("}\n\n");
        }

        out
    }
}

impl Default for CppExportUnit {
    fn default() -> Self {
        Self::new()
    }
}

/// Exporter that produces C source files from decompilation results.
///
/// Ports Ghidra's `CppExporter`.
#[derive(Debug)]
pub struct CppExporter {
    /// The export unit being built.
    pub unit: CppExportUnit,
    /// Whether to emit `#pragma once` at the top.
    pub emit_pragma_once: bool,
    /// Whether to emit `extern "C"` guards for C++ compatibility.
    pub emit_extern_c: bool,
}

impl CppExporter {
    /// Create a new exporter.
    pub fn new() -> Self {
        Self {
            unit: CppExportUnit::new(),
            emit_pragma_once: false,
            emit_extern_c: false,
        }
    }

    /// Render the final C source output.
    pub fn export(&self) -> String {
        let mut out = String::new();

        if self.emit_pragma_once {
            out.push_str("#pragma once\n\n");
        }

        if self.emit_extern_c {
            out.push_str("#ifdef __cplusplus\nextern \"C\" {\n#endif\n\n");
        }

        out.push_str(&self.unit.render());

        if self.emit_extern_c {
            out.push_str("#ifdef __cplusplus\n}\n#endif\n");
        }

        out
    }
}

impl Default for CppExporter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_struct_display() {
        let decl = TypeDeclaration::Struct {
            name: "Point".into(),
            fields: vec![("x".into(), "int".into()), ("y".into(), "int".into())],
        };
        let s = decl.to_string();
        assert!(s.contains("struct Point"));
        assert!(s.contains("int x;"));
        assert!(s.contains("int y;"));
    }

    #[test]
    fn test_enum_display() {
        let decl = TypeDeclaration::Enum {
            name: "Color".into(),
            variants: vec![
                ("RED".into(), Some(0)),
                ("GREEN".into(), Some(1)),
                ("BLUE".into(), None),
            ],
        };
        let s = decl.to_string();
        assert!(s.contains("enum Color"));
        assert!(s.contains("RED = 0,"));
        assert!(s.contains("GREEN = 1,"));
        assert!(s.contains("BLUE,"));
    }

    #[test]
    fn test_typedef_display() {
        let decl = TypeDeclaration::Typedef {
            existing_type: "unsigned int".into(),
            new_name: "uint32".into(),
        };
        assert_eq!(decl.to_string(), "typedef unsigned int uint32;");
    }

    #[test]
    fn test_function_signature() {
        let sig = CFunctionSignature::new("int", "add")
            .param("int", "a")
            .param("int", "b");
        assert_eq!(sig.to_prototype(), "int add(int a, int b);");
    }

    #[test]
    fn test_static_function() {
        let mut sig = CFunctionSignature::new("void", "helper");
        sig.is_static = true;
        assert!(sig.to_prototype().starts_with("static "));
    }

    #[test]
    fn test_export_unit_render() {
        let mut unit = CppExportUnit::new();
        unit.add_include("stdint.h");
        unit.add_include("stdio.h");
        unit.add_type(TypeDeclaration::Typedef {
            existing_type: "unsigned int".into(),
            new_name: "u32".into(),
        });
        unit.add_function(
            CFunctionSignature::new("int", "main"),
            "return 0;".to_string(),
        );
        let output = unit.render();
        assert!(output.contains("#include <stdint.h>"));
        assert!(output.contains("typedef unsigned int u32;"));
        assert!(output.contains("int main"));
        assert!(output.contains("return 0;"));
    }

    #[test]
    fn test_cpp_exporter() {
        let mut exp = CppExporter::new();
        exp.emit_pragma_once = true;
        exp.emit_extern_c = true;
        exp.unit.add_include("stdlib.h");
        let output = exp.export();
        assert!(output.contains("#pragma once"));
        assert!(output.contains("extern \"C\""));
        assert!(output.contains("#include <stdlib.h>"));
    }

    #[test]
    fn test_global_variable() {
        let mut unit = CppExportUnit::new();
        unit.add_global("int", "counter", Some("0"));
        unit.add_global("char*", "name", None::<String>);
        let output = unit.render();
        assert!(output.contains("int counter = 0;"));
        assert!(output.contains("char* name;"));
    }

    #[test]
    fn test_local_includes() {
        let mut unit = CppExportUnit::new();
        unit.add_local_include("myheader.h");
        let output = unit.render();
        assert!(output.contains("#include \"myheader.h\""));
    }

    #[test]
    fn test_empty_export() {
        let exp = CppExporter::new();
        let output = exp.export();
        // Should not panic on empty export.
        assert!(output.is_empty());
    }

    #[test]
    fn test_union_display() {
        let decl = TypeDeclaration::Union {
            name: "Value".into(),
            fields: vec![("i".into(), "int".into()), ("f".into(), "float".into())],
        };
        let s = decl.to_string();
        assert!(s.contains("union Value"));
        assert!(s.contains("int i;"));
        assert!(s.contains("float f;"));
    }

    #[test]
    fn test_function_no_params() {
        let sig = CFunctionSignature::new("void", "init");
        assert_eq!(sig.to_prototype(), "void init();");
    }

    #[test]
    fn test_definition_header() {
        let sig = CFunctionSignature::new("int", "add").param("int", "a");
        let header = sig.to_definition_header();
        assert!(header.contains("int add(int a)"));
        assert!(!header.contains(';'));
    }
}
