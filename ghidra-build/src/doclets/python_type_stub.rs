//! Python type stub (.pyi) generation.
//!
//! Port of `ghidra.doclets.typestubs.PythonTypeStub*` classes.
//!
//! Models the data structures and logic for generating Python type stubs
//! from Java class information.

use std::collections::HashMap;
use std::fmt::Write;

use super::json_doclet::{sanitize_python_name, sanitize_qualified_name};

/// Python indentation unit (4 spaces).
pub const PY_INDENT: &str = "    ";

/// Triple-quote docstring delimiter.
pub const DOC_QUOTES: &str = "\"\"\"";

/// Alternative triple-quote docstring delimiter.
pub const ALT_DOC_QUOTES: &str = "'''";

/// Mapping from Java generic types to their Python equivalents.
pub fn generic_customizers() -> HashMap<&'static str, &'static str> {
    let mut m = HashMap::new();
    m.insert("java.lang.Iterable", "collections.abc.Iterable");
    m.insert("java.util.Collection", "collections.abc.Collection");
    m.insert("java.util.List", "list");
    m.insert("java.util.Map", "dict");
    m.insert("java.util.Set", "set");
    m.insert("java.util.Map.Entry", "tuple");
    m.insert("java.util.Iterator", "collections.abc.Iterator");
    m.insert("java.util.Enumeration", "collections.abc.Iterator");
    m
}

/// Mapping from Java auto-conversion types to their Python union types (for parameters).
pub fn auto_conversions() -> HashMap<&'static str, &'static str> {
    let mut m = HashMap::new();
    m.insert("java.lang.Boolean", "typing.Union[java.lang.Boolean, bool]");
    m.insert("java.lang.Byte", "typing.Union[java.lang.Byte, int]");
    m.insert(
        "java.lang.Character",
        "typing.Union[java.lang.Character, int, str]",
    );
    m.insert(
        "java.lang.Double",
        "typing.Union[java.lang.Double, float]",
    );
    m.insert("java.lang.Float", "typing.Union[java.lang.Float, float]");
    m.insert(
        "java.lang.Integer",
        "typing.Union[java.lang.Integer, int]",
    );
    m.insert("java.lang.Long", "typing.Union[java.lang.Long, int]");
    m.insert(
        "java.lang.Short",
        "typing.Union[java.lang.Short, int]",
    );
    m.insert(
        "java.lang.String",
        "typing.Union[java.lang.String, str]",
    );
    m.insert("java.io.File", "jpype.protocol.SupportsPath");
    m.insert("java.nio.file.Path", "jpype.protocol.SupportsPath");
    m.insert(
        "java.lang.Iterable",
        "collections.abc.Sequence",
    );
    m.insert(
        "java.util.Collection",
        "collections.abc.Sequence",
    );
    m.insert("java.util.Map", "collections.abc.Mapping");
    m.insert("java.time.Instant", "datetime.datetime");
    m.insert("java.sql.Time", "datetime.time");
    m.insert("java.sql.Date", "datetime.date");
    m.insert("java.sql.Timestamp", "datetime.datetime");
    m.insert("java.math.BigDecimal", "decimal.Decimal");
    m
}

/// Mapping from Java result types to their Python equivalents (for return types).
pub fn result_conversions() -> HashMap<&'static str, &'static str> {
    let mut m = HashMap::new();
    m.insert("java.lang.Boolean", "bool");
    m.insert("java.lang.Byte", "int");
    m.insert("java.lang.Character", "str");
    m.insert("java.lang.Double", "float");
    m.insert("java.lang.Float", "float");
    m.insert("java.lang.Integer", "int");
    m.insert("java.lang.Long", "int");
    m.insert("java.lang.Short", "int");
    m.insert("java.lang.String", "str");
    m
}

/// Convert a Java primitive type kind to its Python result type.
pub fn convert_primitive_result(type_kind: &str) -> Option<&'static str> {
    match type_kind {
        "BOOLEAN" => Some("bool"),
        "BYTE" => Some("int"),
        "CHAR" => Some("str"),
        "DOUBLE" => Some("float"),
        "FLOAT" => Some("float"),
        "INT" => Some("int"),
        "LONG" => Some("int"),
        "SHORT" => Some("int"),
        "VOID" => Some("None"),
        _ => None,
    }
}

/// Convert a Java primitive type kind to its Python parameter union type.
pub fn convert_primitive_param(type_kind: &str) -> Option<&'static str> {
    match type_kind {
        "BOOLEAN" => Some("typing.Union[jpype.JBoolean, bool]"),
        "BYTE" => Some("typing.Union[jpype.JByte, int]"),
        "CHAR" => Some("typing.Union[jpype.JChar, int, str]"),
        "DOUBLE" => Some("typing.Union[jpype.JDouble, float]"),
        "FLOAT" => Some("typing.Union[jpype.JFloat, float]"),
        "INT" => Some("typing.Union[jpype.JInt, int]"),
        "LONG" => Some("typing.Union[jpype.JLong, int]"),
        "SHORT" => Some("typing.Union[jpype.JShort, int]"),
        _ => None,
    }
}

/// Check if a Java type name is a primitive.
pub fn is_primitive(type_kind: &str) -> bool {
    matches!(
        type_kind,
        "BOOLEAN" | "BYTE" | "CHAR" | "DOUBLE" | "FLOAT" | "INT" | "LONG" | "SHORT"
    )
}

/// Convert a float constant value to its Python representation.
pub fn convert_float_constant(value: f64) -> String {
    if value.is_infinite() {
        if value < 0.0 {
            "float(\"-inf\")".to_string()
        } else {
            "float(\"inf\")".to_string()
        }
    } else if value.is_nan() {
        "float(\"nan\")".to_string()
    } else {
        value.to_string()
    }
}

/// Model for a Python type stub package.
#[derive(Debug, Clone)]
pub struct StubPackage {
    pub name: String,
    pub types: Vec<StubType>,
    pub doc: String,
}

/// Model for a Python type stub class/interface.
#[derive(Debug, Clone)]
pub struct StubType {
    pub name: String,
    pub doc: String,
    pub is_public: bool,
    pub is_deprecated: bool,
    pub deprecated_message: Option<String>,
    pub extends: Option<String>,
    pub implements: Vec<String>,
    pub type_params: Vec<String>,
    pub fields: Vec<StubField>,
    pub methods: Vec<StubMethod>,
    pub nested_types: Vec<StubType>,
}

/// Model for a Python type stub field.
#[derive(Debug, Clone)]
pub struct StubField {
    pub name: String,
    pub doc: String,
    pub type_name: String,
    pub is_static: bool,
    pub is_final: bool,
    pub constant_value: Option<String>,
}

/// Model for a Python type stub method.
#[derive(Debug, Clone)]
pub struct StubMethod {
    pub name: String,
    pub doc: String,
    pub is_static: bool,
    pub is_constructor: bool,
    pub params: Vec<StubParam>,
    pub return_type: String,
    pub type_params: Vec<String>,
    pub is_overload: bool,
    pub is_deprecated: bool,
    pub deprecated_message: Option<String>,
}

/// Model for a Python type stub parameter.
#[derive(Debug, Clone)]
pub struct StubParam {
    pub name: String,
    pub type_name: String,
}

/// Generate the standard Python stub file header.
pub fn write_stub_header(output: &mut String, package_doc: &str) {
    if !package_doc.is_empty() {
        let quotes = if package_doc.contains(DOC_QUOTES) {
            ALT_DOC_QUOTES
        } else {
            DOC_QUOTES
        };
        output.push_str(quotes);
        output.push('\n');
        output.push_str(package_doc);
        output.push('\n');
        output.push_str(quotes);
        output.push('\n');
    }
    output.push_str("from __future__ import annotations\n");
    output.push_str("import collections.abc\n");
    output.push_str("import datetime\n");
    output.push_str("import typing\n");
    output.push_str("from warnings import deprecated # type: ignore\n");
    output.push('\n');
    output.push_str("import jpype # type: ignore\n");
    output.push_str("import jpype.protocol # type: ignore\n");
    output.push('\n');
}

/// Write a Python type stub class definition to the output string.
pub fn write_type_stub(output: &mut String, stub: &StubType, indent: &str) {
    if !stub.is_public {
        let _ = writeln!(output, "{indent}@typing.type_check_only");
    }
    if stub.is_deprecated {
        if let Some(ref msg) = stub.deprecated_message {
            let _ = writeln!(output, "{indent}@deprecated({msg})");
        }
    }

    let _ = write!(output, "{indent}class {}", sanitize_python_name(&stub.name));

    // Build base class list
    let mut bases = Vec::new();
    if let Some(ref ext) = stub.extends {
        bases.push(sanitize_qualified_name(ext));
    }
    for iface in &stub.implements {
        bases.push(sanitize_qualified_name(iface));
    }
    if !stub.type_params.is_empty() {
        let generic_type = format!("typing.Generic[{}]", stub.type_params.join(", "));
        bases.push(generic_type);
    }

    if !bases.is_empty() {
        let _ = write!(output, "({})", bases.join(", "));
    }
    output.push_str(":\n");

    let inner_indent = format!("{indent}{PY_INDENT}");

    // Docstring
    if !stub.doc.is_empty() {
        let quotes = if stub.doc.contains(DOC_QUOTES) {
            ALT_DOC_QUOTES
        } else {
            DOC_QUOTES
        };
        let _ = writeln!(output, "{inner_indent}{quotes}");
        let _ = writeln!(output, "{inner_indent}{}", stub.doc);
        let _ = writeln!(output, "{inner_indent}{quotes}");
    }

    // Nested types
    for nested in &stub.nested_types {
        write_type_stub(output, nested, &inner_indent);
    }

    // Class literal field
    let _ = writeln!(
        output,
        "{inner_indent}class_: typing.ClassVar[java.lang.Class]"
    );

    // Fields
    for field in &stub.fields {
        write_field_stub(output, field, &inner_indent);
    }

    output.push('\n');

    // Methods
    for method in &stub.methods {
        write_method_stub(output, method, &inner_indent);
    }

    if stub.nested_types.is_empty() && stub.fields.is_empty() && stub.methods.is_empty() {
        let _ = writeln!(output, "{inner_indent}...");
    }

    output.push('\n');
}

/// Write a field stub.
fn write_field_stub(output: &mut String, field: &StubField, indent: &str) {
    let name = sanitize_python_name(&field.name);
    if let Some(ref constant) = field.constant_value {
        let _ = writeln!(output, "{indent}{name}: typing.Final = {constant}");
    } else {
        let type_str = &field.type_name;
        let wrapped = if field.is_final {
            format!("typing.Final[{type_str}]")
        } else if field.is_static {
            format!("typing.ClassVar[{type_str}]")
        } else {
            type_str.clone()
        };
        let _ = writeln!(output, "{indent}{name}: {wrapped}");
    }
}

/// Write a method stub.
fn write_method_stub(output: &mut String, method: &StubMethod, indent: &str) {
    let name = if method.is_constructor {
        "__init__".to_string()
    } else {
        sanitize_python_name(&method.name)
    };

    if method.is_static {
        let _ = writeln!(output, "{indent}@staticmethod");
    }
    if method.is_overload {
        let _ = writeln!(output, "{indent}@typing.overload");
    }
    if method.is_deprecated {
        if let Some(ref msg) = method.deprecated_message {
            let _ = writeln!(output, "{indent}@deprecated({msg})");
        }
    }

    let params_str = if method.is_static || method.is_constructor {
        method
            .params
            .iter()
            .map(|p| format!("{}: {}", sanitize_python_name(&p.name), p.type_name))
            .collect::<Vec<_>>()
            .join(", ")
    } else {
        let self_part = "self";
        let params: Vec<String> = method
            .params
            .iter()
            .map(|p| format!("{}: {}", sanitize_python_name(&p.name), p.type_name))
            .collect();
        if params.is_empty() {
            self_part.to_string()
        } else {
            format!("{}, {}", self_part, params.join(", "))
        }
    };

    let _ = writeln!(
        output,
        "{indent}def {name}({params_str}) -> {}:",
        method.return_type
    );

    let inner = format!("{indent}{PY_INDENT}");
    if method.doc.is_empty() {
        let _ = writeln!(output, "{inner}...");
    } else {
        let quotes = if method.doc.contains(DOC_QUOTES) {
            ALT_DOC_QUOTES
        } else {
            DOC_QUOTES
        };
        let _ = writeln!(output, "{inner}{quotes}");
        let _ = writeln!(output, "{inner}{}", method.doc);
        let _ = writeln!(output, "{inner}{quotes}");
    }
    output.push('\n');
}

/// Check if a method name looks like a Python property getter/setter/is-method.
pub fn is_property_candidate(name: &str, is_static: bool, param_count: usize, is_void: bool) -> bool {
    if is_static {
        return false;
    }
    if param_count > 1 {
        return false;
    }
    if name.starts_with("get") && name.len() > 3 {
        let c = name.chars().nth(3).unwrap();
        c.is_uppercase() && !is_void
    } else if name.starts_with("is") && name.len() > 2 {
        let c = name.chars().nth(2).unwrap();
        c.is_uppercase() && !is_void
    } else if name.starts_with("set") && name.len() > 3 {
        let c = name.chars().nth(3).unwrap();
        c.is_uppercase() && is_void && param_count == 1
    } else {
        false
    }
}

/// Extract the property name from a getter/setter method name.
pub fn get_property_name(method_name: &str) -> Option<String> {
    if let Some(rest) = method_name.strip_prefix("get") {
        if rest.len() > 0 {
            let first = rest.chars().next().unwrap().to_lowercase().to_string();
            return Some(format!("{}{}", first, &rest[1..]));
        }
    }
    if let Some(rest) = method_name.strip_prefix("set") {
        if rest.len() > 0 {
            let first = rest.chars().next().unwrap().to_lowercase().to_string();
            return Some(format!("{}{}", first, &rest[1..]));
        }
    }
    if let Some(rest) = method_name.strip_prefix("is") {
        if rest.len() > 0 {
            let first = rest.chars().next().unwrap().to_lowercase().to_string();
            return Some(format!("{}{}", first, &rest[1..]));
        }
    }
    None
}

/// Write the `__all__` export list at the end of a stub file.
pub fn write_all_exports(output: &mut String, exports: &[String]) {
    output.push_str("__all__ = [");
    for (i, name) in exports.iter().enumerate() {
        if i > 0 {
            output.push_str(", ");
        }
        let _ = write!(output, "\"{name}\"");
    }
    output.push_str("]\n");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_write_stub_header() {
        let mut out = String::new();
        write_stub_header(&mut out, "Test package");
        assert!(out.contains("from __future__ import annotations"));
        assert!(out.contains("import jpype"));
        assert!(out.contains("Test package"));
    }

    #[test]
    fn test_write_type_stub_simple() {
        let stub = StubType {
            name: "MyClass".to_string(),
            doc: "A test class.".to_string(),
            is_public: true,
            is_deprecated: false,
            deprecated_message: None,
            extends: Some("java.lang.Object".to_string()),
            implements: vec![],
            type_params: vec![],
            fields: vec![],
            methods: vec![],
            nested_types: vec![],
        };
        let mut out = String::new();
        write_type_stub(&mut out, &stub, "");
        assert!(out.contains("class MyClass(java.lang.Object):"));
        assert!(out.contains("A test class."));
    }

    #[test]
    fn test_write_type_stub_with_method() {
        let stub = StubType {
            name: "Foo".to_string(),
            doc: String::new(),
            is_public: true,
            is_deprecated: false,
            deprecated_message: None,
            extends: None,
            implements: vec![],
            type_params: vec![],
            fields: vec![],
            methods: vec![StubMethod {
                name: "doSomething".to_string(),
                doc: "Does something".to_string(),
                is_static: false,
                is_constructor: false,
                params: vec![StubParam {
                    name: "arg".to_string(),
                    type_name: "int".to_string(),
                }],
                return_type: "None".to_string(),
                type_params: vec![],
                is_overload: false,
                is_deprecated: false,
                deprecated_message: None,
            }],
            nested_types: vec![],
        };
        let mut out = String::new();
        write_type_stub(&mut out, &stub, "");
        assert!(out.contains("def doSomething(self, arg: int) -> None:"));
        assert!(out.contains("Does something"));
    }

    #[test]
    fn test_convert_float_constant() {
        assert_eq!(convert_float_constant(f64::INFINITY), "float(\"inf\")");
        assert_eq!(
            convert_float_constant(f64::NEG_INFINITY),
            "float(\"-inf\")"
        );
        assert_eq!(convert_float_constant(f64::NAN), "float(\"nan\")");
        assert_eq!(convert_float_constant(3.14), "3.14");
    }

    #[test]
    fn test_is_property_candidate() {
        assert!(is_property_candidate("getValue", false, 0, false));
        assert!(is_property_candidate("isActive", false, 0, false));
        assert!(is_property_candidate("setValue", false, 1, true));
        assert!(!is_property_candidate("getValue", true, 0, false));
        assert!(!is_property_candidate("doSomething", false, 0, false));
    }

    #[test]
    fn test_get_property_name() {
        assert_eq!(
            get_property_name("getValue"),
            Some("value".to_string())
        );
        assert_eq!(
            get_property_name("isActive"),
            Some("active".to_string())
        );
        assert_eq!(
            get_property_name("setName"),
            Some("name".to_string())
        );
        assert_eq!(get_property_name("doSomething"), None);
    }

    #[test]
    fn test_write_all_exports() {
        let mut out = String::new();
        write_all_exports(
            &mut out,
            &["Foo".to_string(), "Bar".to_string()],
        );
        assert_eq!(out, "__all__ = [\"Foo\", \"Bar\"]\n");
    }

    #[test]
    fn test_convert_primitive_result() {
        assert_eq!(convert_primitive_result("BOOLEAN"), Some("bool"));
        assert_eq!(convert_primitive_result("VOID"), Some("None"));
        assert_eq!(convert_primitive_result("UNKNOWN"), None);
    }

    #[test]
    fn test_convert_primitive_param() {
        assert_eq!(
            convert_primitive_param("INT"),
            Some("typing.Union[jpype.JInt, int]")
        );
        assert_eq!(convert_primitive_param("UNKNOWN"), None);
    }

    #[test]
    fn test_is_primitive() {
        assert!(is_primitive("INT"));
        assert!(is_primitive("BOOLEAN"));
        assert!(!is_primitive("java.lang.String"));
    }

    #[test]
    fn test_generic_customizers() {
        let gc = generic_customizers();
        assert_eq!(gc.get("java.util.List"), Some(&"list"));
        assert_eq!(gc.get("java.util.Map"), Some(&"dict"));
    }

    #[test]
    fn test_auto_conversions() {
        let ac = auto_conversions();
        assert!(ac.contains_key("java.lang.String"));
        assert!(ac.contains_key("java.io.File"));
    }

    #[test]
    fn test_result_conversions() {
        let rc = result_conversions();
        assert_eq!(rc.get("java.lang.Boolean"), Some(&"bool"));
        assert_eq!(rc.get("java.lang.String"), Some(&"str"));
    }
}
