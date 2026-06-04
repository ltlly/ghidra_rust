//! JSON documentation generator.
//!
//! Port of `ghidra.doclets.json.JsonDoclet`.
//!
//! Converts class/interface documentation into JSON format for consumption by
//! other tools (e.g., Python bindings).

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// The access modifier of a Java element.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum AccessModifier {
    Public,
    Private,
    Protected,
    #[default]
    #[serde(rename = "")]
    None,
}

/// A parameter in a method or constructor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParamInfo {
    pub name: String,
    pub type_long: String,
    pub type_short: String,
    #[serde(default)]
    pub comment: String,
}

/// Return type information for a method.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReturnInfo {
    pub type_long: String,
    pub type_short: String,
    #[serde(default)]
    pub comment: String,
}

/// Exception/thrown type information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThrowsInfo {
    pub type_long: String,
    pub type_short: String,
    #[serde(default)]
    pub comment: String,
}

/// A field in a class.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldInfo {
    pub name: String,
    #[serde(default)]
    pub comment: String,
    #[serde(default)]
    pub javadoc: String,
    #[serde(default)]
    pub r#static: bool,
    #[serde(default)]
    pub access: AccessModifier,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub type_long: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub type_short: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub constant_value: Option<String>,
}

/// A method or constructor in a class.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MethodInfo {
    pub name: String,
    #[serde(default)]
    pub comment: String,
    #[serde(default)]
    pub javadoc: String,
    #[serde(default)]
    pub r#static: bool,
    #[serde(default)]
    pub access: AccessModifier,
    #[serde(default)]
    pub params: Vec<ParamInfo>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub r#return: Option<ReturnInfo>,
    #[serde(default)]
    pub throws: Vec<ThrowsInfo>,
}

/// Complete documentation for a class or interface.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClassDoc {
    pub name: String,
    #[serde(default)]
    pub comment: String,
    #[serde(default)]
    pub javadoc: String,
    #[serde(default)]
    pub r#static: bool,
    #[serde(default)]
    pub access: AccessModifier,
    #[serde(default)]
    pub implements: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extends: Option<String>,
    #[serde(default)]
    pub fields: Vec<FieldInfo>,
    #[serde(default)]
    pub methods: Vec<MethodInfo>,
}

/// Convert a qualified Java class name to a file path.
fn qualified_name_to_path(name: &str) -> PathBuf {
    PathBuf::from(name.replace('.', "/")).with_extension("json")
}

/// Write a `ClassDoc` to a JSON file in the given destination directory.
pub fn write_class_doc(dest_dir: &Path, class_doc: &ClassDoc) -> Result<PathBuf, std::io::Error> {
    let rel_path = qualified_name_to_path(&class_doc.name);
    let file_path = dest_dir.join(rel_path);
    if let Some(parent) = file_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let json = serde_json::to_string_pretty(class_doc)?;
    std::fs::write(&file_path, format!("{json}\n"))?;
    Ok(file_path)
}

/// Read a `ClassDoc` from a JSON file.
pub fn read_class_doc(path: &Path) -> Result<ClassDoc, Box<dyn std::error::Error>> {
    let content = std::fs::read_to_string(path)?;
    let doc: ClassDoc = serde_json::from_str(&content)?;
    Ok(doc)
}

/// Helper to get the short type name from a fully qualified name.
///
/// For declared types, this extracts the simple name after the last `.`.
/// For primitive/array types, returns the full name.
pub fn get_short_type(type_name: &str) -> String {
    if type_name.starts_with('[') {
        // Array type - return as-is
        return type_name.to_string();
    }
    type_name
        .rsplit_once('.')
        .map(|(_, short)| short.to_string())
        .unwrap_or_else(|| type_name.to_string())
}

/// Helper to sanitize a name for Python compatibility.
///
/// Appends `_` to names that collide with Python keywords.
pub fn sanitize_python_name(name: &str) -> String {
    const PY_KEYWORDS: &[&str] = &[
        "False", "None", "True", "and", "as", "assert", "async", "await", "break", "class",
        "continue", "def", "del", "elif", "else", "except", "exec", "finally", "for", "from",
        "global", "if", "import", "in", "is", "lambda", "nonlocal", "not", "or", "pass", "raise",
        "return", "try", "while", "with", "yield",
    ];
    if PY_KEYWORDS.contains(&name) {
        format!("{name}_")
    } else {
        name.to_string()
    }
}

/// Sanitize a fully qualified name for Python, replacing each component.
pub fn sanitize_qualified_name(name: &str) -> String {
    name.split('.')
        .map(sanitize_python_name)
        .collect::<Vec<_>>()
        .join(".")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_class_doc_serialization() {
        let doc = ClassDoc {
            name: "com.example.MyClass".to_string(),
            comment: "A test class".to_string(),
            javadoc: String::new(),
            r#static: false,
            access: AccessModifier::Public,
            implements: vec!["java.io.Serializable".to_string()],
            extends: Some("java.lang.Object".to_string()),
            fields: vec![FieldInfo {
                name: "value".to_string(),
                comment: String::new(),
                javadoc: String::new(),
                r#static: false,
                access: AccessModifier::Private,
                type_long: Some("int".to_string()),
                type_short: Some("int".to_string()),
                constant_value: None,
            }],
            methods: vec![MethodInfo {
                name: "getValue".to_string(),
                comment: "Get the value".to_string(),
                javadoc: String::new(),
                r#static: false,
                access: AccessModifier::Public,
                params: vec![],
                r#return: Some(ReturnInfo {
                    type_long: "int".to_string(),
                    type_short: "int".to_string(),
                    comment: String::new(),
                }),
                throws: vec![],
            }],
        };

        let json = serde_json::to_string_pretty(&doc).unwrap();
        assert!(json.contains("com.example.MyClass"));
        assert!(json.contains("getValue"));

        let parsed: ClassDoc = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.name, "com.example.MyClass");
        assert_eq!(parsed.fields.len(), 1);
        assert_eq!(parsed.methods.len(), 1);
    }

    #[test]
    fn test_qualified_name_to_path() {
        assert_eq!(
            qualified_name_to_path("com.example.MyClass"),
            PathBuf::from("com/example/MyClass.json")
        );
    }

    #[test]
    fn test_get_short_type() {
        assert_eq!(get_short_type("java.lang.String"), "String");
        assert_eq!(get_short_type("int"), "int");
        assert_eq!(get_short_type("[Ljava.lang.String;"), "[Ljava.lang.String;");
    }

    #[test]
    fn test_sanitize_python_name() {
        assert_eq!(sanitize_python_name("class"), "class_");
        assert_eq!(sanitize_python_name("return"), "return_");
        assert_eq!(sanitize_python_name("normal"), "normal");
    }

    #[test]
    fn test_sanitize_qualified_name() {
        assert_eq!(
            sanitize_qualified_name("com.class.for"),
            "com.class_.for_"
        );
    }

    #[test]
    fn test_write_and_read_class_doc() {
        let dir = tempfile::tempdir().unwrap();
        let doc = ClassDoc {
            name: "pkg.MyClass".to_string(),
            comment: String::new(),
            javadoc: String::new(),
            r#static: false,
            access: AccessModifier::Public,
            implements: vec![],
            extends: None,
            fields: vec![],
            methods: vec![],
        };

        let path = write_class_doc(dir.path(), &doc).unwrap();
        assert!(path.exists());

        let loaded = read_class_doc(&path).unwrap();
        assert_eq!(loaded.name, "pkg.MyClass");
    }
}
