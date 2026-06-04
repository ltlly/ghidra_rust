//! DecompiledFunction: holds pieces of a decompiled function.
//!
//! Port of Ghidra's `ghidra.app.decompiler.DecompiledFunction`.

/// A class to hold pieces of a decompiled function.
///
/// Contains both the function signature (prototype) and the complete
/// C code of the decompiled function as separate strings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecompiledFunction {
    /// The function signature or prototype (e.g., "int foo(double d)").
    signature: Option<String>,
    /// The complete C code of the function.
    c_code: String,
}

impl DecompiledFunction {
    /// Create a new DecompiledFunction.
    pub fn new(signature: Option<String>, c_code: String) -> Self {
        Self { signature, c_code }
    }

    /// Returns the function signature or prototype.
    pub fn signature(&self) -> Option<&str> {
        self.signature.as_deref()
    }

    /// Returns the complete C code of the function.
    pub fn c_code(&self) -> &str {
        &self.c_code
    }

    /// Returns the complete C code as an owned String.
    pub fn into_c_code(self) -> String {
        self.c_code
    }
}

impl fmt::Display for DecompiledFunction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(sig) = &self.signature {
            writeln!(f, "{}", sig)?;
        }
        write!(f, "{}", self.c_code)
    }
}

use std::fmt;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decompiled_function_basic() {
        let df = DecompiledFunction::new(
            Some("int main(int argc, char **argv)".to_string()),
            "int main(int argc, char **argv) {\n    return 0;\n}\n".to_string(),
        );
        assert_eq!(df.signature(), Some("int main(int argc, char **argv)"));
        assert!(df.c_code().contains("return 0"));
    }

    #[test]
    fn test_decompiled_function_no_signature() {
        let df = DecompiledFunction::new(None, "void foo() {}".to_string());
        assert!(df.signature().is_none());
        assert_eq!(df.c_code(), "void foo() {}");
    }

    #[test]
    fn test_display() {
        let df = DecompiledFunction::new(
            Some("int x()".to_string()),
            "int x() { return 1; }\n".to_string(),
        );
        let s = format!("{}", df);
        assert!(s.contains("int x()"));
        assert!(s.contains("return 1"));
    }
}
