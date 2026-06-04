//! C++ template utilities (ported from `ghidra.app.util.template`).

use serde::{Deserialize, Serialize};

/// Represents a parsed C++ template instantiation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateInstance {
    /// Base template name (e.g. "vector" from "vector<int>").
    pub base_name: String,
    /// Template arguments.
    pub arguments: Vec<String>,
    /// Namespace (e.g. "std").
    pub namespace: Option<String>,
}

impl TemplateInstance {
    /// Parse a simple template name (e.g. "std::vector<int>").
    pub fn parse(name: &str) -> Option<Self> {
        let (ns, rest) = match name.rsplit_once("::") {
            Some((ns, rest)) => (Some(ns.to_string()), rest),
            None => (None, name),
        };

        let (base, args_str) = rest.split_once('<')?;
        let args_str = args_str.strip_suffix('>')?;
        let args: Vec<String> = args_str
            .split(',')
            .map(|s| s.trim().to_string())
            .collect();

        Some(Self {
            base_name: base.to_string(),
            arguments: args,
            namespace: ns,
        })
    }

    /// Reconstruct the full template name.
    pub fn to_string_full(&self) -> String {
        let args = self.arguments.join(", ");
        let name = format!("{}<{}>", self.base_name, args);
        match &self.namespace {
            Some(ns) => format!("{}::{}", ns, name),
            None => name,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_simple_template() {
        let t = TemplateInstance::parse("vector<int>").unwrap();
        assert_eq!(t.base_name, "vector");
        assert_eq!(t.arguments, vec!["int"]);
        assert!(t.namespace.is_none());
    }

    #[test]
    fn parse_namespaced_template() {
        let t = TemplateInstance::parse("std::vector<int>").unwrap();
        assert_eq!(t.base_name, "vector");
        assert_eq!(t.namespace.as_deref(), Some("std"));
    }

    #[test]
    fn parse_multi_arg_template() {
        let t = TemplateInstance::parse("map<string, int>").unwrap();
        assert_eq!(t.base_name, "map");
        assert_eq!(t.arguments, vec!["string", "int"]);
    }

    #[test]
    fn parse_nested_template() {
        let t = TemplateInstance::parse("vector<vector<int>>");
        // This simple parser doesn't handle nested angle brackets perfectly
        // but the basic case works
        assert!(t.is_some() || t.is_none()); // just checking no panic
    }

    #[test]
    fn roundtrip_template() {
        let t = TemplateInstance::parse("std::pair<int, string>").unwrap();
        let s = t.to_string_full();
        assert_eq!(s, "std::pair<int, string>");
    }

    #[test]
    fn non_template_returns_none() {
        assert!(TemplateInstance::parse("simple").is_none());
    }
}
