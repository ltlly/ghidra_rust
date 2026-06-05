//! SarifWriter - writes taint analysis results in SARIF format.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.debug.taint.SarifKeyValueWriter`
//! and `SarifLogicalLocationWriter`.

use serde::{Deserialize, Serialize};

/// A SARIF logical location (function, file, etc.).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifLogicalLocation {
    /// The kind of location (e.g., "function", "module").
    pub kind: String,
    /// The fully qualified name.
    pub name: String,
    /// The parent index in the logical locations array.
    pub parent_index: Option<usize>,
    /// Decorated name (mangled).
    pub decorated_name: Option<String>,
}

/// A SARIF region (address range in a binary).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifRegion {
    /// Start offset (byte address).
    pub start_offset: u64,
    /// End offset (byte address).
    pub end_offset: u64,
    /// Start line number (if source available).
    pub start_line: Option<u32>,
    /// End line number (if source available).
    pub end_line: Option<u32>,
}

/// A SARIF result entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifResult {
    /// The rule ID that was triggered.
    pub rule_id: String,
    /// The message describing the result.
    pub message: String,
    /// The severity level.
    pub level: SarifLevel,
    /// The locations where this result applies.
    pub locations: Vec<SarifLocation>,
    /// Key-value properties.
    pub properties: Vec<(String, String)>,
}

/// A SARIF location reference.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifLocation {
    /// The physical location (address in binary).
    pub physical: Option<SarifRegion>,
    /// The logical location index.
    pub logical_index: Option<usize>,
    /// The message for this location.
    pub message: Option<String>,
}

/// SARIF result severity level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SarifLevel {
    /// An informational result.
    Note,
    /// A warning.
    Warning,
    /// An error.
    Error,
    /// A fatal error.
    Fatal,
}

/// Writer for SARIF format taint analysis output.
///
/// Ported from Ghidra's `SarifKeyValueWriter` and `SarifLogicalLocationWriter`.
#[derive(Debug, Default)]
pub struct SarifWriter {
    logical_locations: Vec<SarifLogicalLocation>,
    results: Vec<SarifResult>,
    tool_name: String,
    tool_version: String,
}

impl SarifWriter {
    /// Create a new SARIF writer.
    pub fn new(tool_name: impl Into<String>, tool_version: impl Into<String>) -> Self {
        Self {
            tool_name: tool_name.into(),
            tool_version: tool_version.into(),
            ..Default::default()
        }
    }

    /// Add a logical location.
    pub fn add_logical_location(&mut self, loc: SarifLogicalLocation) -> usize {
        let idx = self.logical_locations.len();
        self.logical_locations.push(loc);
        idx
    }

    /// Add a function location.
    pub fn add_function(
        &mut self,
        name: impl Into<String>,
        decorated: Option<String>,
        parent: Option<usize>,
    ) -> usize {
        self.add_logical_location(SarifLogicalLocation {
            kind: "function".into(),
            name: name.into(),
            parent_index: parent,
            decorated_name: decorated,
        })
    }

    /// Add a module location.
    pub fn add_module(&mut self, name: impl Into<String>) -> usize {
        self.add_logical_location(SarifLogicalLocation {
            kind: "module".into(),
            name: name.into(),
            parent_index: None,
            decorated_name: None,
        })
    }

    /// Add a result.
    pub fn add_result(&mut self, result: SarifResult) {
        self.results.push(result);
    }

    /// Add a taint result at an address.
    pub fn add_taint_result(
        &mut self,
        rule_id: impl Into<String>,
        message: impl Into<String>,
        level: SarifLevel,
        address: u64,
        logical_index: Option<usize>,
    ) {
        self.results.push(SarifResult {
            rule_id: rule_id.into(),
            message: message.into(),
            level,
            locations: vec![SarifLocation {
                physical: Some(SarifRegion {
                    start_offset: address,
                    end_offset: address + 1,
                    start_line: None,
                    end_line: None,
                }),
                logical_index,
                message: None,
            }],
            properties: Vec::new(),
        });
    }

    /// Add a key-value property to the last result.
    pub fn add_property(&mut self, key: impl Into<String>, value: impl Into<String>) {
        if let Some(last) = self.results.last_mut() {
            last.properties.push((key.into(), value.into()));
        }
    }

    /// Get all logical locations.
    pub fn logical_locations(&self) -> &[SarifLogicalLocation] {
        &self.logical_locations
    }

    /// Get all results.
    pub fn results(&self) -> &[SarifResult] {
        &self.results
    }

    /// Write the SARIF output as JSON.
    pub fn to_json(&self) -> String {
        let output = SarifOutput {
            version: "2.1.0".into(),
            runs: vec![SarifRun {
                tool: SarifTool {
                    driver: SarifDriver {
                        name: self.tool_name.clone(),
                        version: self.tool_version.clone(),
                    },
                },
                logical_locations: self.logical_locations.clone(),
                results: self.results.clone(),
            }],
        };
        serde_json::to_string_pretty(&output).unwrap_or_default()
    }

    /// Get the number of results.
    pub fn result_count(&self) -> usize {
        self.results.len()
    }
}

#[derive(Serialize)]
struct SarifOutput {
    version: String,
    runs: Vec<SarifRun>,
}

#[derive(Serialize)]
struct SarifRun {
    tool: SarifTool,
    #[serde(rename = "logicalLocations")]
    logical_locations: Vec<SarifLogicalLocation>,
    results: Vec<SarifResult>,
}

#[derive(Serialize)]
struct SarifTool {
    driver: SarifDriver,
}

#[derive(Serialize)]
struct SarifDriver {
    name: String,
    version: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sarif_writer_new() {
        let w = SarifWriter::new("Ghidra", "10.0");
        assert_eq!(w.result_count(), 0);
    }

    #[test]
    fn test_add_locations() {
        let mut w = SarifWriter::new("test", "1.0");
        let mod_idx = w.add_module("libc.so");
        let fn_idx = w.add_function("malloc", Some("malloc".into()), Some(mod_idx));
        assert_eq!(w.logical_locations().len(), 2);
        assert_eq!(w.logical_locations()[fn_idx].parent_index, Some(mod_idx));
    }

    #[test]
    fn test_add_taint_result() {
        let mut w = SarifWriter::new("test", "1.0");
        let fn_idx = w.add_function("main", None, None);
        w.add_taint_result("TAINT001", "Tainted data flows to sink", SarifLevel::Warning, 0x400000, Some(fn_idx));
        assert_eq!(w.result_count(), 1);
        assert_eq!(w.results()[0].rule_id, "TAINT001");
    }

    #[test]
    fn test_add_property() {
        let mut w = SarifWriter::new("test", "1.0");
        w.add_taint_result("R1", "msg", SarifLevel::Note, 0x100, None);
        w.add_property("source", "user_input");
        assert_eq!(w.results()[0].properties.len(), 1);
    }

    #[test]
    fn test_to_json() {
        let mut w = SarifWriter::new("Ghidra", "10.0");
        w.add_module("test.so");
        w.add_taint_result("T001", "test", SarifLevel::Error, 0x1000, None);
        let json = w.to_json();
        assert!(json.contains("Ghidra"));
        assert!(json.contains("T001"));
    }

    #[test]
    fn test_sarif_level() {
        assert_ne!(SarifLevel::Note, SarifLevel::Error);
        assert_eq!(SarifLevel::Warning, SarifLevel::Warning);
    }
}
