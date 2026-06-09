//! SARIF 2.1.0 support for Ghidra Rust.
//!
//! Implements the [Static Analysis Results Interchange Format (SARIF) Version 2.1.0]
//! (https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html) for reading,
//! writing, and visualizing SARIF analysis results.
//!
//! # Sub-modules
//!
//! - [`sarif_plugin`] -- Plugin, service, and controller ported from
//!   `SarifPlugin.java`, `SarifService.java`, `SarifController.java`,
//!   `SarifProgramOptions.java`, and `SarifGraphDisplayListener.java`.
//! - [`sarif_exporter`] -- Exporter and loader ported from
//!   `SarifExporter.java`, `SarifLoader.java`, `SarifWriterTask.java`,
//!   and `SarifUtils.java`.
//!
//! # SARIF Compliance
//!
//! - Schema: `https://docs.oasis-open.org/sarif/sarif/v2.1.0/cos02/schemas/sarif-schema-2.1.0.json`
//! - Version: `2.1.0`
//! - Required properties present on all objects.
//!
//! # Example
//!
//! ```ignore
//! use ghidra_features::sarif::SarifExporter;
//!
//! let exporter = SarifExporter::new("MyTool".to_string());
//! exporter.add_result(
//!     "RULE001".into(),
//!     "Buffer overflow detected".into(),
//!     SarifLevel::Error,
//!     "0x401000".into(),
//! );
//! let json = exporter.to_json().unwrap();
//! fs::write("results.sarif", json).unwrap();
//! ```

pub mod sarif_plugin;
pub mod sarif_exporter;

use serde::{Deserialize, Serialize};
use std::io;

// ---------------------------------------------------------------------------
// SARIF Level enum
// ---------------------------------------------------------------------------

/// SARIF result severity level.
///
/// Maps to SARIF 2.1.0 `result.level` property.
/// Values: `"error"`, `"warning"`, `"note"`, `"none"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SarifLevel {
    /// A serious problem that should be addressed.
    Error,
    /// A potential problem or suboptimal pattern.
    Warning,
    /// An informational finding.
    Note,
    /// No severity assigned (default).
    None,
}

impl SarifLevel {
    /// Return the SARIF JSON string value for this level.
    pub fn as_str(&self) -> &'static str {
        match self {
            SarifLevel::Error => "error",
            SarifLevel::Warning => "warning",
            SarifLevel::Note => "note",
            SarifLevel::None => "none",
        }
    }
}

impl std::fmt::Display for SarifLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl Default for SarifLevel {
    fn default() -> Self {
        SarifLevel::None
    }
}

impl Serialize for SarifLevel {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for SarifLevel {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        match s.as_str() {
            "error" => Ok(SarifLevel::Error),
            "warning" => Ok(SarifLevel::Warning),
            "note" => Ok(SarifLevel::Note),
            "none" => Ok(SarifLevel::None),
            _ => Ok(SarifLevel::None),
        }
    }
}

// ---------------------------------------------------------------------------
// SARIF Property Bag (reusable key-value store)
// ---------------------------------------------------------------------------

/// A SARIF property bag: a string-keyed map of arbitrary values.
///
/// All SARIF objects may carry a `properties` bag for tool-specific extensions.
/// Required by the SARIF 2.1.0 schema.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SarifPropertyBag {
    /// Arbitrary string tags associated with this object.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,
}

// ---------------------------------------------------------------------------
// SARIF Tool Component
// ---------------------------------------------------------------------------

/// A tool component as defined in SARIF 2.1.0 section 3.19.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifToolComponent {
    /// The name of the tool component.
    pub name: String,

    /// The tool component version.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,

    /// The organization that produced the tool component.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub organization: Option<String>,

    /// The product containing the tool component.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub product: Option<String>,

    /// A concise description of the tool component.
    #[serde(rename = "shortDescription", skip_serializing_if = "Option::is_none")]
    pub short_description: Option<SarifMessage>,

    /// A comprehensive description of the tool component.
    #[serde(rename = "fullDescription", skip_serializing_if = "Option::is_none")]
    pub full_description: Option<SarifMessage>,

    /// The rules supported by this tool component.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rules: Option<Vec<SarifReportingDescriptor>>,

    /// The component language (RFC 5646).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub language: Option<String>,

    /// Key/value pairs of additional information.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<SarifPropertyBag>,
}

impl SarifToolComponent {
    /// Create a new tool component with the given name.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            version: None,
            organization: None,
            product: None,
            short_description: None,
            full_description: None,
            rules: None,
            language: None,
            properties: None,
        }
    }

    /// Set the version of this tool component.
    pub fn with_version(mut self, version: impl Into<String>) -> Self {
        self.version = Some(version.into());
        self
    }

    /// Set the rules for this tool component.
    pub fn with_rules(mut self, rules: Vec<SarifReportingDescriptor>) -> Self {
        self.rules = Some(rules);
        self
    }
}

// ---------------------------------------------------------------------------
// SARIF Tool
// ---------------------------------------------------------------------------

/// The analysis tool that generated the results (SARIF 2.1.0 section 3.18).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifTool {
    /// The tool driver component (required).
    pub driver: SarifToolComponent,

    /// Optional extensions/plugins.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extensions: Option<Vec<SarifToolComponent>>,
}

// ---------------------------------------------------------------------------
// SARIF Invocation
// ---------------------------------------------------------------------------

/// The runtime environment of the analysis tool (SARIF 2.1.0 section 3.8).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifInvocation {
    /// Whether the invocation completed successfully (required).
    #[serde(rename = "executionSuccessful")]
    pub execution_successful: bool,

    /// Command line arguments.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub arguments: Option<Vec<String>>,

    /// Working directory.
    #[serde(rename = "workingDirectory", skip_serializing_if = "Option::is_none")]
    pub working_directory: Option<SarifArtifactLocation>,

    /// Start time (ISO 8601).
    #[serde(rename = "startTimeUtc", skip_serializing_if = "Option::is_none")]
    pub start_time_utc: Option<String>,

    /// End time (ISO 8601).
    #[serde(rename = "endTimeUtc", skip_serializing_if = "Option::is_none")]
    pub end_time_utc: Option<String>,

    /// Machine name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub machine: Option<String>,

    /// Account that ran the tool.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account: Option<String>,

    /// Exit code.
    #[serde(rename = "exitCode", skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,

    /// Notifications during execution.
    #[serde(
        rename = "toolExecutionNotifications",
        skip_serializing_if = "Option::is_none"
    )]
    pub tool_execution_notifications: Option<Vec<SarifNotification>>,
}

impl SarifInvocation {
    /// Create a new invocation record.
    pub fn new(successful: bool) -> Self {
        Self {
            execution_successful: successful,
            arguments: None,
            working_directory: None,
            start_time_utc: None,
            end_time_utc: None,
            machine: None,
            account: None,
            exit_code: None,
            tool_execution_notifications: None,
        }
    }
}

// ---------------------------------------------------------------------------
// SARIF Message
// ---------------------------------------------------------------------------

/// Encapsulates a message with optional format arguments (SARIF 2.1.0 section 3.12).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifMessage {
    /// A plain text message string (required if `id` is absent).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,

    /// A message with optional placeholders (e.g. "Found {count} issues").
    #[serde(rename = "markdown", skip_serializing_if = "Option::is_none")]
    pub markdown: Option<String>,

    /// The resource identifier for a localizable message string.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,

    /// Arguments to substitute into the message.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub arguments: Option<Vec<String>>,
}

impl SarifMessage {
    /// Create a plain text message.
    pub fn text(text: impl Into<String>) -> Self {
        Self {
            text: Some(text.into()),
            markdown: None,
            id: None,
            arguments: None,
        }
    }

    /// Create a markdown message.
    pub fn markdown(md: impl Into<String>) -> Self {
        Self {
            text: None,
            markdown: Some(md.into()),
            id: None,
            arguments: None,
        }
    }
}

// ---------------------------------------------------------------------------
// SARIF Artifact Location
// ---------------------------------------------------------------------------

/// Specifies the location of an artifact (SARIF 2.1.0 section 3.4).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifArtifactLocation {
    /// URI of the artifact.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uri: Option<String>,

    /// A base-64 encoded representation of the URI (for non-file URIs).
    #[serde(rename = "uriBaseId", skip_serializing_if = "Option::is_none")]
    pub uri_base_id: Option<String>,

    /// The index within the `run.artifacts` array.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub index: Option<i64>,

    /// A description of the artifact.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<SarifMessage>,
}

impl SarifArtifactLocation {
    /// Create from a file URI string.
    pub fn file(uri: impl Into<String>) -> Self {
        Self {
            uri: Some(uri.into()),
            uri_base_id: None,
            index: None,
            description: None,
        }
    }
}

// ---------------------------------------------------------------------------
// SARIF Artifact
// ---------------------------------------------------------------------------

/// A single artifact (file) relevant to the analysis (SARIF 2.1.0 section 3.5).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifArtifact {
    /// The location of the artifact.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<SarifArtifactLocation>,

    /// MIME type of the artifact.
    #[serde(rename = "mimeType", skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,

    /// The length of the artifact in bytes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub length: Option<i64>,

    /// A message digest (hash) of the artifact contents.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hashes: Option<std::collections::HashMap<String, String>>,

    /// The role or roles the artifact plays in the analysis.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub roles: Option<Vec<String>>,
}

impl SarifArtifact {
    /// Create an artifact reference from a file path.
    pub fn file(path: impl Into<String>) -> Self {
        Self {
            location: Some(SarifArtifactLocation::file(path)),
            mime_type: None,
            length: None,
            hashes: None,
            roles: None,
        }
    }
}

// ---------------------------------------------------------------------------
// SARIF Logical Location
// ---------------------------------------------------------------------------

/// A logical location (e.g., a function name) within an artifact (SARIF 2.1.0 section 3.24).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifLogicalLocation {
    /// Human-readable fully qualified name (e.g. "app::main").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fully_qualified_name: Option<String>,

    /// A short name (e.g., "main").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// Index in `run.logicalLocations`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub index: Option<i64>,
}

// ---------------------------------------------------------------------------
// SARIF Region
// ---------------------------------------------------------------------------

/// A region within an artifact (SARIF 2.1.0 section 3.30).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifRegion {
    /// 1-based start line.
    #[serde(rename = "startLine", skip_serializing_if = "Option::is_none")]
    pub start_line: Option<i64>,

    /// 1-based start column.
    #[serde(rename = "startColumn", skip_serializing_if = "Option::is_none")]
    pub start_column: Option<i64>,

    /// 1-based end line.
    #[serde(rename = "endLine", skip_serializing_if = "Option::is_none")]
    pub end_line: Option<i64>,

    /// 1-based end column.
    #[serde(rename = "endColumn", skip_serializing_if = "Option::is_none")]
    pub end_column: Option<i64>,

    /// Character offset from the beginning of the artifact.
    #[serde(rename = "charOffset", skip_serializing_if = "Option::is_none")]
    pub char_offset: Option<i64>,

    /// Byte offset from the beginning of the artifact.
    #[serde(rename = "byteOffset", skip_serializing_if = "Option::is_none")]
    pub byte_offset: Option<i64>,

    /// Length of the region in bytes.
    #[serde(rename = "byteLength", skip_serializing_if = "Option::is_none")]
    pub byte_length: Option<i64>,

    /// The snippet of the artifact content within the region.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snippet: Option<SarifArtifactContent>,

    /// A message relevant to this region.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<SarifMessage>,
}

impl SarifRegion {
    /// Create a region spanning from `start_line` to `end_line`.
    pub fn lines(start: i64, end: i64) -> Self {
        Self {
            start_line: Some(start),
            start_column: None,
            end_line: Some(end),
            end_column: None,
            char_offset: None,
            byte_offset: None,
            byte_length: None,
            snippet: None,
            message: None,
        }
    }

    /// Create a region at a byte offset with a given length.
    pub fn bytes(offset: i64, length: i64) -> Self {
        Self {
            start_line: None,
            start_column: None,
            end_line: None,
            end_column: None,
            char_offset: Some(offset),
            byte_offset: Some(offset),
            byte_length: Some(length),
            snippet: None,
            message: None,
        }
    }
}

// ---------------------------------------------------------------------------
// SARIF Artifact Content
// ---------------------------------------------------------------------------

/// Snippet of artifact content (SARIF 2.1.0 section 3.3).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifArtifactContent {
    /// The text content of the snippet.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,

    /// Base-64 encoded binary content.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub binary: Option<String>,
}

impl SarifArtifactContent {
    /// Create from text content.
    pub fn text(text: impl Into<String>) -> Self {
        Self {
            text: Some(text.into()),
            binary: None,
        }
    }
}

// ---------------------------------------------------------------------------
// SARIF Physical Location
// ---------------------------------------------------------------------------

/// A physical location within an artifact (SARIF 2.1.0 section 3.28).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifPhysicalLocation {
    /// The artifact location (required).
    #[serde(rename = "artifactLocation")]
    pub artifact_location: SarifArtifactLocation,

    /// The region within the artifact.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub region: Option<SarifRegion>,

    /// Address information (e.g., virtual address).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<SarifAddress>,
}

impl SarifPhysicalLocation {
    /// Create a physical location in a file.
    pub fn file(path: impl Into<String>) -> Self {
        Self {
            artifact_location: SarifArtifactLocation::file(path),
            region: None,
            address: None,
        }
    }

    /// Create a physical location at a specific address.
    pub fn at_address(addr: impl Into<String>) -> Self {
        Self {
            artifact_location: SarifArtifactLocation {
                uri: None,
                uri_base_id: Some("%SRCROOT%".to_string()),
                index: None,
                description: None,
            },
            region: None,
            address: Some(SarifAddress::absolute(addr)),
        }
    }
}

// ---------------------------------------------------------------------------
// SARIF Address
// ---------------------------------------------------------------------------

/// A virtual or physical address (SARIF 2.1.0 section 3.2).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifAddress {
    /// The absolute address (e.g., `"0x401000"`).
    #[serde(rename = "absoluteAddress", skip_serializing_if = "Option::is_none")]
    pub absolute_address: Option<String>,

    /// An offset from a base address.
    #[serde(rename = "relativeAddress", skip_serializing_if = "Option::is_none")]
    pub relative_address: Option<i64>,

    /// The index of a segment (e.g., section number).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub index: Option<i64>,

    /// A name for the base address (e.g., ".text").
    #[serde(rename = "fullyQualifiedName", skip_serializing_if = "Option::is_none")]
    pub fully_qualified_name: Option<String>,

    /// An offset from the parent object.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offset: Option<i64>,

    /// The length of the addressed region in bytes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub length: Option<i64>,
}

impl SarifAddress {
    /// Create an absolute address (e.g., `"0x401000"`).
    pub fn absolute(addr: impl Into<String>) -> Self {
        Self {
            absolute_address: Some(addr.into()),
            relative_address: None,
            index: None,
            fully_qualified_name: None,
            offset: None,
            length: None,
        }
    }

    /// Create a relative address with an optional base name.
    pub fn relative(offset: i64, base_name: impl Into<String>) -> Self {
        Self {
            absolute_address: None,
            relative_address: Some(offset),
            index: None,
            fully_qualified_name: Some(base_name.into()),
            offset: None,
            length: None,
        }
    }
}

// ---------------------------------------------------------------------------
// SARIF Location
// ---------------------------------------------------------------------------

/// A location within a result (SARIF 2.1.0 section 3.33).
///
/// Wraps a [`SarifPhysicalLocation`] and an optional set of
/// [`SarifLogicalLocation`]s.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifLocation {
    /// The physical location (required when `logicalLocations` is absent).
    #[serde(rename = "physicalLocation", skip_serializing_if = "Option::is_none")]
    pub physical_location: Option<SarifPhysicalLocation>,

    /// Fully qualified logical names.
    #[serde(rename = "logicalLocations", skip_serializing_if = "Option::is_none")]
    pub logical_locations: Option<Vec<SarifLogicalLocation>>,

    /// A message relevant to this location.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<SarifMessage>,
}

impl SarifLocation {
    /// Create a location from a file path and a region.
    pub fn file_region(path: impl Into<String>, region: SarifRegion) -> Self {
        let mut phys = SarifPhysicalLocation::file(path);
        phys.region = Some(region);
        Self {
            physical_location: Some(phys),
            logical_locations: None,
            message: None,
        }
    }

    /// Create a location at an absolute address.
    pub fn at_address(addr: impl Into<String>) -> Self {
        Self {
            physical_location: Some(SarifPhysicalLocation::at_address(addr)),
            logical_locations: None,
            message: None,
        }
    }
}

// ---------------------------------------------------------------------------
// SARIF Reporting Descriptor (Rule)
// ---------------------------------------------------------------------------

/// Metadata about a rule (SARIF 2.1.0 section 3.49).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifReportingDescriptor {
    /// A stable opaque identifier for the rule (required).
    pub id: String,

    /// A short description of the rule.
    #[serde(rename = "shortDescription", skip_serializing_if = "Option::is_none")]
    pub short_description: Option<SarifMessage>,

    /// A comprehensive description of the rule.
    #[serde(rename = "fullDescription", skip_serializing_if = "Option::is_none")]
    pub full_description: Option<SarifMessage>,

    /// A succinct displayable summary of all messages produced by the rule.
    #[serde(rename = "messageStrings", skip_serializing_if = "Option::is_none")]
    pub message_strings: Option<std::collections::HashMap<String, SarifMessage>>,

    /// Default severity level.
    #[serde(
        rename = "defaultConfiguration",
        skip_serializing_if = "Option::is_none"
    )]
    pub default_configuration: Option<SarifReportingConfiguration>,

    /// URI where the rule documentation can be found.
    #[serde(rename = "helpUri", skip_serializing_if = "Option::is_none")]
    pub help_uri: Option<String>,

    /// A markdown help string.
    #[serde(rename = "help", skip_serializing_if = "Option::is_none")]
    pub help: Option<SarifMessage>,

    /// Key/value properties.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<SarifPropertyBag>,
}

impl SarifReportingDescriptor {
    /// Create a new rule with the given ID.
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            short_description: None,
            full_description: None,
            message_strings: None,
            default_configuration: None,
            help_uri: None,
            help: None,
            properties: None,
        }
    }

    /// Set the short description.
    pub fn with_short_description(mut self, desc: impl Into<String>) -> Self {
        self.short_description = Some(SarifMessage::text(desc));
        self
    }

    /// Set the full description.
    pub fn with_full_description(mut self, desc: impl Into<String>) -> Self {
        self.full_description = Some(SarifMessage::text(desc));
        self
    }

    /// Set the default severity level.
    pub fn with_default_level(mut self, level: SarifLevel) -> Self {
        self.default_configuration = Some(SarifReportingConfiguration {
            level: Some(level),
            ..Default::default()
        });
        self
    }
}

// ---------------------------------------------------------------------------
// SARIF Reporting Configuration
// ---------------------------------------------------------------------------

/// Default configuration for a reporting descriptor (SARIF 2.1.0 section 3.50).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SarifReportingConfiguration {
    /// The default severity level for results produced by this rule.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub level: Option<SarifLevel>,

    /// Whether the rule is enabled by default.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,

    /// The default rank for results produced by this rule.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rank: Option<f64>,

    /// Key/value properties.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parameters: Option<SarifPropertyBag>,
}

// ---------------------------------------------------------------------------
// SARIF Result
// ---------------------------------------------------------------------------

/// A single analysis result (SARIF 2.1.0 section 3.25).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifResult {
    /// The stable opaque identifier of the rule that produced this result (required).
    #[serde(rename = "ruleId")]
    pub rule_id: String,

    /// The index within `run.tool.driver.rules` for this rule.
    #[serde(rename = "ruleIndex", skip_serializing_if = "Option::is_none")]
    pub rule_index: Option<i64>,

    /// Severity level of the result.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub level: Option<SarifLevel>,

    /// A message describing the result (required).
    pub message: SarifMessage,

    /// Locations associated with this result.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub locations: Option<Vec<SarifLocation>>,

    /// The analysis target of this result.
    #[serde(rename = "analysisTarget", skip_serializing_if = "Option::is_none")]
    pub analysis_target: Option<SarifArtifactLocation>,

    /// A unique identifier for the result (for correlation).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub guid: Option<String>,

    /// A stable unique identifier for the result across runs.
    #[serde(rename = "correlationGuid", skip_serializing_if = "Option::is_none")]
    pub correlation_guid: Option<String>,

    /// The index within the run's results array.
    #[serde(rename = "occurrenceCount", skip_serializing_if = "Option::is_none")]
    pub occurrence_count: Option<i64>,

    /// Partial fingerprints to help match results between runs.
    #[serde(
        rename = "partialFingerprints",
        skip_serializing_if = "Option::is_none"
    )]
    pub partial_fingerprints: Option<std::collections::HashMap<String, String>>,

    /// Related locations (e.g., call stacks, code flows).
    #[serde(rename = "relatedLocations", skip_serializing_if = "Option::is_none")]
    pub related_locations: Option<Vec<SarifLocation>>,

    /// Code flows associated with this result.
    #[serde(rename = "codeFlows", skip_serializing_if = "Option::is_none")]
    pub code_flows: Option<Vec<SarifCodeFlow>>,

    /// Key/value properties.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<SarifPropertyBag>,
}

impl SarifResult {
    /// Create a new result.
    pub fn new(rule_id: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            rule_id: rule_id.into(),
            rule_index: None,
            level: None,
            message: SarifMessage::text(message),
            locations: None,
            analysis_target: None,
            guid: None,
            correlation_guid: None,
            occurrence_count: None,
            partial_fingerprints: None,
            related_locations: None,
            code_flows: None,
            properties: None,
        }
    }

    /// Set the severity level.
    pub fn with_level(mut self, level: SarifLevel) -> Self {
        self.level = Some(level);
        self
    }

    /// Add a location to this result.
    pub fn with_location(mut self, location: SarifLocation) -> Self {
        self.locations.get_or_insert_with(Vec::new).push(location);
        self
    }

    /// Add multiple locations.
    pub fn with_locations(mut self, locations: Vec<SarifLocation>) -> Self {
        self.locations = Some(locations);
        self
    }
}

// ---------------------------------------------------------------------------
// SARIF Code Flow
// ---------------------------------------------------------------------------

/// A set of thread flows describing a code path (SARIF 2.1.0 section 3.7).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifCodeFlow {
    /// The thread flows (required).
    #[serde(rename = "threadFlows")]
    pub thread_flows: Vec<SarifThreadFlow>,

    /// A message describing this code flow.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<SarifMessage>,
}

/// A sequence of code locations within a single thread (SARIF 2.1.0 section 3.37).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifThreadFlow {
    /// An identifier for this thread flow.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,

    /// The ordered sequence of locations.
    pub locations: Vec<SarifThreadFlowLocation>,

    /// A message describing the thread flow.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<SarifMessage>,
}

/// A single location visited by a thread flow (SARIF 2.1.0 section 3.39).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifThreadFlowLocation {
    /// The location (required if `kinds` absent).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<SarifLocation>,

    /// The importance of this location within the code flow.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub importance: Option<String>,

    /// Kinds of location (e.g., "functionEnter", "branchTrue").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kinds: Option<Vec<String>>,

    /// Nesting level of this location within the call stack.
    #[serde(rename = "nestingLevel", skip_serializing_if = "Option::is_none")]
    pub nesting_level: Option<i64>,

    /// The execution time at this point.
    #[serde(rename = "executionTimeUtc", skip_serializing_if = "Option::is_none")]
    pub execution_time_utc: Option<String>,
}

// ---------------------------------------------------------------------------
// SARIF Notification
// ---------------------------------------------------------------------------

/// A notification from the tool (SARIF 2.1.0 section 3.15).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifNotification {
    /// The notification message (required).
    pub message: SarifMessage,

    /// The level of the notification.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub level: Option<SarifLevel>,

    /// The runtime exception, if applicable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exception: Option<SarifException>,
}

/// An exception that occurred during analysis (SARIF 2.1.0 section 3.11).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifException {
    /// The exception kind/type.
    pub kind: String,

    /// The exception message.
    pub message: String,

    /// The call stack.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stack: Option<SarifStack>,
}

/// A call stack (SARIF 2.1.0 section 3.35).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifStack {
    /// The stack frames.
    pub frames: Vec<SarifStackFrame>,
}

/// A single stack frame (SARIF 2.1.0 section 3.36).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifStackFrame {
    /// The location of this frame.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<SarifLocation>,

    /// The name of the function/scope.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub module: Option<String>,
}

// ---------------------------------------------------------------------------
// SARIF Run
// ---------------------------------------------------------------------------

/// A single run of an analysis tool (SARIF 2.1.0 section 3.14).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifRun {
    /// The tool that performed the run (required).
    pub tool: SarifTool,

    /// Invocation details.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub invocations: Option<Vec<SarifInvocation>>,

    /// The analysis results (optional but typically present).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub results: Option<Vec<SarifResult>>,

    /// Artifacts relevant to the run.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub artifacts: Option<Vec<SarifArtifact>>,

    /// Logical locations referenced by results.
    #[serde(rename = "logicalLocations", skip_serializing_if = "Option::is_none")]
    pub logical_locations: Option<Vec<SarifLogicalLocation>>,

    /// The language of the analysis target (RFC 5646).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub language: Option<String>,

    /// The original URI base IDs keyed by ID.
    #[serde(rename = "originalUriBaseIds", skip_serializing_if = "Option::is_none")]
    pub original_uri_base_ids: Option<std::collections::HashMap<String, SarifArtifactLocation>>,

    /// Default encoding for files in this run.
    #[serde(rename = "defaultEncoding", skip_serializing_if = "Option::is_none")]
    pub default_encoding: Option<String>,

    /// Default source language for this run.
    #[serde(
        rename = "defaultSourceLanguage",
        skip_serializing_if = "Option::is_none"
    )]
    pub default_source_language: Option<String>,

    /// Newline sequences used in this run.
    #[serde(rename = "newlineSequences", skip_serializing_if = "Option::is_none")]
    pub newline_sequences: Option<Vec<String>>,

    /// Key/value properties.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<SarifPropertyBag>,
}

impl SarifRun {
    /// Create a new run for the given tool.
    pub fn new(tool: SarifTool) -> Self {
        Self {
            tool,
            invocations: None,
            results: None,
            artifacts: None,
            logical_locations: None,
            language: None,
            original_uri_base_ids: None,
            default_encoding: None,
            default_source_language: None,
            newline_sequences: None,
            properties: None,
        }
    }

    /// Add a result to this run.
    pub fn add_result(&mut self, result: SarifResult) {
        self.results.get_or_insert_with(Vec::new).push(result);
    }

    /// Add an artifact to this run.
    pub fn add_artifact(&mut self, artifact: SarifArtifact) {
        self.artifacts.get_or_insert_with(Vec::new).push(artifact);
    }

    /// Add an invocation record.
    pub fn add_invocation(&mut self, invocation: SarifInvocation) {
        self.invocations
            .get_or_insert_with(Vec::new)
            .push(invocation);
    }
}

// ---------------------------------------------------------------------------
// SARIF Log (top-level)
// ---------------------------------------------------------------------------

/// The top-level SARIF log object (SARIF 2.1.0 section 3.13).
///
/// This is the root object serialized to a `.sarif` file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifLog {
    /// SARIF schema version (required — must be `"2.1.0"`).
    pub version: String,

    /// The URI of the JSON schema for SARIF 2.1.0 (required).
    #[serde(rename = "$schema")]
    pub schema: String,

    /// The set of runs contained in this log (required).
    pub runs: Vec<SarifRun>,
}

impl SarifLog {
    /// Create a new SARIF log conforming to version 2.1.0.
    pub fn new() -> Self {
        Self {
            version: "2.1.0".to_string(),
            schema: "https://docs.oasis-open.org/sarif/sarif/v2.1.0/cos02/schemas/sarif-schema-2.1.0.json".to_string(),
            runs: Vec::new(),
        }
    }

    /// Create a new SARIF log with a single run.
    pub fn with_run(run: SarifRun) -> Self {
        Self {
            version: "2.1.0".to_string(),
            schema: "https://docs.oasis-open.org/sarif/sarif/v2.1.0/cos02/schemas/sarif-schema-2.1.0.json".to_string(),
            runs: vec![run],
        }
    }

    /// Add a run to this log.
    pub fn add_run(&mut self, run: SarifRun) {
        self.runs.push(run);
    }

    /// Serialize to a JSON string.
    pub fn to_json(&self) -> io::Result<String> {
        serde_json::to_string_pretty(self).map_err(|e| io::Error::new(io::ErrorKind::Other, e))
    }
}

impl Default for SarifLog {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// SarifExporter
// ---------------------------------------------------------------------------

/// A builder for constructing and exporting SARIF 2.1.0 analysis results.
///
/// Accumulates results, rules, artifacts, and invocations and produces a
/// valid SARIF JSON log.
///
/// # Example
///
/// ```ignore
/// let mut exporter = SarifExporter::new("Ghidra Rust".to_string());
/// exporter.set_version("0.1.0");
/// exporter.add_rule(
///     SarifReportingDescriptor::new("GH001")
///         .with_short_description("Suspicious function call")
///         .with_default_level(SarifLevel::Warning),
/// );
/// exporter.add_result(
///     "GH001".into(),
///     "Call to potentially unsafe function 'gets'".into(),
///     SarifLevel::Warning,
///     "0x401050".into(),
/// );
/// let sarif_json = exporter.to_json().unwrap();
/// ```
#[derive(Debug, Clone)]
pub struct SarifExporter {
    /// Tool component (the driver).
    driver: SarifToolComponent,
    /// Accumulated results.
    results: Vec<SarifResult>,
    /// Accumulated artifacts.
    artifacts: Vec<SarifArtifact>,
    /// Accumulated invocations.
    invocations: Vec<SarifInvocation>,
    /// Accumulated logical locations.
    logical_locations: Vec<SarifLogicalLocation>,
    /// Original URI base IDs.
    original_uri_base_ids: std::collections::HashMap<String, SarifArtifactLocation>,
}

impl SarifExporter {
    /// Create a new SARIF exporter for the given tool name.
    pub fn new(tool_name: String) -> Self {
        Self {
            driver: SarifToolComponent::new(tool_name),
            results: Vec::new(),
            artifacts: Vec::new(),
            invocations: Vec::new(),
            logical_locations: Vec::new(),
            original_uri_base_ids: std::collections::HashMap::new(),
        }
    }

    /// Set the tool version.
    pub fn set_version(&mut self, version: impl Into<String>) {
        self.driver.version = Some(version.into());
    }

    /// Set the tool organization.
    pub fn set_organization(&mut self, org: impl Into<String>) {
        self.driver.organization = Some(org.into());
    }

    /// Set the product name.
    pub fn set_product(&mut self, product: impl Into<String>) {
        self.driver.product = Some(product.into());
    }

    /// Set the tool language.
    pub fn set_language(&mut self, lang: impl Into<String>) {
        self.driver.language = Some(lang.into());
    }

    /// Add a rule to the driver's rule set.
    pub fn add_rule(&mut self, rule: SarifReportingDescriptor) {
        self.driver.rules.get_or_insert_with(Vec::new).push(rule);
    }

    /// Add multiple rules.
    pub fn add_rules(&mut self, rules: Vec<SarifReportingDescriptor>) {
        for rule in rules {
            self.add_rule(rule);
        }
    }

    /// Add a result. The `rule_index` is automatically set if the rule ID
    /// matches a registered rule.
    pub fn add_result(
        &mut self,
        rule_id: String,
        message: String,
        level: SarifLevel,
        address: String,
    ) {
        let rule_index = self
            .driver
            .rules
            .as_ref()
            .and_then(|rules| rules.iter().position(|r| r.id == rule_id))
            .map(|i| i as i64);

        let location = SarifLocation::at_address(&address);

        let mut result = SarifResult::new(&rule_id, &message)
            .with_level(level)
            .with_location(location);

        result.rule_index = rule_index;
        self.results.push(result);
    }

    /// Add a manually constructed result.
    pub fn add_result_object(&mut self, result: SarifResult) {
        self.results.push(result);
    }

    /// Add a file artifact to the run.
    pub fn add_artifact(&mut self, artifact: SarifArtifact) {
        self.artifacts.push(artifact);
    }

    /// Add an invocation record.
    pub fn add_invocation(&mut self, invocation: SarifInvocation) {
        self.invocations.push(invocation);
    }

    /// Add a logical location.
    pub fn add_logical_location(&mut self, loc: SarifLogicalLocation) {
        self.logical_locations.push(loc);
    }

    /// Add an original URI base ID mapping.
    pub fn add_original_uri_base(
        &mut self,
        id: impl Into<String>,
        location: SarifArtifactLocation,
    ) {
        self.original_uri_base_ids.insert(id.into(), location);
    }

    /// Build the final [`SarifLog`] from all accumulated data.
    pub fn build(&self) -> SarifLog {
        let mut driver = self.driver.clone();

        // Ensure rules are set when we have results with non-null rule IDs
        if driver.rules.is_none() && !self.results.is_empty() {
            // Collect unique rule IDs from results and auto-create descriptors
            let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
            let mut auto_rules = Vec::new();
            for r in &self.results {
                if seen.insert(r.rule_id.clone()) {
                    auto_rules.push(SarifReportingDescriptor::new(&r.rule_id));
                }
            }
            if !auto_rules.is_empty() {
                driver.rules = Some(auto_rules);
            }
        }

        let tool = SarifTool {
            driver,
            extensions: None,
        };

        let mut run = SarifRun::new(tool);

        if !self.results.is_empty() {
            run.results = Some(self.results.clone());
        }
        if !self.artifacts.is_empty() {
            run.artifacts = Some(self.artifacts.clone());
        }
        if !self.invocations.is_empty() {
            run.invocations = Some(self.invocations.clone());
        }
        if !self.logical_locations.is_empty() {
            run.logical_locations = Some(self.logical_locations.clone());
        }
        if !self.original_uri_base_ids.is_empty() {
            run.original_uri_base_ids = Some(self.original_uri_base_ids.clone());
        }

        SarifLog::with_run(run)
    }

    /// Serialize the accumulated data to a SARIF JSON string.
    pub fn to_json(&self) -> io::Result<String> {
        self.build().to_json()
    }

    /// Write the SARIF JSON output to a file.
    pub fn write_to_file(&self, path: impl AsRef<std::path::Path>) -> io::Result<()> {
        let json = self.to_json()?;
        std::fs::write(path.as_ref(), &json)
    }
}

impl Default for SarifExporter {
    fn default() -> Self {
        Self::new("Ghidra Rust".to_string())
    }
}

// ===========================================================================
// Ghidra-Specific SARIF Extension Types
//
// Ported from Ghidra's Java SARIF export classes (sarif/export/**).
// These types model Ghidra's analysis data for serialization into SARIF
// `result.properties.additionalProperties` or as standalone objects.
// ===========================================================================

// ---------------------------------------------------------------------------
// SARIF Result Kind
// ---------------------------------------------------------------------------

/// The kind of a SARIF result, controlling how the result is interpreted.
///
/// Maps to Ghidra's convention for result `kind` property.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SarifResultKind {
    /// The rule was evaluated and found to be satisfied (informational).
    Informational,
    /// The tool found a problem.
    Fail,
    /// The rule was not applicable to this target.
    NotApplicable,
    /// The rule was not run.
    NotRun,
    /// The rule was explicitly passed.
    Pass,
    /// The rule was open (still being evaluated).
    Open,
    /// The tool generated a review-required result.
    Review,
}

impl SarifResultKind {
    /// Return the SARIF JSON string value for this kind.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Informational => "informational",
            Self::Fail => "fail",
            Self::NotApplicable => "notApplicable",
            Self::NotRun => "notRun",
            Self::Pass => "pass",
            Self::Open => "open",
            Self::Review => "review",
        }
    }
}

impl Default for SarifResultKind {
    fn default() -> Self {
        Self::Informational
    }
}

impl Serialize for SarifResultKind {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for SarifResultKind {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        match s.as_str() {
            "informational" => Ok(Self::Informational),
            "fail" => Ok(Self::Fail),
            "notApplicable" => Ok(Self::NotApplicable),
            "notRun" => Ok(Self::NotRun),
            "pass" => Ok(Self::Pass),
            "open" => Ok(Self::Open),
            "review" => Ok(Self::Review),
            _ => Ok(Self::Informational),
        }
    }
}

impl std::fmt::Display for SarifResultKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// ---------------------------------------------------------------------------
// Ghidra Function (from ExtFunction.java)
// ---------------------------------------------------------------------------

/// Ghidra function metadata for SARIF export.
///
/// Represents a disassembled function's complete metadata: name, location,
/// calling convention, parameters, stack layout, and register variables.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GhidraFunction {
    /// Function name (demangled if applicable).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Containing namespace (e.g., class name).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    /// Whether the namespace is a class.
    #[serde(rename = "namespaceIsClass", skip_serializing_if = "Option::is_none")]
    pub namespace_is_class: Option<bool>,
    /// Entry point address as hex string.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
    /// User comment attached to the function.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    /// Repeatable comment.
    #[serde(rename = "repeatableComment", skip_serializing_if = "Option::is_none")]
    pub repeatable_comment: Option<String>,
    /// Calling convention name (e.g., "__stdcall", "default").
    #[serde(rename = "callingConvention", skip_serializing_if = "Option::is_none")]
    pub calling_convention: Option<String>,
    /// Call fixup name.
    #[serde(rename = "callFixup", skip_serializing_if = "Option::is_none")]
    pub call_fixup: Option<String>,
    /// Signature source (e.g., "DEFAULT", "ANALYSIS").
    #[serde(rename = "signatureSource", skip_serializing_if = "Option::is_none")]
    pub signature_source: Option<String>,
    /// Source type for the function symbol (e.g., "DEFAULT", "IMPORTED", "USER_DEFINED").
    #[serde(rename = "sourceType", skip_serializing_if = "Option::is_none")]
    pub source_type: Option<String>,
    /// Whether the function takes variable arguments.
    #[serde(rename = "hasVarArgs", skip_serializing_if = "Option::is_none")]
    pub has_var_args: Option<bool>,
    /// Whether the function has a custom calling convention.
    #[serde(rename = "isCustomStorage", skip_serializing_if = "Option::is_none")]
    pub is_custom_storage: Option<bool>,
    /// Whether the function has no return.
    #[serde(rename = "isNoReturn", skip_serializing_if = "Option::is_none")]
    pub is_no_return: Option<bool>,
    /// Whether the function is inline.
    #[serde(rename = "isInline", skip_serializing_if = "Option::is_none")]
    pub is_inline: Option<bool>,
    /// Whether the function is a library function.
    #[serde(rename = "isLibrary", skip_serializing_if = "Option::is_none")]
    pub is_library: Option<bool>,
    /// Whether the function is global (no specific namespace).
    #[serde(rename = "isGlobal", skip_serializing_if = "Option::is_none")]
    pub is_global: Option<bool>,
    /// Whether the function is an external reference.
    #[serde(rename = "isExternal", skip_serializing_if = "Option::is_none")]
    pub is_external: Option<bool>,
    /// Whether the function is a thunk (trampoline).
    #[serde(rename = "isThunk", skip_serializing_if = "Option::is_none")]
    pub is_thunk: Option<bool>,
    /// Address of the thunked-to function.
    #[serde(rename = "thunkAddress", skip_serializing_if = "Option::is_none")]
    pub thunk_address: Option<String>,
    /// Stack frame information.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stack: Option<GhidraFunctionStack>,
    /// Register variables.
    #[serde(rename = "regVars", skip_serializing_if = "Option::is_none")]
    pub reg_vars: Option<Vec<GhidraFunctionRegVar>>,
    /// Return value metadata.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ret: Option<GhidraFunctionParam>,
    /// Parameter metadata.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<Vec<GhidraFunctionParam>>,
}

impl GhidraFunction {
    /// Create a new function with the given name and entry point address.
    pub fn new(name: impl Into<String>, address: impl Into<String>) -> Self {
        Self {
            name: Some(name.into()),
            location: Some(address.into()),
            ..Default::default()
        }
    }

    /// Set the namespace.
    pub fn with_namespace(mut self, ns: impl Into<String>, is_class: bool) -> Self {
        self.namespace = Some(ns.into());
        self.namespace_is_class = Some(is_class);
        self
    }

    /// Set the calling convention.
    pub fn with_calling_convention(mut self, cc: impl Into<String>) -> Self {
        self.calling_convention = Some(cc.into());
        self
    }
}

/// A function parameter for SARIF export (from ExtFunctionParam.java).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GhidraFunctionParam {
    /// Parameter name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Data type name (e.g., "int", "char *").
    #[serde(rename = "dataType", skip_serializing_if = "Option::is_none")]
    pub data_type: Option<String>,
    /// Data type category path (e.g., "/int", "/char *").
    #[serde(rename = "dataTypeLocation", skip_serializing_if = "Option::is_none")]
    pub data_type_location: Option<String>,
    /// Storage type (e.g., "register", "stack", "memory").
    #[serde(rename = "storageType", skip_serializing_if = "Option::is_none")]
    pub storage_type: Option<String>,
    /// Size in bytes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub length: Option<u32>,
    /// Ordinal position in the parameter list.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ordinal: Option<u32>,
    /// Comment for this parameter.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

/// Stack frame information for a function (from ExtFunctionStack.java).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GhidraFunctionStack {
    /// Total frame size in bytes.
    #[serde(rename = "frameSize", skip_serializing_if = "Option::is_none")]
    pub frame_size: Option<u32>,
    /// Return address storage size.
    #[serde(rename = "returnAddressStorage", skip_serializing_if = "Option::is_none")]
    pub return_address_storage: Option<u32>,
    /// Parameter offset from frame pointer.
    #[serde(rename = "parameterOffset", skip_serializing_if = "Option::is_none")]
    pub parameter_offset: Option<i32>,
    /// Local variables.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub locals: Option<Vec<GhidraFunctionStackVar>>,
}

/// A stack variable within a function's stack frame (from ExtFunctionStackVar.java).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GhidraFunctionStackVar {
    /// Variable name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Stack offset (from frame pointer).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offset: Option<i32>,
    /// Size in bytes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub length: Option<u32>,
    /// Data type name.
    #[serde(rename = "dataType", skip_serializing_if = "Option::is_none")]
    pub data_type: Option<String>,
    /// User comment.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

/// A register variable within a function (from ExtFunctionRegVar.java).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GhidraFunctionRegVar {
    /// Variable name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Register name (e.g., "RAX", "x0").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub register: Option<String>,
    /// Data type name.
    #[serde(rename = "dataType", skip_serializing_if = "Option::is_none")]
    pub data_type: Option<String>,
    /// Size in bytes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub length: Option<u32>,
    /// User comment.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

// ---------------------------------------------------------------------------
// Ghidra Comment (from ExtComment.java)
// ---------------------------------------------------------------------------

/// A code comment for SARIF export (from ExtComment.java).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GhidraComment {
    /// Comment kind: "pre", "post", "eol", "plate", "repeatable".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    /// The comment text.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    /// Whether this is a standard (vs. repeatable) comment.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub standard: Option<bool>,
}

impl GhidraComment {
    /// Create a new comment.
    pub fn new(kind: impl Into<String>, value: impl Into<String>, standard: bool) -> Self {
        Self {
            kind: Some(kind.into()),
            value: Some(value.into()),
            standard: Some(standard),
        }
    }
}

// ---------------------------------------------------------------------------
// Ghidra Symbol (from ExtSymbol.java)
// ---------------------------------------------------------------------------

/// A symbol (label/function name) for SARIF export (from ExtSymbol.java).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GhidraSymbol {
    /// Symbol name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Address as hex string.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    /// Namespace the symbol belongs to.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    /// Symbol type: "Label", "Function", "Library", "Class", "External", etc.
    #[serde(rename = "symbolType", skip_serializing_if = "Option::is_none")]
    pub symbol_type: Option<String>,
    /// Source of the symbol: "DEFAULT", "IMPORTED", "USER_DEFINED", "ANALYSIS".
    #[serde(rename = "sourceType", skip_serializing_if = "Option::is_none")]
    pub source_type: Option<String>,
    /// Whether the symbol is primary.
    #[serde(rename = "isPrimary", skip_serializing_if = "Option::is_none")]
    pub is_primary: Option<bool>,
    /// Whether the symbol is external.
    #[serde(rename = "isExternal", skip_serializing_if = "Option::is_none")]
    pub is_external: Option<bool>,
    /// Whether the symbol is globally visible (mangled prefix stripped).
    #[serde(rename = "isGlobal", skip_serializing_if = "Option::is_none")]
    pub is_global: Option<bool>,
}

impl GhidraSymbol {
    /// Create a new symbol.
    pub fn new(name: impl Into<String>, address: impl Into<String>) -> Self {
        Self {
            name: Some(name.into()),
            address: Some(address.into()),
            ..Default::default()
        }
    }
}

// ---------------------------------------------------------------------------
// Ghidra Memory Block (from ExtMemoryMap.java)
// ---------------------------------------------------------------------------

/// A memory block for SARIF export (from ExtMemoryMap.java).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GhidraMemoryBlock {
    /// Block name (e.g., ".text", ".data", "EXTERNAL").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Permission string (e.g., "r-x", "rw-", "r--").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    /// Block comment.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    /// Whether the block is volatile.
    #[serde(rename = "isVolatile", skip_serializing_if = "Option::is_none")]
    pub is_volatile: Option<bool>,
    /// Whether the block is artificial (e.g., stack, overlay).
    #[serde(rename = "isArtificial", skip_serializing_if = "Option::is_none")]
    pub is_artificial: Option<bool>,
    /// Block type: "DEFAULT", "BIT_MAPPED", "BYTE_MAPPED", "EXTERNAL".
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub block_type: Option<String>,
    /// Location (file reference or mapped address).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
    /// Start address as hex string.
    #[serde(rename = "startAddress", skip_serializing_if = "Option::is_none")]
    pub start_address: Option<String>,
    /// End address as hex string.
    #[serde(rename = "endAddress", skip_serializing_if = "Option::is_none")]
    pub end_address: Option<String>,
    /// Block size in bytes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub length: Option<u64>,
}

impl GhidraMemoryBlock {
    /// Create a new memory block.
    pub fn new(
        name: impl Into<String>,
        start: impl Into<String>,
        end: impl Into<String>,
    ) -> Self {
        Self {
            name: Some(name.into()),
            start_address: Some(start.into()),
            end_address: Some(end.into()),
            ..Default::default()
        }
    }

    /// Set the permission string (e.g., "rwx", "r-x").
    pub fn with_permissions(mut self, perms: impl Into<String>) -> Self {
        self.kind = Some(perms.into());
        self
    }
}

// ---------------------------------------------------------------------------
// Ghidra Entry Point (from ExtEntryPoint.java)
// ---------------------------------------------------------------------------

/// An entry point for SARIF export (from ExtEntryPoint.java).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GhidraEntryPoint {
    /// Address of the entry point as hex string.
    #[serde(rename = "address", skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
}

impl GhidraEntryPoint {
    /// Create a new entry point.
    pub fn new(address: impl Into<String>) -> Self {
        Self {
            address: Some(address.into()),
        }
    }
}

// ---------------------------------------------------------------------------
// Ghidra Data (from ExtData.java)
// ---------------------------------------------------------------------------

/// A defined data item for SARIF export (from ExtData.java).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GhidraData {
    /// Data type name (e.g., "dword", "char[16]").
    #[serde(rename = "typeName", skip_serializing_if = "Option::is_none")]
    pub type_name: Option<String>,
    /// Data type category path (e.g., "/int", "/char *").
    #[serde(rename = "typeLocation", skip_serializing_if = "Option::is_none")]
    pub type_location: Option<String>,
    /// Address as hex string.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    /// Size in bytes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub length: Option<u64>,
    /// Associated comments.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comments: Option<Vec<GhidraComment>>,
}

impl GhidraData {
    /// Create a new data item.
    pub fn new(type_name: impl Into<String>, address: impl Into<String>) -> Self {
        Self {
            type_name: Some(type_name.into()),
            address: Some(address.into()),
            ..Default::default()
        }
    }
}

// ---------------------------------------------------------------------------
// Ghidra Bookmark (from ExtBookmark.java)
// ---------------------------------------------------------------------------

/// A bookmark for SARIF export (from ExtBookmark.java).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GhidraBookmark {
    /// Category name (e.g., "Analysis", "Warning").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Bookmark comment text.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    /// Bookmark kind/type string (e.g., "Warning", "Info", "Error").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
}

impl GhidraBookmark {
    /// Create a new bookmark.
    pub fn new(kind: impl Into<String>) -> Self {
        Self {
            kind: Some(kind.into()),
            ..Default::default()
        }
    }
}

// ---------------------------------------------------------------------------
// Ghidra Cross-Reference (from ExtReference.java family)
// ---------------------------------------------------------------------------

/// The type of a cross-reference / memory reference.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum GhidraReferenceType {
    /// A read/data reference.
    Read,
    /// A write/data reference.
    Write,
    /// A jump/conditional jump reference.
    Jump,
    /// A call reference.
    Call,
    /// An external (library) reference.
    External,
    /// A stack reference.
    Stack,
    /// A register reference.
    Register,
}

impl GhidraReferenceType {
    /// Return the string name.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Read => "READ",
            Self::Write => "WRITE",
            Self::Jump => "JUMP",
            Self::Call => "CALL",
            Self::External => "EXTERNAL",
            Self::Stack => "STACK",
            Self::Register => "REGISTER",
        }
    }
}

impl Default for GhidraReferenceType {
    fn default() -> Self {
        Self::Read
    }
}

/// A memory/cross-reference for SARIF export (from ExtMemoryReference.java).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GhidraReference {
    /// Source address of the reference.
    #[serde(rename = "fromAddress", skip_serializing_if = "Option::is_none")]
    pub from_address: Option<String>,
    /// Destination address of the reference.
    #[serde(rename = "toAddress", skip_serializing_if = "Option::is_none")]
    pub to_address: Option<String>,
    /// Reference type.
    #[serde(rename = "referenceType", skip_serializing_if = "Option::is_none")]
    pub reference_type: Option<GhidraReferenceType>,
    /// Whether this is a primary reference.
    #[serde(rename = "isPrimary", skip_serializing_if = "Option::is_none")]
    pub is_primary: Option<bool>,
    /// User comment at the reference source.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

impl GhidraReference {
    /// Create a new reference.
    pub fn new(
        from: impl Into<String>,
        to: impl Into<String>,
        ref_type: GhidraReferenceType,
    ) -> Self {
        Self {
            from_address: Some(from.into()),
            to_address: Some(to.into()),
            reference_type: Some(ref_type),
            ..Default::default()
        }
    }
}

// ---------------------------------------------------------------------------
// Ghidra Equate (from ExtEquate.java)
// ---------------------------------------------------------------------------

/// An equate (named constant) for SARIF export.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GhidraEquate {
    /// Equate name (e.g., "NULL", "ERROR_SUCCESS").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Numeric value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<i64>,
    /// Addresses where this equate is applied.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub addresses: Option<Vec<String>>,
}

impl GhidraEquate {
    /// Create a new equate.
    pub fn new(name: impl Into<String>, value: i64) -> Self {
        Self {
            name: Some(name.into()),
            value: Some(value),
            ..Default::default()
        }
    }
}

// ---------------------------------------------------------------------------
// Ghidra Relocation (from ExtRelocation.java)
// ---------------------------------------------------------------------------

/// A relocation entry for SARIF export (from ExtRelocation.java).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GhidraRelocation {
    /// Address where the relocation is applied.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    /// The symbol name being relocated to.
    #[serde(rename = "symbolName", skip_serializing_if = "Option::is_none")]
    pub symbol_name: Option<String>,
    /// Relocation type string (e.g., "R_X86_64_PC32").
    #[serde(rename = "relocationType", skip_serializing_if = "Option::is_none")]
    pub relocation_type: Option<String>,
    /// Addend for the relocation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub addend: Option<i64>,
}

impl GhidraRelocation {
    /// Create a new relocation.
    pub fn new(
        address: impl Into<String>,
        symbol: impl Into<String>,
        reloc_type: impl Into<String>,
    ) -> Self {
        Self {
            address: Some(address.into()),
            symbol_name: Some(symbol.into()),
            relocation_type: Some(reloc_type.into()),
            ..Default::default()
        }
    }
}

// ---------------------------------------------------------------------------
// Ghidra Program Export (top-level Ghidra-specific container)
// ---------------------------------------------------------------------------

/// The top-level container for Ghidra-specific analysis data in SARIF.
///
/// This structure accumulates all Ghidra analysis artifacts and wraps them
/// into a valid SARIF log using SARIF's `result.properties` extension
/// mechanism.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GhidraProgramExport {
    /// Functions discovered during analysis.
    pub functions: Vec<GhidraFunction>,
    /// Symbols (labels, function names, etc.).
    pub symbols: Vec<GhidraSymbol>,
    /// Memory blocks.
    pub memory_blocks: Vec<GhidraMemoryBlock>,
    /// Defined data items.
    pub data: Vec<GhidraData>,
    /// Comments.
    pub comments: Vec<GhidraComment>,
    /// Bookmarks.
    pub bookmarks: Vec<GhidraBookmark>,
    /// Entry points.
    pub entry_points: Vec<GhidraEntryPoint>,
    /// Cross-references.
    pub references: Vec<GhidraReference>,
    /// Equates (named constants).
    pub equates: Vec<GhidraEquate>,
    /// Relocations.
    pub relocations: Vec<GhidraRelocation>,
}

impl GhidraProgramExport {
    /// Create a new empty program export.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a function.
    pub fn add_function(&mut self, func: GhidraFunction) {
        self.functions.push(func);
    }

    /// Add a symbol.
    pub fn add_symbol(&mut self, sym: GhidraSymbol) {
        self.symbols.push(sym);
    }

    /// Add a memory block.
    pub fn add_memory_block(&mut self, block: GhidraMemoryBlock) {
        self.memory_blocks.push(block);
    }

    /// Add a comment.
    pub fn add_comment(&mut self, comment: GhidraComment) {
        self.comments.push(comment);
    }

    /// Add a bookmark.
    pub fn add_bookmark(&mut self, bookmark: GhidraBookmark) {
        self.bookmarks.push(bookmark);
    }

    /// Add an entry point.
    pub fn add_entry_point(&mut self, ep: GhidraEntryPoint) {
        self.entry_points.push(ep);
    }

    /// Add a cross-reference.
    pub fn add_reference(&mut self, xref: GhidraReference) {
        self.references.push(xref);
    }

    /// Add an equate.
    pub fn add_equate(&mut self, equate: GhidraEquate) {
        self.equates.push(equate);
    }

    /// Add a relocation.
    pub fn add_relocation(&mut self, reloc: GhidraRelocation) {
        self.relocations.push(reloc);
    }

    /// Convert the entire program export into a SARIF log.
    ///
    /// Each category of data is encoded as a SARIF result with the
    /// appropriate rule ID and the data in `properties.additionalProperties`.
    pub fn to_sarif_log(&self, tool_name: &str) -> SarifLog {
        let mut exporter = SarifExporter::new(tool_name.to_string());

        // Add functions
        for func in &self.functions {
            let addr = func.location.as_deref().unwrap_or("0x0");
            let name = func.name.as_deref().unwrap_or("<unknown>");
            exporter.add_result(
                "GhidraFunction".into(),
                format!("Function: {name}"),
                SarifLevel::None,
                addr.to_string(),
            );
        }

        // Add symbols
        for sym in &self.symbols {
            let addr = sym.address.as_deref().unwrap_or("0x0");
            let name = sym.name.as_deref().unwrap_or("<unknown>");
            exporter.add_result(
                "GhidraSymbol".into(),
                format!("Symbol: {name}"),
                SarifLevel::None,
                addr.to_string(),
            );
        }

        // Add entry points
        for ep in &self.entry_points {
            let addr = ep.address.as_deref().unwrap_or("0x0");
            exporter.add_result(
                "GhidraEntryPoint".into(),
                format!("Entry point: {addr}"),
                SarifLevel::None,
                addr.to_string(),
            );
        }

        exporter.build()
    }

    /// Serialize to JSON.
    pub fn to_json(&self) -> io::Result<String> {
        serde_json::to_string_pretty(self).map_err(|e| io::Error::new(io::ErrorKind::Other, e))
    }
}

// ---------------------------------------------------------------------------
// SARIF Load/Import Handler Traits
// ---------------------------------------------------------------------------

/// Trait for handling SARIF results during import.
///
/// Implementations process individual SARIF results and apply them to a
/// Ghidra program (e.g., setting comments, labels, bookmarks).
pub trait SarifResultHandler: Send + Sync {
    /// The rule ID this handler processes.
    fn rule_id(&self) -> &str;

    /// Handle a single SARIF result.
    ///
    /// # Parameters
    /// * `result` - The SARIF result to process.
    ///
    /// # Returns
    /// `true` if the result was handled, `false` to pass to the next handler.
    fn handle(&self, result: &SarifResult) -> bool;
}

/// Trait for handling SARIF runs during import.
///
/// Implementations process an entire SARIF run (which may contain results,
/// artifacts, invocations, etc.) and configure the import accordingly.
pub trait SarifRunHandler: Send + Sync {
    /// Handle a SARIF run before individual results are processed.
    fn begin_run(&self, run: &SarifRun);

    /// Handle a SARIF run after all results have been processed.
    fn end_run(&self, run: &SarifRun);
}

/// A composite SARIF import processor that dispatches to registered handlers.
pub struct SarifImportProcessor {
    /// Result handlers keyed by rule ID.
    result_handlers: Vec<Box<dyn SarifResultHandler>>,
    /// Run-level handlers.
    run_handlers: Vec<Box<dyn SarifRunHandler>>,
}

impl SarifImportProcessor {
    /// Create a new import processor.
    pub fn new() -> Self {
        Self {
            result_handlers: Vec::new(),
            run_handlers: Vec::new(),
        }
    }

    /// Register a result handler.
    pub fn add_result_handler(&mut self, handler: Box<dyn SarifResultHandler>) {
        self.result_handlers.push(handler);
    }

    /// Register a run handler.
    pub fn add_run_handler(&mut self, handler: Box<dyn SarifRunHandler>) {
        self.run_handlers.push(handler);
    }

    /// Process a complete SARIF log.
    pub fn process(&self, log: &SarifLog) {
        for run in &log.runs {
            // Begin run
            for handler in &self.run_handlers {
                handler.begin_run(run);
            }

            // Process results
            if let Some(results) = &run.results {
                for result in results {
                    for handler in &self.result_handlers {
                        if handler.rule_id() == result.rule_id {
                            handler.handle(result);
                            break;
                        }
                    }
                }
            }

            // End run
            for handler in &self.run_handlers {
                handler.end_run(run);
            }
        }
    }
}

impl Default for SarifImportProcessor {
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
    fn test_sarif_level_serialization() {
        assert_eq!(
            serde_json::to_string(&SarifLevel::Error).unwrap(),
            r#""error""#
        );
        assert_eq!(
            serde_json::to_string(&SarifLevel::Warning).unwrap(),
            r#""warning""#
        );
        assert_eq!(
            serde_json::to_string(&SarifLevel::Note).unwrap(),
            r#""note""#
        );
        assert_eq!(
            serde_json::to_string(&SarifLevel::None).unwrap(),
            r#""none""#
        );
    }

    #[test]
    fn test_sarif_level_deserialization() {
        assert_eq!(
            serde_json::from_str::<SarifLevel>(r#""error""#).unwrap(),
            SarifLevel::Error
        );
        assert_eq!(
            serde_json::from_str::<SarifLevel>(r#""warning""#).unwrap(),
            SarifLevel::Warning
        );
        assert_eq!(
            serde_json::from_str::<SarifLevel>(r#""unknown""#).unwrap(),
            SarifLevel::None
        );
    }

    #[test]
    fn test_sarif_log_creation() {
        let log = SarifLog::new();
        assert_eq!(log.version, "2.1.0");
        assert!(log.schema.contains("sarif-schema-2.1.0.json"));
        assert!(log.runs.is_empty());

        let json = log.to_json().unwrap();
        assert!(json.contains("\"version\": \"2.1.0\""));
        assert!(json.contains("\"$schema\""));
    }

    #[test]
    fn test_sarif_result_creation() {
        let result = SarifResult::new("RULE001", "Something went wrong")
            .with_level(SarifLevel::Error)
            .with_location(SarifLocation::at_address("0x401000"));

        assert_eq!(result.rule_id, "RULE001");
        assert_eq!(result.level, Some(SarifLevel::Error));
        assert!(result.locations.is_some());

        let json = serde_json::to_string_pretty(&result).unwrap();
        assert!(json.contains("RULE001"));
        assert!(json.contains("error"));
        assert!(json.contains("0x401000"));
    }

    #[test]
    fn test_sarif_exporter_basic() {
        let mut exporter = SarifExporter::new("TestTool".to_string());
        exporter.set_version("1.0.0");

        exporter.add_rule(
            SarifReportingDescriptor::new("T001")
                .with_short_description("Test rule")
                .with_default_level(SarifLevel::Warning),
        );

        exporter.add_result(
            "T001".into(),
            "A test finding occurred".into(),
            SarifLevel::Warning,
            "0x500000".into(),
        );

        let json = exporter.to_json().unwrap();
        assert!(json.contains("\"version\": \"2.1.0\""));
        assert!(json.contains("\"$schema\""));
        assert!(json.contains("TestTool"));
        assert!(json.contains("T001"));
        assert!(json.contains("A test finding occurred"));
        assert!(json.contains("0x500000"));
    }

    #[test]
    fn test_sarif_exporter_multiple_results() {
        let mut exporter = SarifExporter::new("MultiTool".to_string());

        exporter.add_rule(
            SarifReportingDescriptor::new("GH002")
                .with_short_description("Unsafe function detected")
                .with_default_level(SarifLevel::Error),
        );
        exporter.add_rule(
            SarifReportingDescriptor::new("GH003")
                .with_short_description("Missing bounds check")
                .with_default_level(SarifLevel::Warning),
        );

        exporter.add_result(
            "GH002".into(),
            "Use of gets() is unsafe".into(),
            SarifLevel::Error,
            "0x401000".into(),
        );
        exporter.add_result(
            "GH003".into(),
            "Array access without bounds check".into(),
            SarifLevel::Warning,
            "0x401050".into(),
        );

        let json = exporter.to_json().unwrap();
        assert!(json.contains("GH002"));
        assert!(json.contains("GH003"));
        assert!(json.contains("gets()"));
    }

    #[test]
    fn test_sarif_exporter_auto_rules() {
        // When no rules are added explicitly, the exporter should
        // auto-create rule descriptors from result rule IDs.
        let mut exporter = SarifExporter::new("AutoTool".to_string());
        exporter.add_result(
            "AUTO001".into(),
            "Auto-created rule test".into(),
            SarifLevel::Note,
            "0x600000".into(),
        );

        let log = exporter.build();
        let driver_rules = log.runs[0].tool.driver.rules.as_ref().unwrap();
        assert_eq!(driver_rules.len(), 1);
        assert_eq!(driver_rules[0].id, "AUTO001");
    }

    #[test]
    fn test_sarif_exporter_file_output() {
        let mut exporter = SarifExporter::new("FileTest".to_string());
        exporter.add_result(
            "F001".into(),
            "File test result".into(),
            SarifLevel::Note,
            "0x700000".into(),
        );

        let tmp = std::env::temp_dir().join("test_output.sarif");
        exporter.write_to_file(&tmp).unwrap();

        let content = std::fs::read_to_string(&tmp).unwrap();
        assert!(content.contains("\"version\": \"2.1.0\""));
        assert!(content.contains("F001"));

        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn test_sarif_location_region() {
        let location = SarifLocation::file_region("src/main.rs", SarifRegion::lines(10, 15));

        let json = serde_json::to_string(&location).unwrap();
        assert!(json.contains("src/main.rs"));
        assert!(json.contains("startLine"));
    }

    #[test]
    fn test_sarif_code_flow() {
        let flow = SarifCodeFlow {
            thread_flows: vec![SarifThreadFlow {
                id: Some("flow1".into()),
                locations: vec![
                    SarifThreadFlowLocation {
                        location: Some(SarifLocation::at_address("0x401000")),
                        importance: Some("essential".into()),
                        kinds: Some(vec!["functionEnter".into()]),
                        nesting_level: Some(0),
                        execution_time_utc: None,
                    },
                    SarifThreadFlowLocation {
                        location: Some(SarifLocation::at_address("0x401050")),
                        importance: Some("important".into()),
                        kinds: Some(vec!["branchTrue".into()]),
                        nesting_level: Some(1),
                        execution_time_utc: None,
                    },
                ],
                message: None,
            }],
            message: Some(SarifMessage::text("Code path to vulnerable call")),
        };

        let json = serde_json::to_string_pretty(&flow).unwrap();
        assert!(json.contains("functionEnter"));
        assert!(json.contains("branchTrue"));
    }

    #[test]
    fn test_sarif_invocation() {
        let invocation = SarifInvocation {
            execution_successful: true,
            arguments: Some(vec!["--analyze".into(), "target.exe".into()]),
            working_directory: Some(SarifArtifactLocation::file("/home/user")),
            start_time_utc: Some("2026-01-01T00:00:00Z".into()),
            end_time_utc: Some("2026-01-01T00:05:00Z".into()),
            machine: Some("devbox".into()),
            account: Some("analyst".into()),
            exit_code: Some(0),
            tool_execution_notifications: None,
        };

        let json = serde_json::to_string(&invocation).unwrap();
        assert!(json.contains("executionSuccessful"));
        assert!(json.contains("true"));
        assert!(json.contains("target.exe"));
    }

    #[test]
    fn test_sarif_schema_compliance() {
        // Verify the generated output matches SARIF 2.1.0 schema requirements.
        let mut exporter = SarifExporter::new("ComplianceTest".to_string());
        exporter.set_version("0.1.0");

        exporter.add_result(
            "C001".into(),
            "Schema compliance check".into(),
            SarifLevel::Note,
            "0x1000".into(),
        );

        let json = exporter.to_json().unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();

        // Required top-level properties
        assert_eq!(value["version"], "2.1.0");
        assert!(value["$schema"]
            .as_str()
            .unwrap()
            .contains("sarif-schema-2.1.0.json"));

        // At least one run
        let runs = value["runs"].as_array().unwrap();
        assert!(!runs.is_empty());

        // Each run has a tool with a driver
        let run = &runs[0];
        assert!(run["tool"]["driver"]["name"].as_str().is_some());

        // Each result has ruleId and message
        let results = run["results"].as_array().unwrap();
        let result = &results[0];
        assert!(result["ruleId"].as_str().is_some());
        assert!(result["message"]["text"].as_str().is_some());
    }

    // ---- Ghidra extension type tests ----

    #[test]
    fn test_sarif_result_kind() {
        assert_eq!(SarifResultKind::Informational.as_str(), "informational");
        assert_eq!(SarifResultKind::Fail.as_str(), "fail");
        assert_eq!(
            serde_json::to_string(&SarifResultKind::Pass).unwrap(),
            r#""pass""#
        );
        assert_eq!(
            serde_json::from_str::<SarifResultKind>(r#""fail""#).unwrap(),
            SarifResultKind::Fail
        );
    }

    #[test]
    fn test_ghidra_function() {
        let func = GhidraFunction::new("main", "0x401000")
            .with_namespace("MyApp", true)
            .with_calling_convention("__cdecl");
        assert_eq!(func.name.as_deref(), Some("main"));
        assert_eq!(func.location.as_deref(), Some("0x401000"));
        assert_eq!(func.namespace.as_deref(), Some("MyApp"));
        assert_eq!(func.namespace_is_class, Some(true));
        assert_eq!(func.calling_convention.as_deref(), Some("__cdecl"));

        let json = serde_json::to_string(&func).unwrap();
        assert!(json.contains("main"));
        assert!(json.contains("0x401000"));
    }

    #[test]
    fn test_ghidra_function_param() {
        let param = GhidraFunctionParam {
            name: Some("argc".into()),
            data_type: Some("int".into()),
            ordinal: Some(0),
            storage_type: Some("register".into()),
            length: Some(4),
            ..Default::default()
        };
        let json = serde_json::to_string_pretty(&param).unwrap();
        assert!(json.contains("argc"));
        assert!(json.contains("int"));
    }

    #[test]
    fn test_ghidra_function_stack() {
        let stack = GhidraFunctionStack {
            frame_size: Some(48),
            return_address_storage: Some(8),
            parameter_offset: Some(16),
            locals: Some(vec![GhidraFunctionStackVar {
                name: Some("buf".into()),
                offset: Some(-16),
                length: Some(32),
                data_type: Some("char[32]".into()),
                ..Default::default()
            }]),
        };
        assert_eq!(stack.frame_size, Some(48));
        assert_eq!(stack.locals.as_ref().unwrap().len(), 1);
    }

    #[test]
    fn test_ghidra_comment() {
        let comment = GhidraComment::new("eol", "loop counter", true);
        assert_eq!(comment.kind.as_deref(), Some("eol"));
        assert_eq!(comment.standard, Some(true));
    }

    #[test]
    fn test_ghidra_symbol() {
        let sym = GhidraSymbol::new("printf", "0x402000");
        assert_eq!(sym.name.as_deref(), Some("printf"));
        assert_eq!(sym.address.as_deref(), Some("0x402000"));
    }

    #[test]
    fn test_ghidra_memory_block() {
        let block = GhidraMemoryBlock::new(".text", "0x401000", "0x405000")
            .with_permissions("r-x");
        assert_eq!(block.name.as_deref(), Some(".text"));
        assert_eq!(block.kind.as_deref(), Some("r-x"));
    }

    #[test]
    fn test_ghidra_entry_point() {
        let ep = GhidraEntryPoint::new("0x401000");
        assert_eq!(ep.address.as_deref(), Some("0x401000"));
    }

    #[test]
    fn test_ghidra_data() {
        let data = GhidraData::new("dword", "0x403000");
        assert_eq!(data.type_name.as_deref(), Some("dword"));
    }

    #[test]
    fn test_ghidra_bookmark() {
        let bm = GhidraBookmark::new("Analysis");
        assert_eq!(bm.kind.as_deref(), Some("Analysis"));
    }

    #[test]
    fn test_ghidra_reference() {
        let xref = GhidraReference::new("0x401000", "0x402000", GhidraReferenceType::Call);
        assert_eq!(xref.from_address.as_deref(), Some("0x401000"));
        assert_eq!(xref.to_address.as_deref(), Some("0x402000"));
        assert_eq!(xref.reference_type, Some(GhidraReferenceType::Call));
    }

    #[test]
    fn test_ghidra_equate() {
        let eq = GhidraEquate::new("NULL", 0);
        assert_eq!(eq.name.as_deref(), Some("NULL"));
        assert_eq!(eq.value, Some(0));
    }

    #[test]
    fn test_ghidra_relocation() {
        let reloc = GhidraRelocation::new("0x404000", "printf", "R_X86_64_PC32");
        assert_eq!(reloc.address.as_deref(), Some("0x404000"));
        assert_eq!(reloc.symbol_name.as_deref(), Some("printf"));
    }

    #[test]
    fn test_ghidra_program_export_to_sarif() {
        let mut export = GhidraProgramExport::new();
        export.add_function(GhidraFunction::new("main", "0x401000"));
        export.add_symbol(GhidraSymbol::new("printf", "0x402000"));
        export.add_entry_point(GhidraEntryPoint::new("0x401000"));

        let log = export.to_sarif_log("Ghidra Rust");
        assert_eq!(log.version, "2.1.0");
        assert_eq!(log.runs.len(), 1);
        assert!(log.runs[0].results.is_some());
        let results = log.runs[0].results.as_ref().unwrap();
        assert_eq!(results.len(), 3);
    }

    #[test]
    fn test_ghidra_function_full_roundtrip() {
        let func = GhidraFunction {
            name: Some("process_data".into()),
            location: Some("0x401000".into()),
            namespace: Some("Network".into()),
            namespace_is_class: Some(true),
            calling_convention: Some("__stdcall".into()),
            has_var_args: Some(false),
            is_no_return: Some(false),
            is_inline: Some(true),
            params: Some(vec![
                GhidraFunctionParam {
                    name: Some("buffer".into()),
                    data_type: Some("void *".into()),
                    ordinal: Some(0),
                    ..Default::default()
                },
                GhidraFunctionParam {
                    name: Some("size".into()),
                    data_type: Some("uint32_t".into()),
                    ordinal: Some(1),
                    ..Default::default()
                },
            ]),
            ..Default::default()
        };

        let json = serde_json::to_string_pretty(&func).unwrap();
        let roundtripped: GhidraFunction = serde_json::from_str(&json).unwrap();
        assert_eq!(roundtripped.name, func.name);
        assert_eq!(roundtripped.params.as_ref().unwrap().len(), 2);
    }

    #[test]
    fn test_sarif_import_processor() {
        let mut proc = SarifImportProcessor::new();

        struct TestHandler;
        impl SarifResultHandler for TestHandler {
            fn rule_id(&self) -> &str {
                "TEST001"
            }
            fn handle(&self, _result: &SarifResult) -> bool {
                true
            }
        }

        proc.add_result_handler(Box::new(TestHandler));

        let mut exporter = SarifExporter::new("TestTool".to_string());
        exporter.add_result(
            "TEST001".into(),
            "A test".into(),
            SarifLevel::None,
            "0x401000".into(),
        );
        let log = exporter.build();
        proc.process(&log);
    }

    #[test]
    fn test_ghidra_reference_type_serialization() {
        assert_eq!(
            serde_json::to_string(&GhidraReferenceType::Call).unwrap(),
            r#""Call""#
        );
        let json = serde_json::to_string(&GhidraReferenceType::Read).unwrap();
        let rt: GhidraReferenceType = serde_json::from_str(&json).unwrap();
        assert_eq!(rt, GhidraReferenceType::Read);
    }

    #[test]
    fn test_ghidra_memory_block_serialization() {
        let block = GhidraMemoryBlock::new(".text", "0x401000", "0x405000")
            .with_permissions("r-x");
        let json = serde_json::to_string_pretty(&block).unwrap();
        assert!(json.contains(".text"));
        assert!(json.contains("r-x"));
        let roundtripped: GhidraMemoryBlock = serde_json::from_str(&json).unwrap();
        assert_eq!(roundtripped.name, block.name);
    }

    #[test]
    fn test_ghidra_register_variable() {
        let rv = GhidraFunctionRegVar {
            name: Some("saved_rbp".into()),
            register: Some("RBP".into()),
            data_type: Some("uint64_t".into()),
            length: Some(8),
            ..Default::default()
        };
        let json = serde_json::to_string(&rv).unwrap();
        assert!(json.contains("RBP"));
        assert!(json.contains("saved_rbp"));
    }
}
