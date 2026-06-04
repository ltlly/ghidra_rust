//! Ghidra `app/util` framework -- ported from Java.
//!
//! This module provides the application-utility layer that sits between the
//! core program model and the higher-level features.  It mirrors the Java
//! package `ghidra.app.util` and its many sub-packages.
//!
//! # Sub-modules
//!
//! | Rust module | Java package | Purpose |
//! |---|---|---|
//! | [`bin`] | `ghidra.app.util.bin` | Random-access byte providers, LEB128, BinaryReader |
//! | [`importer`] | `ghidra.app.util.importer` | Automatic / headless import pipeline |
//! | [`opinion`] | `ghidra.app.util.opinion` | Loader framework (LoadSpec, Loader trait) |
//! | [`demangler`] | `ghidra.app.util.demangler` | Name demangling (MSVC, GNU) |
//! | [`html`] | `ghidra.app.util.html` | HTML data-type representations |
//! | [`dialog`] | `ghidra.app.util.dialog` | Common dialogs |
//! | [`task`] | `ghidra.app.util.task` | Task / monitor integration |
//! | [`pcode`] | `ghidra.app.util.pcode` | P-code utility helpers |
//! | [`datatype`] | `ghidra.app.util.datatype` | Data-type selection / navigation |
//! | [`parser`] | `ghidra.app.util.parser` | Expression / address parsing |
//! | [`query`] | `ghidra.app.util.query` | Symbol / address queries |
//! | [`recognizer`] | `ghidra.app.util.recognizer` | Format recognition helpers |
//! | [`navigation`] | `ghidra.app.util.navigation` | GoTo / address navigation |
//! | [`template`] | `ghidra.app.util.template` | C++ template utilities |
//! | [`xml`] | `ghidra.app.util.xml` | XML parsing helpers |
//! | [`headless`] | `ghidra.app.util.headless` | Headless analysis support |
//!
//! # Top-level types (ported from the root `ghidra.app.util` package)
//!
//! * [`Option`] / [`OptionValue`] -- configurable option with name/value/category
//! * [`Permissions`] -- read/write/execute permissions triple
//! * [`CommentType`] -- pre/post/eol/plate/repeatable comment kinds
//! * [`MemoryBlockUtils`] -- convenience helpers for creating memory blocks
//! * [`XReferenceUtils`] -- cross-reference query helpers
//! * [`DataTypeNamingUtil`] -- naming conventions for data types

pub mod bin;
pub mod importer;
pub mod opinion;
pub mod demangler;
pub mod html;
pub mod dialog;
pub mod task;
pub mod pcode;
pub mod datatype;
pub mod parser;
pub mod query;
pub mod recognizer;
pub mod navigation;
pub mod template;
pub mod xml;
pub mod headless;

// ---------------------------------------------------------------------------
// Root-level types  (ghidra.app.util.*)
// ---------------------------------------------------------------------------

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ===================================================================
// Option  (ghidra.app.util.Option)
// ===================================================================

/// A configurable option for loaders, analyzers, and exporters.
///
/// Each option has a *name*, an optional *group* (for UI grouping), a
/// polymorphic *value*, an optional *command-line argument* name, and
/// an optional *description*.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GhidraOption {
    /// Option name (e.g. `"Apply Signature"`).
    pub name: String,
    /// Optional group / category (e.g. `"Analysis"`).
    pub group: Option<String>,
    /// Current value.
    pub value: OptionValue,
    /// Optional command-line argument (e.g. `"--apply-sig"`).
    pub command_line_argument: Option<String>,
    /// Human-readable description.
    pub description: Option<String>,
    /// State key for persistence.
    pub state_key: Option<String>,
    /// Whether this option is hidden from the user.
    pub hidden: bool,
}

/// Polymorphic option value.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum OptionValue {
    /// Boolean toggle.
    Boolean(bool),
    /// Signed integer.
    Integer(i64),
    /// Floating point.
    Float(f64),
    /// String value.
    String(String),
    /// List of strings.
    StringList(Vec<String>),
    /// Nested map of name-to-value (for compound options).
    Map(HashMap<String, OptionValue>),
}

impl fmt::Display for OptionValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Boolean(v) => write!(f, "{v}"),
            Self::Integer(v) => write!(f, "{v}"),
            Self::Float(v) => write!(f, "{v}"),
            Self::String(v) => write!(f, "{v}"),
            Self::StringList(v) => write!(f, "[{}]", v.join(", ")),
            Self::Map(m) => write!(f, "{m:?}"),
        }
    }
}

/// Error returned when setting an option value fails.
#[derive(Debug, Error)]
pub enum OptionError {
    /// The value type does not match what the option expects.
    #[error("type mismatch: expected {expected}, got {actual}")]
    TypeMismatch {
        /// Expected type name.
        expected: String,
        /// Actual type name.
        actual: String,
    },
    /// The option name was not found.
    #[error("option not found: {0}")]
    NotFound(String),
}

impl GhidraOption {
    /// Create a new boolean option.
    pub fn bool_opt(name: impl Into<String>, value: bool) -> Self {
        Self {
            name: name.into(),
            group: None,
            value: OptionValue::Boolean(value),
            command_line_argument: None,
            description: None,
            state_key: None,
            hidden: false,
        }
    }

    /// Create a new integer option.
    pub fn int_opt(name: impl Into<String>, value: i64) -> Self {
        Self {
            name: name.into(),
            group: None,
            value: OptionValue::Integer(value),
            command_line_argument: None,
            description: None,
            state_key: None,
            hidden: false,
        }
    }

    /// Create a new string option.
    pub fn str_opt(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            group: None,
            value: OptionValue::String(value.into()),
            command_line_argument: None,
            description: None,
            state_key: None,
            hidden: false,
        }
    }

    /// Builder-style setter for group.
    pub fn with_group(mut self, group: impl Into<String>) -> Self {
        self.group = Some(group.into());
        self
    }

    /// Builder-style setter for description.
    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = Some(desc.into());
        self
    }

    /// Builder-style setter for command-line argument.
    pub fn with_arg(mut self, arg: impl Into<String>) -> Self {
        self.command_line_argument = Some(arg.into());
        self
    }

    /// Builder-style setter for hidden flag.
    pub fn with_hidden(mut self, hidden: bool) -> Self {
        self.hidden = hidden;
        self
    }

    /// Builder-style setter for state key.
    pub fn with_state_key(mut self, key: impl Into<String>) -> Self {
        self.state_key = Some(key.into());
        self
    }
}

// ===================================================================
// AbstractOptionBuilder  (ghidra.app.util.AbstractOptionBuilder)
// ===================================================================

/// Builder pattern for creating [`GhidraOption`] instances.
///
/// # Example
///
/// ```rust
/// use ghidra_app::util::{OptionBuilder, OptionValue};
///
/// let opt = OptionBuilder::new("Apply Signature")
///     .group("Analysis")
///     .description("Apply demangled function signatures")
///     .arg("--apply-sig")
///     .value(OptionValue::Boolean(true))
///     .build();
/// assert_eq!(opt.name, "Apply Signature");
/// ```
pub struct OptionBuilder {
    name: String,
    group: Option<String>,
    value: Option<OptionValue>,
    command_line_argument: Option<String>,
    description: Option<String>,
    state_key: Option<String>,
    hidden: bool,
}

impl OptionBuilder {
    /// Start building an option with the given name.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            group: None,
            value: None,
            command_line_argument: None,
            description: None,
            state_key: None,
            hidden: false,
        }
    }

    /// Set the group.
    pub fn group(mut self, g: impl Into<String>) -> Self {
        self.group = Some(g.into());
        self
    }

    /// Set the value.
    pub fn value(mut self, v: OptionValue) -> Self {
        self.value = Some(v);
        self
    }

    /// Set the command-line argument.
    pub fn arg(mut self, a: impl Into<String>) -> Self {
        self.command_line_argument = Some(a.into());
        self
    }

    /// Set the description.
    pub fn description(mut self, d: impl Into<String>) -> Self {
        self.description = Some(d.into());
        self
    }

    /// Set the state key.
    pub fn state_key(mut self, k: impl Into<String>) -> Self {
        self.state_key = Some(k.into());
        self
    }

    /// Mark as hidden.
    pub fn hidden(mut self, h: bool) -> Self {
        self.hidden = h;
        self
    }

    /// Build the [`GhidraOption`].
    pub fn build(self) -> GhidraOption {
        GhidraOption {
            name: self.name,
            group: self.group,
            value: self.value.unwrap_or(OptionValue::Boolean(false)),
            command_line_argument: self.command_line_argument,
            description: self.description,
            state_key: self.state_key,
            hidden: self.hidden,
        }
    }
}

// ===================================================================
// OptionListener  (ghidra.app.util.OptionListener)
// ===================================================================

/// Callback invoked when an option value changes.
pub trait OptionListener: Send + Sync {
    /// Notification that the given option changed.
    fn option_changed(&self, option: &GhidraOption);
}

// ===================================================================
// OptionUtils  (ghidra.app.util.OptionUtils)
// ===================================================================

/// Utility functions for working with lists of options.
pub struct OptionUtils;

impl OptionUtils {
    /// Find an option by name in a list.
    pub fn find_option<'a>(
        options: &'a [GhidraOption],
        name: &str,
    ) -> Option<&'a GhidraOption> {
        options.iter().find(|o| o.name == name)
    }

    /// Find a mutable option by name in a list.
    pub fn find_option_mut<'a>(
        options: &'a mut [GhidraOption],
        name: &str,
    ) -> Option<&'a mut GhidraOption> {
        options.iter_mut().find(|o| o.name == name)
    }

    /// Extract the boolean value of the named option (defaults to `false`).
    pub fn get_boolean(options: &[GhidraOption], name: &str) -> bool {
        Self::find_option(options, name)
            .and_then(|o| match &o.value {
                OptionValue::Boolean(b) => Some(*b),
                _ => None,
            })
            .unwrap_or(false)
    }

    /// Extract the integer value of the named option (defaults to `0`).
    pub fn get_integer(options: &[GhidraOption], name: &str) -> i64 {
        Self::find_option(options, name)
            .and_then(|o| match &o.value {
                OptionValue::Integer(i) => Some(*i),
                _ => None,
            })
            .unwrap_or(0)
    }

    /// Extract the string value of the named option (defaults to `""`).
    pub fn get_string<'a>(options: &'a [GhidraOption], name: &str) -> &'a str {
        Self::find_option(options, name)
            .and_then(|o| match &o.value {
                OptionValue::String(s) => Some(s.as_str()),
                _ => None,
            })
            .unwrap_or("")
    }

    /// Convert options list to a name-indexed map.
    pub fn to_map(options: &[GhidraOption]) -> HashMap<&str, &OptionValue> {
        options.iter().map(|o| (o.name.as_str(), &o.value)).collect()
    }

    /// Validate that all required option names exist.
    pub fn validate_required(
        options: &[GhidraOption],
        required: &[&str],
    ) -> Result<(), Vec<String>> {
        let missing: Vec<String> = required
            .iter()
            .filter(|r| Self::find_option(options, r).is_none())
            .map(|s| s.to_string())
            .collect();
        if missing.is_empty() {
            Ok(())
        } else {
            Err(missing)
        }
    }
}

// ===================================================================
// OptionValidator  (ghidra.app.util.OptionValidator)
// ===================================================================

/// Trait for validating option values.
pub trait OptionValidator: Send + Sync {
    /// Validate the given option value.  Returns `Ok(())` if valid.
    fn validate(&self, option: &GhidraOption) -> Result<(), String>;

    /// Human-readable description of what this validator checks.
    fn description(&self) -> &str;
}

// ===================================================================
// Permissions  (ghidra.app.util.Permissions)
// ===================================================================

/// Simple read/write/execute permission triple.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Permissions {
    /// Read permission.
    pub read: bool,
    /// Write permission.
    pub write: bool,
    /// Execute permission.
    pub execute: bool,
}

impl Permissions {
    /// Full read/write/execute.
    pub const ALL: Self = Self {
        read: true,
        write: true,
        execute: true,
    };
    /// Read-only.
    pub const READ_ONLY: Self = Self {
        read: true,
        write: false,
        execute: false,
    };
    /// Read + execute.
    pub const READ_EXECUTE: Self = Self {
        read: true,
        write: false,
        execute: true,
    };
    /// Read + write.
    pub const READ_WRITE: Self = Self {
        read: true,
        write: true,
        execute: false,
    };
    /// No permissions.
    pub const NONE: Self = Self {
        read: false,
        write: false,
        execute: false,
    };
}

impl fmt::Display for Permissions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}{}{}",
            if self.read { 'r' } else { '-' },
            if self.write { 'w' } else { '-' },
            if self.execute { 'x' } else { '-' },
        )
    }
}

// ===================================================================
// CommentType  (ghidra.app.util.CommentTypes  /  CommentType enum)
// ===================================================================

/// The different kinds of comments that can appear on a code unit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CommentType {
    /// Comment preceding the code unit.
    Pre,
    /// Comment following the code unit.
    Post,
    /// End-of-line comment.
    Eol,
    /// Plate (block header) comment.
    Plate,
    /// Repeatable comment (propagated to references).
    Repeatable,
}

impl CommentType {
    /// All five comment types in canonical order.
    pub const ALL: [Self; 5] = [
        Self::Pre,
        Self::Post,
        Self::Eol,
        Self::Plate,
        Self::Repeatable,
    ];

    /// Return the Ghidra integer constant for this comment type.
    pub fn to_int(self) -> i32 {
        match self {
            Self::Pre => 0,
            Self::Post => 1,
            Self::Eol => 2,
            Self::Plate => 3,
            Self::Repeatable => 4,
        }
    }

    /// Try to convert an integer back to a `CommentType`.
    pub fn from_int(v: i32) -> Option<Self> {
        match v {
            0 => Some(Self::Pre),
            1 => Some(Self::Post),
            2 => Some(Self::Eol),
            3 => Some(Self::Plate),
            4 => Some(Self::Repeatable),
            _ => None,
        }
    }
}

impl fmt::Display for CommentType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pre => write!(f, "Pre"),
            Self::Post => write!(f, "Post"),
            Self::Eol => write!(f, "EOL"),
            Self::Plate => write!(f, "Plate"),
            Self::Repeatable => write!(f, "Repeatable"),
        }
    }
}

// ===================================================================
// ClipboardType  (ghidra.app.util.ClipboardType)
// ===================================================================

/// Defines a "type" for items in the clipboard.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClipboardType {
    /// MIME type identifier.
    pub mime_type: String,
    /// Human-readable name.
    pub type_name: String,
}

impl ClipboardType {
    /// Create a new clipboard type.
    pub fn new(mime_type: impl Into<String>, type_name: impl Into<String>) -> Self {
        Self {
            mime_type: mime_type.into(),
            type_name: type_name.into(),
        }
    }
}

// ===================================================================
// ColorAndStyle  (ghidra.app.util.ColorAndStyle)
// ===================================================================

/// A foreground/background colour pair with a text style.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ColorAndStyle {
    /// Foreground colour as ARGB hex.
    pub foreground: u32,
    /// Background colour as ARGB hex (0 for transparent).
    pub background: u32,
    /// Whether text should be bold.
    pub bold: bool,
    /// Whether text should be italic.
    pub italic: bool,
    /// Whether text should be underlined.
    pub underline: bool,
}

impl Default for ColorAndStyle {
    fn default() -> Self {
        Self {
            foreground: 0xFF000000, // black
            background: 0x00000000, // transparent
            bold: false,
            italic: false,
            underline: false,
        }
    }
}

// ===================================================================
// CodeUnitInfo  (ghidra.app.util.CodeUnitInfo)
// ===================================================================

/// Summary information about a code unit at an address.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeUnitInfo {
    /// Address (as a hex string for serialization portability).
    pub address: u64,
    /// Length of the code unit in bytes.
    pub length: usize,
    /// Label / symbol name, if any.
    pub label: Option<String>,
    /// Mnemonic (for instructions) or data type name.
    pub mnemonic: String,
}

// ===================================================================
// SearchConstants  (ghidra.app.util.SearchConstants)
// ===================================================================

/// Constants used for search operations.
pub struct SearchConstants;

impl SearchConstants {
    /// Maximum number of results returned from a search.
    pub const MAX_RESULTS: usize = 1000;
    /// Default search timeout in milliseconds.
    pub const DEFAULT_TIMEOUT_MS: u64 = 30_000;
    /// Default maximum search memory in bytes (256 MiB).
    pub const DEFAULT_MAX_MEMORY: usize = 256 * 1024 * 1024;
}

// ===================================================================
// HexLong  (ghidra.app.util.HexLong)
// ===================================================================

/// A wrapper around `u64` that formats as hexadecimal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct HexLong(pub u64);

impl fmt::Display for HexLong {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{:x}", self.0)
    }
}

impl fmt::UpperHex for HexLong {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{:X}", self.0)
    }
}

// ===================================================================
// DomainObjectService  (ghidra.app.util.DomainObjectService)
// ===================================================================

/// Lazy accessor for a domain object.
///
/// Used to delay the opening of a domain object until it is needed
/// (e.g., during export).
pub trait DomainObjectService: Send + Sync {
    /// Get the domain object.  Returns `None` if export is limited to a file.
    fn get_domain_object_id(&self) -> Option<String>;
}

// ===================================================================
// ListingHighlightProvider  (ghidra.app.util.ListingHighlightProvider)
// ===================================================================

/// Provides highlight information for a listing row.
pub trait ListingHighlightProvider: Send + Sync {
    /// Return the background colour (ARGB) for the given column and
    /// offset, or `None` for the default.
    fn get_background_color(
        &self,
        row: usize,
        column: usize,
        offset: usize,
    ) -> Option<u32>;
}

// ===================================================================
// AddressFactoryService  (ghidra.app.util.AddressFactoryService)
// ===================================================================

/// Simple service for obtaining an address factory.
pub trait AddressFactoryService: Send + Sync {
    /// Return the name of the address space.
    fn default_address_space_name(&self) -> &str;

    /// Return the address size in bits.
    fn address_size(&self) -> usize;
}

// ===================================================================
// SelectionTransferData  (ghidra.app.util.SelectionTransferData)
// ===================================================================

/// Data payload for transferring address selections.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelectionTransferData {
    /// Program name.
    pub program_name: String,
    /// Selected addresses as (start, end) pairs.
    pub ranges: Vec<(u64, u64)>,
}

// ===================================================================
// RefRepeatComment  (ghidra.app.util.RefRepeatComment)
// ===================================================================

/// A repeatable comment from a referenced address.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefRepeatComment {
    /// The address from which the reference originates.
    pub from_address: u64,
    /// The repeatable comment text.
    pub comment: String,
}

// ===================================================================
// EolComments  (ghidra.app.util.EolComments)
// ===================================================================

/// Collector for end-of-line comment strings from a code unit.
///
/// Collects EOL, repeatable, reference-repeatable, and auto-generated
/// comments that can be displayed in the listing.
#[derive(Debug, Default)]
pub struct EolComments {
    eols: Vec<String>,
    repeatables: Vec<String>,
    ref_repeatables: Vec<RefRepeatComment>,
    autos: Vec<String>,
}

impl EolComments {
    /// Create a new empty collector.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an EOL comment.
    pub fn add_eol(&mut self, comment: impl Into<String>) {
        self.eols.push(comment.into());
    }

    /// Add a repeatable comment.
    pub fn add_repeatable(&mut self, comment: impl Into<String>) {
        self.repeatables.push(comment.into());
    }

    /// Add a reference repeatable comment.
    pub fn add_ref_repeatable(&mut self, from_address: u64, comment: impl Into<String>) {
        self.ref_repeatables.push(RefRepeatComment {
            from_address,
            comment: comment.into(),
        });
    }

    /// Add an auto-generated comment.
    pub fn add_auto(&mut self, comment: impl Into<String>) {
        self.autos.push(comment.into());
    }

    /// Get all collected EOL comments.
    pub fn eols(&self) -> &[String] {
        &self.eols
    }

    /// Get all collected repeatable comments.
    pub fn repeatables(&self) -> &[String] {
        &self.repeatables
    }

    /// Get all collected reference-repeatable comments.
    pub fn ref_repeatables(&self) -> &[RefRepeatComment] {
        &self.ref_repeatables
    }

    /// Get all collected auto-generated comments.
    pub fn autos(&self) -> &[String] {
        &self.autos
    }

    /// Merge all comments into a single EOL string separated by newlines.
    pub fn to_eol_string(&self) -> String {
        let mut parts = Vec::new();
        parts.extend(self.eols.iter().cloned());
        parts.extend(self.repeatables.iter().cloned());
        for rrc in &self.ref_repeatables {
            parts.push(format!("-> {}", rrc.comment));
        }
        parts.extend(self.autos.iter().cloned());
        parts.join("\n")
    }

    /// Return `true` if no comments were collected.
    pub fn is_empty(&self) -> bool {
        self.eols.is_empty()
            && self.repeatables.is_empty()
            && self.ref_repeatables.is_empty()
            && self.autos.is_empty()
    }
}

// ===================================================================
// DataTypeNamingUtil  (ghidra.app.util.DataTypeNamingUtil)
// ===================================================================

/// Utility for generating and validating data-type names.
pub struct DataTypeNamingUtil;

impl DataTypeNamingUtil {
    /// Generate a unique name by appending a numeric suffix.
    pub fn unique_name(base: &str, existing: &[&str]) -> String {
        if !existing.contains(&base) {
            return base.to_string();
        }
        for i in 2.. {
            let candidate = format!("{base}_{i}");
            if !existing.contains(&candidate.as_str()) {
                return candidate;
            }
        }
        unreachable!()
    }

    /// Strip namespace prefixes from a name (e.g. `"std::string"` -> `"string"`).
    pub fn strip_namespace(name: &str) -> &str {
        name.rsplit_once("::").map(|(_, n)| n).unwrap_or(name)
    }

    /// Return the namespace portion of a name, or `""` if none.
    pub fn namespace_of(name: &str) -> &str {
        name.rsplit_once("::").map(|(ns, _)| ns).unwrap_or("")
    }

    /// Validate that a name contains only valid identifier characters.
    pub fn is_valid_name(name: &str) -> bool {
        if name.is_empty() {
            return false;
        }
        let first = name.as_bytes()[0];
        if !first.is_ascii_alphabetic() && first != b'_' {
            return false;
        }
        name.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_')
    }
}

// ===================================================================
// HelpTopics  (ghidra.app.util.HelpTopics)
// ===================================================================

/// Constants for help topic identifiers.
pub struct HelpTopics;

impl HelpTopics {
    pub const CODE_BROWSER: &str = "CodeBrowser";
    pub const DATA: &str = "Data";
    pub const FUNCTIONS: &str = "Functions";
    pub const IMPORT: &str = "Import";
    pub const EXPORT: &str = "Export";
    pub const SEARCH: &str = "Search";
    pub const MEMORY: &str = "Memory";
    pub const SYMBOLS: &str = "Symbols";
    pub const REFERENCES: &str = "References";
}

// ===================================================================
// ProcessorInfo  (ghidra.app.util.ProcessorInfo)
// ===================================================================

/// Minimal information about a processor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessorInfo {
    /// Processor name (e.g. `"x86"`, `"ARM"`, `"MIPS"`).
    pub processor: String,
    /// Language variant (e.g. `"LE"`, `"BE"`, `"v7"`).
    pub variant: String,
    /// Address size in bits (16, 32, 64).
    pub address_size: usize,
    /// Endianness.
    pub big_endian: bool,
}

// ===================================================================
// MemoryBlockUtils  (ghidra.app.util.MemoryBlockUtils)
// ===================================================================

/// Convenience methods for creating memory blocks.
///
/// These mirror the Java `MemoryBlockUtils` static methods but operate
/// on the Rust `Program` model.
pub struct MemoryBlockUtils;

/// Parameters for creating a memory block.
pub struct BlockParams {
    /// Block name.
    pub name: String,
    /// Start address.
    pub start: u64,
    /// Length in bytes.
    pub length: u64,
    /// Comment text.
    pub comment: String,
    /// Source description.
    pub source: String,
    /// Permissions.
    pub permissions: Permissions,
    /// Whether this is an overlay block.
    pub is_overlay: bool,
}

impl MemoryBlockUtils {

    /// Validate block parameters.
    pub fn validate_params(params: &BlockParams) -> Result<(), String> {
        if params.name.is_empty() {
            return Err("Block name cannot be empty".into());
        }
        if params.length == 0 {
            return Err("Block length cannot be zero".into());
        }
        // Check for address overflow
        if params.start.checked_add(params.length).is_none() {
            return Err("Address overflow: start + length exceeds u64::MAX".into());
        }
        Ok(())
    }

    /// Generate a summary string for a block.
    pub fn block_summary(params: &BlockParams) -> String {
        format!(
            "{} [{:#x}..{:#x}] {} {}",
            params.name,
            params.start,
            params.start + params.length,
            params.permissions,
            params.comment,
        )
    }
}

// ===================================================================
// XReferenceUtils  (ghidra.app.util.XReferenceUtils)
// ===================================================================

/// Represents a cross-reference between two addresses.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XReference {
    /// Source address.
    pub from_address: u64,
    /// Target address.
    pub to_address: u64,
    /// Reference type.
    pub ref_type: XRefType,
}

/// Types of cross-references.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum XRefType {
    /// Unconditional flow (call, jump).
    Flow,
    /// Data read reference.
    Read,
    /// Data write reference.
    Write,
    /// Data read/write reference.
    ReadWrite,
    /// Indirect reference.
    Indirect,
}

/// Utility functions for querying cross-references.
pub struct XReferenceUtils;

impl XReferenceUtils {
    /// Get cross-references to an address from a list.
    pub fn get_xrefs_to(xrefs: &[XReference], address: u64) -> Vec<&XReference> {
        xrefs.iter().filter(|x| x.to_address == address).collect()
    }

    /// Get cross-references from an address from a list.
    pub fn get_xrefs_from(xrefs: &[XReference], address: u64) -> Vec<&XReference> {
        xrefs.iter().filter(|x| x.from_address == address).collect()
    }

    /// Get offcut (mid-instruction/data) cross-references.
    ///
    /// Returns references whose target falls within the range
    /// `[start+1 ..= end]`.
    pub fn get_offcut_xrefs(
        xrefs: &[XReference],
        start: u64,
        end: u64,
    ) -> Vec<&XReference> {
        xrefs
            .iter()
            .filter(|x| x.to_address > start && x.to_address <= end)
            .collect()
    }

    /// Count references to an address.
    pub fn count_xrefs_to(xrefs: &[XReference], address: u64) -> usize {
        xrefs.iter().filter(|x| x.to_address == address).count()
    }

    /// Collect unique source addresses referencing the target.
    pub fn unique_from_addresses(xrefs: &[XReference], to: u64) -> Vec<u64> {
        let mut addrs: Vec<u64> = xrefs
            .iter()
            .filter(|x| x.to_address == to)
            .map(|x| x.from_address)
            .collect();
        addrs.sort_unstable();
        addrs.dedup();
        addrs
    }
}

// ===================================================================
// Tests
// ===================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn option_builder_roundtrip() {
        let opt = OptionBuilder::new("Test")
            .group("Group")
            .description("A test option")
            .arg("--test")
            .value(OptionValue::Integer(42))
            .build();
        assert_eq!(opt.name, "Test");
        assert_eq!(opt.group.as_deref(), Some("Group"));
        assert_eq!(opt.value, OptionValue::Integer(42));
        assert_eq!(opt.command_line_argument.as_deref(), Some("--test"));
        assert_eq!(opt.description.as_deref(), Some("A test option"));
    }

    #[test]
    fn option_value_display() {
        assert_eq!(OptionValue::Boolean(true).to_string(), "true");
        assert_eq!(OptionValue::Integer(42).to_string(), "42");
        assert_eq!(OptionValue::String("abc".into()).to_string(), "abc");
    }

    #[test]
    fn option_utils_find() {
        let opts = vec![
            GhidraOption::bool_opt("Apply Signature", true),
            GhidraOption::int_opt("Max Results", 500),
        ];
        assert!(OptionUtils::find_option(&opts, "Apply Signature").is_some());
        assert!(OptionUtils::find_option(&opts, "Missing").is_none());
        assert!(OptionUtils::get_boolean(&opts, "Apply Signature"));
        assert_eq!(OptionUtils::get_integer(&opts, "Max Results"), 500);
        assert!(!OptionUtils::get_boolean(&opts, "Missing"));
    }

    #[test]
    fn option_utils_validate_required() {
        let opts = vec![GhidraOption::bool_opt("A", true)];
        assert!(OptionUtils::validate_required(&opts, &["A"]).is_ok());
        let result = OptionUtils::validate_required(&opts, &["A", "B", "C"]);
        assert!(result.is_err());
        let missing = result.unwrap_err();
        assert_eq!(missing, vec!["B", "C"]);
    }

    #[test]
    fn option_utils_to_map() {
        let opts = vec![
            GhidraOption::bool_opt("X", true),
            GhidraOption::int_opt("Y", 7),
        ];
        let map = OptionUtils::to_map(&opts);
        assert_eq!(map.len(), 2);
        assert_eq!(map.get("X"), Some(&&OptionValue::Boolean(true)));
    }

    #[test]
    fn permissions_display() {
        assert_eq!(Permissions::ALL.to_string(), "rwx");
        assert_eq!(Permissions::READ_ONLY.to_string(), "r--");
        assert_eq!(Permissions::READ_EXECUTE.to_string(), "r-x");
        assert_eq!(Permissions::NONE.to_string(), "---");
    }

    #[test]
    fn permissions_equality() {
        assert_eq!(Permissions::ALL, Permissions::ALL);
        assert_ne!(Permissions::ALL, Permissions::READ_ONLY);
    }

    #[test]
    fn comment_type_roundtrip() {
        for ct in &CommentType::ALL {
            let int_val = ct.to_int();
            assert_eq!(CommentType::from_int(int_val), Some(*ct));
        }
        assert!(CommentType::from_int(99).is_none());
    }

    #[test]
    fn comment_type_display() {
        assert_eq!(CommentType::Pre.to_string(), "Pre");
        assert_eq!(CommentType::Eol.to_string(), "EOL");
        assert_eq!(CommentType::Repeatable.to_string(), "Repeatable");
    }

    #[test]
    fn clipboard_type_basic() {
        let ct = ClipboardType::new("text/plain", "Plain Text");
        assert_eq!(ct.mime_type, "text/plain");
        assert_eq!(ct.type_name, "Plain Text");
    }

    #[test]
    fn hex_long_display() {
        assert_eq!(HexLong(0xDEAD).to_string(), "0xdead");
        assert_eq!(format!("{:X}", HexLong(0xBEEF)), "0xBEEF");
    }

    #[test]
    fn data_type_naming_util() {
        assert_eq!(DataTypeNamingUtil::unique_name("foo", &["bar", "baz"]), "foo");
        assert_eq!(DataTypeNamingUtil::unique_name("foo", &["foo", "bar"]), "foo_2");
        assert_eq!(
            DataTypeNamingUtil::unique_name("foo", &["foo", "foo_2"]),
            "foo_3"
        );
    }

    #[test]
    fn data_type_naming_util_namespace() {
        assert_eq!(DataTypeNamingUtil::strip_namespace("std::string"), "string");
        assert_eq!(DataTypeNamingUtil::strip_namespace("basic"), "basic");
        assert_eq!(DataTypeNamingUtil::namespace_of("std::string"), "std");
        assert_eq!(DataTypeNamingUtil::namespace_of("basic"), "");
    }

    #[test]
    fn data_type_naming_util_valid_name() {
        assert!(DataTypeNamingUtil::is_valid_name("foo"));
        assert!(DataTypeNamingUtil::is_valid_name("_bar"));
        assert!(DataTypeNamingUtil::is_valid_name("Foo123"));
        assert!(!DataTypeNamingUtil::is_valid_name(""));
        assert!(!DataTypeNamingUtil::is_valid_name("1abc"));
        assert!(!DataTypeNamingUtil::is_valid_name("a-b"));
    }

    #[test]
    fn eol_comments_basic() {
        let mut eol = EolComments::new();
        assert!(eol.is_empty());
        eol.add_eol("my eol");
        eol.add_repeatable("repeat me");
        eol.add_ref_repeatable(0x4000, "from ref");
        assert!(!eol.is_empty());
        assert_eq!(eol.eols().len(), 1);
        assert_eq!(eol.repeatables().len(), 1);
        assert_eq!(eol.ref_repeatables().len(), 1);
        let s = eol.to_eol_string();
        assert!(s.contains("my eol"));
        assert!(s.contains("repeat me"));
        assert!(s.contains("-> from ref"));
    }

    #[test]
    fn xref_utils_query() {
        let xrefs = vec![
            XReference {
                from_address: 0x100,
                to_address: 0x200,
                ref_type: XRefType::Flow,
            },
            XReference {
                from_address: 0x110,
                to_address: 0x200,
                ref_type: XRefType::Read,
            },
            XReference {
                from_address: 0x120,
                to_address: 0x300,
                ref_type: XRefType::Write,
            },
        ];
        assert_eq!(XReferenceUtils::get_xrefs_to(&xrefs, 0x200).len(), 2);
        assert_eq!(XReferenceUtils::count_xrefs_to(&xrefs, 0x200), 2);
        assert_eq!(XReferenceUtils::get_xrefs_from(&xrefs, 0x100).len(), 1);
        assert_eq!(XReferenceUtils::unique_from_addresses(&xrefs, 0x200).len(), 2);
    }

    #[test]
    fn xref_offcut() {
        let xrefs = vec![
            XReference {
                from_address: 0x100,
                to_address: 0x200,
                ref_type: XRefType::Flow,
            },
            XReference {
                from_address: 0x110,
                to_address: 0x201,
                ref_type: XRefType::Read,
            },
            XReference {
                from_address: 0x120,
                to_address: 0x202,
                ref_type: XRefType::Read,
            },
        ];
        // Offcut: (200, 202] => 201, 202
        let offcut = XReferenceUtils::get_offcut_xrefs(&xrefs, 0x200, 0x202);
        assert_eq!(offcut.len(), 2);
    }

    #[test]
    fn memory_block_utils_validate() {
        let params = BlockParams {
            name: ".text".into(),
            start: 0x400000,
            length: 0x1000,
            comment: "code".into(),
            source: "ELF".into(),
            permissions: Permissions::READ_EXECUTE,
            is_overlay: false,
        };
        assert!(MemoryBlockUtils::validate_params(&params).is_ok());
        assert!(MemoryBlockUtils::block_summary(&params).contains(".text"));
    }

    #[test]
    fn memory_block_utils_validate_empty_name() {
        let params = BlockParams {
            name: "".into(),
            start: 0x400000,
            length: 0x1000,
            comment: String::new(),
            source: String::new(),
            permissions: Permissions::ALL,
            is_overlay: false,
        };
        assert!(MemoryBlockUtils::validate_params(&params).is_err());
    }

    #[test]
    fn memory_block_utils_validate_zero_length() {
        let params = BlockParams {
            name: ".bss".into(),
            start: 0x400000,
            length: 0,
            comment: String::new(),
            source: String::new(),
            permissions: Permissions::ALL,
            is_overlay: false,
        };
        assert!(MemoryBlockUtils::validate_params(&params).is_err());
    }

    #[test]
    fn selection_transfer_data() {
        let data = SelectionTransferData {
            program_name: "test.exe".into(),
            ranges: vec![(0x400000, 0x401000), (0x500000, 0x501000)],
        };
        assert_eq!(data.ranges.len(), 2);
        assert_eq!(data.program_name, "test.exe");
    }

    #[test]
    fn processor_info_display() {
        let info = ProcessorInfo {
            processor: "x86".into(),
            variant: "LE".into(),
            address_size: 64,
            big_endian: false,
        };
        assert_eq!(info.processor, "x86");
        assert_eq!(info.address_size, 64);
        assert!(!info.big_endian);
    }

    #[test]
    fn color_and_style_default() {
        let cs = ColorAndStyle::default();
        assert!(!cs.bold);
        assert!(!cs.italic);
        assert!(!cs.underline);
    }

    #[test]
    fn option_serialize_roundtrip() {
        let opt = GhidraOption::bool_opt("SerializeTest", true)
            .with_group("test");
        let json = serde_json::to_string(&opt).unwrap();
        let back: GhidraOption = serde_json::from_str(&json).unwrap();
        assert_eq!(back.name, "SerializeTest");
        assert_eq!(back.value, OptionValue::Boolean(true));
        assert_eq!(back.group.as_deref(), Some("test"));
    }
}
