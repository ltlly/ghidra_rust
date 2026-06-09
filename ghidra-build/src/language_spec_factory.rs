//! Factory for creating language specifications from `.ldefs` files.
//!
//! Port of Ghidra's `SleighLanguageProvider.createLanguageDescriptions()` and
//! related XML parsing logic from `ghidra.app.plugin.processors.sleigh`.
//!
//! The [`LanguageSpecFactory`] parses Ghidra `.ldefs` XML files and produces
//! [`LanguageSpec`](super::language_spec::LanguageSpec) instances. It handles
//! the `<language_definitions>` root element and its `<language>` children,
//! including compiler specs, external names, and truncation rules.

use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use super::language_spec::{
    CompilerSpecDescription, CompilerSpecID, Endian, LanguageSpec, LanguageSpecID,
};

// ============================================================================
// Error types
// ============================================================================

/// Errors that can occur when parsing language specification files.
#[derive(Debug, thiserror::Error)]
pub enum LanguageSpecError {
    /// An I/O error occurred while reading the file.
    #[error("I/O error reading {path}: {source}")]
    Io {
        path: PathBuf,
        source: io::Error,
    },

    /// The XML content could not be parsed.
    #[error("XML parse error in {path}: {message}")]
    Parse { path: PathBuf, message: String },

    /// A required attribute is missing from an XML element.
    #[error("Missing attribute '{attribute}' in {path} at {element}")]
    MissingAttribute {
        path: PathBuf,
        element: String,
        attribute: String,
    },

    /// An attribute value could not be converted to the expected type.
    #[error("Invalid attribute value '{value}' for '{attribute}' in {path}: {reason}")]
    InvalidValue {
        path: PathBuf,
        attribute: String,
        value: String,
        reason: String,
    },
}

// ============================================================================
// Simple XML element (lightweight parser)
// ============================================================================

/// A minimal XML element used for parsing `.ldefs` files.
///
/// This is a simplified representation that handles the subset of XML
/// needed for Ghidra language definition files.
#[derive(Debug, Clone)]
pub struct XmlElement {
    /// The element tag name.
    pub name: String,
    /// Element attributes.
    pub attributes: HashMap<String, String>,
    /// Child elements.
    pub children: Vec<XmlElement>,
    /// Text content (if any).
    pub text: String,
}

impl XmlElement {
    /// Get an attribute value by name.
    pub fn attr(&self, name: &str) -> Option<&str> {
        self.attributes.get(name).map(|s| s.as_str())
    }

    /// Get a required attribute, returning an error if missing.
    pub fn require_attr(&self, name: &str, path: &Path) -> Result<&str, LanguageSpecError> {
        self.attr(name).ok_or_else(|| LanguageSpecError::MissingAttribute {
            path: path.to_path_buf(),
            element: self.name.clone(),
            attribute: name.to_string(),
        })
    }

    /// Get an attribute as a boolean (parses "true"/"1" as true).
    pub fn attr_bool(&self, name: &str) -> bool {
        match self.attr(name) {
            Some("true") | Some("1") => true,
            _ => false,
        }
    }
}

// ============================================================================
// Simple XML parser
// ============================================================================

/// A minimal XML parser for `.ldefs` files.
///
/// Ghidra's `.ldefs` files use a straightforward XML structure that does not
/// require a full SAX/DOM parser. This lightweight implementation handles
/// elements with attributes, nested children, and text content.
fn parse_xml(content: &str, path: &Path) -> Result<XmlElement, LanguageSpecError> {
    let mut chars = content.chars().peekable();
    parse_element_inner(&mut chars, path)
}

fn parse_element_inner(
    chars: &mut std::iter::Peekable<std::str::Chars<'_>>,
    path: &Path,
) -> Result<XmlElement, LanguageSpecError> {
    // Skip to the next '<'
    skip_to_tag(chars);

    if chars.peek().is_none() {
        return Err(LanguageSpecError::Parse {
            path: path.to_path_buf(),
            message: "Unexpected end of input".to_string(),
        });
    }

    // Consume '<'
    chars.next();

    // Skip XML declarations and comments
    if chars.peek() == Some(&'?') || chars.peek() == Some(&'!') {
        skip_to_end_tag(chars);
        return parse_element_inner(chars, path);
    }

    // Skip closing tags (shouldn't happen at top level, but handle gracefully)
    if chars.peek() == Some(&'/') {
        skip_to_end_tag(chars);
        return parse_element_inner(chars, path);
    }

    // Read tag name
    let tag_name = read_tag_name(chars);

    // Read attributes
    let attributes = read_attributes(chars, path)?;

    // Check for self-closing tag
    if chars.peek() == Some(&'/') {
        chars.next(); // consume '/'
        if chars.peek() == Some(&'>') {
            chars.next(); // consume '>'
        }
        return Ok(XmlElement {
            name: tag_name,
            attributes,
            children: Vec::new(),
            text: String::new(),
        });
    }

    // Consume '>'
    if chars.peek() == Some(&'>') {
        chars.next();
    }

    // Read children and text
    let mut children = Vec::new();
    let mut text = String::new();

    loop {
        // Collect text until next '<'
        while let Some(&c) = chars.peek() {
            if c == '<' {
                break;
            }
            text.push(c);
            chars.next();
        }

        if chars.peek().is_none() {
            break;
        }

        // Save position - check if this is a closing tag
        chars.next(); // consume '<'

        if chars.peek() == Some(&'/') {
            // Closing tag - skip to '>'
            chars.next(); // consume '/'
            skip_to_end_tag(chars);
            break;
        }

        // It's a child element - put '<' back by re-parsing
        // We already consumed '<', so we need to handle this child
        let child_tag = read_tag_name(chars);
        let child_attrs = read_attributes(chars, path)?;

        if chars.peek() == Some(&'/') {
            chars.next(); // consume '/'
            if chars.peek() == Some(&'>') {
                chars.next(); // consume '>'
            }
            children.push(XmlElement {
                name: child_tag,
                attributes: child_attrs,
                children: Vec::new(),
                text: String::new(),
            });
            continue;
        }

        if chars.peek() == Some(&'>') {
            chars.next(); // consume '>'
        }

        // Recursively parse child content
        let mut child_children = Vec::new();
        let mut child_text = String::new();

        loop {
            while let Some(&c) = chars.peek() {
                if c == '<' {
                    break;
                }
                child_text.push(c);
                chars.next();
            }

            if chars.peek().is_none() {
                break;
            }

            chars.next(); // consume '<'

            if chars.peek() == Some(&'/') {
                chars.next();
                skip_to_end_tag(chars);
                break;
            }

            let sub_tag = read_tag_name(chars);
            let sub_attrs = read_attributes(chars, path)?;

            if chars.peek() == Some(&'/') {
                chars.next();
                if chars.peek() == Some(&'>') {
                    chars.next();
                }
                child_children.push(XmlElement {
                    name: sub_tag,
                    attributes: sub_attrs,
                    children: Vec::new(),
                    text: String::new(),
                });
                continue;
            }

            if chars.peek() == Some(&'>') {
                chars.next();
            }

            // Read sub-child text content
            let mut sub_text = String::new();
            while let Some(&c) = chars.peek() {
                if c == '<' {
                    break;
                }
                sub_text.push(c);
                chars.next();
            }

            // Skip closing tag
            if chars.peek() == Some(&'<') {
                chars.next();
                if chars.peek() == Some(&'/') {
                    chars.next();
                    skip_to_end_tag(chars);
                }
            }

            child_children.push(XmlElement {
                name: sub_tag,
                attributes: sub_attrs,
                children: Vec::new(),
                text: sub_text,
            });
        }

        children.push(XmlElement {
            name: child_tag,
            attributes: child_attrs,
            children: child_children,
            text: child_text,
        });
    }

    Ok(XmlElement {
        name: tag_name,
        attributes,
        children,
        text: text.trim().to_string(),
    })
}

fn skip_to_tag(chars: &mut std::iter::Peekable<std::str::Chars<'_>>) {
    while let Some(&c) = chars.peek() {
        if c == '<' {
            break;
        }
        chars.next();
    }
}

fn skip_to_end_tag(chars: &mut std::iter::Peekable<std::str::Chars<'_>>) {
    while let Some(c) = chars.next() {
        if c == '>' {
            break;
        }
    }
}

fn read_tag_name(chars: &mut std::iter::Peekable<std::str::Chars<'_>>) -> String {
    let mut name = String::new();
    while let Some(&c) = chars.peek() {
        if c.is_whitespace() || c == '>' || c == '/' {
            break;
        }
        name.push(c);
        chars.next();
    }
    name
}

fn read_attributes(
    chars: &mut std::iter::Peekable<std::str::Chars<'_>>,
    _path: &Path,
) -> Result<HashMap<String, String>, LanguageSpecError> {
    let mut attrs = HashMap::new();

    loop {
        // Skip whitespace
        while let Some(&c) = chars.peek() {
            if !c.is_whitespace() {
                break;
            }
            chars.next();
        }

        // Check for end of tag
        if chars.peek() == Some(&'>') || chars.peek() == Some(&'/') {
            break;
        }
        if chars.peek().is_none() {
            break;
        }

        // Read attribute name
        let mut attr_name = String::new();
        while let Some(&c) = chars.peek() {
            if c == '=' || c.is_whitespace() || c == '>' || c == '/' {
                break;
            }
            attr_name.push(c);
            chars.next();
        }

        // Skip whitespace and '='
        while let Some(&c) = chars.peek() {
            if !c.is_whitespace() {
                break;
            }
            chars.next();
        }

        if chars.peek() != Some(&'=') {
            continue;
        }
        chars.next(); // consume '='

        while let Some(&c) = chars.peek() {
            if !c.is_whitespace() {
                break;
            }
            chars.next();
        }

        // Read attribute value (quoted)
        let quote = chars.next().unwrap_or('"');
        let mut value = String::new();
        while let Some(c) = chars.next() {
            if c == quote {
                break;
            }
            value.push(c);
        }

        attrs.insert(attr_name, value);
    }

    Ok(attrs)
}

// ============================================================================
// LanguageSpecFactory
// ============================================================================

/// Factory for creating [`LanguageSpec`] instances from `.ldefs` files.
///
/// Corresponds to the language-loading portion of Ghidra's
/// `SleighLanguageProvider`. The factory reads `.ldefs` XML files,
/// parses `<language_definitions>` and their `<language>` children,
/// and produces a vector of `LanguageSpec` values.
///
/// # Example
///
/// ```
/// use ghidra_build::language_spec_factory::LanguageSpecFactory;
///
/// let factory = LanguageSpecFactory::new();
/// // factory.load_from_file(Path::new("x86.ldefs"))?;
/// // let specs = factory.language_specs();
/// ```
#[derive(Debug, Default)]
pub struct LanguageSpecFactory {
    specs: Vec<LanguageSpec>,
    failures: Vec<(PathBuf, LanguageSpecError)>,
}

impl LanguageSpecFactory {
    /// Create a new empty factory.
    pub fn new() -> Self {
        Self::default()
    }

    /// Load language specifications from a `.ldefs` file.
    ///
    /// Parses the XML and appends any successfully parsed language specs
    /// to the internal list. Parse errors for individual languages are
    /// collected but do not prevent other languages from loading.
    pub fn load_from_file(&mut self, path: &Path) -> Result<usize, LanguageSpecError> {
        let content = fs::read_to_string(path).map_err(|e| LanguageSpecError::Io {
            path: path.to_path_buf(),
            source: e,
        })?;
        self.load_from_str(&content, path)
    }

    /// Load language specifications from an XML string.
    ///
    /// This is the core parsing method. It parses the `<language_definitions>`
    /// root element and iterates over its `<language>` children.
    pub fn load_from_str(&mut self, content: &str, path: &Path) -> Result<usize, LanguageSpecError> {
        let root = parse_xml(content, path)?;
        let mut count = 0;

        // The root should be <language_definitions>
        // If the root element IS the language_definitions, iterate its children
        // Otherwise, look for language_definitions in children
        let ldefs = if root.name == "language_definitions" {
            &root
        } else {
            root.children
                .iter()
                .find(|c| c.name == "language_definitions")
                .unwrap_or(&root)
        };

        // Process <language> elements
        let lang_elements: Vec<&XmlElement> = ldefs
            .children
            .iter()
            .filter(|c| c.name == "language")
            .collect();

        for lang_elem in lang_elements {
            match parse_language_element(lang_elem, path) {
                Ok(spec) => {
                    self.specs.push(spec);
                    count += 1;
                }
                Err(e) => {
                    self.failures.push((path.to_path_buf(), e));
                }
            }
        }

        Ok(count)
    }

    /// Load all `.ldefs` files from a directory tree (non-recursive).
    pub fn load_from_directory(&mut self, dir: &Path) -> Result<usize, LanguageSpecError> {
        let mut total = 0;
        let entries = fs::read_dir(dir).map_err(|e| LanguageSpecError::Io {
            path: dir.to_path_buf(),
            source: e,
        })?;

        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().map_or(false, |ext| ext == "ldefs") {
                total += self.load_from_file(&path)?;
            }
        }

        Ok(total)
    }

    /// Load all `.ldefs` files recursively from a directory tree.
    pub fn load_from_directory_recursive(&mut self, dir: &Path) -> Result<usize, LanguageSpecError> {
        let mut total = 0;
        self.load_from_directory_recursive_inner(dir, &mut total)?;
        Ok(total)
    }

    fn load_from_directory_recursive_inner(
        &mut self,
        dir: &Path,
        total: &mut usize,
    ) -> Result<(), LanguageSpecError> {
        let entries = fs::read_dir(dir).map_err(|e| LanguageSpecError::Io {
            path: dir.to_path_buf(),
            source: e,
        })?;

        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                self.load_from_directory_recursive_inner(&path, total)?;
            } else if path.extension().map_or(false, |ext| ext == "ldefs") {
                *total += self.load_from_file(&path)?;
            }
        }

        Ok(())
    }

    /// Get a reference to all loaded language specs.
    pub fn language_specs(&self) -> &[LanguageSpec] {
        &self.specs
    }

    /// Consume the factory and return all loaded language specs.
    pub fn into_language_specs(self) -> Vec<LanguageSpec> {
        self.specs
    }

    /// Get a reference to the collected failures.
    pub fn failures(&self) -> &[(PathBuf, LanguageSpecError)] {
        &self.failures
    }

    /// Returns true if any load failures occurred.
    pub fn had_failures(&self) -> bool {
        !self.failures.is_empty()
    }

    /// Find a language spec by its ID string.
    pub fn find_by_id(&self, id: &str) -> Option<&LanguageSpec> {
        self.specs.iter().find(|s| s.id.to_string() == id)
    }

    /// Find all language specs for a given processor.
    pub fn find_by_processor(&self, processor: &str) -> Vec<&LanguageSpec> {
        self.specs
            .iter()
            .filter(|s| s.processor == processor)
            .collect()
    }

    /// Get the number of loaded language specs.
    pub fn len(&self) -> usize {
        self.specs.len()
    }

    /// Returns true if no language specs have been loaded.
    pub fn is_empty(&self) -> bool {
        self.specs.is_empty()
    }
}

/// Parse a single `<language>` element into a `LanguageSpec`.
fn parse_language_element(elem: &XmlElement, path: &Path) -> Result<LanguageSpec, LanguageSpecError> {
    let _id_str = elem.require_attr("id", path)?;
    let processor_name = elem.require_attr("processor", path)?;
    let endian_str = elem.require_attr("endian", path)?;
    let size_str = elem.require_attr("size", path)?;
    let variant = elem.require_attr("variant", path)?;
    let version_str = elem.require_attr("version", path)?;
    let deprecated = elem.attr_bool("deprecated");
    let hidden = elem.attr_bool("hidden");
    let sla_file = elem.attr("slafile").unwrap_or("").to_string();
    let processor_spec = elem.attr("processorspec").unwrap_or("").to_string();
    let manual_index = elem.attr("manualindexfile").map(|s| s.to_string());

    let endian = Endian::parse(endian_str).ok_or_else(|| LanguageSpecError::InvalidValue {
        path: path.to_path_buf(),
        attribute: "endian".to_string(),
        value: endian_str.to_string(),
        reason: "expected LE or BE".to_string(),
    })?;

    let instruction_endian_str = elem.attr("instructionEndian").unwrap_or(endian_str);
    let instruction_endian =
        Endian::parse(instruction_endian_str).unwrap_or(endian);

    let size: usize = size_str.parse().map_err(|_| LanguageSpecError::InvalidValue {
        path: path.to_path_buf(),
        attribute: "size".to_string(),
        value: size_str.to_string(),
        reason: "expected integer".to_string(),
    })?;

    // Parse version as "major.minor"
    let version_parts: Vec<&str> = version_str.split('.').collect();
    let version: u32 = version_parts
        .first()
        .and_then(|s| s.parse().ok())
        .unwrap_or(1);
    let minor_version: u32 = version_parts
        .get(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    let spec_id = LanguageSpecID::new(processor_name, endian, size, variant);

    let description = elem
        .children
        .iter()
        .find(|c| c.name == "description")
        .map(|c| c.text.clone())
        .unwrap_or_default();

    // Parse compiler specs
    let mut compiler_specs = Vec::new();
    for child in &elem.children {
        if child.name == "compiler" {
            let cs_id = child.attr("id").unwrap_or("default");
            let cs_name = child.attr("name").unwrap_or(cs_id);
            let cs_spec = child.attr("spec").unwrap_or("");
            compiler_specs.push(CompilerSpecDescription::new(
                CompilerSpecID::new(cs_id),
                cs_name,
                cs_spec,
            ));
        }
    }

    // Parse external names
    let mut external_names = HashMap::new();
    for child in &elem.children {
        if child.name == "external_name" {
            if let (Some(tool), Some(name)) = (child.attr("tool"), child.attr("name")) {
                if !tool.is_empty() && !name.is_empty() {
                    external_names
                        .entry(tool.to_string())
                        .or_insert_with(Vec::new)
                        .push(name.to_string());
                }
            }
        }
    }

    // Parse truncation rules
    let mut truncate_spaces = Vec::new();
    for child in &elem.children {
        if child.name == "truncate_space" {
            if let (Some(space), Some(size_str)) = (child.attr("space"), child.attr("size")) {
                if let Ok(size) = size_str.parse::<usize>() {
                    truncate_spaces.push(super::language_spec::TruncateSpace {
                        space: space.to_string(),
                        size,
                    });
                }
            }
        }
    }

    let mut spec = LanguageSpec::new(spec_id, description, version, minor_version, sla_file, processor_spec);
    spec.instruction_endian = instruction_endian;
    spec.deprecated = deprecated;
    spec.hidden = hidden;
    spec.manual_index_file = manual_index;
    spec.compiler_specs = compiler_specs;
    spec.external_names = external_names;
    spec.truncate_spaces = truncate_spaces;

    Ok(spec)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_LDEFS: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<language_definitions>
  <language id="x86:LE:64:default" processor="x86" endian="LE" size="64"
            variant="default" version="1.0" deprecated="false"
            slafile="x86.sla" processorspec="x86.pspec">
    <description>x86 64-bit little-endian</description>
    <compiler id="default" name="default" spec="default.cspec"/>
    <compiler id="windows" name="windows" spec="windows.cspec"/>
    <external_name tool="IDA-PRO" name="metapc"/>
  </language>
  <language id="ARM:LE:32:v7" processor="ARM" endian="LE" size="32"
            variant="v7" version="1.0" deprecated="false"
            slafile="arm.sla" processorspec="arm.pspec">
    <description>ARM 32-bit little-endian v7</description>
    <compiler id="default" name="default" spec="default.cspec"/>
    <truncate_space space="register" size="4"/>
  </language>
  <language id="MIPS:BE:32:default" processor="MIPS" endian="BE" size="32"
            variant="default" version="2.1" deprecated="true"
            slafile="mips.sla" processorspec="mips.pspec">
    <description>MIPS 32-bit big-endian (deprecated)</description>
    <compiler id="default" name="default" spec="default.cspec"/>
  </language>
</language_definitions>"#;

    #[test]
    fn test_factory_new() {
        let factory = LanguageSpecFactory::new();
        assert!(factory.is_empty());
        assert_eq!(factory.len(), 0);
        assert!(!factory.had_failures());
    }

    #[test]
    fn test_factory_load_from_str() {
        let mut factory = LanguageSpecFactory::new();
        let count = factory
            .load_from_str(SAMPLE_LDEFS, Path::new("test.ldefs"))
            .unwrap();
        assert_eq!(count, 3);
        assert_eq!(factory.len(), 3);
        assert!(!factory.had_failures());
    }

    #[test]
    fn test_factory_x86_spec() {
        let mut factory = LanguageSpecFactory::new();
        factory
            .load_from_str(SAMPLE_LDEFS, Path::new("test.ldefs"))
            .unwrap();
        let spec = factory.find_by_id("x86:LE:64:default").unwrap();
        assert_eq!(spec.id.processor, "x86");
        assert_eq!(spec.id.endian, Endian::Little);
        assert_eq!(spec.id.size, 64);
        assert_eq!(spec.id.variant, "default");
        assert_eq!(spec.description, "x86 64-bit little-endian");
        assert_eq!(spec.sla_file, "x86.sla");
        assert_eq!(spec.processor_spec, "x86.pspec");
        assert!(!spec.deprecated);
        assert_eq!(spec.compiler_specs.len(), 2);
        assert_eq!(spec.compiler_specs[0].id.0, "default");
        assert_eq!(spec.compiler_specs[1].id.0, "windows");
    }

    #[test]
    fn test_factory_arm_spec() {
        let mut factory = LanguageSpecFactory::new();
        factory
            .load_from_str(SAMPLE_LDEFS, Path::new("test.ldefs"))
            .unwrap();
        let spec = factory.find_by_id("ARM:LE:32:v7").unwrap();
        assert_eq!(spec.id.processor, "ARM");
        assert_eq!(spec.description, "ARM 32-bit little-endian v7");
        assert_eq!(spec.truncate_spaces.len(), 1);
        assert_eq!(spec.truncate_spaces[0].space, "register");
        assert_eq!(spec.truncate_spaces[0].size, 4);
    }

    #[test]
    fn test_factory_mips_deprecated() {
        let mut factory = LanguageSpecFactory::new();
        factory
            .load_from_str(SAMPLE_LDEFS, Path::new("test.ldefs"))
            .unwrap();
        let spec = factory.find_by_id("MIPS:BE:32:default").unwrap();
        assert!(spec.deprecated);
        assert_eq!(spec.version, 2);
        assert_eq!(spec.minor_version, 1);
    }

    #[test]
    fn test_factory_find_by_processor() {
        let mut factory = LanguageSpecFactory::new();
        factory
            .load_from_str(SAMPLE_LDEFS, Path::new("test.ldefs"))
            .unwrap();
        let x86_specs = factory.find_by_processor("x86");
        assert_eq!(x86_specs.len(), 1);
        let arm_specs = factory.find_by_processor("ARM");
        assert_eq!(arm_specs.len(), 1);
        let missing = factory.find_by_processor("RISC-V");
        assert!(missing.is_empty());
    }

    #[test]
    fn test_factory_find_by_id_not_found() {
        let mut factory = LanguageSpecFactory::new();
        factory
            .load_from_str(SAMPLE_LDEFS, Path::new("test.ldefs"))
            .unwrap();
        assert!(factory.find_by_id("nonexistent:LE:64:default").is_none());
    }

    #[test]
    fn test_factory_into_language_specs() {
        let mut factory = LanguageSpecFactory::new();
        factory
            .load_from_str(SAMPLE_LDEFS, Path::new("test.ldefs"))
            .unwrap();
        let specs = factory.into_language_specs();
        assert_eq!(specs.len(), 3);
    }

    #[test]
    fn test_factory_external_names() {
        let mut factory = LanguageSpecFactory::new();
        factory
            .load_from_str(SAMPLE_LDEFS, Path::new("test.ldefs"))
            .unwrap();
        let spec = factory.find_by_id("x86:LE:64:default").unwrap();
        let ida = spec.get_external_names("IDA-PRO").unwrap();
        assert_eq!(ida, &vec!["metapc".to_string()]);
    }

    #[test]
    fn test_factory_empty_file() {
        let mut factory = LanguageSpecFactory::new();
        // An empty/invalid XML should produce an error
        let result = factory.load_from_str("", Path::new("empty.ldefs"));
        assert!(result.is_err());
    }

    #[test]
    fn test_xml_element_attr() {
        let elem = XmlElement {
            name: "test".to_string(),
            attributes: {
                let mut m = HashMap::new();
                m.insert("key".to_string(), "value".to_string());
                m
            },
            children: Vec::new(),
            text: String::new(),
        };
        assert_eq!(elem.attr("key"), Some("value"));
        assert_eq!(elem.attr("missing"), None);
        assert_eq!(elem.require_attr("key", Path::new("test.xml")).unwrap(), "value");
        assert!(elem.require_attr("missing", Path::new("test.xml")).is_err());
    }

    #[test]
    fn test_xml_element_attr_bool() {
        let elem_true = XmlElement {
            name: "t".to_string(),
            attributes: {
                let mut m = HashMap::new();
                m.insert("flag".to_string(), "true".to_string());
                m
            },
            children: Vec::new(),
            text: String::new(),
        };
        assert!(elem_true.attr_bool("flag"));

        let elem_false = XmlElement {
            name: "t".to_string(),
            attributes: HashMap::new(),
            children: Vec::new(),
            text: String::new(),
        };
        assert!(!elem_false.attr_bool("flag"));
    }

    #[test]
    fn test_language_spec_error_display() {
        let err = LanguageSpecError::MissingAttribute {
            path: PathBuf::from("test.ldefs"),
            element: "language".to_string(),
            attribute: "id".to_string(),
        };
        let s = format!("{}", err);
        assert!(s.contains("Missing attribute"));
        assert!(s.contains("id"));
    }

    #[test]
    fn test_version_parsing() {
        let xml = r#"<?xml version="1.0"?>
<language_definitions>
  <language id="TEST:LE:32:default" processor="TEST" endian="LE" size="32"
            variant="default" version="3.5" slafile="t.sla" processorspec="t.pspec">
    <description>Test</description>
    <compiler id="default" name="default" spec="d.cspec"/>
  </language>
</language_definitions>"#;

        let mut factory = LanguageSpecFactory::new();
        factory.load_from_str(xml, Path::new("test.ldefs")).unwrap();
        let spec = factory.find_by_id("TEST:LE:32:default").unwrap();
        assert_eq!(spec.version, 3);
        assert_eq!(spec.minor_version, 5);
        assert_eq!(spec.version_string(), "3.5");
    }

    #[test]
    fn test_hidden_language() {
        let xml = r#"<?xml version="1.0"?>
<language_definitions>
  <language id="HIDDEN:LE:64:def" processor="HIDDEN" endian="LE" size="64"
            variant="def" version="1" hidden="true" slafile="h.sla" processorspec="h.pspec">
    <description>Hidden Language</description>
    <compiler id="default" name="default" spec="d.cspec"/>
  </language>
</language_definitions>"#;

        let mut factory = LanguageSpecFactory::new();
        factory.load_from_str(xml, Path::new("test.ldefs")).unwrap();
        let spec = factory.find_by_id("HIDDEN:LE:64:def").unwrap();
        assert!(spec.hidden);
    }
}
