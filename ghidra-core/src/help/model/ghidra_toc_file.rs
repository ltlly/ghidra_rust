// Port of help.validator.model.GhidraTOCFile

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use super::toc_item::{TocItem, TocItemDefinition, TocItemReference};

/// Represents a parsed `TOC_Source.xml` file that defines the Table of Contents structure.
///
/// The XML format uses `<tocdef>` tags for definitions and `<tocref>` tags for references.
#[derive(Debug)]
pub struct GhidraTocFile {
    source_toc_file: PathBuf,
    definitions_by_id: HashMap<String, TocItemDefinition>,
    references: Vec<TocItemReference>,
    all_items: Vec<TocItem>,
}

impl GhidraTocFile {
    /// Create a new GhidraTOCFile by parsing the given XML file.
    pub fn new(source_toc_file: PathBuf) -> Result<Self, String> {
        let mut file = GhidraTocFile {
            source_toc_file: source_toc_file.clone(),
            definitions_by_id: HashMap::new(),
            references: Vec::new(),
            all_items: Vec::new(),
        };

        file.parse_toc_file()?;
        Ok(file)
    }

    /// Create an empty GhidraTocFile (used when no TOC source exists).
    pub fn empty(source_toc_file: PathBuf) -> Self {
        GhidraTocFile {
            source_toc_file,
            definitions_by_id: HashMap::new(),
            references: Vec::new(),
            all_items: Vec::new(),
        }
    }

    /// Get the source TOC file path.
    pub fn get_file(&self) -> &Path {
        &self.source_toc_file
    }

    /// Get all TOC definitions mapped by ID.
    pub fn get_toc_definition_by_id_mapping(&self) -> &HashMap<String, TocItemDefinition> {
        &self.definitions_by_id
    }

    /// Get all TOC references.
    pub fn get_toc_references(&self) -> &[TocItemReference] {
        &self.references
    }

    /// Get all TOC definitions.
    pub fn get_toc_definitions(&self) -> Vec<&TocItemDefinition> {
        self.definitions_by_id.values().collect()
    }

    /// Get all TOC items (both definitions and references).
    pub fn get_all_toc_items(&self) -> &[TocItem] {
        &self.all_items
    }

    fn parse_toc_file(&mut self) -> Result<(), String> {
        let content = std::fs::read_to_string(&self.source_toc_file)
            .map_err(|e| format!("Failed to read TOC file: {}", e))?;

        // Simple XML parser for the TOC format
        // Expected format:
        //   <tocroot>
        //     <tocdef id="..." text="..." target="..." sortgroup="..." />
        //     <tocref id="..." />
        //   </tocroot>

        let mut line_number = 0;
        let source = self.source_toc_file.clone();

        for line in content.lines() {
            line_number += 1;
            let trimmed = line.trim();

            if trimmed.starts_with("<tocdef") || trimmed.starts_with("<tocDEF") {
                if let Some(item) = parse_tocdef_element(trimmed, &source, line_number) {
                    let def = match item {
                        TocItem::Definition(d) => d,
                        _ => unreachable!(),
                    };
                    self.definitions_by_id
                        .insert(def.id.clone(), def.clone());
                    self.all_items.push(TocItem::Definition(def));
                }
            } else if trimmed.starts_with("<tocref") || trimmed.starts_with("<tocREF") {
                if let Some(item) = parse_tocref_element(trimmed, &source, line_number) {
                    let reference = match item {
                        TocItem::Reference(r) => r,
                        _ => unreachable!(),
                    };
                    self.references.push(reference.clone());
                    self.all_items.push(TocItem::Reference(reference));
                }
            }
        }

        Ok(())
    }
}

impl std::fmt::Display for GhidraTocFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.source_toc_file.display())
    }
}

// ---------------------------------------------------------------------------
// XML parsing helpers
// ---------------------------------------------------------------------------

use regex::Regex;
use std::sync::LazyLock;

static ATTR_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(\w+)\s*=\s*"([^"]*)""#).unwrap()
});

fn parse_attributes(tag_text: &str) -> HashMap<String, String> {
    let mut attrs = HashMap::new();
    for cap in ATTR_RE.captures_iter(tag_text) {
        attrs.insert(cap[1].to_lowercase(), cap[2].to_string());
    }
    attrs
}

fn parse_tocdef_element(
    tag_text: &str,
    source_file: &Path,
    line_number: usize,
) -> Option<TocItem> {
    let attrs = parse_attributes(tag_text);
    let id = attrs.get("id")?.clone();
    let text = attrs.get("text").cloned();
    let target = attrs.get("target").cloned();
    let sort_group = attrs.get("sortgroup").cloned();

    let def = TocItemDefinition::new(
        source_file.to_path_buf(),
        id,
        text,
        target,
        sort_group,
        line_number,
    );
    Some(TocItem::Definition(def))
}

fn parse_tocref_element(
    tag_text: &str,
    source_file: &Path,
    line_number: usize,
) -> Option<TocItem> {
    let attrs = parse_attributes(tag_text);
    let id = attrs.get("id")?.clone();

    let reference = TocItemReference::new(source_file.to_path_buf(), id, line_number);
    Some(TocItem::Reference(reference))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_parse_tocdef_element() {
        let tag = r#"<tocdef id="my_id" text="My Text" target="help/topics/Foo/page.html" sortgroup="custom" />"#;
        let source = PathBuf::from("/test/TOC_Source.xml");
        let item = parse_tocdef_element(tag, &source, 5);
        assert!(item.is_some());
        let item = item.unwrap();
        assert_eq!(item.id_attribute(), "my_id");
        assert_eq!(item.text_attribute(), Some("My Text"));
        assert_eq!(
            item.target_attribute(),
            Some("help/topics/Foo/page.html")
        );
        assert_eq!(item.sort_preference(), "custom");
    }

    #[test]
    fn test_parse_tocref_element() {
        let tag = r#"<tocref id="ref_id" />"#;
        let source = PathBuf::from("/test/TOC_Source.xml");
        let item = parse_tocref_element(tag, &source, 3);
        assert!(item.is_some());
        let item = item.unwrap();
        assert_eq!(item.id_attribute(), "ref_id");
    }

    #[test]
    fn test_ghidra_toc_file_parse() {
        let dir = tempfile::tempdir().unwrap();
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<tocroot>
<tocdef id="root" text="Root" />
<tocdef id="child1" text="Child 1" target="help/topics/Mod/page.html" />
<tocref id="external_ref" />
</tocroot>"#;
        let path = dir.path().join("TOC_Source.xml");
        let mut f = std::fs::File::create(&path).unwrap();
        write!(f, "{}", xml).unwrap();

        let toc = GhidraTocFile::new(path);
        assert!(toc.is_ok());
        let toc = toc.unwrap();
        assert_eq!(toc.get_toc_definitions().len(), 2);
        assert_eq!(toc.get_toc_references().len(), 1);
        assert_eq!(toc.get_all_toc_items().len(), 3);
    }

    #[test]
    fn test_ghidra_toc_file_empty() {
        let toc = GhidraTocFile::empty(PathBuf::from("/empty/TOC_Source.xml"));
        assert!(toc.get_toc_definitions().is_empty());
        assert!(toc.get_toc_references().is_empty());
    }

    #[test]
    fn test_ghidra_toc_file_missing_file() {
        let toc = GhidraTocFile::new(PathBuf::from("/nonexistent/TOC_Source.xml"));
        assert!(toc.is_err());
    }
}
