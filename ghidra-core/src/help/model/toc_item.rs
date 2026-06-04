// Port of help.validator.model.TOCItem, TOCItemDefinition, TOCItemExternal, TOCItemReference

use std::collections::HashSet;
use std::path::PathBuf;

use crate::help::validator::LinkDatabase;

/// Indentation levels for TOC XML output.
const INDENTS: [&str; 9] = [
    "",
    "\t",
    "\t\t",
    "\t\t\t",
    "\t\t\t\t",
    "\t\t\t\t\t",
    "\t\t\t\t\t\t",
    "\t\t\t\t\t\t\t",
    "\t\t\t\t\t\t\t\t",
];

const TOC_TAG_NAME: &str = "tocitem";
const TOC_ITEM_CLOSE_TAG: &str = "</tocitem>";

/// Table of Contents item types.
#[derive(Debug, Clone)]
pub enum TocItem {
    /// A `<tocdef>` tag -- defines a TOC item entry.
    Definition(TocItemDefinition),
    /// A `<tocref>` tag -- references a TOC item defined elsewhere.
    Reference(TocItemReference),
    /// An external TOC item from a pre-built help module.
    External(TocItemExternal),
}

impl TocItem {
    pub fn id_attribute(&self) -> &str {
        match self {
            TocItem::Definition(d) => &d.id,
            TocItem::Reference(r) => &r.id,
            TocItem::External(e) => &e.id,
        }
    }

    pub fn text_attribute(&self) -> Option<&str> {
        match self {
            TocItem::Definition(d) => d.text.as_deref(),
            TocItem::Reference(_) => None,
            TocItem::External(e) => e.text.as_deref(),
        }
    }

    pub fn target_attribute(&self) -> Option<&str> {
        match self {
            TocItem::Definition(d) => d.target.as_deref(),
            TocItem::Reference(_) => None,
            TocItem::External(e) => e.target.as_deref(),
        }
    }

    pub fn sort_preference(&self) -> &str {
        match self {
            TocItem::Definition(d) => &d.sort_preference,
            TocItem::Reference(r) => &r.sort_preference,
            TocItem::External(e) => &e.sort_preference,
        }
    }

    pub fn source_file(&self) -> &PathBuf {
        match self {
            TocItem::Definition(d) => &d.source_file,
            TocItem::Reference(r) => &r.source_file,
            TocItem::External(e) => &e.source_file,
        }
    }

    pub fn line_number(&self) -> usize {
        match self {
            TocItem::Definition(d) => d.line_number,
            TocItem::Reference(r) => r.line_number,
            TocItem::External(e) => e.line_number,
        }
    }

    pub fn children(&self) -> &HashSet<usize> {
        match self {
            TocItem::Definition(d) => &d.children,
            TocItem::Reference(r) => &r.children,
            TocItem::External(e) => &e.children,
        }
    }

    /// Validate this TOC item against the link database.
    pub fn validate(&self, link_database: &LinkDatabase) -> bool {
        match self {
            TocItem::Definition(d) => d.validate(link_database),
            TocItem::Reference(r) => r.validate(link_database),
            TocItem::External(e) => e.validate(link_database),
        }
    }

    /// Generate the TOC item XML tag for output.
    pub fn generate_toc_item_tag(
        &self,
        link_database: &LinkDatabase,
        is_inline_tag: bool,
        indent_level: usize,
    ) -> String {
        match self {
            TocItem::Definition(d) => d.generate_toc_item_tag(link_database, is_inline_tag, indent_level),
            TocItem::Reference(r) => r.generate_toc_item_tag(indent_level),
            TocItem::External(e) => e.generate_toc_item_tag(is_inline_tag, indent_level),
        }
    }

    /// Write this TOC item and its children to a string buffer.
    pub fn write_contents(&self, link_database: &LinkDatabase, indent_level: usize) -> String {
        let children = self.children();
        if children.is_empty() {
            format!(
                "{}{}\n",
                get_indent(indent_level),
                self.generate_toc_item_tag(link_database, true, indent_level)
            )
        } else {
            let mut result = format!(
                "{}{}\n",
                get_indent(indent_level),
                self.generate_toc_item_tag(link_database, false, indent_level)
            );
            // Note: children are referenced by index in the items list.
            // The caller is responsible for resolving children indices.
            result.push_str(&format!("{}{}\n", get_indent(indent_level), TOC_ITEM_CLOSE_TAG));
            result
        }
    }
}

impl PartialEq for TocItem {
    fn eq(&self, other: &Self) -> bool {
        self.id_attribute() == other.id_attribute()
            && self.sort_preference() == other.sort_preference()
            && self.source_file() == other.source_file()
            && self.target_attribute() == other.target_attribute()
            && self.text_attribute() == other.text_attribute()
    }
}

impl Eq for TocItem {}

impl std::hash::Hash for TocItem {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.id_attribute().hash(state);
    }
}

// ---------------------------------------------------------------------------
// TocItemDefinition
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct TocItemDefinition {
    pub id: String,
    pub text: Option<String>,
    pub target: Option<String>,
    pub sort_preference: String,
    pub source_file: PathBuf,
    pub line_number: usize,
    pub children: HashSet<usize>,
}

impl TocItemDefinition {
    pub fn new(
        source_file: PathBuf,
        id: String,
        text: Option<String>,
        target: Option<String>,
        sort_preference: Option<String>,
        line_number: usize,
    ) -> Self {
        let sort_pref = match sort_preference {
            Some(ref s) => s.to_lowercase(),
            None => text.as_deref().unwrap_or("").to_lowercase(),
        };

        TocItemDefinition {
            id,
            text,
            target,
            sort_preference: sort_pref,
            source_file,
            line_number,
            children: HashSet::new(),
        }
    }

    fn validate(&self, link_database: &LinkDatabase) -> bool {
        if let Some(ref target) = self.target {
            link_database.get_id_for_link(target).is_some()
        } else {
            true // no target to validate
        }
    }

    fn generate_toc_item_tag(
        &self,
        link_database: &LinkDatabase,
        is_inline_tag: bool,
        indent_level: usize,
    ) -> String {
        generate_toc_tag(
            &self.sort_preference,
            self.target.as_deref(),
            self.text.as_deref().unwrap_or(""),
            &self.id,
            link_database,
            is_inline_tag,
            indent_level,
        )
    }
}

impl std::fmt::Display for TocItemDefinition {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "<tocdef id=\"{}\" text=\"{}\" sortgroup=\"{}\" target=\"{}\" />\n\t\t[source file=\"{}\" (line:{})]",
            self.id,
            self.text.as_deref().unwrap_or(""),
            self.sort_preference,
            self.target.as_deref().unwrap_or(""),
            self.source_file.display(),
            self.line_number,
        )
    }
}

// ---------------------------------------------------------------------------
// TocItemExternal
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct TocItemExternal {
    pub id: String,
    pub text: Option<String>,
    pub target: Option<String>,
    pub sort_preference: String,
    pub source_file: PathBuf,
    pub line_number: usize,
    pub children: HashSet<usize>,
}

impl TocItemExternal {
    pub fn new(
        source_file: PathBuf,
        id: String,
        text: Option<String>,
        target: Option<String>,
        sort_preference: Option<String>,
        line_number: usize,
    ) -> Self {
        let sort_pref = match sort_preference {
            Some(ref s) => s.to_lowercase(),
            None => text.as_deref().unwrap_or("").to_lowercase(),
        };

        TocItemExternal {
            id,
            text,
            target,
            sort_preference: sort_pref,
            source_file,
            line_number,
            children: HashSet::new(),
        }
    }

    fn validate(&self, link_database: &LinkDatabase) -> bool {
        if let Some(ref target) = self.target {
            link_database.get_id_for_link(target).is_some()
        } else {
            true
        }
    }

    fn generate_toc_item_tag(
        &self,
        is_inline_tag: bool,
        indent_level: usize,
    ) -> String {
        let mut tag = format!("{}<{}", get_indent(indent_level), TOC_TAG_NAME);
        tag.push_str(&format!(" text=\"{}\"", self.sort_preference));
        if let Some(ref target) = self.target {
            tag.push_str(&format!(" target=\"{}\"", target));
        }
        tag.push_str(" mergetype=\"javax.help.SortMerge\"");
        tag.push_str(&format!(
            " display=\"{}\"",
            self.text.as_deref().unwrap_or("")
        ));
        tag.push_str(&format!(" toc_id=\"{}\"", self.id));
        if is_inline_tag {
            tag.push_str(" />");
        } else {
            tag.push('>');
        }
        tag
    }
}

impl std::fmt::Display for TocItemExternal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "<tocitem id=\"{}\" sort=\"{}\" text=\"{}\" target=\"{}\" />\n\tTOC file=\"{}\n",
            self.id,
            self.sort_preference,
            self.text.as_deref().unwrap_or(""),
            self.target.as_deref().unwrap_or(""),
            self.source_file.display(),
        )
    }
}

// ---------------------------------------------------------------------------
// TocItemReference
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct TocItemReference {
    pub id: String,
    pub sort_preference: String,
    pub source_file: PathBuf,
    pub line_number: usize,
    pub children: HashSet<usize>,
}

impl TocItemReference {
    pub fn new(source_file: PathBuf, id: String, line_number: usize) -> Self {
        TocItemReference {
            id,
            sort_preference: String::new(),
            source_file,
            line_number,
            children: HashSet::new(),
        }
    }

    fn validate(&self, link_database: &LinkDatabase) -> bool {
        // Check if this reference resolves to a definition or external
        link_database.get_toc_definition_for_id(&self.id).is_some()
            || link_database.get_toc_external_for_id(&self.id).is_some()
    }

    fn generate_toc_item_tag(&self, indent_level: usize) -> String {
        format!(
            "{}<!-- WARNING: Unresolved reference ID\n{}\t<tocref id=\"{}\"/>\n{}-->",
            get_indent(indent_level),
            get_indent(indent_level),
            self.id,
            get_indent(indent_level),
        )
    }
}

impl std::fmt::Display for TocItemReference {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "<tocref id=\"{}\"/>\n\t[source file=\"{}\" (line:{})]",
            self.id,
            self.source_file.display(),
            self.line_number,
        )
    }
}

impl PartialEq for TocItemReference {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
            && self.sort_preference == other.sort_preference
            && self.source_file == other.source_file
    }
}

impl Eq for TocItemReference {}

impl PartialOrd for TocItemReference {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for TocItemReference {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.source_file
            .cmp(&other.source_file)
            .then_with(|| self.id.cmp(&other.id))
    }
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

fn get_indent(level: usize) -> &'static str {
    if level < INDENTS.len() {
        INDENTS[level]
    } else {
        "\t\t\t\t\t\t\t\t\t" // fallback
    }
}

/// Generate the common `<tocitem ...>` tag.
fn generate_toc_tag(
    sort_preference: &str,
    target: Option<&str>,
    text: &str,
    id: &str,
    link_database: &LinkDatabase,
    is_inline_tag: bool,
    indent_level: usize,
) -> String {
    let mut tag = format!("{}<{}", get_indent(indent_level), TOC_TAG_NAME);

    // text attribute is used for sorting, not display
    tag.push_str(&format!(" text=\"{}\"", sort_preference));

    // target attribute
    if let Some(t) = target {
        let resolved_id = link_database.get_id_for_link(t).unwrap_or_else(|| t.to_string());
        tag.push_str(&format!(" target=\"{}\"", resolved_id));
    }

    tag.push_str(" mergetype=\"javax.help.SortMerge\"");

    // custom display text attribute
    tag.push_str(&format!(" display=\"{}\"", text));

    // custom toc id attribute
    tag.push_str(&format!(" toc_id=\"{}\"", id));

    if is_inline_tag {
        tag.push_str(" />");
    } else {
        tag.push('>');
    }

    tag
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_toc_item_definition_basic() {
        let def = TocItemDefinition::new(
            PathBuf::from("/src/TOC_Source.xml"),
            "my_id".to_string(),
            Some("My Text".to_string()),
            Some("help/topics/MyTopic/page.html".to_string()),
            None,
            10,
        );
        let item = TocItem::Definition(def);
        assert_eq!(item.id_attribute(), "my_id");
        assert_eq!(item.text_attribute(), Some("My Text"));
        assert_eq!(
            item.target_attribute(),
            Some("help/topics/MyTopic/page.html")
        );
        assert_eq!(item.sort_preference(), "my text");
        assert_eq!(item.line_number(), 10);
    }

    #[test]
    fn test_toc_item_reference() {
        let reference = TocItemReference::new(
            PathBuf::from("/src/TOC_Source.xml"),
            "ref_id".to_string(),
            5,
        );
        let item = TocItem::Reference(reference);
        assert_eq!(item.id_attribute(), "ref_id");
        assert_eq!(item.text_attribute(), None);
        assert_eq!(item.target_attribute(), None);
    }

    #[test]
    fn test_toc_item_external() {
        let ext = TocItemExternal::new(
            PathBuf::from("/prebuilt/TOC.xml"),
            "ext_id".to_string(),
            Some("External Item".to_string()),
            Some("help/topics/Ext/page.html".to_string()),
            Some("custom_sort".to_string()),
            0,
        );
        let item = TocItem::External(ext);
        assert_eq!(item.id_attribute(), "ext_id");
        assert_eq!(item.sort_preference(), "custom_sort");
    }

    #[test]
    fn test_toc_item_sort_preference_default_from_text() {
        let def = TocItemDefinition::new(
            PathBuf::from("/src/TOC_Source.xml"),
            "id1".to_string(),
            Some("Hello World".to_string()),
            None,
            None,
            1,
        );
        let item = TocItem::Definition(def);
        assert_eq!(item.sort_preference(), "hello world");
    }

    #[test]
    fn test_toc_item_equality() {
        let d1 = TocItem::Definition(TocItemDefinition::new(
            PathBuf::from("/a.xml"),
            "x".to_string(),
            Some("t".to_string()),
            None,
            None,
            1,
        ));
        let d2 = TocItem::Definition(TocItemDefinition::new(
            PathBuf::from("/a.xml"),
            "x".to_string(),
            Some("t".to_string()),
            None,
            None,
            1,
        ));
        assert_eq!(d1, d2);
    }
}
