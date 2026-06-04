// Port of help.validator.model.AnchorDefinition

use std::path::{Path, PathBuf};

use super::{get_help_topic_dir, relativize_with_help_topics};

/// A help location that can be a file or a file with an anchor inside.
///
/// Generates target information for TOC files and link information for help map files.
/// The generated ID is of the form: `TopicName_anchorName` or `TopicName_Filename`.
#[derive(Debug, Clone)]
pub struct AnchorDefinition {
    source_file: PathBuf,
    help_relative_path: Option<PathBuf>,
    anchor_name: Option<String>,
    line_num: i32,
    id: String,
}

impl AnchorDefinition {
    pub fn new(file: &Path, anchor_name: Option<&str>, line_num: i32) -> Self {
        let prefix = get_anchor_definition_prefix(file);
        let anchor = match anchor_name {
            Some(name) => name.to_string(),
            None => get_default_anchor(file),
        };

        let raw_id = format!("{}_{}", prefix, anchor);
        let id = raw_id
            .replace(' ', "_")
            .replace('-', "_")
            .replace('.', "_");

        let help_relative_path = relativize_with_help_topics(file);

        AnchorDefinition {
            source_file: file.to_path_buf(),
            help_relative_path,
            anchor_name: anchor_name.map(|s| s.to_string()),
            line_num,
            id,
        }
    }

    /// The anchor name, or None for file-level anchors.
    pub fn anchor_name(&self) -> Option<&str> {
        self.anchor_name.as_deref()
    }

    /// The source file containing this anchor.
    pub fn src_file(&self) -> &Path {
        &self.source_file
    }

    /// The generated unique ID for this anchor.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// The line number in the source file, or -1 for file-level anchors.
    pub fn line_number(&self) -> i32 {
        self.line_num
    }

    /// Returns the help path relative to `help/topics`, including anchor if present.
    pub fn help_path(&self) -> String {
        let base = self
            .help_relative_path
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_default();
        if let Some(ref anchor) = self.anchor_name {
            format!("{}#{}", base, anchor)
        } else {
            base
        }
    }
}

impl std::fmt::Display for AnchorDefinition {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.line_num < 0 {
            write!(
                f,
                "Anchor Definition: {} (File ID) in {}",
                self.id,
                self.source_file.display()
            )
        } else {
            write!(
                f,
                "<a name=\"{}\"> (line {}) in {}",
                self.anchor_name.as_deref().unwrap_or(""),
                self.line_num,
                self.source_file.display()
            )
        }
    }
}

impl PartialEq for AnchorDefinition {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Eq for AnchorDefinition {}

impl std::hash::Hash for AnchorDefinition {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.id.hash(state);
    }
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

fn get_anchor_definition_prefix(anchor_source_file: &Path) -> String {
    match get_help_topic_dir(anchor_source_file) {
        Some(topic_dir) => topic_dir
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "Unknown".to_string()),
        None => "Unknown".to_string(),
    }
}

fn get_default_anchor(file: &Path) -> String {
    let filename = file
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();
    let lower = filename.to_lowercase();
    if let Some(pos) = lower.find(".htm") {
        filename[..pos].to_string()
    } else {
        filename
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_anchor_definition_with_name() {
        let file = PathBuf::from("/repo/help/help/topics/MyTopic/page.html");
        let anchor = AnchorDefinition::new(&file, Some("section1"), 42);
        assert_eq!(anchor.anchor_name(), Some("section1"));
        assert_eq!(anchor.line_number(), 42);
        assert!(anchor.id().contains("MyTopic"));
        assert!(anchor.id().contains("section1"));
        assert!(anchor.help_path().contains("#section1"));
    }

    #[test]
    fn test_anchor_definition_file_level() {
        let file = PathBuf::from("/repo/help/help/topics/MyTopic/index.html");
        let anchor = AnchorDefinition::new(&file, None, -1);
        assert_eq!(anchor.anchor_name(), None);
        assert_eq!(anchor.line_number(), -1);
        assert!(anchor.id().contains("MyTopic"));
        assert!(anchor.id().contains("index"));
    }

    #[test]
    fn test_anchor_id_sanitization() {
        let file = PathBuf::from("/repo/help/help/topics/My-Topic/my file.html");
        let anchor = AnchorDefinition::new(&file, None, -1);
        // Spaces, dashes, dots should be replaced with underscores
        assert!(!anchor.id().contains(' '));
        assert!(!anchor.id().contains('-'));
        assert!(!anchor.id().contains('.'));
    }

    #[test]
    fn test_default_anchor_strips_html_extension() {
        let file = PathBuf::from("/repo/help/help/topics/MyTopic/page.html");
        let anchor = AnchorDefinition::new(&file, None, -1);
        assert!(anchor.id().contains("page"));
        assert!(!anchor.id().ends_with("html"));
    }
}
