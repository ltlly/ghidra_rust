// Port of help.validator.model.HelpFile

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use super::anchor_definition::AnchorDefinition;
use super::{relativize_with_help_topics, Href, Img};

use crate::help::PathKey;

/// Represents a single HTML help file and its parsed anchors, HREFs, and IMGs.
#[derive(Debug)]
pub struct HelpFile {
    help_file: PathBuf,
    relative_path: Option<PathBuf>,
    anchors_by_help_path: HashMap<PathKey, AnchorDefinition>,
    anchors_by_name: HashMap<String, AnchorDefinition>,
    anchors_by_id: HashMap<String, AnchorDefinition>,
    hrefs: Vec<Href>,
    imgs: Vec<Img>,
    duplicate_anchors_by_id: HashMap<String, Vec<AnchorDefinition>>,
}

impl HelpFile {
    /// Create a new HelpFile by parsing the given HTML file.
    pub fn new(help_file: PathBuf) -> Self {
        let relative_path = relativize_with_help_topics(&help_file);
        let mut hf = HelpFile {
            help_file,
            relative_path,
            anchors_by_help_path: HashMap::new(),
            anchors_by_name: HashMap::new(),
            anchors_by_id: HashMap::new(),
            hrefs: Vec::new(),
            imgs: Vec::new(),
            duplicate_anchors_by_id: HashMap::new(),
        };

        // Add the file-level anchor
        hf.add_anchor(&hf.help_file.clone(), None, -1);

        // Parse the HTML file
        hf.parse_links();
        hf
    }

    /// All HREFs found in this file.
    pub fn get_all_hrefs(&self) -> &[Href] {
        &self.hrefs
    }

    /// All IMGs found in this file.
    pub fn get_all_imgs(&self) -> &[Img] {
        &self.imgs
    }

    /// The relative path from `help/topics/`.
    pub fn get_relative_path(&self) -> Option<&Path> {
        self.relative_path.as_deref()
    }

    /// Check if this file contains a named anchor.
    pub fn contains_anchor(&self, anchor_name: &str) -> bool {
        self.anchors_by_name.contains_key(anchor_name)
    }

    /// Get duplicate anchor definitions grouped by ID.
    pub fn get_duplicate_anchors_by_id(&self) -> &HashMap<String, Vec<AnchorDefinition>> {
        &self.duplicate_anchors_by_id
    }

    /// Get the anchor definition for a given help path.
    pub fn get_anchor_definition(&self, help_path: &Path) -> Option<&AnchorDefinition> {
        let key = PathKey::from_path(help_path);
        self.anchors_by_help_path.get(&key)
    }

    /// Get all anchor definitions in this file.
    pub fn get_all_anchor_definitions(&self) -> Vec<&AnchorDefinition> {
        self.anchors_by_help_path.values().collect()
    }

    /// The absolute file path.
    pub fn get_file(&self) -> &Path {
        &self.help_file
    }

    /// Add an anchor definition for the given file and optional anchor name.
    pub fn add_anchor(&mut self, file: &Path, anchor_name: Option<&str>, line_num: i32) {
        let anchor = AnchorDefinition::new(file, anchor_name, line_num);
        let id = anchor.id().to_string();

        if self.anchors_by_id.contains_key(&id) {
            self.add_duplicate_anchor(anchor_name, anchor, &id);
            return;
        }

        self.anchors_by_id.insert(id, anchor.clone());
        let key = PathKey::from_string(&anchor.help_path());
        self.anchors_by_help_path.insert(key, anchor.clone());

        if let Some(name) = anchor_name {
            self.anchors_by_name.insert(name.to_string(), anchor);
        }
    }

    fn add_duplicate_anchor(
        &mut self,
        anchor_name: Option<&str>,
        anchor: AnchorDefinition,
        id: &str,
    ) {
        let list = self
            .duplicate_anchors_by_id
            .entry(id.to_string())
            .or_insert_with(|| {
                // First time we see a duplicate: add the original
                let mut v = Vec::new();
                if let Some(orig) = self.anchors_by_id.get(id) {
                    v.push(orig.clone());
                }
                v
            });
        list.push(anchor.clone());

        // Make sure at least one named anchor makes it into the maps
        if let Some(name) = anchor_name {
            if !self.anchors_by_name.contains_key(name) {
                self.anchors_by_name.insert(name.to_string(), anchor.clone());
                let key = PathKey::from_string(&anchor.help_path());
                self.anchors_by_help_path.insert(key, anchor);
            }
        }
    }

    /// Add an HREF reference found during parsing.
    pub fn add_href(&mut self, href: Href) {
        self.hrefs.push(href);
    }

    /// Add an IMG reference found during parsing.
    pub fn add_img(&mut self, img: Img) {
        self.imgs.push(img);
    }

    // Simple HTML parsing to extract anchors, hrefs, and imgs
    fn parse_links(&mut self) {
        let content = match std::fs::read_to_string(&self.help_file) {
            Ok(c) => c,
            Err(_) => return, // file not readable
        };

        let file = self.help_file.clone();
        let fname = file
            .file_name()
            .map(|n| n.to_string_lossy().to_lowercase())
            .unwrap_or_default();

        if !fname.ends_with(".htm") && !fname.ends_with(".html") {
            return;
        }

        for (line_num, line) in content.lines().enumerate() {
            let _line_lower = line.to_lowercase();

            // Parse <a name="..."> tags for anchor definitions
            parse_anchors(&file, line, line_num, &mut self.anchors_by_help_path, &mut self.anchors_by_name, &mut self.anchors_by_id);

            // Parse <a href="..."> tags for HREFs
            for href in parse_hrefs_from_line(&file, line, line_num + 1) {
                self.hrefs.push(href);
            }

            // Parse <img src="..."> tags for IMGs
            for img in parse_imgs_from_line(&file, line, line_num + 1) {
                self.imgs.push(img);
            }
        }
    }
}

impl std::fmt::Display for HelpFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.help_file.display())
    }
}

// ---------------------------------------------------------------------------
// HTML parsing helpers
// ---------------------------------------------------------------------------

use regex::Regex;
use std::sync::LazyLock;

static A_NAME_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)<a\s+[^>]*name\s*=\s*"([^"]+)""#).unwrap()
});

static A_HREF_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)<a\s+[^>]*href\s*=\s*"([^"]+)""#).unwrap()
});

static IMG_SRC_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)<img\s+[^>]*src\s*=\s*"([^"]+)""#).unwrap()
});

fn parse_anchors(
    file: &Path,
    line: &str,
    line_num: usize,
    by_help_path: &mut HashMap<PathKey, AnchorDefinition>,
    by_name: &mut HashMap<String, AnchorDefinition>,
    by_id: &mut HashMap<String, AnchorDefinition>,
) {
    for cap in A_NAME_RE.captures_iter(line) {
        let anchor_name = &cap[1];
        let anchor = AnchorDefinition::new(file, Some(anchor_name), line_num as i32);
        let id = anchor.id().to_string();
        if !by_id.contains_key(&id) {
            by_id.insert(id, anchor.clone());
            let key = PathKey::from_string(&anchor.help_path());
            by_help_path.insert(key, anchor.clone());
            by_name.insert(anchor_name.to_string(), anchor);
        }
    }
}

fn parse_hrefs_from_line(file: &Path, line: &str, line_num: usize) -> Vec<Href> {
    let mut hrefs = Vec::new();
    for cap in A_HREF_RE.captures_iter(line) {
        let href_str = &cap[1];
        hrefs.push(Href::new(file.to_path_buf(), href_str.to_string(), line_num));
    }
    hrefs
}

fn parse_imgs_from_line(file: &Path, line: &str, line_num: usize) -> Vec<Img> {
    let mut imgs = Vec::new();
    for cap in IMG_SRC_RE.captures_iter(line) {
        let src = &cap[1];
        imgs.push(Img::new(file.to_path_buf(), src.to_string(), line_num));
    }
    imgs
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn create_test_html(dir: &std::path::Path, name: &str, content: &str) -> PathBuf {
        std::fs::create_dir_all(dir).unwrap();
        let path = dir.join(name);
        let mut f = std::fs::File::create(&path).unwrap();
        write!(f, "{}", content).unwrap();
        path
    }

    #[test]
    fn test_help_file_parse_anchors() {
        let dir = tempfile::tempdir().unwrap();
        let html = r#"<html><body>
<a name="intro">Introduction</a>
<a name="details">Details</a>
</body></html>"#;
        let path = create_test_html(dir.path(), "page.html", html);
        let hf = HelpFile::new(path);
        assert!(hf.contains_anchor("intro"));
        assert!(hf.contains_anchor("details"));
        assert!(!hf.contains_anchor("nonexistent"));
    }

    #[test]
    fn test_help_file_parse_hrefs() {
        let dir = tempfile::tempdir().unwrap();
        let html = concat!(
            "<html><body>\n",
            "<a href=\"other.html\">Link</a>\n",
            "<a href=\"https://example.com\">External</a>\n",
            "<a href=\"#local\">Local</a>\n",
            "</body></html>"
        );
        let path = create_test_html(dir.path(), "page.html", html);
        let hf = HelpFile::new(path);
        assert_eq!(hf.get_all_hrefs().len(), 3);
        assert!(hf.get_all_hrefs()[0].is_local_anchor() == false);
        assert!(hf.get_all_hrefs()[1].is_remote);
        assert!(hf.get_all_hrefs()[2].is_local_anchor());
    }

    #[test]
    fn test_help_file_parse_imgs() {
        let dir = tempfile::tempdir().unwrap();
        let html = r#"<html><body>
<img src="images/icon.png" />
<img src="Icons.ERROR_ICON" />
</body></html>"#;
        let path = create_test_html(dir.path(), "page.html", html);
        let hf = HelpFile::new(path);
        assert_eq!(hf.get_all_imgs().len(), 2);
        assert!(!hf.get_all_imgs()[0].is_runtime());
        assert!(hf.get_all_imgs()[1].is_runtime());
    }

    #[test]
    fn test_help_file_file_level_anchor() {
        let dir = tempfile::tempdir().unwrap();
        let html = "<html><body>Minimal</body></html>";
        let path = create_test_html(dir.path(), "index.html", html);
        let hf = HelpFile::new(path);
        // Should have the file-level anchor
        assert!(!hf.get_all_anchor_definitions().is_empty());
    }
}
