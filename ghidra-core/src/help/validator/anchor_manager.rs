// Port of help.validator.AnchorManager

use std::collections::HashMap;
use std::path::Path;

use crate::help::model::{AnchorDefinition, Href, Img};
use crate::help::PathKey;

/// Manages anchor definitions, references, and image references for help file parsing.
///
/// Collects `<a name="...">` anchors and `<a href="...">` / `<img src="...">` references
/// as help files are parsed.
pub struct AnchorManager {
    anchors_by_help_path: HashMap<PathKey, AnchorDefinition>,
    anchors_by_id: HashMap<String, AnchorDefinition>,
    anchors_by_name: HashMap<String, AnchorDefinition>,
    duplicate_anchors_by_id: HashMap<String, Vec<AnchorDefinition>>,

    anchor_refs: Vec<Href>,
    img_refs: Vec<Img>,
}

impl AnchorManager {
    pub fn new() -> Self {
        AnchorManager {
            anchors_by_help_path: HashMap::new(),
            anchors_by_id: HashMap::new(),
            anchors_by_name: HashMap::new(),
            duplicate_anchors_by_id: HashMap::new(),
            anchor_refs: Vec::new(),
            img_refs: Vec::new(),
        }
    }

    /// Add an anchor definition for the given file and optional name.
    pub fn add_anchor(&mut self, file: &Path, anchor_name: Option<&str>, src_line_no: i32) {
        let anchor = AnchorDefinition::new(file, anchor_name, src_line_no);
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
                let mut v = Vec::new();
                if let Some(orig) = self.anchors_by_id.get(id) {
                    v.push(orig.clone());
                }
                v
            });
        list.push(anchor.clone());

        if let Some(name) = anchor_name {
            if !self.anchors_by_name.contains_key(name) {
                self.anchors_by_name.insert(name.to_string(), anchor.clone());
                let key = PathKey::from_string(&anchor.help_path());
                self.anchors_by_help_path.insert(key, anchor);
            }
        }
    }

    /// Get all anchors by their help path.
    pub fn get_anchors_by_help_path(&self) -> &HashMap<PathKey, AnchorDefinition> {
        &self.anchors_by_help_path
    }

    /// Look up an anchor by help path string.
    pub fn get_anchor_for_help_path(&self, path: &str) -> Option<&AnchorDefinition> {
        let key = PathKey::from_string(path);
        self.anchors_by_help_path.get(&key)
    }

    /// Add an HREF reference.
    pub fn add_anchor_ref(&mut self, href: Href) {
        self.anchor_refs.push(href);
    }

    /// Add an IMG reference.
    pub fn add_image_ref(&mut self, img: Img) {
        self.img_refs.push(img);
    }

    /// Get all HREF references.
    pub fn get_anchor_refs(&self) -> &[Href] {
        &self.anchor_refs
    }

    /// Get all IMG references.
    pub fn get_image_refs(&self) -> &[Img] {
        &self.img_refs
    }

    /// Look up an anchor by name.
    pub fn get_anchor_for_name(&self, anchor_name: &str) -> Option<&AnchorDefinition> {
        self.anchors_by_name.get(anchor_name)
    }

    /// Get duplicate anchor definitions grouped by ID, after cleanup.
    pub fn get_duplicate_anchors_by_id(&mut self) -> &HashMap<String, Vec<AnchorDefinition>> {
        self.cleanup_duplicate_anchors();
        &self.duplicate_anchors_by_id
    }

    fn cleanup_duplicate_anchors(&mut self) {
        let ids_to_check: Vec<String> = self.duplicate_anchors_by_id.keys().cloned().collect();

        for id in ids_to_check {
            let should_remove = if let Some(list) = self.duplicate_anchors_by_id.get_mut(&id) {
                // Remove anchor definitions (line_number < 0) as they are file-level
                list.retain(|a| a.line_number() >= 0);
                list.len() <= 1
            } else {
                false
            };

            if should_remove {
                self.duplicate_anchors_by_id.remove(&id);
            }
        }
    }
}

impl Default for AnchorManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_anchor_manager_add_anchor() {
        let mut mgr = AnchorManager::new();
        let file = PathBuf::from("/repo/help/help/topics/MyTopic/page.html");
        mgr.add_anchor(&file, Some("section1"), 10);

        assert!(mgr.get_anchor_for_name("section1").is_some());
        assert!(mgr.get_anchor_for_name("nonexistent").is_none());
    }

    #[test]
    fn test_anchor_manager_file_level_anchor() {
        let mut mgr = AnchorManager::new();
        let file = PathBuf::from("/repo/help/help/topics/MyTopic/page.html");
        mgr.add_anchor(&file, None, -1);
        mgr.add_anchor(&file, Some("named"), 5);

        // Should have at least 2 anchors
        assert!(mgr.get_anchors_by_help_path().len() >= 2);
    }

    #[test]
    fn test_anchor_manager_duplicate_detection() {
        let mut mgr = AnchorManager::new();
        let file = PathBuf::from("/repo/help/help/topics/MyTopic/page.html");
        mgr.add_anchor(&file, Some("dup"), 10);
        mgr.add_anchor(&file, Some("dup"), 20);

        let duplicates = mgr.get_duplicate_anchors_by_id();
        // Both named anchors on the same file create duplicates
        assert!(!duplicates.is_empty());
    }

    #[test]
    fn test_anchor_manager_refs() {
        let mut mgr = AnchorManager::new();
        let href = Href::new(
            PathBuf::from("/src/help/topics/MyTopic/page.html"),
            "other.html".to_string(),
            5,
        );
        mgr.add_anchor_ref(href);
        assert_eq!(mgr.get_anchor_refs().len(), 1);

        let img = Img::new(
            PathBuf::from("/src/help/topics/MyTopic/page.html"),
            "icon.png".to_string(),
            10,
        );
        mgr.add_image_ref(img);
        assert_eq!(mgr.get_image_refs().len(), 1);
    }
}
