// Help framework: help module locations (ported from help.validator.location Java package)

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::help::model::{
    AnchorDefinition, GhidraTocFile, HelpTopic, Href, Img, TocItemDefinition,
};

// ---------------------------------------------------------------------------
// HelpModuleLocation (trait + impl)
// ---------------------------------------------------------------------------

/// Represents a location where help content can be found (directory or JAR).
#[derive(Debug)]
pub struct HelpModuleLocation {
    help_dir: PathBuf,
    help_topics: Vec<HelpTopic>,
    source_toc_file: Option<GhidraTocFile>,
    is_input_source: bool,
}

impl HelpModuleLocation {
    /// Create a new directory-based help module location.
    pub fn from_directory(dir: &Path) -> Result<Self, String> {
        let mut loc = HelpModuleLocation {
            help_dir: dir.to_path_buf(),
            help_topics: Vec::new(),
            source_toc_file: None,
            is_input_source: true,
        };

        loc.load_help_topics();
        loc.source_toc_file = loc.load_source_toc_file();
        Ok(loc)
    }

    /// Create a new help module location from a pre-built source (JAR or generated).
    pub fn from_prebuilt(dir: PathBuf) -> Result<Self, String> {
        let mut loc = HelpModuleLocation {
            help_dir: dir,
            help_topics: Vec::new(),
            source_toc_file: None,
            is_input_source: false,
        };
        loc.load_help_topics();
        loc.source_toc_file = loc.load_source_toc_file();
        Ok(loc)
    }

    /// Whether this location is an input source for building help.
    pub fn is_help_input_source(&self) -> bool {
        self.is_input_source
    }

    /// The help directory path.
    pub fn get_help_location(&self) -> &Path {
        &self.help_dir
    }

    /// Get the module location (4 levels up from help dir).
    pub fn get_help_module_location(&self) -> Option<PathBuf> {
        // help dir format: <module>/src/main/help/help/
        self.help_dir
            .parent() // help
            .and_then(|p| p.parent()) // main
            .and_then(|p| p.parent()) // src
            .and_then(|p| p.parent()) // module
            .map(|p| p.to_path_buf())
    }

    /// Get the repo root path.
    pub fn get_module_repo_root(&self) -> Option<PathBuf> {
        self.get_help_module_location().and_then(|module| {
            module
                .parent() // category
                .and_then(|p| p.parent()) // repo
                .and_then(|p| p.parent()) // repo root
                .map(|p| p.to_path_buf())
        })
    }

    /// Get the source TOC file.
    pub fn get_source_toc_file(&self) -> Option<&GhidraTocFile> {
        self.source_toc_file.as_ref()
    }

    /// Get all help topics.
    pub fn get_help_topics(&self) -> &[HelpTopic] {
        &self.help_topics
    }

    /// Get all HREFs from all topics (owned clones).
    pub fn get_all_hrefs(&self) -> Vec<Href> {
        self.help_topics
            .iter()
            .flat_map(|t| t.get_all_hrefs().into_iter())
            .collect()
    }

    /// Get all IMGs from all topics (owned clones).
    pub fn get_all_imgs(&self) -> Vec<Img> {
        self.help_topics
            .iter()
            .flat_map(|t| t.get_all_imgs().into_iter())
            .collect()
    }

    /// Get all anchor definitions (owned clones).
    pub fn get_all_anchor_definitions(&self) -> Vec<AnchorDefinition> {
        self.help_topics
            .iter()
            .flat_map(|t| t.get_all_anchor_definitions().into_iter())
            .collect()
    }

    /// Check if this location contains any help files.
    pub fn contains_help(&self) -> bool {
        self.help_topics.iter().any(|t| t.help_file_count() > 0)
    }

    /// Get duplicate anchors by file.
    pub fn get_duplicate_anchors_by_file(
        &self,
    ) -> HashMap<PathBuf, HashMap<String, Vec<AnchorDefinition>>> {
        let mut result = HashMap::new();
        for topic in &self.help_topics {
            result.extend(topic.get_duplicate_anchors());
        }
        result
    }

    // Private helpers

    fn load_help_topics(&mut self) {
        let topics_dir = self.help_dir.join("topics");
        if !topics_dir.is_dir() {
            return;
        }

        let entries = match std::fs::read_dir(&topics_dir) {
            Ok(e) => e,
            Err(_) => return,
        };

        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                self.help_topics.push(HelpTopic::new(path));
            }
        }
    }

    fn load_source_toc_file(&self) -> Option<GhidraTocFile> {
        let toc_path = self.help_dir.join("TOC_Source.xml");
        if toc_path.exists() {
            GhidraTocFile::new(toc_path).ok()
        } else {
            None
        }
    }
}

impl std::fmt::Display for HelpModuleLocation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.help_dir.display())
    }
}

// ---------------------------------------------------------------------------
// HelpModuleCollection
// ---------------------------------------------------------------------------

/// A collection of help module locations.
///
/// Holds one input help source and zero or more external/pre-built help sources.
pub struct HelpModuleCollection {
    help_locations: Vec<HelpModuleLocation>,
    input_help_index: Option<usize>,
}

impl HelpModuleCollection {
    /// Create a collection from a single help directory.
    pub fn from_help_directory(dir: &Path) -> Result<Self, String> {
        let loc = HelpModuleLocation::from_directory(dir)?;
        let mut collection = HelpModuleCollection {
            help_locations: vec![loc],
            input_help_index: None,
        };
        collection.initialize();
        Ok(collection)
    }

    /// Create a collection from multiple directory paths.
    pub fn from_directories(dirs: &[PathBuf]) -> Result<Self, String> {
        let mut locations = Vec::new();
        for dir in dirs {
            if dir.is_dir() {
                match HelpModuleLocation::from_directory(dir) {
                    Ok(loc) => locations.push(loc),
                    Err(e) => log::warn!("Failed to load help from {}: {}", dir.display(), e),
                }
            }
        }

        let mut collection = HelpModuleCollection {
            help_locations: locations,
            input_help_index: None,
        };
        collection.initialize();
        Ok(collection)
    }

    fn initialize(&mut self) {
        // Find the input help source
        for (i, loc) in self.help_locations.iter().enumerate() {
            if loc.is_help_input_source() {
                self.input_help_index = Some(i);
                break;
            }
        }
    }

    /// Get the source TOC file from the input help module.
    pub fn get_source_toc_file(&self) -> Option<&GhidraTocFile> {
        self.input_help_index
            .and_then(|i| self.help_locations[i].get_source_toc_file())
    }

    /// Get the help roots from all locations.
    pub fn get_help_roots(&self) -> Vec<&Path> {
        self.help_locations
            .iter()
            .map(|l| l.get_help_location())
            .collect()
    }

    /// Get all HREFs from all locations.
    pub fn get_all_hrefs(&self) -> Vec<Href> {
        self.help_locations
            .iter()
            .flat_map(|l| l.get_all_hrefs().into_iter())
            .collect()
    }

    /// Get all IMGs from all locations.
    pub fn get_all_imgs(&self) -> Vec<Img> {
        self.help_locations
            .iter()
            .flat_map(|l| l.get_all_imgs().into_iter())
            .collect()
    }

    /// Get all anchor definitions from all locations.
    pub fn get_all_anchor_definitions(&self) -> Vec<AnchorDefinition> {
        self.help_locations
            .iter()
            .flat_map(|l| l.get_all_anchor_definitions().into_iter())
            .collect()
    }

    /// Find a help file by its help path.
    pub fn get_help_file(&self, help_path: &Path) -> Option<()> {
        for loc in &self.help_locations {
            for topic in loc.get_help_topics() {
                if topic.find_help_file(help_path).is_some() {
                    return Some(());
                }
            }
        }
        None
    }

    /// Get TOC definitions by ID from the input help module.
    pub fn get_toc_definitions_by_id(&self) -> HashMap<String, &TocItemDefinition> {
        let mut map = HashMap::new();
        if let Some(idx) = self.input_help_index {
            if let Some(toc) = self.help_locations[idx].get_source_toc_file() {
                for (id, def) in toc.get_toc_definition_by_id_mapping() {
                    map.insert(id.clone(), def);
                }
            }
        }
        map
    }

    /// Get all input TOC items.
    pub fn get_input_toc_items(&self) -> Vec<&crate::help::model::TocItem> {
        if let Some(idx) = self.input_help_index {
            if let Some(toc) = self.help_locations[idx].get_source_toc_file() {
                return toc.get_all_toc_items().iter().collect();
            }
        }
        Vec::new()
    }

    /// Get duplicate anchors by file from all locations.
    pub fn get_duplicate_anchors_by_file(
        &self,
    ) -> HashMap<PathBuf, HashMap<String, Vec<AnchorDefinition>>> {
        let mut result = HashMap::new();
        for loc in &self.help_locations {
            result.extend(loc.get_duplicate_anchors_by_file());
        }
        result
    }

    /// Whether any location contains help files.
    pub fn contains_help_files(&self) -> bool {
        self.help_locations.iter().any(|l| l.contains_help())
    }
}

impl std::fmt::Display for HelpModuleCollection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let paths: Vec<_> = self
            .help_locations
            .iter()
            .map(|l| l.get_help_location().display().to_string())
            .collect();
        write!(f, "[{}]", paths.join(", "))
    }
}

// Add get_help_topics_mut to HelpModuleLocation
impl HelpModuleLocation {
    pub fn get_help_topics_mut(&mut self) -> &mut [HelpTopic] {
        &mut self.help_topics
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn create_help_module(base: &Path, name: &str) -> PathBuf {
        let help_dir = base.join(name).join("src").join("main").join("help").join("help");
        let topics_dir = help_dir.join("topics").join("TestTopic");
        std::fs::create_dir_all(&topics_dir).unwrap();

        // Create a TOC_Source.xml
        let toc_xml = r#"<?xml version="1.0"?>
<tocroot>
<tocdef id="root" text="Root" />
</tocroot>"#;
        let mut f = std::fs::File::create(help_dir.join("TOC_Source.xml")).unwrap();
        write!(f, "{}", toc_xml).unwrap();

        // Create an HTML file
        let html = "<html><body><a name=\"top\">Top</a></body></html>";
        let mut f = std::fs::File::create(topics_dir.join("index.html")).unwrap();
        write!(f, "{}", html).unwrap();

        help_dir
    }

    #[test]
    fn test_help_module_location_from_directory() {
        let dir = tempfile::tempdir().unwrap();
        let help_dir = create_help_module(dir.path(), "TestModule");
        let loc = HelpModuleLocation::from_directory(&help_dir);
        assert!(loc.is_ok());
        let loc = loc.unwrap();
        assert!(loc.is_help_input_source());
        assert!(!loc.get_help_topics().is_empty());
        assert!(loc.get_source_toc_file().is_some());
    }

    #[test]
    fn test_help_module_collection_from_directory() {
        let dir = tempfile::tempdir().unwrap();
        let help_dir = create_help_module(dir.path(), "TestModule");
        let coll = HelpModuleCollection::from_help_directory(&help_dir);
        assert!(coll.is_ok());
        let coll = coll.unwrap();
        assert!(coll.get_source_toc_file().is_some());
        assert_eq!(coll.get_help_roots().len(), 1);
    }

    #[test]
    fn test_help_module_location_display() {
        let dir = tempfile::tempdir().unwrap();
        let help_dir = create_help_module(dir.path(), "Mod");
        let loc = HelpModuleLocation::from_directory(&help_dir).unwrap();
        let display = format!("{}", loc);
        assert!(!display.is_empty());
    }
}
