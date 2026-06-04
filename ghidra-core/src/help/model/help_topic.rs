// Port of help.validator.model.HelpTopic

use std::cell::RefCell;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

use super::help_file::HelpFile;
use super::{relativize_with_help_topics, AnchorDefinition, Href, Img};

/// A help topic directory containing multiple help files.
///
/// Represents a directory under `help/topics/<TopicName>` and lazily loads
/// all HTML help files within it. Uses `RefCell` for interior mutability
/// to allow lazy loading from `&self` references.
#[derive(Debug)]
pub struct HelpTopic {
    topic_dir: PathBuf,
    relative_path: Option<PathBuf>,
    help_files: RefCell<Option<HashMap<PathBuf, HelpFile>>>,
}

impl HelpTopic {
    pub fn new(topic_dir: PathBuf) -> Self {
        let relative_path = relativize_with_help_topics(&topic_dir);
        HelpTopic {
            topic_dir,
            relative_path,
            help_files: RefCell::new(None),
        }
    }

    /// Create a HelpTopic from a single HTML file path.
    pub fn from_html_file(topic_file: &Path) -> Option<Self> {
        let topic = topic_file.parent()?;
        let _topic_name = topic.file_name()?;
        Some(HelpTopic::new(topic.to_path_buf()))
    }

    pub fn get_topic_dir(&self) -> &Path {
        &self.topic_dir
    }

    pub fn get_relative_path(&self) -> Option<&Path> {
        self.relative_path.as_deref()
    }

    pub fn get_name(&self) -> &str {
        self.topic_dir
            .file_name()
            .map(|n| n.to_str().unwrap_or(""))
            .unwrap_or("")
    }

    /// Lazily load all help files from the topic directory.
    fn lazy_load(&self) {
        let mut borrow = self.help_files.borrow_mut();
        if borrow.is_some() {
            return;
        }

        let mut files = HashMap::new();
        Self::load_help_files_static(&self.topic_dir, self.relative_path.as_deref(), &mut files);
        *borrow = Some(files);
    }

    fn load_help_files_static(
        dir: &Path,
        relative_path: Option<&Path>,
        files: &mut HashMap<PathBuf, HelpFile>,
    ) {
        if !dir.is_dir() {
            return;
        }

        let entries = match std::fs::read_dir(dir) {
            Ok(e) => e,
            Err(_) => return,
        };

        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                Self::load_help_files_static(&path, relative_path, files);
            } else {
                let fname = path
                    .file_name()
                    .map(|n| n.to_string_lossy().to_lowercase())
                    .unwrap_or_default();
                if fname.ends_with(".htm") || fname.ends_with(".html") {
                    let rel_path = relative_path
                        .and_then(|rel_dir| {
                            relativize_with_help_topics(&path)
                                .map(|file_rel| rel_dir.join(file_rel))
                        })
                        .unwrap_or_else(|| {
                            path.file_name()
                                .map(|n| PathBuf::from(n))
                                .unwrap_or_default()
                        });

                    let help_file = HelpFile::new(path);
                    files.insert(rel_path, help_file);
                }
            }
        }
    }

    /// Add a pre-parsed help file to this topic.
    pub fn add_help_file(&self, rel_path: PathBuf, help_file: HelpFile) {
        self.lazy_load();
        let mut borrow = self.help_files.borrow_mut();
        if let Some(ref mut files) = *borrow {
            files.insert(rel_path, help_file);
        }
    }

    /// Get all HREFs from all help files in this topic (cloned).
    pub fn get_all_hrefs(&self) -> Vec<Href> {
        self.lazy_load();
        let borrow = self.help_files.borrow();
        borrow
            .as_ref()
            .map(|files| {
                files
                    .values()
                    .flat_map(|hf| hf.get_all_hrefs().iter().cloned())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Get all IMGs from all help files in this topic (cloned).
    pub fn get_all_imgs(&self) -> Vec<Img> {
        self.lazy_load();
        let borrow = self.help_files.borrow();
        borrow
            .as_ref()
            .map(|files| {
                files
                    .values()
                    .flat_map(|hf| hf.get_all_imgs().iter().cloned())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Get all anchor definitions from all help files in this topic (cloned).
    pub fn get_all_anchor_definitions(&self) -> Vec<AnchorDefinition> {
        self.lazy_load();
        let borrow = self.help_files.borrow();
        borrow
            .as_ref()
            .map(|files| {
                files
                    .values()
                    .flat_map(|hf| hf.get_all_anchor_definitions().into_iter().cloned())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Get the number of help files in this topic.
    pub fn help_file_count(&self) -> usize {
        self.lazy_load();
        let borrow = self.help_files.borrow();
        borrow.as_ref().map(|f| f.len()).unwrap_or(0)
    }

    /// Get help files as a vector of cloned data.
    pub fn get_help_files_vec(&self) -> Vec<HelpFileSummary> {
        self.lazy_load();
        let borrow = self.help_files.borrow();
        borrow
            .as_ref()
            .map(|files| {
                files
                    .values()
                    .map(|hf| HelpFileSummary {
                        relative_path: hf.get_relative_path().map(|p| p.to_path_buf()),
                        file: hf.get_file().to_path_buf(),
                        anchor_count: hf.get_all_anchor_definitions().len(),
                        href_count: hf.get_all_hrefs().len(),
                        img_count: hf.get_all_imgs().len(),
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Check if a file exists by path key.
    pub fn has_file_for_path(&self, path: &Path) -> bool {
        self.lazy_load();
        let borrow = self.help_files.borrow();
        borrow
            .as_ref()
            .map(|files| {
                files.values().any(|hf| {
                    hf.get_relative_path()
                        .map(|rp| rp == path)
                        .unwrap_or(false)
                })
            })
            .unwrap_or(false)
    }

    /// Find a help file by relative path.
    pub fn find_help_file(&self, rel_path: &Path) -> Option<()> {
        self.lazy_load();
        let borrow = self.help_files.borrow();
        borrow.as_ref().and_then(|files| {
            if files.contains_key(rel_path) {
                Some(())
            } else {
                None
            }
        })
    }

    /// Get duplicate anchors from all files.
    pub fn get_duplicate_anchors(&self) -> HashMap<PathBuf, HashMap<String, Vec<AnchorDefinition>>> {
        self.lazy_load();
        let borrow = self.help_files.borrow();
        borrow
            .as_ref()
            .map(|files| {
                let mut result = HashMap::new();
                for (_, hf) in files {
                    let dups = hf.get_duplicate_anchors_by_id().clone();
                    if !dups.is_empty() {
                        result.insert(hf.get_file().to_path_buf(), dups);
                    }
                }
                result
            })
            .unwrap_or_default()
    }
}

/// Summary information about a help file (avoiding borrow issues).
#[derive(Debug, Clone)]
pub struct HelpFileSummary {
    pub relative_path: Option<PathBuf>,
    pub file: PathBuf,
    pub anchor_count: usize,
    pub href_count: usize,
    pub img_count: usize,
}

impl PartialEq for HelpTopic {
    fn eq(&self, other: &Self) -> bool {
        self.topic_dir == other.topic_dir
    }
}

impl Eq for HelpTopic {}

impl PartialOrd for HelpTopic {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for HelpTopic {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.topic_dir.cmp(&other.topic_dir)
    }
}

impl std::fmt::Display for HelpTopic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.topic_dir.display())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn create_topic_with_html(dir: &Path, topic_name: &str) -> PathBuf {
        let topic_dir = dir.join("help").join("help").join("topics").join(topic_name);
        std::fs::create_dir_all(&topic_dir).unwrap();

        let html = "<html><body><a name=\"top\">Top</a></body></html>";
        let file_path = topic_dir.join("index.html");
        let mut f = std::fs::File::create(&file_path).unwrap();
        write!(f, "{}", html).unwrap();

        topic_dir
    }

    #[test]
    fn test_help_topic_lazy_load() {
        let dir = tempfile::tempdir().unwrap();
        let topic_dir = create_topic_with_html(dir.path(), "MyPlugin");
        let topic = HelpTopic::new(topic_dir);
        assert_eq!(topic.get_name(), "MyPlugin");
        assert!(topic.help_file_count() > 0);
    }

    #[test]
    fn test_help_topic_get_hrefs() {
        let dir = tempfile::tempdir().unwrap();
        let topic_dir = dir.path().join("help").join("help").join("topics").join("Test");
        std::fs::create_dir_all(&topic_dir).unwrap();
        let html = "<html><body><a href=\"other.html\">Link</a></body></html>";
        let mut f = std::fs::File::create(topic_dir.join("page.html")).unwrap();
        write!(f, "{}", html).unwrap();

        let topic = HelpTopic::new(topic_dir);
        let hrefs = topic.get_all_hrefs();
        assert_eq!(hrefs.len(), 1);
    }

    #[test]
    fn test_help_topic_get_files_vec() {
        let dir = tempfile::tempdir().unwrap();
        let topic_dir = create_topic_with_html(dir.path(), "TestTopic");
        let topic = HelpTopic::new(topic_dir);
        let files = topic.get_help_files_vec();
        assert!(!files.is_empty());
    }
}
