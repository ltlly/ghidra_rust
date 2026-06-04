// Help framework: model types (ported from help.validator.model Java package)

mod anchor_definition;
mod toc_item;
mod help_file;
mod help_topic;
mod ghidra_toc_file;

pub use anchor_definition::AnchorDefinition;
pub use toc_item::{TocItem, TocItemDefinition, TocItemExternal, TocItemReference};
pub use help_file::HelpFile;
pub use help_topic::HelpTopic;
pub use ghidra_toc_file::GhidraTocFile;

use std::path::{Path, PathBuf};
use std::fmt;

/// Represents a hyperlink reference (`<a href="...">`) found in HTML help files.
#[derive(Debug, Clone)]
pub struct Href {
    pub source_file: PathBuf,
    pub href: String,
    pub line_number: usize,
    pub resolved_file: Option<PathBuf>,
    pub anchor_name: Option<String>,
    pub is_remote: bool,
    pub is_local_anchor: bool,
    pub relative_path: Option<PathBuf>,
}

impl Href {
    pub fn new(
        source_file: PathBuf,
        href: String,
        line_number: usize,
    ) -> Self {
        let is_remote = is_remote_uri(&href);
        let (resolved_file, anchor_name, is_local_anchor) = if !is_remote {
            if let Some(hash_pos) = href.find('#') {
                let file_part = &href[..hash_pos];
                let anchor = &href[hash_pos + 1..];
                if file_part.is_empty() {
                    // local anchor reference (#anchor)
                    (Some(source_file.clone()), Some(anchor.to_string()), true)
                } else {
                    // file with anchor
                    let resolved = resolve_reference(&source_file, file_part);
                    (resolved, Some(anchor.to_string()), false)
                }
            } else {
                // no anchor
                let resolved = resolve_reference(&source_file, &href);
                (resolved, None, false)
            }
        } else {
            (None, None, false)
        };

        let relative_path = resolved_file.as_ref().and_then(|f| relativize_with_help_topics(f));

        Href {
            source_file,
            href,
            line_number,
            resolved_file,
            anchor_name,
            is_remote,
            is_local_anchor,
            relative_path,
        }
    }

    /// Returns true if this HREF points to a remote URL.
    pub fn is_url(&self) -> bool {
        self.is_remote
    }

    /// Returns true if this is a local anchor reference within the same file.
    pub fn is_local_anchor(&self) -> bool {
        self.is_local_anchor
    }

    /// The reference string from the HTML source.
    pub fn ref_string(&self) -> &str {
        &self.href
    }

    /// The relative help path to the destination.
    pub fn reference_file_help_path(&self) -> Option<&Path> {
        self.relative_path.as_deref()
    }

    /// Returns the full help path including anchor if present.
    pub fn help_path(&self) -> Option<String> {
        self.relative_path.as_ref().map(|p| {
            if let Some(ref anchor) = self.anchor_name {
                format!("{}#{}", p.display(), anchor)
            } else {
                p.display().to_string()
            }
        })
    }
}

impl fmt::Display for Href {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "<a href=\"{}\">\n\t\t\tFrom: {} (line:{}),\n\t\t\tResolved to: {:?}",
            self.href,
            self.source_file.display(),
            self.line_number,
            self.resolved_file
        )
    }
}

impl PartialEq for Href {
    fn eq(&self, other: &Self) -> bool {
        self.source_file == other.source_file
            && self.href == other.href
            && self.line_number == other.line_number
            && self.resolved_file == other.resolved_file
            && self.anchor_name == other.anchor_name
    }
}

impl Eq for Href {}

impl PartialOrd for Href {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Href {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.source_file
            .cmp(&other.source_file)
            .then(self.line_number.cmp(&other.line_number))
            .then(self.href.cmp(&other.href))
    }
}

/// Represents an image reference (`<img src="...">`) found in HTML help files.
#[derive(Debug, Clone)]
pub struct Img {
    pub source_file: PathBuf,
    pub relative_path: Option<PathBuf>,
    pub img_src: String,
    pub resolved_path: Option<PathBuf>,
    pub is_remote: bool,
    pub is_runtime: bool,
    pub is_invalid_runtime: bool,
    pub line_number: usize,
}

impl Img {
    pub fn new(source_file: PathBuf, img_src: String, line_number: usize) -> Self {
        let is_remote = is_remote_uri(&img_src);
        let is_runtime = img_src.starts_with("Icons.") || img_src.starts_with("icon.");
        let relative_path = relativize_with_help_topics(&source_file);

        let resolved_path = if is_remote || is_runtime {
            None
        } else {
            resolve_image_reference(&source_file, &img_src)
        };

        Img {
            source_file,
            relative_path,
            img_src,
            resolved_path,
            is_remote,
            is_runtime,
            is_invalid_runtime: false,
            line_number,
        }
    }

    /// Returns true if this image points to a remote URL.
    pub fn is_remote(&self) -> bool {
        self.is_remote
    }

    /// Returns true if this is a runtime icon reference.
    pub fn is_runtime(&self) -> bool {
        self.is_runtime
    }

    /// Returns true if a runtime image could not be located.
    pub fn is_invalid(&self) -> bool {
        self.is_invalid_runtime
    }
}

impl fmt::Display for Img {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "<img src=\"{}\">  [\n\t\tFrom: {:?},\n\t\tResolved: {:?}\n\t]",
            self.img_src, self.relative_path, self.resolved_path
        )
    }
}

impl PartialEq for Img {
    fn eq(&self, other: &Self) -> bool {
        self.source_file == other.source_file
            && self.img_src == other.img_src
            && self.line_number == other.line_number
    }
}

impl Eq for Img {}

impl PartialOrd for Img {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Img {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.source_file
            .cmp(&other.source_file)
            .then(self.line_number.cmp(&other.line_number))
            .then(self.img_src.cmp(&other.img_src))
    }
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

const HELP_TOPICS_ROOT: &str = "help/topics";
pub(crate) const HELP_SHARED_PREFIX: &str = "help/shared/";

/// Returns true if the given string represents a remote resource.
pub fn is_remote_uri(uri: &str) -> bool {
    if uri.starts_with("http://") || uri.starts_with("https://") || uri.starts_with("ftp://") {
        return true;
    }
    if uri.contains("://") {
        // Some other scheme; treat as remote unless file:
        return !uri.starts_with("file:");
    }
    false
}

/// Resolve a relative reference against a source file path.
fn resolve_reference(source_file: &Path, relative: &str) -> Option<PathBuf> {
    if relative.is_empty() || relative.starts_with('/') || relative.contains(':') {
        return None;
    }

    if relative.starts_with(HELP_SHARED_PREFIX) {
        return None; // would need application root
    }

    source_file.parent().map(|p| p.join(relative))
}

/// Resolve an image reference against a source file path.
fn resolve_image_reference(source_file: &Path, img_src: &str) -> Option<PathBuf> {
    if img_src.is_empty() || img_src.starts_with('/') || img_src.contains(':') {
        return None;
    }

    if img_src.starts_with(HELP_SHARED_PREFIX) {
        return None;
    }

    source_file.parent().map(|p| p.join(img_src))
}

/// Relativize a path to start from the `help/topics` component.
pub fn relativize_with_help_topics(p: &Path) -> Option<PathBuf> {
    let components: Vec<_> = p.components().collect();
    for i in 0..components.len() {
        let sub: PathBuf = components[i..].iter().collect();
        let sub_str = sub.to_string_lossy();
        if sub_str.starts_with("help/topics") || sub_str.starts_with("help\\topics") {
            return Some(sub);
        }
    }
    None
}

/// Find the help topic directory for the given file.
pub fn get_help_topic_dir(file: &Path) -> Option<PathBuf> {
    let components: Vec<_> = file.components().collect();
    for i in 0..components.len() {
        let sub: PathBuf = components[i..].iter().collect();
        let sub_str = sub.to_string_lossy();
        if sub_str.starts_with("help/topics") || sub_str.starts_with("help\\topics") {
            // help/topics/<topic_name> is the first 3 components
            if i + 3 <= components.len() {
                return Some(components[..i + 3].iter().collect());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_remote_uri() {
        assert!(is_remote_uri("http://example.com"));
        assert!(is_remote_uri("https://example.com/img.png"));
        assert!(is_remote_uri("ftp://server/file"));
        assert!(!is_remote_uri("file:///tmp/test.html"));
        assert!(!is_remote_uri("images/icon.png"));
        assert!(!is_remote_uri("../other/file.html"));
    }

    #[test]
    fn test_href_new_local() {
        let src = PathBuf::from("/src/help/topics/MyTopic/page.html");
        let href = Href::new(src, "other.html".to_string(), 10);
        assert!(!href.is_remote);
        assert!(!href.is_local_anchor);
        assert!(href.resolved_file.is_some());
    }

    #[test]
    fn test_href_new_local_anchor() {
        let src = PathBuf::from("/src/help/topics/MyTopic/page.html");
        let href = Href::new(src, "#section1".to_string(), 5);
        assert!(!href.is_remote);
        assert!(href.is_local_anchor);
        assert_eq!(href.anchor_name.as_deref(), Some("section1"));
    }

    #[test]
    fn test_href_new_remote() {
        let src = PathBuf::from("/src/help/topics/MyTopic/page.html");
        let href = Href::new(src, "https://example.com".to_string(), 1);
        assert!(href.is_remote);
        assert!(href.resolved_file.is_none());
    }

    #[test]
    fn test_img_new_local() {
        let src = PathBuf::from("/src/help/topics/MyTopic/page.html");
        let img = Img::new(src, "images/screenshot.png".to_string(), 20);
        assert!(!img.is_remote());
        assert!(!img.is_runtime());
        assert!(img.resolved_path.is_some());
    }

    #[test]
    fn test_img_new_runtime() {
        let src = PathBuf::from("/src/help/topics/MyTopic/page.html");
        let img = Img::new(src, "Icons.ERROR_ICON".to_string(), 15);
        assert!(!img.is_remote());
        assert!(img.is_runtime());
    }

    #[test]
    fn test_relativize_with_help_topics() {
        let p = Path::new("/repo/Ghidra/Framework/Help/src/main/help/help/topics/MyTopic/foo.html");
        let rel = relativize_with_help_topics(p);
        assert!(rel.is_some());
        let rel_str = rel.unwrap().to_string_lossy().to_string();
        assert!(rel_str.contains("help/topics"));
    }

    #[test]
    fn test_get_help_topic_dir() {
        let p = Path::new("/repo/help/help/topics/MyPlugin/index.html");
        let dir = get_help_topic_dir(p);
        assert!(dir.is_some());
        let dir_str = dir.unwrap().display().to_string();
        assert!(dir_str.contains("MyPlugin"));
    }
}
