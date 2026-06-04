// Port of help.ImageLocation

use std::path::PathBuf;

/// Represents the location of an image in an HTML help file, including
/// its resolved path within the help system.
///
/// Some images are represented by runtime values (e.g., Java Icons) that
/// do not have a valid URL.
#[derive(Debug, Clone)]
pub struct ImageLocation {
    source_file: PathBuf,
    image_src: String,
    resolved_path: Option<PathBuf>,
    is_remote: bool,
    is_runtime: bool,
    invalid_runtime_image: bool,
}

impl ImageLocation {
    /// Create a local image location (found on the file system).
    pub fn local(
        source_file: PathBuf,
        image_src: String,
        resolved_path: Option<PathBuf>,
    ) -> Self {
        ImageLocation {
            source_file,
            image_src,
            resolved_path,
            is_remote: false,
            is_runtime: false,
            invalid_runtime_image: false,
        }
    }

    /// Create a runtime image location (loaded from a Java class at runtime).
    pub fn runtime(source_file: PathBuf, image_src: String) -> Self {
        ImageLocation {
            source_file,
            image_src,
            resolved_path: None,
            is_remote: false,
            is_runtime: true,
            invalid_runtime_image: false,
        }
    }

    /// Create an invalid runtime image location (runtime image could not be found).
    pub fn invalid_runtime(source_file: PathBuf, image_src: String) -> Self {
        ImageLocation {
            source_file,
            image_src,
            resolved_path: None,
            is_remote: false,
            is_runtime: true,
            invalid_runtime_image: true,
        }
    }

    /// Create a remote image location (pointing to a web server).
    pub fn remote(source_file: PathBuf, image_src: String) -> Self {
        ImageLocation {
            source_file,
            image_src,
            resolved_path: None,
            is_remote: true,
            is_runtime: false,
            invalid_runtime_image: false,
        }
    }

    /// The source file that contains this image reference.
    pub fn get_source_file(&self) -> &PathBuf {
        &self.source_file
    }

    /// The image src attribute from the HTML.
    pub fn get_image_src(&self) -> &str {
        &self.image_src
    }

    /// The resolved path to the image file on disk.
    pub fn get_resolved_path(&self) -> Option<&PathBuf> {
        self.resolved_path.as_ref()
    }

    /// Whether the image points to a remote URL.
    pub fn is_remote(&self) -> bool {
        self.is_remote
    }

    /// Whether the image is loaded at runtime from a class.
    pub fn is_runtime(&self) -> bool {
        self.is_runtime
    }

    /// Whether the runtime image could not be located.
    pub fn is_invalid_runtime_image(&self) -> bool {
        self.invalid_runtime_image
    }
}

impl std::fmt::Display for ImageLocation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{{\n\tsource file: {},\n\tsrc: {},\n\tpath: {:?},\n\tis runtime: {},\n\tis remote: {}\n}}",
            self.source_file.display(),
            self.image_src,
            self.resolved_path,
            self.is_runtime,
            self.is_remote,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_local_image_location() {
        let loc = ImageLocation::local(
            PathBuf::from("/src/help/topics/Foo/Foo.html"),
            "images/icon.png".to_string(),
            Some(PathBuf::from("/src/help/topics/Foo/images/icon.png")),
        );
        assert!(!loc.is_remote());
        assert!(!loc.is_runtime());
        assert!(!loc.is_invalid_runtime_image());
        assert!(loc.get_resolved_path().is_some());
    }

    #[test]
    fn test_remote_image_location() {
        let loc = ImageLocation::remote(
            PathBuf::from("/src/help/topics/Foo/Foo.html"),
            "http://example.com/img.png".to_string(),
        );
        assert!(loc.is_remote());
        assert!(!loc.is_runtime());
    }

    #[test]
    fn test_runtime_image_location() {
        let loc = ImageLocation::runtime(
            PathBuf::from("/src/help/topics/Foo/Foo.html"),
            "Icons.ERROR_ICON".to_string(),
        );
        assert!(!loc.is_remote());
        assert!(loc.is_runtime());
        assert!(!loc.is_invalid_runtime_image());
    }

    #[test]
    fn test_invalid_runtime_image_location() {
        let loc = ImageLocation::invalid_runtime(
            PathBuf::from("/src/help/topics/Foo/Foo.html"),
            "Icons.NONEXISTENT".to_string(),
        );
        assert!(loc.is_runtime());
        assert!(loc.is_invalid_runtime_image());
    }

    #[test]
    fn test_image_location_display() {
        let loc = ImageLocation::local(
            PathBuf::from("/src/page.html"),
            "icon.png".to_string(),
            Some(PathBuf::from("/src/icon.png")),
        );
        let display = format!("{}", loc);
        assert!(display.contains("icon.png"));
        assert!(display.contains("page.html"));
    }
}
