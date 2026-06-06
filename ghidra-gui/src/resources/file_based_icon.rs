//! Port of Ghidra's `resources.icons.FileBasedIcon`.

/// Trait for icons loaded from files (JAR resources, filesystem paths).
pub trait FileBasedIcon: Send + Sync + std::fmt::Debug {
    /// The original resource path or filename of this icon.
    fn resource_path(&self) -> &str;
    /// The width of the icon in pixels.
    fn width(&self) -> u32;
    /// The height of the icon in pixels.
    fn height(&self) -> u32;
    /// Whether the icon has been loaded successfully.
    fn is_loaded(&self) -> bool { true }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug)]
    struct TestIcon { path: String, w: u32, h: u32 }
    impl FileBasedIcon for TestIcon {
        fn resource_path(&self) -> &str { &self.path }
        fn width(&self) -> u32 { self.w }
        fn height(&self) -> u32 { self.h }
    }

    #[test]
    fn test_file_based_icon() {
        let icon = TestIcon { path: "/images/test.png".into(), w: 16, h: 16 };
        assert_eq!(icon.resource_path(), "/images/test.png");
        assert_eq!(icon.width(), 16);
        assert!(icon.is_loaded());
    }
}
