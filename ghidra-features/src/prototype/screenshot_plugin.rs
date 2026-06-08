//! Screenshot Plugin.
//!
//! Ported from `ghidra.app.plugin.prototype.debug.ScreenshotPlugin`.
//!
//! Captures screenshots of the current Ghidra tool (active component or
//! full tool frame) and exports them to PNG format.  The Java original uses
//! Swing/AWT for image capture and `JFileChooser` for file selection.
//! Since those are GUI-only features, the Rust port provides the full data
//! model: format selection, filename generation, capture-target tracking,
//! and status reporting.  Actual rendering is left to the integration layer.

use std::fmt;
use std::path::{Path, PathBuf};

// ---------------------------------------------------------------------------
// Screenshot format
// ---------------------------------------------------------------------------

/// Supported screenshot output formats.
///
/// The Java original only supports PNG (via `ImageIO.write(image, "png", file)`).
/// The Rust port extends this to cover common raster formats for future use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ScreenshotFormat {
    /// Portable Network Graphics.
    Png,
    /// JPEG / JFIF.
    Jpeg,
    /// Bitmap (BMP).
    Bmp,
}

impl ScreenshotFormat {
    /// File extension (without dot) for this format.
    pub fn extension(&self) -> &'static str {
        match self {
            ScreenshotFormat::Png => "png",
            ScreenshotFormat::Jpeg => "jpg",
            ScreenshotFormat::Bmp => "bmp",
        }
    }

    /// MIME type for this format.
    pub fn mime_type(&self) -> &'static str {
        match self {
            ScreenshotFormat::Png => "image/png",
            ScreenshotFormat::Jpeg => "image/jpeg",
            ScreenshotFormat::Bmp => "image/bmp",
        }
    }

    /// Human-readable name.
    pub fn display_name(&self) -> &'static str {
        match self {
            ScreenshotFormat::Png => "Portable Network Graphics",
            ScreenshotFormat::Jpeg => "JPEG Image",
            ScreenshotFormat::Bmp => "Bitmap Image",
        }
    }
}

impl fmt::Display for ScreenshotFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.display_name())
    }
}

impl Default for ScreenshotFormat {
    fn default() -> Self {
        Self::Png
    }
}

// ---------------------------------------------------------------------------
// Capture target
// ---------------------------------------------------------------------------

/// Which window or component to capture.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CaptureTarget {
    /// The currently active component provider within the tool.
    ActiveComponent {
        /// Name of the component (from `getComponentWindowingPlaceholder().getName()`).
        component_name: String,
    },
    /// The entire tool frame.
    ToolFrame {
        /// Title of the tool frame window.
        window_title: String,
    },
}

impl CaptureTarget {
    /// Generate a default filename stem for this capture target.
    pub fn filename_stem(&self) -> String {
        match self {
            CaptureTarget::ActiveComponent { component_name } => sanitize_filename(component_name),
            CaptureTarget::ToolFrame { window_title } => {
                if window_title.is_empty() {
                    "Ghidra Window".to_string()
                } else {
                    sanitize_filename(window_title)
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Capture result
// ---------------------------------------------------------------------------

/// Result of a screenshot capture operation.
#[derive(Debug, Clone)]
pub struct CaptureResult {
    /// Path to the saved file.
    pub file_path: PathBuf,
    /// Width of the captured image in pixels.
    pub width: u32,
    /// Height of the captured image in pixels.
    pub height: u32,
    /// Format used for saving.
    pub format: ScreenshotFormat,
    /// Size of the written file in bytes (0 if unknown).
    pub file_size: u64,
}

impl CaptureResult {
    /// Human-readable summary.
    pub fn summary(&self) -> String {
        format!(
            "Captured {}x{} to {} ({})",
            self.width,
            self.height,
            self.file_path.display(),
            self.format.display_name()
        )
    }
}

// ---------------------------------------------------------------------------
// Screenshot plugin status
// ---------------------------------------------------------------------------

/// Status of the last screenshot operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScreenshotStatus {
    /// No operation has been performed yet.
    Idle,
    /// Capture succeeded.
    Success(String),
    /// Capture failed.
    Error(String),
}

impl fmt::Display for ScreenshotStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ScreenshotStatus::Idle => write!(f, "Idle"),
            ScreenshotStatus::Success(msg) => write!(f, "Success: {}", msg),
            ScreenshotStatus::Error(msg) => write!(f, "Error: {}", msg),
        }
    }
}

impl Default for ScreenshotStatus {
    fn default() -> Self {
        Self::Idle
    }
}

// ---------------------------------------------------------------------------
// ScreenshotPlugin
// ---------------------------------------------------------------------------

/// Screenshot Plugin.
///
/// The ScreenshotPlugin captures a screenshot of the current Ghidra tool
/// and saves it to a file.  It exposes two actions:
///
/// - **Capture Active Component** (`Alt+F11`): captures the currently active
///   component provider within the tool.
/// - **Capture Current Tool Frame** (`Alt+F12`): captures the entire tool
///   frame window.
///
/// The Java original uses Swing/AWT for rendering and `JFileChooser` for
/// file selection.  The Rust port provides the data model, action registry,
/// filename generation, and status tracking; actual image capture is
/// delegated to the integration layer.
#[derive(Debug, Clone)]
pub struct ScreenshotPlugin {
    /// Plugin name.
    pub name: String,
    /// Default output format.
    pub format: ScreenshotFormat,
    /// Default output directory (None = use file chooser).
    pub output_directory: Option<PathBuf>,
    /// Status of the last operation.
    pub status: ScreenshotStatus,
    /// Registered actions.
    pub actions: Vec<ScreenshotAction>,
    /// Whether the plugin has been disposed.
    disposed: bool,
}

/// A screenshot action (capture active component or capture tool frame).
#[derive(Debug, Clone)]
pub struct ScreenshotAction {
    /// Action name (used in menus).
    pub name: String,
    /// Description shown in tooltips.
    pub description: String,
    /// Keyboard shortcut (human-readable).
    pub key_binding: String,
    /// Menu group.
    pub group: String,
    /// Menu path.
    pub menu_path: Vec<String>,
}

impl ScreenshotPlugin {
    /// Plugin name constant.
    pub const NAME: &'static str = "ScreenshotPlugin";

    /// Menu group for screenshot actions.
    pub const MENU_GROUP: &'static str = "ScreenCapture";

    /// Create a new screenshot plugin.
    pub fn new() -> Self {
        let mut plugin = Self {
            name: Self::NAME.to_string(),
            format: ScreenshotFormat::default(),
            output_directory: None,
            status: ScreenshotStatus::default(),
            actions: Vec::new(),
            disposed: false,
        };
        plugin.setup_actions();
        plugin
    }

    /// Initialize the plugin (called after construction).
    pub fn init(&mut self) {
        // No-op in the Rust port; the Java original calls super.init().
    }

    /// Dispose of the plugin, releasing resources.
    pub fn dispose(&mut self) {
        self.actions.clear();
        self.disposed = true;
    }

    /// Whether the plugin has been disposed.
    pub fn is_disposed(&self) -> bool {
        self.disposed
    }

    // -----------------------------------------------------------------------
    // Action setup
    // -----------------------------------------------------------------------

    /// Register the two screenshot actions.
    fn setup_actions(&mut self) {
        self.actions.push(ScreenshotAction {
            name: "Capture Active Component".to_string(),
            description: "Takes a screenshot of the active component provider and exports it to PNG format."
                .to_string(),
            key_binding: "Alt+F11".to_string(),
            group: Self::MENU_GROUP.to_string(),
            menu_path: vec!["Tools".to_string(), "Capture Active Component".to_string()],
        });

        self.actions.push(ScreenshotAction {
            name: "Capture Current Tool Frame".to_string(),
            description: "Takes a screenshot of the active tool and exports it to PNG format."
                .to_string(),
            key_binding: "Alt+F12".to_string(),
            group: Self::MENU_GROUP.to_string(),
            menu_path: vec![
                "Tools".to_string(),
                "Capture Current Tool Frame".to_string(),
            ],
        });
    }

    // -----------------------------------------------------------------------
    // File handling
    // -----------------------------------------------------------------------

    /// Generate the output file path for a capture target.
    ///
    /// This mirrors the Java `getFile()` method which:
    /// 1. Creates a default filename from the component/window name.
    /// 2. Ensures the `.png` extension is present.
    pub fn generate_output_path(&self, target: &CaptureTarget) -> PathBuf {
        let stem = target.filename_stem();
        let filename = ensure_extension(&stem, self.format.extension());

        if let Some(ref dir) = self.output_directory {
            dir.join(&filename)
        } else {
            PathBuf::from(&filename)
        }
    }

    /// Ensure the file path has the correct extension for the current format.
    pub fn ensure_correct_extension(&self, path: &Path) -> PathBuf {
        ensure_path_extension(path, self.format.extension())
    }

    // -----------------------------------------------------------------------
    // Capture operations (stubs -- actual rendering requires GUI layer)
    // -----------------------------------------------------------------------

    /// Capture the active component.
    ///
    /// In the full implementation this would:
    /// 1. Get the active component from the DockingWindowManager.
    /// 2. Call `component.createImage(width, height)` and paint into it.
    /// 3. Write the image to disk via `ImageIO.write`.
    ///
    /// Returns a `CaptureResult` describing what would be saved.
    pub fn capture_active_component(
        &mut self,
        component_name: &str,
        width: u32,
        height: u32,
    ) -> ScreenshotResult {
        let target = CaptureTarget::ActiveComponent {
            component_name: component_name.to_string(),
        };
        let path = self.generate_output_path(&target);
        self.status = ScreenshotStatus::Success(format!("Captured tool to {}", path.display()));
        ScreenshotResult::Ok(CaptureResult {
            file_path: path,
            width,
            height,
            format: self.format,
            file_size: 0,
        })
    }

    /// Capture the entire tool frame.
    ///
    /// In the full implementation this would:
    /// 1. Get the active window from DockingWindowManager.
    /// 2. Call `window.createImage(width, height)` and paint into it.
    /// 3. Write the image to disk via `ImageIO.write`.
    ///
    /// Returns a `CaptureResult` describing what would be saved.
    pub fn capture_tool_frame(
        &mut self,
        window_title: &str,
        width: u32,
        height: u32,
    ) -> ScreenshotResult {
        let target = CaptureTarget::ToolFrame {
            window_title: window_title.to_string(),
        };
        let path = self.generate_output_path(&target);
        self.status = ScreenshotStatus::Success(format!("Captured tool to {}", path.display()));
        ScreenshotResult::Ok(CaptureResult {
            file_path: path,
            width,
            height,
            format: self.format,
            file_size: 0,
        })
    }

    /// Get the current status message (mirrors `tool.setStatusInfo()`).
    pub fn status_message(&self) -> String {
        self.status.to_string()
    }
}

impl Default for ScreenshotPlugin {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// ScreenshotResult
// ---------------------------------------------------------------------------

/// Result of a screenshot capture attempt.
#[derive(Debug)]
pub enum ScreenshotResult {
    /// Capture succeeded.
    Ok(CaptureResult),
    /// No active component found.
    NoActiveComponent,
    /// File dialog was cancelled.
    Cancelled,
    /// An error occurred during capture or save.
    Error(String),
}

impl ScreenshotResult {
    /// Whether the capture succeeded.
    pub fn is_ok(&self) -> bool {
        matches!(self, ScreenshotResult::Ok(_))
    }

    /// Get the capture result, if successful.
    pub fn result(&self) -> Option<&CaptureResult> {
        match self {
            ScreenshotResult::Ok(r) => Some(r),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Utility functions
// ---------------------------------------------------------------------------

/// Sanitize a string for use as a filename.
///
/// Replaces characters that are invalid in filenames on common operating
/// systems with underscores.
fn sanitize_filename(name: &str) -> String {
    name.chars()
        .map(|c| match c {
            '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|' => '_',
            c if c.is_control() => '_',
            c => c,
        })
        .collect()
}

/// Ensure a filename has the given extension.
fn ensure_extension(stem: &str, ext: &str) -> String {
    let dot_ext = format!(".{}", ext);
    if stem.ends_with(&dot_ext) {
        stem.to_string()
    } else {
        format!("{}{}", stem, dot_ext)
    }
}

/// Ensure a file path has the given extension.
fn ensure_path_extension(path: &Path, ext: &str) -> PathBuf {
    match path.extension() {
        Some(existing) if existing.to_string_lossy().eq_ignore_ascii_case(ext) => {
            path.to_path_buf()
        }
        _ => {
            let mut new_path = path.to_path_buf();
            new_path.set_extension(ext);
            new_path
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plugin_creation() {
        let plugin = ScreenshotPlugin::new();
        assert_eq!(plugin.name, "ScreenshotPlugin");
        assert_eq!(plugin.format, ScreenshotFormat::Png);
        assert!(!plugin.disposed);
    }

    #[test]
    fn test_plugin_actions() {
        let plugin = ScreenshotPlugin::new();
        assert_eq!(plugin.actions.len(), 2);
        assert_eq!(plugin.actions[0].name, "Capture Active Component");
        assert_eq!(plugin.actions[0].key_binding, "Alt+F11");
        assert_eq!(plugin.actions[1].name, "Capture Current Tool Frame");
        assert_eq!(plugin.actions[1].key_binding, "Alt+F12");
    }

    #[test]
    fn test_plugin_dispose() {
        let mut plugin = ScreenshotPlugin::new();
        assert!(!plugin.is_disposed());
        plugin.dispose();
        assert!(plugin.is_disposed());
        assert!(plugin.actions.is_empty());
    }

    #[test]
    fn test_plugin_init() {
        let mut plugin = ScreenshotPlugin::new();
        plugin.init(); // should not panic
    }

    #[test]
    fn test_format_extension() {
        assert_eq!(ScreenshotFormat::Png.extension(), "png");
        assert_eq!(ScreenshotFormat::Jpeg.extension(), "jpg");
        assert_eq!(ScreenshotFormat::Bmp.extension(), "bmp");
    }

    #[test]
    fn test_format_mime_type() {
        assert_eq!(ScreenshotFormat::Png.mime_type(), "image/png");
        assert_eq!(ScreenshotFormat::Jpeg.mime_type(), "image/jpeg");
        assert_eq!(ScreenshotFormat::Bmp.mime_type(), "image/bmp");
    }

    #[test]
    fn test_format_display_name() {
        assert_eq!(ScreenshotFormat::Png.display_name(), "Portable Network Graphics");
        assert_eq!(
            format!("{}", ScreenshotFormat::Jpeg),
            "JPEG Image"
        );
    }

    #[test]
    fn test_format_default() {
        assert_eq!(ScreenshotFormat::default(), ScreenshotFormat::Png);
    }

    #[test]
    fn test_capture_target_filename_stem() {
        let target = CaptureTarget::ActiveComponent {
            component_name: "Listing".to_string(),
        };
        assert_eq!(target.filename_stem(), "Listing");

        let target = CaptureTarget::ToolFrame {
            window_title: "CodeBrowser".to_string(),
        };
        assert_eq!(target.filename_stem(), "CodeBrowser");
    }

    #[test]
    fn test_capture_target_empty_title() {
        let target = CaptureTarget::ToolFrame {
            window_title: String::new(),
        };
        assert_eq!(target.filename_stem(), "Ghidra Window");
    }

    #[test]
    fn test_capture_target_special_chars() {
        let target = CaptureTarget::ActiveComponent {
            component_name: "My:Component/Name".to_string(),
        };
        let stem = target.filename_stem();
        assert!(!stem.contains(':'));
        assert!(!stem.contains('/'));
    }

    #[test]
    fn test_generate_output_path() {
        let plugin = ScreenshotPlugin::new();
        let target = CaptureTarget::ActiveComponent {
            component_name: "Listing".to_string(),
        };
        let path = plugin.generate_output_path(&target);
        assert_eq!(path, PathBuf::from("Listing.png"));
    }

    #[test]
    fn test_generate_output_path_with_dir() {
        let mut plugin = ScreenshotPlugin::new();
        plugin.output_directory = Some(PathBuf::from("/tmp/screenshots"));
        let target = CaptureTarget::ToolFrame {
            window_title: "CodeBrowser".to_string(),
        };
        let path = plugin.generate_output_path(&target);
        assert_eq!(path, PathBuf::from("/tmp/screenshots/CodeBrowser.png"));
    }

    #[test]
    fn test_ensure_correct_extension() {
        let plugin = ScreenshotPlugin::new();
        let path = PathBuf::from("screenshot.bmp");
        let result = plugin.ensure_correct_extension(&path);
        assert_eq!(result, PathBuf::from("screenshot.png"));

        let path = PathBuf::from("screenshot.png");
        let result = plugin.ensure_correct_extension(&path);
        assert_eq!(result, PathBuf::from("screenshot.png"));

        let path = PathBuf::from("screenshot");
        let result = plugin.ensure_correct_extension(&path);
        assert_eq!(result, PathBuf::from("screenshot.png"));
    }

    #[test]
    fn test_capture_active_component() {
        let mut plugin = ScreenshotPlugin::new();
        let result = plugin.capture_active_component("Listing", 800, 600);
        assert!(result.is_ok());
        let cap = result.result().unwrap();
        assert_eq!(cap.width, 800);
        assert_eq!(cap.height, 600);
        assert_eq!(cap.format, ScreenshotFormat::Png);
        assert_eq!(cap.file_path, PathBuf::from("Listing.png"));
    }

    #[test]
    fn test_capture_tool_frame() {
        let mut plugin = ScreenshotPlugin::new();
        let result = plugin.capture_tool_frame("CodeBrowser", 1024, 768);
        assert!(result.is_ok());
        let cap = result.result().unwrap();
        assert_eq!(cap.width, 1024);
        assert_eq!(cap.height, 768);
    }

    #[test]
    fn test_status_after_capture() {
        let mut plugin = ScreenshotPlugin::new();
        assert_eq!(plugin.status, ScreenshotStatus::Idle);
        plugin.capture_active_component("Test", 100, 100);
        assert!(matches!(plugin.status, ScreenshotStatus::Success(_)));
    }

    #[test]
    fn test_status_message() {
        let plugin = ScreenshotPlugin::new();
        assert_eq!(plugin.status_message(), "Idle");

        let mut plugin = ScreenshotPlugin::new();
        plugin.capture_tool_frame("Test", 100, 100);
        assert!(plugin.status_message().contains("Success"));
    }

    #[test]
    fn test_capture_result_summary() {
        let result = CaptureResult {
            file_path: PathBuf::from("/tmp/test.png"),
            width: 1920,
            height: 1080,
            format: ScreenshotFormat::Png,
            file_size: 50000,
        };
        let summary = result.summary();
        assert!(summary.contains("1920x1080"));
        assert!(summary.contains("test.png"));
        assert!(summary.contains("Portable Network Graphics"));
    }

    #[test]
    fn test_screenshot_status_display() {
        assert_eq!(ScreenshotStatus::Idle.to_string(), "Idle");
        assert_eq!(
            ScreenshotStatus::Success("ok".into()).to_string(),
            "Success: ok"
        );
        assert_eq!(
            ScreenshotStatus::Error("fail".into()).to_string(),
            "Error: fail"
        );
    }

    #[test]
    fn test_sanitize_filename() {
        assert_eq!(sanitize_filename("hello"), "hello");
        assert_eq!(sanitize_filename("my/file"), "my_file");
        assert_eq!(sanitize_filename("a:b*c?d"), "a_b_c_d");
        assert_eq!(sanitize_filename("normal_name"), "normal_name");
    }

    #[test]
    fn test_ensure_extension() {
        assert_eq!(ensure_extension("test", "png"), "test.png");
        assert_eq!(ensure_extension("test.png", "png"), "test.png");
        assert_eq!(ensure_extension("test.bmp", "png"), "test.bmp.png");
    }

    #[test]
    fn test_ensure_path_extension() {
        assert_eq!(
            ensure_path_extension(Path::new("test.png"), "png"),
            PathBuf::from("test.png")
        );
        assert_eq!(
            ensure_path_extension(Path::new("test.bmp"), "png"),
            PathBuf::from("test.png")
        );
        assert_eq!(
            ensure_path_extension(Path::new("test"), "png"),
            PathBuf::from("test.png")
        );
    }

    #[test]
    fn test_menu_paths() {
        let plugin = ScreenshotPlugin::new();
        assert!(plugin.actions[0].menu_path.contains(&"Tools".to_string()));
        assert!(plugin.actions[1].menu_path.contains(&"Tools".to_string()));
    }

    #[test]
    fn test_menu_group() {
        let plugin = ScreenshotPlugin::new();
        for action in &plugin.actions {
            assert_eq!(action.group, "ScreenCapture");
        }
    }

    #[test]
    fn test_format_change() {
        let mut plugin = ScreenshotPlugin::new();
        plugin.format = ScreenshotFormat::Jpeg;
        let path = plugin.generate_output_path(&CaptureTarget::ActiveComponent {
            component_name: "Test".to_string(),
        });
        assert_eq!(path, PathBuf::from("Test.jpg"));
    }
}
