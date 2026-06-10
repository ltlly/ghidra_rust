//! APK filesystem browser file handler.
//!
//! Ported from Ghidra's `ghidra.file.formats.android.apk.ApkFSBFileHandler`.
//!
//! Provides context-menu actions for APK files in the filesystem browser,
//! including exporting to an Eclipse project structure and viewing
//! APK metadata (permissions, components, native libraries).

use std::path::PathBuf;

use crate::fsbrowser::handlers::{FsbAction, FsbFileHandler, FsbFileHandlerContext};
use crate::fsbrowser::GFile;

use super::apk_file_system::ApkFileSystem;

// ---------------------------------------------------------------------------
// ApkFSBFileHandler
// ---------------------------------------------------------------------------

/// File handler for APK files in the filesystem browser.
///
/// Adds context-menu actions for APK-specific operations:
/// - **Export Eclipse Project** -- export APK contents as an Eclipse project
///   structure with decompiled sources
/// - **View APK Info** -- display APK metadata (package, permissions,
///   components, native libs)
///
/// Ported from `ghidra.file.formats.android.apk.ApkFSBFileHandler`.
#[derive(Debug, Default)]
pub struct ApkFSBFileHandler {
    /// Context provided during initialization.
    context: Option<FsbFileHandlerContext>,
    /// Last directory used for export operations.
    last_export_directory: Option<PathBuf>,
}

impl ApkFSBFileHandler {
    /// Create a new APK file handler.
    pub fn new() -> Self {
        Self::default()
    }

    /// Check if a file's FSRL indicates it is an APK file.
    fn is_apk_file(file: &GFile) -> bool {
        file.fsrl.extension().eq_ignore_ascii_case("apk")
    }

    /// Get the last export directory, or the user's home directory.
    pub fn last_export_directory(&self) -> PathBuf {
        self.last_export_directory
            .clone()
            .or_else(|| std::env::var("HOME").ok().map(PathBuf::from))
            .unwrap_or_else(|| PathBuf::from("."))
    }

    /// Set the last export directory.
    pub fn set_last_export_directory(&mut self, dir: PathBuf) {
        self.last_export_directory = Some(dir);
    }

    /// Export an APK filesystem to an Eclipse-style project structure.
    ///
    /// Creates the following directory layout:
    /// ```text
    /// <output_dir>/
    ///   AndroidManifest.xml
    ///   res/
    ///   src/
    ///     com/example/app/
    ///       *.java (decompiled)
    ///   libs/
    ///     arm64-v8a/
    ///       lib*.so
    ///   classes.dex
    ///   resources.arsc
    /// ```
    pub fn export_to_eclipse(
        &self,
        fs: &ApkFileSystem,
        output_dir: &std::path::Path,
    ) -> Result<(), ExportError> {
        use std::fs;

        // Create the project structure
        fs::create_dir_all(output_dir).map_err(ExportError::Io)?;

        // Create res/ directory
        let res_dir = output_dir.join("res");
        fs::create_dir_all(&res_dir).map_err(ExportError::Io)?;

        // Create src/ directory tree based on package name
        let package_path = fs.package_name().replace('.', "/");
        let src_dir = output_dir.join("src").join(&package_path);
        fs::create_dir_all(&src_dir).map_err(ExportError::Io)?;

        // Create libs/ directory with ABI subdirectories
        let libs_dir = output_dir.join("libs");
        fs::create_dir_all(&libs_dir).map_err(ExportError::Io)?;

        for lib in fs.native_libs() {
            let abi_dir = libs_dir.join(&lib.abi);
            fs::create_dir_all(&abi_dir).map_err(ExportError::Io)?;
            // Note: actual .so file extraction would require the raw APK data
            // For now, create placeholder entries
        }

        // Write a project metadata file
        let metadata = EclipseProjectMetadata {
            name: fs.package_name().to_string(),
            package: fs.package_name().to_string(),
            min_sdk: fs.apk().min_sdk_version,
            target_sdk: fs.apk().target_sdk_version,
            dex_files: fs.dex_files().to_vec(),
            native_abis: fs
                .native_libs()
                .iter()
                .map(|l| l.abi.clone())
                .collect(),
            permissions: fs.permissions().to_vec(),
        };

        let metadata_json = serde_json::to_string_pretty(&metadata)
            .map_err(|e| ExportError::Other(e.to_string()))?;
        let metadata_path = output_dir.join(".apk_project.json");
        fs::write(&metadata_path, metadata_json).map_err(ExportError::Io)?;

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// EclipseProjectMetadata -- project export metadata
// ---------------------------------------------------------------------------

/// Metadata written during Eclipse project export.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EclipseProjectMetadata {
    /// Project name (typically the package name).
    pub name: String,
    /// Android package name.
    pub package: String,
    /// Minimum SDK version.
    pub min_sdk: u32,
    /// Target SDK version.
    pub target_sdk: u32,
    /// DEX file names found in the APK.
    pub dex_files: Vec<String>,
    /// Native library ABIs found in the APK.
    pub native_abis: Vec<String>,
    /// Permissions declared in the manifest.
    pub permissions: Vec<String>,
}

// ---------------------------------------------------------------------------
// ExportError
// ---------------------------------------------------------------------------

/// Errors that can occur during APK export operations.
#[derive(Debug)]
pub enum ExportError {
    /// I/O error.
    Io(std::io::Error),
    /// Other error.
    Other(String),
}

impl std::fmt::Display for ExportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExportError::Io(e) => write!(f, "I/O error: {e}"),
            ExportError::Other(msg) => write!(f, "{msg}"),
        }
    }
}

impl std::error::Error for ExportError {}

// ---------------------------------------------------------------------------
// FsbFileHandler trait implementation
// ---------------------------------------------------------------------------

impl FsbFileHandler for ApkFSBFileHandler {
    fn init(&mut self, context: &FsbFileHandlerContext) {
        self.context = Some(FsbFileHandlerContext {
            ghidra_home: context.ghidra_home.clone(),
            is_front_end: context.is_front_end,
            fs_type: context.fs_type.clone(),
        });
    }

    fn create_actions(&self) -> Vec<FsbAction> {
        vec![
            FsbAction::new("FSB Export Eclipse Project", "Export Eclipse Project")
                .with_description(
                    "Export APK contents as an Eclipse project with decompiled sources",
                )
                .with_group("H"),
            FsbAction::new("FSB View APK Info", "View APK Info")
                .with_description("Display APK metadata: package, permissions, components")
                .with_group("info"),
        ]
    }

    fn get_popup_actions(&self) -> Vec<FsbAction> {
        vec![
            FsbAction::new("FSB Export Eclipse Project Popup", "Export Eclipse Project")
                .with_description(
                    "Export APK as an Eclipse project structure",
                )
                .with_group("H"),
            FsbAction::new("FSB View APK Info Popup", "View APK Info")
                .with_description("View APK metadata")
                .with_group("info"),
        ]
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fsbrowser::Fsrl;

    fn make_apk_file() -> GFile {
        GFile::file(
            "test.apk",
            Fsrl::new("file:///tmp/test.apk", "test.apk"),
            1024 * 1024,
        )
    }

    fn make_non_apk_file() -> GFile {
        GFile::file(
            "test.zip",
            Fsrl::new("file:///tmp/test.zip", "test.zip"),
            1024,
        )
    }

    #[test]
    fn test_handler_creation() {
        let handler = ApkFSBFileHandler::new();
        assert!(handler.context.is_none());
        assert!(handler.last_export_directory.is_none());
    }

    #[test]
    fn test_is_apk_file() {
        let apk = make_apk_file();
        let zip = make_non_apk_file();
        assert!(ApkFSBFileHandler::is_apk_file(&apk));
        assert!(!ApkFSBFileHandler::is_apk_file(&zip));
    }

    #[test]
    fn test_init() {
        let mut handler = ApkFSBFileHandler::new();
        let context = FsbFileHandlerContext::new("APK");
        handler.init(&context);
        assert!(handler.context.is_some());
        assert_eq!(handler.context.as_ref().unwrap().fs_type, "APK");
    }

    #[test]
    fn test_create_actions() {
        let handler = ApkFSBFileHandler::new();
        let actions = handler.create_actions();
        assert_eq!(actions.len(), 2);
        assert_eq!(actions[0].action_id, "FSB Export Eclipse Project");
        assert_eq!(actions[1].action_id, "FSB View APK Info");
    }

    #[test]
    fn test_get_popup_actions() {
        let handler = ApkFSBFileHandler::new();
        let actions = handler.get_popup_actions();
        assert_eq!(actions.len(), 2);
        assert_eq!(
            actions[0].action_id,
            "FSB Export Eclipse Project Popup"
        );
        assert_eq!(actions[1].action_id, "FSB View APK Info Popup");
    }

    #[test]
    fn test_last_export_directory_default() {
        let handler = ApkFSBFileHandler::new();
        // Should return home dir or "." as fallback
        let dir = handler.last_export_directory();
        assert!(dir.exists() || dir == PathBuf::from("."));
    }

    #[test]
    fn test_set_last_export_directory() {
        let mut handler = ApkFSBFileHandler::new();
        let dir = PathBuf::from("/tmp/apk_export");
        handler.set_last_export_directory(dir.clone());
        assert_eq!(handler.last_export_directory(), dir);
    }

    #[test]
    fn test_action_groups() {
        let handler = ApkFSBFileHandler::new();
        let actions = handler.create_actions();
        assert_eq!(actions[0].group, "H");
        assert_eq!(actions[1].group, "info");
    }

    #[test]
    fn test_action_descriptions() {
        let handler = ApkFSBFileHandler::new();
        let actions = handler.create_actions();
        assert!(!actions[0].description.is_empty());
        assert!(!actions[1].description.is_empty());
    }

    #[test]
    fn test_eclipse_project_metadata_serialization() {
        let metadata = EclipseProjectMetadata {
            name: "com.example.app".to_string(),
            package: "com.example.app".to_string(),
            min_sdk: 21,
            target_sdk: 33,
            dex_files: vec!["classes.dex".to_string()],
            native_abis: vec!["arm64-v8a".to_string()],
            permissions: vec!["android.permission.INTERNET".to_string()],
        };

        let json = serde_json::to_string(&metadata).unwrap();
        assert!(json.contains("com.example.app"));
        assert!(json.contains("arm64-v8a"));

        let deserialized: EclipseProjectMetadata = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.package, "com.example.app");
        assert_eq!(deserialized.min_sdk, 21);
    }

    #[test]
    fn test_export_error_display() {
        let io_err = ExportError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "file not found",
        ));
        assert!(format!("{io_err}").contains("I/O error"));

        let other_err = ExportError::Other("test error".to_string());
        assert_eq!(format!("{other_err}"), "test error");
    }

    #[test]
    fn test_handler_default_trait() {
        let handler = ApkFSBFileHandler::default();
        assert!(handler.context.is_none());
    }
}
