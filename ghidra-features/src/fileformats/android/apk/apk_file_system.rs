//! APK virtual filesystem implementation.
//!
//! Ported from Ghidra's `ghidra.file.formats.android.apk.ApkFileSystem`.
//!
//! APK files are ZIP archives, so this filesystem delegates to the ZIP
//! filesystem for actual entry enumeration and extraction, adding
//! APK-specific metadata (manifest, DEX files, native libraries,
//! signatures, resource table) as overlays.

use std::collections::HashSet;

use crate::gfilesystem::{FsrlRoot, GFile, GFileSystem};

use super::super::super::apk::{self, ApkFile};

// ---------------------------------------------------------------------------
// ApkFileSystem
// ---------------------------------------------------------------------------

/// A virtual filesystem that exposes the contents of an Android APK package.
///
/// APK is really just a ZIP file, so the filesystem delegates to ZIP
/// parsing for entry enumeration and extraction, and overlays APK-specific
/// metadata (manifest, DEX inventory, native library list, signatures,
/// and resource table).
///
/// Ported from `ghidra.file.formats.android.apk.ApkFileSystem`.
#[derive(Debug, Clone)]
pub struct ApkFileSystem {
    /// The FSRL root for this filesystem instance.
    fsrl_root: FsrlRoot,
    /// Human-readable name (typically the APK filename).
    name: String,
    /// Parsed APK metadata.
    apk: ApkFile,
    /// Root directory entry.
    root: GFile,
    /// Whether the filesystem has been opened/indexed.
    opened: bool,
    /// All ZIP entries as virtual GFile entries.
    entries: Vec<GFile>,
}

impl ApkFileSystem {
    /// The filesystem type identifier.
    pub const FS_TYPE: &'static str = "apk";

    /// Create a new APK filesystem from parsed APK data.
    ///
    /// The `source_name` is the human-readable name (typically the file name).
    pub fn new(source_name: impl Into<String>, apk: ApkFile) -> Self {
        let name = source_name.into();
        let fsrl_root = FsrlRoot::new("apk".to_string());
        let root = GFile::new(
            fsrl_root.clone(),
            String::new(),
            String::new(),
            true,
            -1,
        );

        let mut fs = Self {
            fsrl_root,
            name,
            apk,
            root,
            opened: false,
            entries: Vec::new(),
        };
        fs.index_entries();
        fs
    }

    /// Build the filesystem from raw APK bytes.
    ///
    /// Parses the APK and creates the filesystem in one step.
    pub fn from_bytes(source_name: impl Into<String>, data: &[u8]) -> Result<Self, apk::ApkError> {
        let apk = apk::parse_apk(data)?;
        Ok(Self::new(source_name, apk))
    }

    /// Index all ZIP entries as virtual files and directories.
    fn index_entries(&mut self) {
        // Add manifest as a top-level file
        if self.apk.manifest_xml.is_some() {
            self.entries.push(GFile::new(
                self.fsrl_root.clone(),
                "AndroidManifest.xml".to_string(),
                "AndroidManifest.xml".to_string(),
                false,
                self.apk.manifest_xml.as_ref().map(|v| v.len() as i64).unwrap_or(0),
            ));
        }

        // Add DEX files
        for dex_name in &self.apk.dex_files {
            self.entries.push(GFile::new(
                self.fsrl_root.clone(),
                dex_name.clone(),
                dex_name.clone(),
                false,
                -1,
            ));
        }

        // Add native libraries (create lib/<abi>/ directory structure)
        let mut seen_dirs = HashSet::new();
        for lib in &self.apk.native_libs {
            // Ensure parent directories exist
            let parts: Vec<&str> = lib.path.split('/').collect();
            for i in 1..parts.len() {
                let dir_path = parts[..i].join("/");
                if seen_dirs.insert(dir_path.clone()) {
                    let dir_name = parts[i - 1].to_string();
                    self.entries.push(GFile::new(
                        self.fsrl_root.clone(),
                        dir_path,
                        dir_name,
                        true,
                        -1,
                    ));
                }
            }

            self.entries.push(GFile::new(
                self.fsrl_root.clone(),
                lib.path.clone(),
                lib.filename.clone(),
                false,
                lib.uncompressed_size as i64,
            ));
        }

        // Add resources.arsc
        if self.apk.resources.is_some() {
            self.entries.push(GFile::new(
                self.fsrl_root.clone(),
                "resources.arsc".to_string(),
                "resources.arsc".to_string(),
                false,
                -1,
            ));
        }

        // Add signature files
        for sig in &self.apk.signatures {
            let short_name = sig
                .filename
                .rsplit('/')
                .next()
                .unwrap_or(&sig.filename)
                .to_string();
            // Ensure META-INF directory
            if seen_dirs.insert("META-INF".to_string()) {
                self.entries.push(GFile::new(
                    self.fsrl_root.clone(),
                    "META-INF".to_string(),
                    "META-INF".to_string(),
                    true,
                    -1,
                ));
            }
            self.entries.push(GFile::new(
                self.fsrl_root.clone(),
                sig.filename.clone(),
                short_name,
                false,
                -1,
            ));
        }

        // Add remaining ZIP entries that were not already enumerated
        for entry_name in &self.apk.all_entries {
            let already_added = self.entries.iter().any(|e| e.path() == entry_name.as_str())
                || entry_name == "AndroidManifest.xml"
                || entry_name == "resources.arsc";
            if !already_added {
                let is_dir = entry_name.ends_with('/');
                let display_name = entry_name.trim_end_matches('/').to_string();
                let short_name = display_name
                    .rsplit('/')
                    .next()
                    .unwrap_or(&display_name)
                    .to_string();

                // Ensure parent directories
                let parts: Vec<&str> = display_name.split('/').collect();
                for i in 1..parts.len() {
                    let dir_path = parts[..i].join("/");
                    if seen_dirs.insert(dir_path.clone()) {
                        let dir_name = parts[i - 1].to_string();
                        self.entries.push(GFile::new(
                            self.fsrl_root.clone(),
                            dir_path,
                            dir_name,
                            true,
                            -1,
                        ));
                    }
                }

                if is_dir {
                    if seen_dirs.insert(display_name.clone()) {
                        self.entries.push(GFile::new(
                            self.fsrl_root.clone(),
                            display_name,
                            short_name,
                            true,
                            -1,
                        ));
                    }
                } else {
                    self.entries.push(GFile::new(
                        self.fsrl_root.clone(),
                        entry_name.clone(),
                        short_name,
                        false,
                        -1,
                    ));
                }
            }
        }

        self.opened = true;
    }

    /// Get the parsed APK metadata.
    pub fn apk(&self) -> &ApkFile {
        &self.apk
    }

    /// Get the package name from the APK manifest.
    pub fn package_name(&self) -> &str {
        &self.apk.package_name
    }

    /// Get the list of DEX files found in the APK.
    pub fn dex_files(&self) -> &[String] {
        &self.apk.dex_files
    }

    /// Get the list of native libraries found in the APK.
    pub fn native_libs(&self) -> &[apk::NativeLibInfo] {
        &self.apk.native_libs
    }

    /// Get the permissions declared in the manifest.
    pub fn permissions(&self) -> &[String] {
        &self.apk.permissions
    }

    /// Whether the APK has been fully indexed.
    pub fn is_opened(&self) -> bool {
        self.opened
    }

    /// Total number of file entries (including directories).
    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }
}

// ---------------------------------------------------------------------------
// GFileSystem trait implementation
// ---------------------------------------------------------------------------

impl GFileSystem for ApkFileSystem {
    fn name(&self) -> &str {
        &self.name
    }

    fn fs_type(&self) -> &str {
        Self::FS_TYPE
    }

    fn fsrl_root(&self) -> &FsrlRoot {
        &self.fsrl_root
    }

    fn is_closed(&self) -> bool {
        !self.opened
    }

    fn close(&mut self) {
        self.opened = false;
        self.entries.clear();
    }

    fn file_count(&self) -> i64 {
        self.entries.len() as i64
    }

    fn lookup(&self, path: &str) -> Option<GFile> {
        if path.is_empty() || path == "/" {
            return Some(self.root.clone());
        }
        let normalized = path.trim_start_matches('/');
        self.entries
            .iter()
            .find(|e| {
                let entry_path = e.path();
                entry_path == normalized || entry_path.trim_start_matches('/') == normalized
            })
            .cloned()
    }

    fn get_listing(&self, directory: Option<&GFile>) -> Vec<GFile> {
        let dir_path = match directory {
            Some(d) => d.path().to_string(),
            None => String::new(),
        };
        let normalized = dir_path.trim_start_matches('/').trim_end_matches('/');

        self.entries
            .iter()
            .filter(|e| {
                let entry_path = e.path();
                let entry_trimmed = entry_path.trim_start_matches('/');

                if normalized.is_empty() {
                    // Root listing: entries with no '/' separator
                    !entry_trimmed.contains('/')
                } else {
                    // Subdirectory listing: entries whose parent matches
                    entry_trimmed.starts_with(normalized)
                        && entry_trimmed[normalized.len()..]
                            .trim_start_matches('/')
                            .split('/')
                            .count()
                            == 1
                }
            })
            .cloned()
            .collect()
    }

    fn root_dir(&self) -> Option<GFile> {
        Some(self.root.clone())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_apk() -> ApkFile {
        ApkFile {
            package_name: "com.example.test".to_string(),
            version_code: 1,
            version_name: "1.0".to_string(),
            min_sdk_version: 21,
            target_sdk_version: 33,
            max_sdk_version: None,
            platform_build_version_code: None,
            platform_build_version_name: None,
            compile_sdk_version: Some(33),
            compile_sdk_version_codename: None,
            debuggable: false,
            allow_backup: true,
            application_label: Some("TestApp".to_string()),
            application_icon: None,
            permissions: vec!["android.permission.INTERNET".to_string()],
            permissions_with_max_sdk: Vec::new(),
            features: Vec::new(),
            libraries: Vec::new(),
            activities: Vec::new(),
            services: Vec::new(),
            receivers: Vec::new(),
            providers: Vec::new(),
            dex_files: vec!["classes.dex".to_string(), "classes2.dex".to_string()],
            native_libs: vec![apk::NativeLibInfo {
                path: "lib/arm64-v8a/libnative.so".to_string(),
                abi: "arm64-v8a".to_string(),
                filename: "libnative.so".to_string(),
                compressed_size: 50000,
                uncompressed_size: 120000,
            }],
            signatures: vec![apk::SignatureInfo {
                filename: "META-INF/CERT.RSA".to_string(),
                subject: String::new(),
                issuer: String::new(),
                sha256_fingerprint: String::new(),
                valid_from: String::new(),
                valid_until: String::new(),
            }],
            manifest_xml: Some(b"fake manifest".to_vec()),
            resources: Some(apk::ResourceTable {
                package_name: "com.example.test".to_string(),
                string_pool: Vec::new(),
                entries: std::collections::HashMap::new(),
            }),
            all_entries: vec![
                "AndroidManifest.xml".to_string(),
                "classes.dex".to_string(),
                "classes2.dex".to_string(),
                "lib/".to_string(),
                "lib/arm64-v8a/".to_string(),
                "lib/arm64-v8a/libnative.so".to_string(),
                "META-INF/".to_string(),
                "META-INF/CERT.RSA".to_string(),
                "resources.arsc".to_string(),
                "res/layout/main.xml".to_string(),
            ],
            namespaces: Vec::new(),
        }
    }

    #[test]
    fn test_apk_fs_creation() {
        let apk = make_test_apk();
        let fs = ApkFileSystem::new("test.apk", apk);
        assert_eq!(fs.name(), "test.apk");
        assert_eq!(fs.fs_type(), "apk");
        assert!(fs.is_opened());
    }

    #[test]
    fn test_apk_fs_package_name() {
        let apk = make_test_apk();
        let fs = ApkFileSystem::new("test.apk", apk);
        assert_eq!(fs.package_name(), "com.example.test");
    }

    #[test]
    fn test_apk_fs_dex_files() {
        let apk = make_test_apk();
        let fs = ApkFileSystem::new("test.apk", apk);
        assert_eq!(fs.dex_files().len(), 2);
        assert_eq!(fs.dex_files()[0], "classes.dex");
    }

    #[test]
    fn test_apk_fs_native_libs() {
        let apk = make_test_apk();
        let fs = ApkFileSystem::new("test.apk", apk);
        assert_eq!(fs.native_libs().len(), 1);
        assert_eq!(fs.native_libs()[0].abi, "arm64-v8a");
    }

    #[test]
    fn test_apk_fs_permissions() {
        let apk = make_test_apk();
        let fs = ApkFileSystem::new("test.apk", apk);
        assert!(fs
            .permissions()
            .contains(&"android.permission.INTERNET".to_string()));
    }

    #[test]
    fn test_apk_fs_entry_count() {
        let apk = make_test_apk();
        let fs = ApkFileSystem::new("test.apk", apk);
        assert!(fs.entry_count() > 0);
    }

    #[test]
    fn test_apk_fs_root_lookup() {
        let apk = make_test_apk();
        let fs = ApkFileSystem::new("test.apk", apk);
        let root = fs.lookup("");
        assert!(root.is_some());
        assert!(root.unwrap().is_directory());
    }

    #[test]
    fn test_apk_fs_lookup_by_path() {
        let apk = make_test_apk();
        let fs = ApkFileSystem::new("test.apk", apk);
        let manifest = fs.lookup("AndroidManifest.xml");
        assert!(manifest.is_some());
        assert_eq!(manifest.unwrap().name(), "AndroidManifest.xml");
    }

    #[test]
    fn test_apk_fs_lookup_nonexistent() {
        let apk = make_test_apk();
        let fs = ApkFileSystem::new("test.apk", apk);
        let missing = fs.lookup("nonexistent.txt");
        assert!(missing.is_none());
    }

    #[test]
    fn test_apk_fs_close() {
        let apk = make_test_apk();
        let mut fs = ApkFileSystem::new("test.apk", apk);
        assert!(fs.is_opened());
        fs.close();
        assert!(fs.is_closed());
        assert_eq!(fs.entry_count(), 0);
    }

    #[test]
    fn test_apk_fs_root_dir() {
        let apk = make_test_apk();
        let fs = ApkFileSystem::new("test.apk", apk);
        let root = fs.root_dir();
        assert!(root.is_some());
        assert!(root.unwrap().is_directory());
    }

    #[test]
    fn test_apk_fs_get_listing_root() {
        let apk = make_test_apk();
        let fs = ApkFileSystem::new("test.apk", apk);
        let listing = fs.get_listing(None);
        // Should contain top-level items like AndroidManifest.xml, classes.dex, etc.
        assert!(!listing.is_empty());
    }

    #[test]
    fn test_apk_fs_fsrl_root() {
        let apk = make_test_apk();
        let fs = ApkFileSystem::new("test.apk", apk);
        assert_eq!(fs.fsrl_root().fs_type(), "apk");
    }

    #[test]
    fn test_apk_fs_type_constant() {
        assert_eq!(ApkFileSystem::FS_TYPE, "apk");
    }

    #[test]
    fn test_apk_fs_file_count() {
        let apk = make_test_apk();
        let fs = ApkFileSystem::new("test.apk", apk);
        assert_eq!(fs.file_count() as usize, fs.entry_count());
    }

    #[test]
    fn test_apk_fs_not_closed_initially() {
        let apk = make_test_apk();
        let fs = ApkFileSystem::new("test.apk", apk);
        assert!(!fs.is_closed());
    }
}
