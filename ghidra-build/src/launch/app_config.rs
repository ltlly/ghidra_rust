//! Application configuration for Ghidra launch support.
//!
//! Port of `ghidra.launch.AppConfig`.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use super::java_finder::{JavaFilter, current_platform};
use super::java_version::JavaVersion;
use super::launch_properties::{LaunchProperties, LaunchPropertiesError};

/// Error type for application configuration operations.
#[derive(Debug, thiserror::Error)]
pub enum AppConfigError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Launch properties error: {0}")]
    LaunchProperties(#[from] LaunchPropertiesError),
    #[error("File not found: {0}")]
    FileNotFound(String),
    #[error("Parse error: {0}")]
    Parse(String),
}

/// Application configuration read from `application.properties` and launch properties.
#[derive(Debug)]
pub struct AppConfig {
    application_name: String,
    application_version: String,
    application_release_name: String,
    application_layout_version: String,
    min_supported_java: u32,
    max_supported_java: u32,
    compiler_compliance_level: String,
    launch_properties: Option<LaunchProperties>,
    java_home_save_file: PathBuf,
    python_command_save_file: PathBuf,
}

impl AppConfig {
    /// Create a new `AppConfig` from the installation directory.
    ///
    /// Reads `Ghidra/application.properties` and the launch properties file.
    pub fn new(install_dir: &Path) -> Result<Self, AppConfigError> {
        let app_props = load_application_properties(install_dir)?;
        let application_name = get_required_property(&app_props, "application.name")?;
        let application_version = get_required_property(&app_props, "application.version")?;
        let application_release_name =
            get_required_property(&app_props, "application.release.name")?;
        let application_layout_version =
            get_required_property(&app_props, "application.layout.version")?;
        let compiler_compliance_level =
            get_required_property(&app_props, "application.java.compiler")?;
        let min_supported_java: u32 = get_required_property(&app_props, "application.java.min")?
            .parse()
            .map_err(|_| {
                AppConfigError::Parse(
                    "Failed to parse application.java.min".to_string(),
                )
            })?;
        let max_supported_java: u32 = app_props
            .get("application.java.max")
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .map(|s| {
                s.parse().map_err(|_| {
                    AppConfigError::Parse(
                        "Failed to parse application.java.max".to_string(),
                    )
                })
            })
            .transpose()?
            .unwrap_or(0);

        let launch_properties = load_launch_properties(install_dir)?;

        let java_home_save_file =
            get_save_file(install_dir, &application_name, &application_version,
                          &application_release_name, &application_layout_version,
                          &launch_properties, "java_home.save");
        let python_command_save_file =
            get_save_file(install_dir, &application_name, &application_version,
                          &application_release_name, &application_layout_version,
                          &launch_properties, "python_command.save");

        Ok(Self {
            application_name,
            application_version,
            application_release_name,
            application_layout_version,
            min_supported_java,
            max_supported_java,
            compiler_compliance_level,
            launch_properties,
            java_home_save_file,
            python_command_save_file,
        })
    }

    /// Returns the application name (e.g., "Ghidra").
    pub fn application_name(&self) -> &str {
        &self.application_name
    }

    /// Returns the application version.
    pub fn application_version(&self) -> &str {
        &self.application_version
    }

    /// Returns the release name (e.g., "PUBLIC").
    pub fn application_release_name(&self) -> &str {
        &self.application_release_name
    }

    /// Returns the compiler compliance level.
    pub fn compiler_compliance_level(&self) -> &str {
        &self.compiler_compliance_level
    }

    /// Returns the minimum supported Java major version.
    pub fn min_supported_java(&self) -> u32 {
        self.min_supported_java
    }

    /// Returns the maximum supported Java major version (0 = no limit).
    pub fn max_supported_java(&self) -> u32 {
        self.max_supported_java
    }

    /// Returns the supported architecture (always 64).
    pub fn supported_architecture(&self) -> u32 {
        64
    }

    /// Returns a reference to the launch properties, if loaded.
    pub fn launch_properties(&self) -> Option<&LaunchProperties> {
        self.launch_properties.as_ref()
    }

    /// Returns the application layout version.
    pub fn application_layout_version(&self) -> &str {
        &self.application_layout_version
    }

    /// Tests whether a Java home directory is supported.
    pub fn is_supported_java_home_dir(&self, dir: &Path, filter: JavaFilter) -> bool {
        match self.get_java_version(dir, filter) {
            Some(version) => self.is_java_version_supported(&version),
            None => false,
        }
    }

    /// Tests whether a Java version is supported by this configuration.
    pub fn is_java_version_supported(&self, version: &JavaVersion) -> bool {
        if version.architecture() != self.supported_architecture() {
            return false;
        }
        let major = version.major();
        major >= self.min_supported_java
            && (self.max_supported_java == 0 || major <= self.max_supported_java)
    }

    /// Gets the Java version from a given Java home directory by running `java -version`.
    ///
    /// Returns `None` if the directory is invalid, the java binary is missing,
    /// the filter doesn't match, or the version couldn't be determined.
    pub fn get_java_version(&self, java_home: &Path, filter: JavaFilter) -> Option<JavaVersion> {
        if !java_home.is_dir() {
            return None;
        }

        let bin_dir = java_home.join("bin");
        if !bin_dir.is_dir() {
            return None;
        }

        let java_exe = find_executable(&bin_dir, "java")?;
        let javac_exe = find_executable(&bin_dir, "javac");

        match filter {
            JavaFilter::JdkOnly if javac_exe.is_none() => return None,
            JavaFilter::JreOnly if javac_exe.is_some() => return None,
            _ => {}
        }

        run_and_get_java_version(&java_exe)
    }

    /// Gets the saved Java home from the user's save file.
    pub fn get_saved_java_home(&self) -> Option<PathBuf> {
        let content = fs::read_to_string(&self.java_home_save_file).ok()?;
        let trimmed = content.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(PathBuf::from(trimmed))
        }
    }

    /// Saves the given Java home to the user's save file.
    pub fn save_java_home(&self, java_home: &Path) -> Result<PathBuf, std::io::Error> {
        if let Some(parent) = self.java_home_save_file.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&self.java_home_save_file, format!("{}\n", java_home.display()))?;
        Ok(self.java_home_save_file.clone())
    }

    /// Gets the saved Python command from the user's save file.
    pub fn get_saved_python_command(&self) -> Option<Vec<String>> {
        let content = fs::read_to_string(&self.python_command_save_file).ok()?;
        let lines: Vec<String> = content
            .lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty())
            .collect();
        if lines.is_empty() {
            None
        } else {
            Some(lines)
        }
    }
}

/// Load `application.properties` from the install dir.
fn load_application_properties(install_dir: &Path) -> Result<HashMap<String, String>, AppConfigError> {
    let path = install_dir.join("Ghidra").join("application.properties");
    if !path.is_file() {
        return Err(AppConfigError::FileNotFound(format!(
            "Application properties file does not exist: {}",
            path.display()
        )));
    }
    let content = fs::read_to_string(&path)?;
    Ok(parse_java_properties(&content))
}

/// Load the launch properties file from the install dir.
fn load_launch_properties(install_dir: &Path) -> Result<Option<LaunchProperties>, AppConfigError> {
    let is_dev = install_dir.join("build.gradle").is_file();
    let rel_path = if is_dev {
        PathBuf::from("Ghidra")
            .join("RuntimeScripts")
            .join("Common")
            .join("support")
            .join("launch.properties")
    } else {
        PathBuf::from("support").join("launch.properties")
    };
    let path = install_dir.join(rel_path);
    if !path.is_file() {
        return Ok(None);
    }
    Ok(Some(LaunchProperties::load(&path)?))
}

/// Simple Java-style properties parser (no duplicate keys).
fn parse_java_properties(content: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with("//") {
            continue;
        }
        if let Some(idx) = trimmed.find('=') {
            let key = trimmed[..idx].trim().to_string();
            let value = trimmed[idx + 1..].trim().to_string();
            map.insert(key, value);
        }
    }
    map
}

fn get_required_property(props: &HashMap<String, String>, key: &str) -> Result<String, AppConfigError> {
    props
        .get(key)
        .filter(|v| !v.is_empty())
        .cloned()
        .ok_or_else(|| AppConfigError::Parse(format!("Property \"{key}\" is not defined")))
}

/// Find an executable by name in the given directory.
fn find_executable(dir: &Path, name: &str) -> Option<PathBuf> {
    // Try both plain name and .exe (Windows)
    for suffix in &["", ".exe"] {
        let path = dir.join(format!("{name}{suffix}"));
        if path.is_file() {
            return Some(path);
        }
    }
    None
}

/// Run `java -XshowSettings:properties -version` and parse the output.
fn run_and_get_java_version(java_exe: &Path) -> Option<JavaVersion> {
    let output = Command::new(java_exe)
        .args(["-XshowSettings:properties", "-version"])
        .output()
        .ok()?;

    let stderr = String::from_utf8_lossy(&output.stderr);
    let mut version = String::new();
    let mut arch = String::new();

    for line in stderr.lines() {
        let trimmed = line.trim();
        if version.is_empty() {
            const SEARCH_VERSION: &str = "java.version = ";
            if let Some(rest) = trimmed.strip_prefix(SEARCH_VERSION) {
                version = rest.to_string();
            }
        }
        if arch.is_empty() {
            const SEARCH_ARCH: &str = "sun.arch.data.model = ";
            if let Some(rest) = trimmed.strip_prefix(SEARCH_ARCH) {
                arch = rest.to_string();
            }
        }
    }

    if version.is_empty() || arch.is_empty() {
        return None;
    }

    JavaVersion::new(&version, &arch).ok()
}

/// Compute the user settings directory and build the save file path.
fn get_save_file(
    install_dir: &Path,
    app_name: &str,
    app_version: &str,
    app_release: &str,
    layout_version: &str,
    launch_properties: &Option<LaunchProperties>,
    save_file_name: &str,
) -> PathBuf {
    let is_dev = install_dir.join("build.gradle").is_file();
    let sanitized_name = app_name.replace(char::is_whitespace, "").to_lowercase();
    let sanitized_release = app_release.replace(char::is_whitespace, "").to_uppercase();

    let mut settings_dir_name = format!("{sanitized_name}_{app_version}_{sanitized_release}");

    if is_dev {
        let dir_name = if install_dir.join("ghidra.repos.config").is_file() {
            install_dir
                .parent()
                .unwrap_or(install_dir)
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string()
        } else {
            install_dir
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string()
        };
        settings_dir_name.push_str(&format!("_location_{dir_name}"));
    }

    // Layout version 1 uses dotfile-style config
    if layout_version == "1" {
        let home = dirs_home();
        return home
            .join(format!(".{sanitized_name}"))
            .join(format!(".{settings_dir_name}"))
            .join(save_file_name);
    }

    // Check for -Dapplication.settingsdir in VM args
    if let Some(lp) = launch_properties {
        for arg in lp.vm_arg_list() {
            if let Some(rest) = arg.strip_prefix("-Dapplication.settingsdir") {
                if let Some(eq_pos) = rest.find('=') {
                    let path = rest[eq_pos + 1..].trim();
                    if !path.is_empty() {
                        return PathBuf::from(path)
                            .join(&sanitized_name)
                            .join(&settings_dir_name)
                            .join(save_file_name);
                    }
                }
            }
        }
    }

    // XDG_CONFIG_HOME
    if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
        if !xdg.is_empty() {
            return PathBuf::from(xdg)
                .join(&sanitized_name)
                .join(&settings_dir_name)
                .join(save_file_name);
        }
    }

    let home = dirs_home();
    let settings_dir = match current_platform() {
        super::java_finder::Platform::Windows => {
            let appdata = std::env::var("APPDATA").unwrap_or_default();
            if appdata.is_empty() {
                home.join("AppData")
                    .join("Roaming")
                    .join(&sanitized_name)
                    .join(&settings_dir_name)
            } else {
                PathBuf::from(appdata)
                    .join(&sanitized_name)
                    .join(&settings_dir_name)
            }
        }
        super::java_finder::Platform::Linux => home
            .join(".config")
            .join(&sanitized_name)
            .join(&settings_dir_name),
        super::java_finder::Platform::MacOS => home
            .join("Library")
            .join(&sanitized_name)
            .join(&settings_dir_name),
    };

    settings_dir.join(save_file_name)
}

/// Get the user's home directory.
fn dirs_home() -> PathBuf {
    std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/tmp"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_java_properties() {
        let content = r#"
# comment
application.name=Ghidra
application.version=11.0
application.release.name=PUBLIC
"#;
        let props = parse_java_properties(content);
        assert_eq!(props.get("application.name").unwrap(), "Ghidra");
        assert_eq!(props.get("application.version").unwrap(), "11.0");
    }

    #[test]
    fn test_get_required_property_missing() {
        let props = HashMap::new();
        assert!(get_required_property(&props, "missing").is_err());
    }

    #[test]
    fn test_find_executable_not_found() {
        let result = find_executable(Path::new("/nonexistent"), "java");
        assert!(result.is_none());
    }
}
