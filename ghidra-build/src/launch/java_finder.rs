//! Java installation discovery on the host system.
//!
//! Port of `ghidra.launch.JavaFinder` and its platform-specific subclasses.

use std::path::{Path, PathBuf};

use super::app_config::AppConfig;
use super::java_version::JavaVersion;

/// Filter for what kind of Java installation to accept.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JavaFilter {
    /// JRE only (no javac).
    JreOnly,
    /// JDK only (must have javac).
    JdkOnly,
    /// Either JRE or JDK.
    Any,
}

/// Supported operating system platforms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    Windows,
    MacOS,
    Linux,
}

impl Platform {
    /// Returns the platform-specific prefix key used in launch properties.
    pub fn as_str(self) -> &'static str {
        match self {
            Platform::Windows => "WINDOWS",
            Platform::MacOS => "MACOS",
            Platform::Linux => "LINUX",
        }
    }
}

/// Detect the current platform from `cfg!` attributes.
pub fn current_platform() -> Platform {
    if cfg!(target_os = "windows") {
        Platform::Windows
    } else if cfg!(target_os = "macos") {
        Platform::MacOS
    } else {
        Platform::Linux
    }
}

/// Trait for platform-specific Java installation discovery.
pub trait JavaFinder {
    /// Returns the root directories where Java installations may be found.
    fn java_root_install_dirs(&self) -> Vec<PathBuf>;

    /// Returns the sub-directory within a root install dir where JAVA_HOME lives.
    fn java_home_sub_dir_path(&self) -> &str;

    /// Derive the JRE home from a given Java home path.
    fn jre_home_from_java_home(&self, java_home: &Path) -> PathBuf;

    /// Derive the JDK home from a given Java home path.
    fn jdk_home_from_java_home(&self, java_home: &Path) -> PathBuf;

    /// Find all supported Java home directories from system installations, sorted newest first.
    fn find_supported_java_homes(
        &self,
        app_config: &AppConfig,
        filter: JavaFilter,
    ) -> Vec<PathBuf> {
        let mut results: Vec<(PathBuf, JavaVersion)> = Vec::new();
        for root_dir in self.java_root_install_dirs() {
            if !root_dir.is_dir() {
                continue;
            }
            let entries = match std::fs::read_dir(&root_dir) {
                Ok(e) => e,
                Err(_) => continue,
            };
            for entry in entries.flatten() {
                let dir = entry.path();
                if !dir.is_dir() {
                    continue;
                }
                let sub = self.java_home_sub_dir_path();
                let base = if sub.is_empty() {
                    dir.clone()
                } else {
                    dir.join(sub)
                };

                let mut candidates = Vec::new();
                if matches!(filter, JavaFilter::Any | JavaFilter::JdkOnly) {
                    candidates.push(self.jdk_home_from_java_home(&base));
                }
                if matches!(filter, JavaFilter::Any | JavaFilter::JreOnly) {
                    candidates.push(self.jre_home_from_java_home(&base));
                }

                for candidate in candidates {
                    if let Some(version) = app_config.get_java_version(&candidate, filter) {
                        if app_config.is_java_version_supported(&version) {
                            results.push((candidate, version));
                        }
                    }
                }
            }
        }
        results.sort_by(|a, b| b.1.cmp(&a.1));
        results.into_iter().map(|(p, _)| p).collect()
    }

    /// Find a supported Java home from the current `JAVA_HOME` environment variable.
    fn find_supported_java_home_from_current(
        &self,
        app_config: &AppConfig,
        filter: JavaFilter,
    ) -> Option<PathBuf> {
        let java_home = std::env::var("JAVA_HOME").ok()?;
        let dir = PathBuf::from(java_home);
        let mut candidates = Vec::new();
        if matches!(filter, JavaFilter::Any | JavaFilter::JdkOnly) {
            candidates.push(self.jdk_home_from_java_home(&dir));
        }
        if matches!(filter, JavaFilter::Any | JavaFilter::JreOnly) {
            candidates.push(self.jre_home_from_java_home(&dir));
        }
        for candidate in candidates {
            if let Some(version) = app_config.get_java_version(&candidate, filter) {
                if app_config.is_java_version_supported(&version) {
                    return Some(candidate);
                }
            }
        }
        None
    }
}

/// Linux Java finder.
pub struct LinuxJavaFinder;

impl JavaFinder for LinuxJavaFinder {
    fn java_root_install_dirs(&self) -> Vec<PathBuf> {
        vec![PathBuf::from("/usr/lib/jvm")]
    }

    fn java_home_sub_dir_path(&self) -> &str {
        ""
    }

    fn jre_home_from_java_home(&self, java_home: &Path) -> PathBuf {
        if java_home.is_dir() && java_home.file_name().unwrap_or_default() != "jre" {
            let jre = java_home.join("jre");
            if jre.is_dir() {
                return jre;
            }
        }
        java_home.to_path_buf()
    }

    fn jdk_home_from_java_home(&self, java_home: &Path) -> PathBuf {
        let name = java_home
            .file_name()
            .unwrap_or_default()
            .to_string_lossy();
        if name == "jre" && !java_home.to_string_lossy().contains("org.eclipse.justj") {
            if let Some(parent) = java_home.parent() {
                return parent.to_path_buf();
            }
        }
        java_home.to_path_buf()
    }
}

/// macOS Java finder. Extends Linux's JDK/JRE logic with macOS-specific paths.
pub struct MacJavaFinder;

impl JavaFinder for MacJavaFinder {
    fn java_root_install_dirs(&self) -> Vec<PathBuf> {
        vec![PathBuf::from("/Library/Java/JavaVirtualMachines")]
    }

    fn java_home_sub_dir_path(&self) -> &str {
        "Contents/Home"
    }

    fn jre_home_from_java_home(&self, java_home: &Path) -> PathBuf {
        // Reuse Linux logic
        LinuxJavaFinder.jre_home_from_java_home(java_home)
    }

    fn jdk_home_from_java_home(&self, java_home: &Path) -> PathBuf {
        LinuxJavaFinder.jdk_home_from_java_home(java_home)
    }
}

/// Windows Java finder.
pub struct WindowsJavaFinder;

impl JavaFinder for WindowsJavaFinder {
    fn java_root_install_dirs(&self) -> Vec<PathBuf> {
        vec![
            PathBuf::from("C:\\Java"),
            PathBuf::from("C:\\Program Files\\Java"),
            PathBuf::from("C:\\Program Files\\Amazon Corretto"),
            PathBuf::from("C:\\Program Files\\Eclipse Adoptium"),
            PathBuf::from("C:\\Program Files\\Microsoft"),
        ]
    }

    fn java_home_sub_dir_path(&self) -> &str {
        ""
    }

    fn jre_home_from_java_home(&self, java_home: &Path) -> PathBuf {
        let name = java_home
            .file_name()
            .unwrap_or_default()
            .to_string_lossy();
        if let Some(rest) = name.strip_prefix("jdk") {
            if let Some(parent) = java_home.parent() {
                return parent.join(format!("jre{rest}"));
            }
        }
        java_home.to_path_buf()
    }

    fn jdk_home_from_java_home(&self, java_home: &Path) -> PathBuf {
        let name = java_home
            .file_name()
            .unwrap_or_default()
            .to_string_lossy();
        if let Some(rest) = name.strip_prefix("jre") {
            if let Some(parent) = java_home.parent() {
                return parent.join(format!("jdk{rest}"));
            }
        }
        java_home.to_path_buf()
    }
}

/// Create a `JavaFinder` for the current platform.
pub fn create_java_finder() -> Box<dyn JavaFinder> {
    match current_platform() {
        Platform::Windows => Box::new(WindowsJavaFinder),
        Platform::MacOS => Box::new(MacJavaFinder),
        Platform::Linux => Box::new(LinuxJavaFinder),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_current_platform() {
        // Just ensure it returns something on this Linux build
        let p = current_platform();
        assert_eq!(p, Platform::Linux);
    }

    #[test]
    fn test_linux_jre_home() {
        let finder = LinuxJavaFinder;
        let home = PathBuf::from("/usr/lib/jvm/java-17-openjdk");
        let jre = finder.jre_home_from_java_home(&home);
        // No jre subdir exists, so returns same path
        assert_eq!(jre, home);
    }

    #[test]
    fn test_linux_jdk_home_from_jre() {
        let finder = LinuxJavaFinder;
        let jre = PathBuf::from("/usr/lib/jvm/java-17-openjdk/jre");
        let jdk = finder.jdk_home_from_java_home(&jre);
        assert_eq!(jdk, PathBuf::from("/usr/lib/jvm/java-17-openjdk"));
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn test_windows_jdk_home_from_jre() {
        let finder = WindowsJavaFinder;
        let jre = PathBuf::from("C:\\Program Files\\Java\\jre1.8.0_312");
        let jdk = finder.jdk_home_from_java_home(&jre);
        assert_eq!(
            jdk,
            PathBuf::from("C:\\Program Files\\Java\\jdk1.8.0_312")
        );
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn test_windows_jre_home_from_jdk() {
        let finder = WindowsJavaFinder;
        let jdk = PathBuf::from("C:\\Program Files\\Java\\jdk-17");
        let jre = finder.jre_home_from_java_home(&jdk);
        assert_eq!(
            jre,
            PathBuf::from("C:\\Program Files\\Java\\jre-17")
        );
    }

    #[test]
    fn test_mac_sub_dir() {
        let finder = MacJavaFinder;
        assert_eq!(finder.java_home_sub_dir_path(), "Contents/Home");
    }

    #[test]
    fn test_platform_as_str() {
        assert_eq!(Platform::Windows.as_str(), "WINDOWS");
        assert_eq!(Platform::MacOS.as_str(), "MACOS");
        assert_eq!(Platform::Linux.as_str(), "LINUX");
    }
}
