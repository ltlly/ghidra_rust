//! Ghidra URL protocol handling.
//!
//! Ports the key Java types from `ghidra.framework.protocol.ghidra`:
//! - `GhidraURL` -- parsing and construction of ghidra:// URLs
//! - `Handler` -- protocol handler

use std::fmt;

use super::{ProjectLocator, ProjectResult};

// ============================================================================
// GhidraURL
// ============================================================================

/// Represents a Ghidra URL of the form `ghidra://host:port/project/path[#ref]`.
///
/// In Java: `ghidra.framework.protocol.ghidra.GhidraURL`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct GhidraUrl {
    /// The hostname (empty for local).
    pub host: String,
    /// The port number (0 for default).
    pub port: u16,
    /// The project name.
    pub project: String,
    /// The path within the project.
    pub path: String,
    /// An optional reference within the file.
    pub reference: Option<String>,
}

impl GhidraUrl {
    /// Scheme for Ghidra URLs.
    pub const SCHEME: &'static str = "ghidra";

    /// Create a new Ghidra URL.
    pub fn new(
        host: impl Into<String>,
        port: u16,
        project: impl Into<String>,
        path: impl Into<String>,
    ) -> Self {
        Self {
            host: host.into(),
            port,
            project: project.into(),
            path: path.into(),
            reference: None,
        }
    }

    /// Create a local Ghidra URL (no host/port).
    pub fn local(project: impl Into<String>, path: impl Into<String>) -> Self {
        Self::new("", 0, project, path)
    }

    /// Create a remote Ghidra URL.
    pub fn remote(
        host: impl Into<String>,
        port: u16,
        project: impl Into<String>,
        path: impl Into<String>,
    ) -> Self {
        Self::new(host, port, project, path)
    }

    /// Set the reference fragment.
    pub fn with_reference(mut self, reference: impl Into<String>) -> Self {
        self.reference = Some(reference.into());
        self
    }

    /// Whether this URL is for a local project.
    pub fn is_local(&self) -> bool {
        self.host.is_empty()
    }

    /// Whether this URL is for a remote project.
    pub fn is_remote(&self) -> bool {
        !self.host.is_empty()
    }

    /// Whether this URL refers to a project (vs. a specific file).
    pub fn is_project_url(&self) -> bool {
        self.path.is_empty() || self.path == "/"
    }

    /// Whether this URL refers to a specific file.
    pub fn is_file_url(&self) -> bool {
        !self.path.is_empty() && self.path != "/"
    }

    /// Whether the path refers to a folder (ends with '/').
    pub fn is_folder_url(&self) -> bool {
        self.path.ends_with('/')
    }

    /// The default Ghidra port.
    pub fn default_port(&self) -> u16 {
        if self.port == 0 {
            13100
        } else {
            self.port
        }
    }

    /// Get the ProjectLocator for this URL.
    pub fn project_locator(&self) -> ProjectLocator {
        ProjectLocator::new("", &self.project)
    }
}

impl fmt::Display for GhidraUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}://", Self::SCHEME)?;
        if !self.host.is_empty() {
            write!(f, "{}", self.host)?;
            if self.port != 0 {
                write!(f, ":{}", self.port)?;
            }
            write!(f, "/")?;
        }
        write!(f, "{}", self.project)?;
        if !self.path.is_empty() {
            if !self.path.starts_with('/') {
                write!(f, "/")?;
            }
            write!(f, "{}", self.path)?;
        }
        if let Some(ref reference) = self.reference {
            write!(f, "#{}", reference)?;
        }
        Ok(())
    }
}

/// Parse a Ghidra URL string.
pub fn parse_ghidra_url(url: &str) -> Result<GhidraUrl, GhidraUrlError> {
    if !url.starts_with("ghidra://") {
        return Err(GhidraUrlError::InvalidScheme(
            url.split("://").next().unwrap_or("").to_string(),
        ));
    }

    let rest = &url["ghidra://".len()..];

    // Split off the reference fragment.
    let (rest, reference) = if let Some(pos) = rest.find('#') {
        (rest[..pos].to_string(), Some(rest[pos + 1..].to_string()))
    } else {
        (rest.to_string(), None)
    };

    // Split host:port from path.
    // If the first segment contains a colon (host:port pattern), treat it as remote.
    // Otherwise, the entire rest is the project/path (local URL).
    let (host, port, path_with_project) = if rest.contains('/') {
        let slash_pos = rest.find('/').unwrap();
        let first_segment = &rest[..slash_pos];

        if first_segment.contains(':') {
            // Remote URL: ghidra://host:port/project/path
            let path_part = &rest[slash_pos + 1..];
            let colon_pos = first_segment.rfind(':').unwrap();
            let h = first_segment[..colon_pos].to_string();
            let p = first_segment[colon_pos + 1..].parse::<u16>().unwrap_or(0);
            (h, p, path_part.to_string())
        } else {
            // Local URL: ghidra://project/path (no host)
            (String::new(), 0, rest)
        }
    } else {
        (String::new(), 0, rest)
    };

    // Split project from path.
    let (project, path) = if let Some(slash_pos) = path_with_project.find('/') {
        (
            path_with_project[..slash_pos].to_string(),
            path_with_project[slash_pos..].to_string(),
        )
    } else {
        (path_with_project, String::new())
    };

    Ok(GhidraUrl {
        host,
        port,
        project,
        path,
        reference,
    })
}

/// Errors from URL parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GhidraUrlError {
    /// The URL scheme is not `ghidra`.
    InvalidScheme(String),
    /// The URL is malformed.
    Malformed(String),
}

impl fmt::Display for GhidraUrlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidScheme(s) => write!(f, "Invalid URL scheme: '{}' (expected 'ghidra')", s),
            Self::Malformed(s) => write!(f, "Malformed Ghidra URL: {}", s),
        }
    }
}

impl std::error::Error for GhidraUrlError {}

// ============================================================================
// Handler
// ============================================================================

/// Protocol handler for `ghidra://` URLs.
///
/// In Java: `ghidra.framework.protocol.ghidra.Handler`.
pub trait GhidraUrlHandler: Send + Sync {
    /// Resolve a Ghidra URL to its content.
    fn resolve(&self, url: &GhidraUrl) -> ProjectResult<UrlResource>;

    /// Whether the handler can connect to the specified host.
    fn can_connect(&self, host: &str, port: u16) -> bool;
}

/// A resource resolved from a Ghidra URL.
#[derive(Debug, Clone)]
pub struct UrlResource {
    /// The resolved path.
    pub path: String,
    /// Whether the resource is a file.
    pub is_file: bool,
    /// Whether the resource is a folder.
    pub is_folder: bool,
    /// The content type (if a file).
    pub content_type: Option<String>,
    /// The project locator.
    pub project_locator: ProjectLocator,
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ghidra_url_local() {
        let url = GhidraUrl::local("MyProject", "/path/to/file");
        assert!(url.is_local());
        assert!(!url.is_remote());
        assert!(url.is_file_url());
        assert!(!url.is_folder_url());
        assert_eq!(url.project, "MyProject");
        assert_eq!(url.path, "/path/to/file");
        assert!(url.reference.is_none());
    }

    #[test]
    fn test_ghidra_url_remote() {
        let url = GhidraUrl::remote("ghidra.example.com", 13100, "SharedProj", "/data/file");
        assert!(!url.is_local());
        assert!(url.is_remote());
        assert_eq!(url.host, "ghidra.example.com");
        assert_eq!(url.default_port(), 13100);
    }

    #[test]
    fn test_ghidra_url_with_reference() {
        let url = GhidraUrl::local("proj", "/file").with_reference("addr:0x1000");
        assert_eq!(url.reference, Some("addr:0x1000".to_string()));
    }

    #[test]
    fn test_ghidra_url_project_url() {
        let url = GhidraUrl::local("proj", "");
        assert!(url.is_project_url());
        assert!(!url.is_file_url());

        let url2 = GhidraUrl::local("proj", "/");
        assert!(url2.is_project_url());
    }

    #[test]
    fn test_ghidra_url_display() {
        let url = GhidraUrl::local("MyProject", "/data/file");
        assert_eq!(format!("{}", url), "ghidra://MyProject/data/file");

        let url2 = GhidraUrl::remote("server", 13100, "Proj", "/file");
        assert_eq!(format!("{}", url2), "ghidra://server:13100/Proj/file");

        let url3 = GhidraUrl::local("proj", "/file").with_reference("ref1");
        assert_eq!(format!("{}", url3), "ghidra://proj/file#ref1");
    }

    #[test]
    fn test_parse_ghidra_url() {
        let url = parse_ghidra_url("ghidra://MyProject/path/to/file").unwrap();
        assert!(url.is_local());
        assert_eq!(url.project, "MyProject");
        assert_eq!(url.path, "/path/to/file");

        let url2 = parse_ghidra_url("ghidra://server:13100/Proj/file").unwrap();
        assert!(url2.is_remote());
        assert_eq!(url2.host, "server");
        assert_eq!(url2.port, 13100);
        assert_eq!(url2.project, "Proj");
        assert_eq!(url2.path, "/file");

        let url3 = parse_ghidra_url("ghidra://Proj/file#ref").unwrap();
        assert_eq!(url3.reference, Some("ref".to_string()));
    }

    #[test]
    fn test_parse_ghidra_url_errors() {
        assert!(matches!(
            parse_ghidra_url("http://example.com"),
            Err(GhidraUrlError::InvalidScheme(_))
        ));
        assert!(matches!(
            parse_ghidra_url("ftp://example.com"),
            Err(GhidraUrlError::InvalidScheme(_))
        ));
    }

    #[test]
    fn test_ghidra_url_default_port() {
        let url = GhidraUrl::new("server", 0, "proj", "");
        assert_eq!(url.default_port(), 13100);

        let url2 = GhidraUrl::new("server", 8080, "proj", "");
        assert_eq!(url2.default_port(), 8080);
    }

    #[test]
    fn test_ghidra_url_project_locator() {
        let url = GhidraUrl::local("MyProject", "/file");
        let loc = url.project_locator();
        assert_eq!(loc.project_name, "MyProject");
    }

    #[test]
    fn test_ghidra_url_folder() {
        let url = GhidraUrl::local("proj", "/subdir/");
        assert!(url.is_folder_url());
        assert!(!url.is_project_url());
    }
}
