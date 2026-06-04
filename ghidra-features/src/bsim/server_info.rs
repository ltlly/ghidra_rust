//! BSim server information with URL parsing -- port of Ghidra's
//! `ghidra.features.bsim.query.BSimServerInfo`.
//!
//! Provides a comprehensive server info type that can be constructed from
//! URLs, with support for PostgreSQL, Elasticsearch, and file-based (H2)
//! database types.

use std::fmt;

/// Database types supported by BSim.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum DatabaseType {
    /// PostgreSQL database.
    Postgres,
    /// Elasticsearch database.
    Elastic,
    /// File-based (H2) database.
    File,
}

impl DatabaseType {
    /// All available database types.
    pub fn all() -> &'static [DatabaseType] {
        &[Self::Postgres, Self::Elastic, Self::File]
    }
}

impl fmt::Display for DatabaseType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Postgres => write!(f, "postgres"),
            Self::Elastic => write!(f, "elastic"),
            Self::File => write!(f, "file"),
        }
    }
}

impl std::str::FromStr for DatabaseType {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "postgres" | "postgresql" => Ok(Self::Postgres),
            "elastic" | "elasticsearch" | "https" => Ok(Self::Elastic),
            "file" | "h2" => Ok(Self::File),
            _ => Err(format!("Unknown database type: {}", s)),
        }
    }
}

/// Default port for PostgreSQL.
pub const DEFAULT_POSTGRES_PORT: u16 = 5432;

/// Default port for Elasticsearch.
pub const DEFAULT_ELASTIC_PORT: u16 = 9200;

/// File extension for H2 database files.
pub const H2_FILE_EXTENSION: &str = ".mv.db";

/// BSim server connection information.
///
/// Can be constructed from a URL string or from individual components.
/// Port of Ghidra's `BSimServerInfo` class.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct BSimServerInfo {
    /// Database type.
    pub db_type: DatabaseType,
    /// Username (if any).
    pub username: Option<String>,
    /// Password (if any, discouraged).
    pub password: Option<String>,
    /// Hostname or IP address (None for file-based DBs).
    pub host: Option<String>,
    /// Port number (0 for default).
    pub port: u16,
    /// Database name (or file path for H2).
    pub db_name: String,
}

impl BSimServerInfo {
    /// Create a new server info for a remote database.
    pub fn new_remote(
        db_type: DatabaseType,
        host: impl Into<String>,
        port: u16,
        db_name: impl Into<String>,
    ) -> Self {
        let port = if port == 0 {
            default_port(db_type)
        } else {
            port
        };
        Self {
            db_type,
            username: None,
            password: None,
            host: Some(host.into()),
            port,
            db_name: db_name.into(),
        }
    }

    /// Create a new server info for a file-based database.
    pub fn new_file(db_name: impl Into<String>) -> Self {
        let mut name = db_name.into();
        if !name.ends_with(H2_FILE_EXTENSION) {
            name.push_str(H2_FILE_EXTENSION);
        }
        Self {
            db_type: DatabaseType::File,
            username: None,
            password: None,
            host: None,
            port: 0,
            db_name: name,
        }
    }

    /// Set the username.
    pub fn with_username(mut self, username: impl Into<String>) -> Self {
        self.username = Some(username.into());
        self
    }

    /// Set the password.
    pub fn with_password(mut self, password: impl Into<String>) -> Self {
        self.password = Some(password.into());
        self
    }

    /// Parse a BSim server info from a URL string.
    ///
    /// Supported URL formats:
    /// - `postgresql://host:port/dbname`
    /// - `postgresql://user@host:port/dbname`
    /// - `https://host:port/dbname` (elastic)
    /// - `elastic://host:port/dbname`
    /// - `file:/path/to/db`
    pub fn from_url(url: &str) -> Result<Self, String> {
        let url = url.trim();

        if url.starts_with("postgresql://") {
            Self::parse_postgresql_url(url)
        } else if url.starts_with("https://") || url.starts_with("elastic://") {
            Self::parse_elastic_url(url)
        } else if url.starts_with("file:") || url.starts_with("file:/") {
            Self::parse_file_url(url)
        } else {
            Err(format!("Unsupported BSim URL protocol: {}", url))
        }
    }

    fn parse_postgresql_url(url: &str) -> Result<Self, String> {
        let rest = &url["postgresql://".len()..];
        let (userinfo, after_userinfo) = if let Some(at_pos) = rest.find('@') {
            (Some(&rest[..at_pos]), &rest[at_pos + 1..])
        } else {
            (None, rest)
        };

        let (host_port, db_name) = if let Some(slash_pos) = after_userinfo.find('/') {
            (&after_userinfo[..slash_pos], &after_userinfo[slash_pos + 1..])
        } else {
            return Err("Missing database name in PostgreSQL URL".to_string());
        };

        let (host, port) = parse_host_port(host_port, DEFAULT_POSTGRES_PORT)?;
        let (username, password) = parse_userinfo(userinfo);

        Ok(Self {
            db_type: DatabaseType::Postgres,
            username,
            password,
            host: Some(host),
            port,
            db_name: urldecode(db_name),
        })
    }

    fn parse_elastic_url(url: &str) -> Result<Self, String> {
        let prefix_end = if url.starts_with("https://") {
            "https://".len()
        } else {
            "elastic://".len()
        };
        let rest = &url[prefix_end..];

        let (userinfo, after_userinfo) = if let Some(at_pos) = rest.find('@') {
            (Some(&rest[..at_pos]), &rest[at_pos + 1..])
        } else {
            (None, rest)
        };

        let (host_port, db_name) = if let Some(slash_pos) = after_userinfo.find('/') {
            (&after_userinfo[..slash_pos], &after_userinfo[slash_pos + 1..])
        } else {
            return Err("Missing database name in Elasticsearch URL".to_string());
        };

        let (host, port) = parse_host_port(host_port, DEFAULT_ELASTIC_PORT)?;
        let (username, password) = parse_userinfo(userinfo);

        Ok(Self {
            db_type: DatabaseType::Elastic,
            username,
            password,
            host: Some(host),
            port,
            db_name: urldecode(db_name),
        })
    }

    fn parse_file_url(url: &str) -> Result<Self, String> {
        let path = if url.starts_with("file://") {
            return Err("Remote file URLs not supported".to_string());
        } else if url.starts_with("file:") {
            &url["file:".len()..]
        } else {
            &url["file:/".len()..]
        };

        let path = urldecode(path);
        if path.is_empty() {
            return Err("Empty file path".to_string());
        }

        let mut db_name = path.replace('\\', "/");
        if !db_name.ends_with(H2_FILE_EXTENSION) {
            db_name.push_str(H2_FILE_EXTENSION);
        }

        Ok(Self {
            db_type: DatabaseType::File,
            username: None,
            password: None,
            host: None,
            port: 0,
            db_name,
        })
    }

    /// Convert to a URL string.
    pub fn to_url(&self) -> String {
        match self.db_type {
            DatabaseType::Postgres => {
                let userinfo = format_userinfo(&self.username, &self.password);
                format!(
                    "postgresql://{}{}:{}/{}",
                    userinfo,
                    self.host.as_deref().unwrap_or("localhost"),
                    self.port,
                    urlencode(&self.db_name)
                )
            }
            DatabaseType::Elastic => {
                let userinfo = format_userinfo(&self.username, &self.password);
                format!(
                    "https://{}{}:{}/{}",
                    userinfo,
                    self.host.as_deref().unwrap_or("localhost"),
                    self.port,
                    urlencode(&self.db_name)
                )
            }
            DatabaseType::File => {
                format!("file:{}", urlencode(&self.db_name))
            }
        }
    }

    /// Get the short database name (without path prefix or extension for file DBs).
    pub fn short_db_name(&self) -> String {
        if self.db_type == DatabaseType::File {
            let name = if let Some(pos) = self.db_name.rfind('/') {
                &self.db_name[pos + 1..]
            } else {
                &self.db_name
            };
            // Strip H2 file extension if present.
            if let Some(stripped) = name.strip_suffix(H2_FILE_EXTENSION) {
                stripped.to_string()
            } else {
                name.to_string()
            }
        } else {
            self.db_name.clone()
        }
    }

    /// Whether this is a file-based database.
    pub fn is_file(&self) -> bool {
        self.db_type == DatabaseType::File
    }

    /// Whether the path appears to be a Windows file path.
    pub fn is_windows_file_path(&self) -> bool {
        if self.db_type != DatabaseType::File {
            return false;
        }
        let path = &self.db_name;
        path.len() >= 4
            && path.as_bytes()[0].is_ascii_alphabetic()
            && path.as_bytes()[1] == b':'
            && path.as_bytes()[2] == b'/'
            && path.as_bytes()[3] != b'/'
    }

    /// Whether a password was provided.
    pub fn has_password(&self) -> bool {
        self.password.is_some()
    }

    /// Get the effective username (defaults to "user" if not set).
    pub fn effective_username(&self) -> &str {
        self.username.as_deref().unwrap_or("user")
    }
}

impl fmt::Display for BSimServerInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.db_type {
            DatabaseType::File => write!(f, "{}  ({})", self.short_db_name(), self.db_name),
            _ => write!(
                f,
                "{}  ({}: {}:{})",
                self.db_name,
                self.db_type,
                self.host.as_deref().unwrap_or("localhost"),
                self.port
            ),
        }
    }
}

/// Get the default port for a database type.
fn default_port(db_type: DatabaseType) -> u16 {
    match db_type {
        DatabaseType::Postgres => DEFAULT_POSTGRES_PORT,
        DatabaseType::Elastic => DEFAULT_ELASTIC_PORT,
        DatabaseType::File => 0,
    }
}

/// Parse `host:port` string.
fn parse_host_port(s: &str, default_port: u16) -> Result<(String, u16), String> {
    if s.is_empty() {
        return Err("Empty host".to_string());
    }
    if let Some(colon_pos) = s.rfind(':') {
        let host = s[..colon_pos].to_string();
        let port: u16 = s[colon_pos + 1..]
            .parse()
            .map_err(|_| format!("Invalid port: {}", &s[colon_pos + 1..]))?;
        Ok((host, port))
    } else {
        Ok((s.to_string(), default_port))
    }
}

/// Parse `username[:password]`.
fn parse_userinfo(info: Option<&str>) -> (Option<String>, Option<String>) {
    match info {
        None => (None, None),
        Some(s) => {
            let decoded = urldecode(s);
            if let Some(colon_pos) = decoded.find(':') {
                (
                    Some(decoded[..colon_pos].to_string()),
                    Some(decoded[colon_pos + 1..].to_string()),
                )
            } else {
                (Some(decoded), None)
            }
        }
    }
}

/// Simple URL encoding (percent-encode non-alphanumeric characters).
fn urlencode(s: &str) -> String {
    let mut result = String::with_capacity(s.len() * 3);
    for byte in s.bytes() {
        if byte.is_ascii_alphanumeric() || b"-._~".contains(&byte) {
            result.push(byte as char);
        } else {
            result.push_str(&format!("%{:02X}", byte));
        }
    }
    result
}

/// Simple URL decoding (percent-decode).
fn urldecode(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(byte) = u8::from_str_radix(
                std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or("00"),
                16,
            ) {
                result.push(byte as char);
                i += 3;
                continue;
            }
        }
        if bytes[i] == b'+' {
            result.push(' ');
        } else {
            result.push(bytes[i] as char);
        }
        i += 1;
    }
    result
}

/// Format userinfo for URL.
fn format_userinfo(username: &Option<String>, password: &Option<String>) -> String {
    match (username, password) {
        (Some(user), Some(pass)) => format!("{}:{}@", urlencode(user), urlencode(pass)),
        (Some(user), None) => format!("{}@", urlencode(user)),
        _ => String::new(),
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_remote() {
        let info = BSimServerInfo::new_remote(DatabaseType::Postgres, "myhost", 5432, "mydb");
        assert_eq!(info.db_type, DatabaseType::Postgres);
        assert_eq!(info.host.as_deref(), Some("myhost"));
        assert_eq!(info.port, 5432);
        assert_eq!(info.db_name, "mydb");
    }

    #[test]
    fn test_new_remote_default_port() {
        let info = BSimServerInfo::new_remote(DatabaseType::Elastic, "host", 0, "db");
        assert_eq!(info.port, DEFAULT_ELASTIC_PORT);
    }

    #[test]
    fn test_new_file() {
        let info = BSimServerInfo::new_file("/path/to/db");
        assert_eq!(info.db_type, DatabaseType::File);
        assert!(info.db_name.ends_with(H2_FILE_EXTENSION));
        assert!(info.is_file());
    }

    #[test]
    fn test_parse_postgresql_url() {
        let info = BSimServerInfo::from_url("postgresql://myhost:5432/mydb").unwrap();
        assert_eq!(info.db_type, DatabaseType::Postgres);
        assert_eq!(info.host.as_deref(), Some("myhost"));
        assert_eq!(info.port, 5432);
        assert_eq!(info.db_name, "mydb");
    }

    #[test]
    fn test_parse_postgresql_url_with_user() {
        let info =
            BSimServerInfo::from_url("postgresql://admin@myhost:5432/mydb").unwrap();
        assert_eq!(info.username.as_deref(), Some("admin"));
        assert!(info.password.is_none());
    }

    #[test]
    fn test_parse_elastic_url() {
        let info = BSimServerInfo::from_url("elastic://host:9200/index").unwrap();
        assert_eq!(info.db_type, DatabaseType::Elastic);
        assert_eq!(info.port, 9200);
    }

    #[test]
    fn test_parse_https_url() {
        let info = BSimServerInfo::from_url("https://host:443/index").unwrap();
        assert_eq!(info.db_type, DatabaseType::Elastic);
    }

    #[test]
    fn test_parse_file_url() {
        let info = BSimServerInfo::from_url("file:/tmp/test.db").unwrap();
        assert_eq!(info.db_type, DatabaseType::File);
        assert!(info.db_name.starts_with("/tmp/test.db"));
    }

    #[test]
    fn test_parse_unsupported_protocol() {
        assert!(BSimServerInfo::from_url("ftp://host/db").is_err());
    }

    #[test]
    fn test_to_url_round_trip() {
        let info = BSimServerInfo::new_remote(DatabaseType::Postgres, "host", 5432, "db")
            .with_username("user");
        let url = info.to_url();
        assert!(url.starts_with("postgresql://"));
        let parsed = BSimServerInfo::from_url(&url).unwrap();
        assert_eq!(parsed.db_type, info.db_type);
        assert_eq!(parsed.host, info.host);
        assert_eq!(parsed.port, info.port);
        assert_eq!(parsed.db_name, info.db_name);
    }

    #[test]
    fn test_short_db_name() {
        let info = BSimServerInfo::new_file("/path/to/mydb");
        assert_eq!(info.short_db_name(), "mydb");

        let info2 = BSimServerInfo::new_remote(DatabaseType::Postgres, "h", 5432, "testdb");
        assert_eq!(info2.short_db_name(), "testdb");
    }

    #[test]
    fn test_display() {
        let info = BSimServerInfo::new_remote(DatabaseType::Postgres, "host", 5432, "db");
        let s = format!("{}", info);
        assert!(s.contains("host"));
        assert!(s.contains("5432"));
    }

    #[test]
    fn test_database_type_from_str() {
        assert_eq!("postgres".parse::<DatabaseType>().unwrap(), DatabaseType::Postgres);
        assert_eq!("postgresql".parse::<DatabaseType>().unwrap(), DatabaseType::Postgres);
        assert_eq!("elastic".parse::<DatabaseType>().unwrap(), DatabaseType::Elastic);
        assert_eq!("file".parse::<DatabaseType>().unwrap(), DatabaseType::File);
        assert!("unknown".parse::<DatabaseType>().is_err());
    }

    #[test]
    fn test_is_windows_file_path() {
        let mut info = BSimServerInfo::new_file("C:/test");
        info.db_name = "C:/test.mv.db".to_string();
        assert!(info.is_windows_file_path());

        let info2 = BSimServerInfo::new_file("/unix/path");
        assert!(!info2.is_windows_file_path());
    }

    #[test]
    fn test_with_credentials() {
        let info = BSimServerInfo::new_remote(DatabaseType::Postgres, "h", 5432, "db")
            .with_username("user")
            .with_password("pass");
        assert!(info.has_password());
        assert_eq!(info.effective_username(), "user");
    }

    #[test]
    fn test_file_url_no_remote() {
        assert!(BSimServerInfo::from_url("file://remote/path").is_err());
    }
}
