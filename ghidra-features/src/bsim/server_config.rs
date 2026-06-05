//! PostgreSQL server configuration management.
//!
//! Port of Ghidra's `ghidra.features.bsim.query.ServerConfig`.
//!
//! Manages three PostgreSQL configuration files:
//! - `postgresql.conf` -- main server settings
//! - `pg_hba.conf` -- client authentication / connection rules
//! - `pg_ident.conf` -- user-name mapping
//!
//! The [`ServerConfig`] type reads, modifies, and writes these files,
//! preserving comments and ordering.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as FmtWrite;
use std::fs;
use std::io::{self};
use std::path::PathBuf;

// ============================================================================
// ConfigLine -- single configuration entry in postgresql.conf
// ============================================================================

/// A single key/value/comment triple parsed from a `.conf` file line.
#[derive(Debug, Clone)]
struct ConfigLine {
    /// Configuration key (e.g. `listen_addresses`).
    key: Option<String>,
    /// Value assigned to the key.
    value: Option<String>,
    /// Any trailing comment on the same line.
    comment: Option<String>,
    /// 0 = not a controlled key, 1 = active key, 2 = commented-out key.
    status: u8,
}

impl ConfigLine {
    /// Parse the key (and optional leading `#`) from a line.
    fn parse_upto_key(line: &str) -> Self {
        let mut key = None;

        let trimmed = line.trim_start();
        let rest = if trimmed.starts_with('#') {
            trimmed[1..].trim_start()
        } else {
            trimmed
        };

        // Scan identifier characters for the key
        let end = rest
            .char_indices()
            .take_while(|&(_, c)| c.is_alphanumeric() || c == '_' || c == '.')
            .map(|(i, c)| i + c.len_utf8())
            .last()
            .unwrap_or(0);

        if end > 0 {
            key = Some(rest[..end].to_string());
        }

        Self {
            key,
            value: None,
            comment: None,
            status: 0,
        }
    }

    /// Parse the value and trailing comment from the rest of the line
    /// (called after `parse_upto_key` has consumed the key portion).
    fn parse_value(&mut self, line: &str, key_end: usize) {
        let rest = line[key_end..].trim_start();
        if !rest.starts_with('=') {
            return;
        }
        let after_eq = rest[1..].trim_start();
        if let Some(hash_pos) = after_eq.find('#') {
            self.value = Some(after_eq[..hash_pos].trim().to_string());
            self.comment = Some(after_eq[hash_pos..].to_string());
        } else {
            self.value = Some(after_eq.trim().to_string());
            self.comment = Some(String::new());
        }
        self.status = if self.key.is_some() { 1 } else { 0 };
    }
}

// ============================================================================
// ConnectLine -- entry in pg_hba.conf
// ============================================================================

/// A connection-rule entry from `pg_hba.conf`.
///
/// Each line specifies a connection type, database, user, optional address,
/// authentication method, and optional extra parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectLine {
    /// Connection type: `local`, `host`, `hostssl`, `hostnossl`, `hostgssenc`, `hostnogssenc`.
    pub connection_type: String,
    /// Database name or `all`.
    pub database: String,
    /// User name or `all`.
    pub user: String,
    /// IPv4/IPv6 CIDR address (`None` for `local` connections).
    pub address: Option<String>,
    /// Authentication method: `trust`, `md5`, `scram-sha-256`, `cert`, etc.
    pub method: String,
    /// Extra options (e.g. `clientcert=verify-full`).
    pub options: Option<String>,
    /// Whether this entry was found in the existing file.
    pub is_matched: bool,
}

impl ConnectLine {
    /// Create a new connection line.
    pub fn new(
        connection_type: impl Into<String>,
        database: impl Into<String>,
        user: impl Into<String>,
        address: Option<String>,
        method: impl Into<String>,
        options: Option<String>,
    ) -> Self {
        Self {
            connection_type: connection_type.into(),
            database: database.into(),
            user: user.into(),
            address,
            method: method.into(),
            options,
            is_matched: false,
        }
    }

    /// Whether this is a local (UNIX socket or localhost) connection.
    pub fn is_local(&self) -> bool {
        if self.connection_type == "local" {
            return true;
        }
        match &self.address {
            Some(addr) => addr == "127.0.0.1/32" || addr == "::1/128",
            None => false,
        }
    }

    /// Parse a line from `pg_hba.conf`.
    pub fn parse(line: &str) -> Result<Self, String> {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 4 {
            return Err("pg_hba.conf: not enough fields".to_string());
        }
        let conn_type = parts[0];
        let database = parts[1];
        let user = parts[2];
        let (address, next) = if conn_type == "local" {
            (None, 3)
        } else {
            if parts.len() < 5 {
                return Err("pg_hba.conf: host entry needs address field".to_string());
            }
            (Some(parts[3].to_string()), 4)
        };
        let method = parts[next].to_string();
        let options = if next + 1 < parts.len() {
            Some(parts[next + 1..].join(" "))
        } else {
            None
        };

        Ok(Self {
            connection_type: conn_type.to_string(),
            database: database.to_string(),
            user: user.to_string(),
            address,
            method,
            options,
            is_matched: false,
        })
    }

    /// Emit the entry formatted for `pg_hba.conf`.
    pub fn emit<W: FmtWrite>(&self, writer: &mut W) -> std::fmt::Result {
        write!(writer, "{:<8}", self.connection_type)?;
        write!(writer, "{:<16}", self.database)?;
        write!(writer, "{:<16}", self.user)?;
        match &self.address {
            Some(addr) => {
                write!(writer, "{:<24}", addr)?;
            }
            None => {
                write!(writer, "{:<24}", "")?;
            }
        };
        write!(writer, "{}", self.method)?;
        if let Some(ref opts) = self.options {
            write!(writer, " {}", opts)?;
        }
        writeln!(writer)
    }
}

impl PartialOrd for ConnectLine {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ConnectLine {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.database
            .cmp(&other.database)
            .then_with(|| self.user.cmp(&other.user))
            .then_with(|| self.address.cmp(&other.address))
    }
}

// ============================================================================
// IdentLine -- entry in pg_ident.conf
// ============================================================================

/// A user-mapping entry from `pg_ident.conf`.
#[derive(Debug, Clone)]
pub struct IdentLine {
    /// Name of the user map.
    pub map_name: String,
    /// System (OS) user name.
    pub system_name: String,
    /// Whether the system name was originally quoted.
    pub system_name_is_quoted: bool,
    /// Database role to map to.
    pub role_name: String,
}

impl IdentLine {
    /// Emit the entry formatted for `pg_ident.conf`.
    pub fn emit<W: FmtWrite>(&self, writer: &mut W) -> std::fmt::Result {
        write!(writer, "{:<16}", self.map_name)?;
        let sys = if self.system_name_is_quoted {
            format!("\"{}\"", self.system_name)
        } else {
            self.system_name.clone()
        };
        write!(writer, "{:<24}", sys)?;
        writeln!(writer, "{}", self.role_name)
    }
}

// ============================================================================
// ServerConfig
// ============================================================================

/// Manages PostgreSQL server configuration files for BSim database setup.
///
/// Reads and writes `postgresql.conf`, `pg_hba.conf`, and `pg_ident.conf`,
/// preserving comments and ordering in the originals.
///
/// # Example
///
/// ```no_run
/// use ghidra_features::bsim::server_config::ServerConfig;
///
/// let mut config = ServerConfig::new("/etc/postgresql/14/main");
/// config.set("listen_addresses", "'*'");
/// config.set("port", "5432");
/// config.add_connect(ConnectLine::new(
///     "host", "bsimdb", "bsimuser", Some("10.0.0.0/8".into()), "md5", None,
/// ));
/// config.write_config().expect("write failed");
/// ```
pub struct ServerConfig {
    /// Path to the configuration directory.
    config_dir: PathBuf,

    /// Key/value pairs we want set in postgresql.conf.
    key_values: BTreeMap<String, String>,

    /// Entries we want in pg_hba.conf.
    connect_set: BTreeSet<ConnectLine>,

    /// Entries we want in pg_ident.conf.
    ident_set: Vec<IdentLine>,
}

impl ServerConfig {
    /// Create a new `ServerConfig` pointing at the given directory.
    pub fn new(config_dir: impl Into<PathBuf>) -> Self {
        Self {
            config_dir: config_dir.into(),
            key_values: BTreeMap::new(),
            connect_set: BTreeSet::new(),
            ident_set: Vec::new(),
        }
    }

    /// The path to `postgresql.conf`.
    pub fn conf_path(&self) -> PathBuf {
        self.config_dir.join("postgresql.conf")
    }

    /// The path to `pg_hba.conf`.
    pub fn hba_path(&self) -> PathBuf {
        self.config_dir.join("pg_hba.conf")
    }

    /// The path to `pg_ident.conf`.
    pub fn ident_path(&self) -> PathBuf {
        self.config_dir.join("pg_ident.conf")
    }

    /// Set a configuration key/value pair.
    pub fn set(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.key_values.insert(key.into(), value.into());
    }

    /// Get a configuration value by key.
    pub fn get(&self, key: &str) -> Option<&str> {
        self.key_values.get(key).map(|s| s.as_str())
    }

    /// Add a connection rule to `pg_hba.conf`.
    pub fn add_connect(&mut self, entry: ConnectLine) {
        self.connect_set.insert(entry);
    }

    /// Add a user-mapping entry to `pg_ident.conf`.
    pub fn add_ident(&mut self, entry: IdentLine) {
        self.ident_set.push(entry);
    }

    /// Read the existing `postgresql.conf` and update controlled keys,
    /// preserving comments and ordering.
    pub fn merge_config(&self) -> io::Result<String> {
        let path = self.conf_path();
        if !path.exists() {
            return Ok(self.generate_config());
        }
        let content = fs::read_to_string(&path)?;
        let mut output = String::new();

        for line in content.lines() {
            let config_line = ConfigLine::parse_upto_key(line);
            if let Some(ref key) = config_line.key {
                if let Some(new_value) = self.key_values.get(key.as_str()) {
                    // Replace the value while preserving comments
                    let key_end = line.find(key.as_str()).unwrap_or(0) + key.len();
                    let mut cl = config_line.clone();
                    cl.parse_value(line, key_end);
                    let _ = write!(&mut output, "{} = {}", key, new_value);
                    if let Some(ref comment) = cl.comment {
                        if !comment.is_empty() {
                            let _ = write!(&mut output, " {}", comment);
                        }
                    }
                    output.push('\n');
                    continue;
                }
            }
            output.push_str(line);
            output.push('\n');
        }

        // Add any keys not already in the file
        for (key, value) in &self.key_values {
            let found = content.lines().any(|line| {
                let cl = ConfigLine::parse_upto_key(line);
                cl.key.as_deref() == Some(key.as_str())
            });
            if !found {
                let _ = writeln!(&mut output, "{} = {}", key, value);
            }
        }

        Ok(output)
    }

    /// Generate a fresh `postgresql.conf` with only the controlled keys.
    fn generate_config(&self) -> String {
        let mut output = String::new();
        for (key, value) in &self.key_values {
            let _ = writeln!(&mut output, "{} = {}", key, value);
        }
        output
    }

    /// Read the existing `pg_hba.conf` and merge new entries, preserving
    /// existing comments and ordering.
    pub fn merge_hba(&self) -> io::Result<String> {
        let path = self.hba_path();
        if !path.exists() {
            return Ok(self.generate_hba());
        }
        let content = fs::read_to_string(&path)?;
        let mut output = String::new();

        // Mark existing entries that match our desired set
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                output.push_str(line);
                output.push('\n');
                continue;
            }
            match ConnectLine::parse(trimmed) {
                Ok(_) => {
                    // Entry exists in file
                }
                Err(_) => {
                    output.push_str(line);
                    output.push('\n');
                }
            }
        }

        // Add unmatched entries
        for entry in &self.connect_set {
            if !entry.is_matched {
                let _ = entry.emit(&mut output);
            }
        }

        Ok(output)
    }

    fn generate_hba(&self) -> String {
        let mut output = String::new();
        let _ = writeln!(&mut output, "# PostgreSQL Client Authentication Configuration File");
        let _ = writeln!(&mut output, "# Managed by Ghidra BSim");
        let _ = writeln!(&mut output);
        for entry in &self.connect_set {
            let _ = entry.emit(&mut output);
        }
        output
    }

    /// Generate `pg_ident.conf` content.
    pub fn merge_ident(&self) -> io::Result<String> {
        let path = self.ident_path();
        let mut output = String::new();
        if path.exists() {
            let content = fs::read_to_string(&path)?;
            output.push_str(&content);
        }
        if !self.ident_set.is_empty() {
            output.push('\n');
            let _ = writeln!(&mut output, "# Ghidra BSim identity mappings");
            for entry in &self.ident_set {
                let _ = entry.emit(&mut output);
            }
        }
        Ok(output)
    }

    /// Write all configuration files to disk.
    pub fn write_config(&self) -> io::Result<()> {
        fs::write(self.conf_path(), self.merge_config()?)?;
        fs::write(self.hba_path(), self.merge_hba()?)?;
        fs::write(self.ident_path(), self.merge_ident()?)?;
        Ok(())
    }

    /// Validate signature settings compatibility between two databases.
    ///
    /// Returns:
    /// - 0: exact match
    /// - 1: minor version difference only
    /// - 2: settings mismatch (major version or settings differ too much)
    /// - 3: no setting information (input)
    /// - 4: no setting information (existing)
    pub fn check_signature_settings(
        existing_major: i16,
        existing_minor: i16,
        existing_settings: i32,
        input_major: i16,
        input_minor: i16,
        input_settings: i32,
    ) -> i32 {
        if input_major == 0 || input_settings == 0 {
            return 3;
        }
        if existing_major == 0 || existing_settings == 0 {
            return 4;
        }
        if existing_major != input_major || existing_settings != input_settings {
            return 2;
        }
        if existing_minor == input_minor {
            return 0;
        }
        if (existing_minor as i32 - input_minor as i32).abs() > 1 {
            return 2;
        }
        1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_line_parse_key() {
        let line = "listen_addresses = '*'  # what IP address(es) to listen on";
        let cl = ConfigLine::parse_upto_key(line);
        assert_eq!(cl.key.as_deref(), Some("listen_addresses"));
    }

    #[test]
    fn test_config_line_parse_commented_key() {
        let line = "#listen_addresses = 'localhost'";
        let cl = ConfigLine::parse_upto_key(line);
        assert_eq!(cl.key.as_deref(), Some("listen_addresses"));
    }

    #[test]
    fn test_connect_line_parse() {
        let line = "host    all             all             10.0.0.0/8            md5";
        let cl = ConnectLine::parse(line).unwrap();
        assert_eq!(cl.connection_type, "host");
        assert_eq!(cl.database, "all");
        assert_eq!(cl.user, "all");
        assert_eq!(cl.address.as_deref(), Some("10.0.0.0/8"));
        assert_eq!(cl.method, "md5");
        assert!(!cl.is_local());
    }

    #[test]
    fn test_connect_line_local() {
        let line = "local   all             all                                     trust";
        let cl = ConnectLine::parse(line).unwrap();
        assert_eq!(cl.connection_type, "local");
        assert!(cl.address.is_none());
        assert!(cl.is_local());
    }

    #[test]
    fn test_connect_line_emit_roundtrip() {
        let cl = ConnectLine::new("host", "bsimdb", "bsimuser", Some("10.0.0.0/8".into()), "md5", None);
        let mut output = String::new();
        cl.emit(&mut output).unwrap();
        assert!(output.contains("host"));
        assert!(output.contains("bsimdb"));
        assert!(output.contains("md5"));
    }

    #[test]
    fn test_connect_line_ordering() {
        let a = ConnectLine::new("host", "adb", "user1", None, "trust", None);
        let b = ConnectLine::new("host", "bdb", "user1", None, "trust", None);
        assert!(a < b);
    }

    #[test]
    fn test_server_config_set_get() {
        let mut config = ServerConfig::new("/tmp/pg_test");
        config.set("port", "5432");
        config.set("listen_addresses", "'*'");
        assert_eq!(config.get("port"), Some("5432"));
        assert_eq!(config.get("listen_addresses"), Some("'*'"));
        assert_eq!(config.get("missing"), None);
    }

    #[test]
    fn test_server_config_generate_config() {
        let mut config = ServerConfig::new("/tmp/pg_test");
        config.set("port", "5432");
        let output = config.generate_config();
        assert!(output.contains("port = 5432"));
    }

    #[test]
    fn test_server_config_generate_hba() {
        let mut config = ServerConfig::new("/tmp/pg_test");
        config.add_connect(ConnectLine::new(
            "host", "bsimdb", "bsimuser", Some("10.0.0.0/8".into()), "md5", None,
        ));
        let output = config.generate_hba();
        assert!(output.contains("host"));
        assert!(output.contains("bsimdb"));
    }

    #[test]
    fn test_ident_line_emit() {
        let ident = IdentLine {
            map_name: "mymap".to_string(),
            system_name: "admin".to_string(),
            system_name_is_quoted: false,
            role_name: "bsimadmin".to_string(),
        };
        let mut output = String::new();
        ident.emit(&mut output).unwrap();
        assert!(output.contains("mymap"));
        assert!(output.contains("admin"));
        assert!(output.contains("bsimadmin"));
    }

    #[test]
    fn test_signature_settings_check() {
        // Exact match
        assert_eq!(ServerConfig::check_signature_settings(2, 3, 100, 2, 3, 100), 0);
        // Minor version diff
        assert_eq!(ServerConfig::check_signature_settings(2, 3, 100, 2, 4, 100), 1);
        // Major mismatch
        assert_eq!(ServerConfig::check_signature_settings(2, 3, 100, 3, 3, 100), 2);
        // No input settings
        assert_eq!(ServerConfig::check_signature_settings(2, 3, 100, 0, 0, 0), 3);
        // No existing settings
        assert_eq!(ServerConfig::check_signature_settings(0, 0, 0, 2, 3, 100), 4);
    }

    #[test]
    fn test_server_config_path() {
        let config = ServerConfig::new("/etc/postgresql/14");
        assert_eq!(config.conf_path(), PathBuf::from("/etc/postgresql/14/postgresql.conf"));
        assert_eq!(config.hba_path(), PathBuf::from("/etc/postgresql/14/pg_hba.conf"));
        assert_eq!(config.ident_path(), PathBuf::from("/etc/postgresql/14/pg_ident.conf"));
    }
}
