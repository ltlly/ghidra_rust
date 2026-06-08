//! User management for the Ghidra Server.
//!
//! Ported from `ghidra.server.UserManager`.  Manages the set of users
//! associated with a running GhidraServer, including local password
//! management (salted SHA-256 hashes) and SSH public-key storage.

use std::collections::HashMap;
use std::fmt;
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use super::ServerError;

/// Separator used in the user file between fields.
const FIELD_SEPARATOR: char = ':';

/// The default password for new users.
const DEFAULT_PASSWORD: &str = "changeme";

/// Length of the salt portion of a salted SHA-256 hash.
const SALT_LENGTH: usize = 4;

/// Total length of a salted SHA-256 hash string (salt + hex hash).
const SHA256_SALTED_HASH_LENGTH: usize = SALT_LENGTH + 64;

/// File extension for SSH public key files.
const SSH_PUBKEY_EXT: &str = ".pub";

/// Hidden directory prefix for server-internal files.
const HIDDEN_DIR_PREFIX: &str = ".";

/// Magic value meaning "no password expiration".
const NO_EXPIRATION: i64 = -1;

// ---------------------------------------------------------------------------
// User
// ---------------------------------------------------------------------------

/// A user with their associated permission level.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct User {
    /// The user's name / SID.
    name: String,
    /// Access permission.
    permission: Permission,
}

impl User {
    /// Create a new user entry.
    pub fn new(name: impl Into<String>, permission: Permission) -> Self {
        Self {
            name: name.into(),
            permission,
        }
    }

    /// The user's name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The user's permission type.
    pub fn permission(&self) -> Permission {
        self.permission
    }

    /// Whether the user has admin privileges.
    pub fn is_admin(&self) -> bool {
        self.permission == Permission::Admin
    }

    /// Whether the user has write privileges (admin or write).
    pub fn has_write_permission(&self) -> bool {
        matches!(self.permission, Permission::Write | Permission::Admin)
    }

    /// Whether the user is read-only.
    pub fn is_read_only(&self) -> bool {
        self.permission == Permission::ReadOnly
    }
}

impl fmt::Display for User {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} = {:?}", self.name, self.permission)
    }
}

impl PartialOrd for User {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for User {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.name.cmp(&other.name)
    }
}

/// Access permission levels for repository users.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Permission {
    /// Read-only access.
    ReadOnly = 0,
    /// Read-write access.
    Write = 1,
    /// Full admin access (can modify user lists, delete repos, etc.).
    Admin = 2,
}

impl Permission {
    /// Map an integer index to a `Permission`.
    pub fn from_index(index: i32) -> Option<Self> {
        match index {
            0 => Some(Self::ReadOnly),
            1 => Some(Self::Write),
            2 => Some(Self::Admin),
            _ => None,
        }
    }

    /// Map a string name to a `Permission`.
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "READ_ONLY" => Some(Self::ReadOnly),
            "WRITE" => Some(Self::Write),
            "ADMIN" => Some(Self::Admin),
            _ => None,
        }
    }

    /// Return the string representation used in user-access files.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ReadOnly => "READ_ONLY",
            Self::Write => "WRITE",
            Self::Admin => "ADMIN",
        }
    }
}

// ---------------------------------------------------------------------------
// UserEntry (internal)
// ---------------------------------------------------------------------------

/// Internal user entry stored in the user list.
#[derive(Debug, Clone)]
struct UserEntry {
    username: String,
    password_hash: Option<String>,
    password_time: i64,
    distinguished_name: Option<String>,
}

// ---------------------------------------------------------------------------
// UserManager
// ---------------------------------------------------------------------------

/// Manages the set of users associated with a running GhidraServer.
///
/// Supports local password management (salted SHA-256 hashes) and SSH
/// public-key storage.
///
/// Matches Java's `ghidra.server.UserManager`.
pub struct UserManager {
    root_dir: PathBuf,
    user_file: PathBuf,
    ssh_dir: PathBuf,
    enable_local_passwords: bool,
    default_password_expiration_ms: i64,
    users: Mutex<HashMap<String, UserEntry>>,
}

impl UserManager {
    /// The anonymous username constant.
    pub const ANONYMOUS_USERNAME: &'static str = "anonymous";

    /// Name of the user password file.
    pub const USER_PASSWORD_FILE: &'static str = "users";

    /// Create a new user manager.
    ///
    /// # Arguments
    ///
    /// * `root_dir` -- the server root directory (contains the `users` file).
    /// * `enable_local_passwords` -- whether to manage local passwords.
    /// * `default_password_expiration_days` -- days before the default
    ///   password expires.  `-1` means use the default (1 day).  `0` means
    ///   no expiration.
    pub fn new(
        root_dir: PathBuf,
        enable_local_passwords: bool,
        default_password_expiration_days: i32,
    ) -> Self {
        let exp_days = if default_password_expiration_days < 0 {
            1
        } else {
            default_password_expiration_days
        };
        let exp_ms = exp_days as i64 * 24 * 3600 * 1000;

        let user_file = root_dir.join(Self::USER_PASSWORD_FILE);
        let ssh_dir = root_dir.join(format!("{HIDDEN_DIR_PREFIX}ssh"));

        let mgr = Self {
            root_dir,
            user_file,
            ssh_dir,
            enable_local_passwords,
            default_password_expiration_ms: exp_ms,
            users: Mutex::new(HashMap::new()),
        };

        // Try to load existing user list
        let _ = mgr.read_user_list();

        mgr
    }

    /// Return the server root directory.
    pub fn root_dir(&self) -> &Path {
        &self.root_dir
    }

    /// Add a user with an optional initial password hash.
    ///
    /// If `password_hash` is `None` and local passwords are enabled, a
    /// default password ("changeme") is assigned.
    pub fn add_user(&self, username: &str) -> Result<(), ServerError> {
        self.add_user_with_hash(username, None)
    }

    /// Add a user with an optional salted password hash.
    pub fn add_user_with_hash(
        &self,
        username: &str,
        password_hash: Option<String>,
    ) -> Result<(), ServerError> {
        if username.is_empty() {
            return Err(ServerError::Other("Username cannot be empty".into()));
        }
        if !Self::is_valid_username(username) {
            return Err(ServerError::Other(format!(
                "Invalid username: {username}"
            )));
        }

        let hash = if password_hash.is_some() {
            password_hash
        } else if self.enable_local_passwords {
            Some(Self::default_password_hash())
        } else {
            None
        };

        let mut users = self.users.lock().map_err(|e| ServerError::Other(e.to_string()))?;
        if users.contains_key(username) {
            return Err(ServerError::DuplicateName(format!(
                "User {username} already exists"
            )));
        }

        users.insert(
            username.to_string(),
            UserEntry {
                username: username.to_string(),
                password_hash: hash,
                password_time: current_time_ms(),
                distinguished_name: None,
            },
        );

        self.write_user_list_inner(&users)
    }

    /// Remove a user from the server.
    ///
    /// Returns `true` if the user existed and was removed.
    pub fn remove_user(&self, username: &str) -> Result<bool, ServerError> {
        let mut users = self.users.lock().map_err(|e| ServerError::Other(e.to_string()))?;
        if users.remove(username).is_some() {
            self.write_user_list_inner(&users)?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Check if a user exists.
    pub fn is_valid_user(&self, username: &str) -> bool {
        self.users
            .lock()
            .map(|u| u.contains_key(username))
            .unwrap_or(false)
    }

    /// Get a list of all known users.
    pub fn get_users(&self) -> Vec<String> {
        self.users
            .lock()
            .map(|u| u.keys().cloned().collect())
            .unwrap_or_default()
    }

    /// Authenticate a user with the given password.
    ///
    /// # Errors
    ///
    /// Returns [`ServerError::AuthFailed`] if authentication fails.
    pub fn authenticate_user(&self, username: &str, password: &str) -> Result<(), ServerError> {
        if username.is_empty() || password.is_empty() {
            return Err(ServerError::AuthFailed(
                "Invalid authentication data".into(),
            ));
        }

        let users = self.users.lock().map_err(|e| ServerError::Other(e.to_string()))?;
        let entry = users.get(username).ok_or_else(|| {
            ServerError::AuthFailed(format!("Unknown user: {username}"))
        })?;

        match &entry.password_hash {
            None => Err(ServerError::AuthFailed(
                "User password not set, must be reset".into(),
            )),
            Some(hash) => {
                if Self::verify_password(password, hash) {
                    Ok(())
                } else {
                    Err(ServerError::AuthFailed("Incorrect password".into()))
                }
            }
        }
    }

    /// Set the password for a user.
    ///
    /// `salted_sha256_hash` should be a 4-char salt followed by 64 hex digits.
    pub fn set_password(
        &self,
        username: &str,
        salted_sha256_hash: &str,
        is_temporary: bool,
    ) -> Result<bool, ServerError> {
        if !self.enable_local_passwords {
            return Err(ServerError::Other("Local passwords are not used".into()));
        }
        Self::check_valid_password_hash(salted_sha256_hash)?;

        let mut users = self.users.lock().map_err(|e| ServerError::Other(e.to_string()))?;
        if let Some(entry) = users.get_mut(username) {
            entry.password_hash = Some(salted_sha256_hash.to_string());
            entry.password_time = if is_temporary {
                current_time_ms()
            } else {
                NO_EXPIRATION
            };
            self.write_user_list_inner(&users)?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Reset the user's password to the default ("changeme").
    pub fn reset_password(&self, username: &str) -> Result<bool, ServerError> {
        if !self.enable_local_passwords {
            return Ok(false);
        }
        let hash = Self::default_password_hash();
        self.set_password(username, &hash, true)
    }

    /// Whether local passwords are in use and can be changed.
    pub fn can_set_password(&self, username: &str) -> bool {
        if !self.enable_local_passwords {
            return false;
        }
        self.users
            .lock()
            .map(|u| {
                u.get(username)
                    .and_then(|e| e.password_hash.as_ref())
                    .is_some()
            })
            .unwrap_or(false)
    }

    /// Get the SSH public key file path for a user (if it exists).
    pub fn get_ssh_pub_key_file(&self, username: &str) -> Option<PathBuf> {
        if !self.is_valid_user(username) {
            return None;
        }
        let path = self.ssh_dir.join(format!("{username}{SSH_PUBKEY_EXT}"));
        if path.is_file() {
            Some(path)
        } else {
            None
        }
    }

    /// Set the X.500 distinguished name for a user.
    pub fn set_distinguished_name(
        &self,
        username: &str,
        dn: &str,
    ) -> Result<bool, ServerError> {
        let mut users = self.users.lock().map_err(|e| ServerError::Other(e.to_string()))?;
        if let Some(entry) = users.get_mut(username) {
            entry.distinguished_name = Some(dn.to_string());
            self.write_user_list_inner(&users)?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Get the X.500 distinguished name for a user.
    pub fn get_distinguished_name(&self, username: &str) -> Option<String> {
        self.users
            .lock()
            .ok()
            .and_then(|u| u.get(username).and_then(|e| e.distinguished_name.clone()))
    }

    /// Check if the given username is valid (alphanumeric, `.`, `-`, `_`).
    pub fn is_valid_username(s: &str) -> bool {
        if s.is_empty() {
            return false;
        }
        let first = s.as_bytes()[0];
        if !first.is_ascii_alphanumeric() {
            return false;
        }
        s.bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'.' || c == b'-' || c == b'_')
    }

    /// Clear all expired default passwords.
    pub fn clear_expired_passwords(&self) -> Result<(), ServerError> {
        if self.default_password_expiration_ms == 0 {
            return Ok(());
        }

        let mut users = self.users.lock().map_err(|e| ServerError::Other(e.to_string()))?;
        let now = current_time_ms();
        let mut changed = false;

        for entry in users.values_mut() {
            if entry.password_hash.is_some() {
                let expired = if self.default_password_expiration_ms == 0 || entry.password_time == NO_EXPIRATION {
                    false
                } else if entry.password_time == 0 {
                    true
                } else {
                    (now - entry.password_time) >= self.default_password_expiration_ms
                };
                if expired {
                    entry.password_hash = None;
                    entry.password_time = 0;
                    changed = true;
                }
            }
        }

        if changed {
            self.write_user_list_inner(&users)?;
        }
        Ok(())
    }

    // --- Private helpers ---

    fn default_password_hash() -> String {
        Self::compute_salted_sha256(DEFAULT_PASSWORD)
    }

    fn compute_salted_sha256(password: &str) -> String {
        use sha2::{Digest, Sha256};
        let salt = Self::generate_salt();
        let mut hasher = Sha256::new();
        hasher.update(salt.as_bytes());
        hasher.update(password.as_bytes());
        let hash = format!("{:x}", hasher.finalize());
        format!("{salt}{hash}")
    }

    fn generate_salt() -> String {
        use std::time::{SystemTime, UNIX_EPOCH};
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .subsec_nanos();
        // 4-char alphanumeric salt from nanosecond counter
        let chars: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
        let mut salt = String::with_capacity(SALT_LENGTH);
        let mut v = nanos;
        for _ in 0..SALT_LENGTH {
            salt.push(chars[(v as usize) % chars.len()] as char);
            v = v.wrapping_mul(1103515245).wrapping_add(12345);
        }
        salt
    }

    fn verify_password(password: &str, stored_hash: &str) -> bool {
        if stored_hash.len() < SALT_LENGTH {
            return false;
        }
        let salt = &stored_hash[..SALT_LENGTH];
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(salt.as_bytes());
        hasher.update(password.as_bytes());
        let computed = format!("{salt}{:x}", hasher.finalize());
        computed == stored_hash
    }

    fn check_valid_password_hash(hash: &str) -> Result<(), ServerError> {
        if hash.len() != SHA256_SALTED_HASH_LENGTH {
            return Err(ServerError::Io("Invalid password hash length".into()));
        }
        let salt = &hash[..SALT_LENGTH];
        if !salt
            .bytes()
            .all(|c| c.is_ascii_alphanumeric())
        {
            return Err(ServerError::Io("Invalid salt characters".into()));
        }
        let hex_part = &hash[SALT_LENGTH..];
        if !hex_part.bytes().all(|c| c.is_ascii_hexdigit()) {
            return Err(ServerError::Io("Invalid hash hex characters".into()));
        }
        Ok(())
    }

    fn read_user_list(&self) -> Result<(), ServerError> {
        if !self.user_file.exists() {
            return Ok(());
        }

        let file = fs::File::open(&self.user_file).map_err(|e| ServerError::Io(e.to_string()))?;
        let reader = BufReader::new(file);
        let mut new_map = HashMap::new();

        for line_result in reader.lines() {
            let line = line_result.map_err(|e| ServerError::Io(e.to_string()))?;
            if line.starts_with('#') || line.trim().is_empty() {
                continue;
            }
            let parts: Vec<&str> = line.split(FIELD_SEPARATOR).collect();
            if parts.is_empty() {
                continue;
            }
            let username = parts[0].trim().to_string();
            if !Self::is_valid_username(&username) {
                continue;
            }

            let password_hash = if parts.len() > 1 {
                let h = parts[1].trim();
                if h == "*" || h.is_empty() {
                    None
                } else {
                    Some(h.to_string())
                }
            } else {
                None
            };

            let password_time = if parts.len() > 2 {
                let t = parts[2].trim();
                if t == "*" {
                    NO_EXPIRATION
                } else {
                    i64::from_str_radix(t, 16).unwrap_or(0)
                }
            } else {
                0
            };

            let dn = if parts.len() > 3 {
                let d = parts[3].trim();
                if d.is_empty() {
                    None
                } else {
                    Some(d.to_string())
                }
            } else {
                None
            };

            new_map.insert(
                username.clone(),
                UserEntry {
                    username,
                    password_hash,
                    password_time,
                    distinguished_name: dn,
                },
            );
        }

        let mut users = self.users.lock().map_err(|e| ServerError::Other(e.to_string()))?;
        *users = new_map;
        Ok(())
    }

    fn write_user_list_inner(
        &self,
        users: &HashMap<String, UserEntry>,
    ) -> Result<(), ServerError> {
        let mut content = String::new();
        for entry in users.values() {
            content.push_str(&entry.username);
            content.push(FIELD_SEPARATOR);
            match &entry.password_hash {
                Some(hash) => {
                    content.push_str(hash);
                    content.push(FIELD_SEPARATOR);
                    if entry.password_time == NO_EXPIRATION {
                        content.push('*');
                    } else {
                        content.push_str(&format!("{:x}", entry.password_time));
                    }
                }
                None => {
                    content.push('*');
                    content.push(FIELD_SEPARATOR);
                    content.push('*');
                }
            }
            if let Some(ref dn) = entry.distinguished_name {
                content.push(FIELD_SEPARATOR);
                content.push_str(dn);
            }
            content.push('\n');
        }

        // Write atomically via temp file
        let tmp = self.user_file.with_extension("tmp");
        {
            let mut f = fs::File::create(&tmp).map_err(|e| ServerError::Io(e.to_string()))?;
            f.write_all(content.as_bytes()).map_err(|e| ServerError::Io(e.to_string()))?;
        }
        fs::rename(&tmp, &self.user_file).map_err(|e| ServerError::Io(e.to_string()))?;
        Ok(())
    }
}

/// Return current time in milliseconds since UNIX epoch.
fn current_time_ms() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn temp_user_mgr() -> (UserManager, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let mgr = UserManager::new(dir.path().to_path_buf(), true, 0);
        (mgr, dir)
    }

    #[test]
    fn test_add_and_get_users() {
        let (mgr, _dir) = temp_user_mgr();
        mgr.add_user("alice").unwrap();
        mgr.add_user("bob").unwrap();

        let users = mgr.get_users();
        assert_eq!(users.len(), 2);
        assert!(mgr.is_valid_user("alice"));
        assert!(mgr.is_valid_user("bob"));
        assert!(!mgr.is_valid_user("charlie"));
    }

    #[test]
    fn test_duplicate_user() {
        let (mgr, _dir) = temp_user_mgr();
        mgr.add_user("alice").unwrap();
        let result = mgr.add_user("alice");
        assert!(result.is_err());
    }

    #[test]
    fn test_remove_user() {
        let (mgr, _dir) = temp_user_mgr();
        mgr.add_user("alice").unwrap();
        assert!(mgr.remove_user("alice").unwrap());
        assert!(!mgr.is_valid_user("alice"));
        assert!(!mgr.remove_user("alice").unwrap());
    }

    #[test]
    fn test_authenticate_user() {
        let (mgr, _dir) = temp_user_mgr();
        mgr.add_user("alice").unwrap();
        // Default password is "changeme"
        assert!(mgr.authenticate_user("alice", "changeme").is_ok());
        assert!(mgr.authenticate_user("alice", "wrong").is_err());
        assert!(mgr.authenticate_user("unknown", "changeme").is_err());
    }

    #[test]
    fn test_is_valid_username() {
        assert!(UserManager::is_valid_username("alice"));
        assert!(UserManager::is_valid_username("admin"));
        assert!(UserManager::is_valid_username("user.name"));
        assert!(UserManager::is_valid_username("user-name"));
        assert!(UserManager::is_valid_username("user_name"));
        assert!(UserManager::is_valid_username("u123"));
        assert!(!UserManager::is_valid_username(""));
        assert!(!UserManager::is_valid_username(".hidden"));
        assert!(!UserManager::is_valid_username("user name"));
        assert!(!UserManager::is_valid_username("user@host"));
    }

    #[test]
    fn test_set_and_get_distinguished_name() {
        let (mgr, _dir) = temp_user_mgr();
        mgr.add_user("alice").unwrap();
        mgr.set_distinguished_name("alice", "CN=Alice,O=Example")
            .unwrap();
        let dn = mgr.get_distinguished_name("alice");
        assert_eq!(dn.as_deref(), Some("CN=Alice,O=Example"));
    }

    #[test]
    fn test_password_hash_validation() {
        // Too short
        assert!(UserManager::check_valid_password_hash("abc").is_err());
        // Wrong length
        assert!(UserManager::check_valid_password_hash("abcd1234").is_err());
        // Correct length with valid hex
        let valid = format!("abcd{}", "0".repeat(64));
        assert!(UserManager::check_valid_password_hash(&valid).is_ok());
    }

    #[test]
    fn test_user_permission_checks() {
        let ro_user = User::new("ro", Permission::ReadOnly);
        assert!(ro_user.is_read_only());
        assert!(!ro_user.has_write_permission());
        assert!(!ro_user.is_admin());

        let write_user = User::new("wr", Permission::Write);
        assert!(!write_user.is_read_only());
        assert!(write_user.has_write_permission());
        assert!(!write_user.is_admin());

        let admin_user = User::new("adm", Permission::Admin);
        assert!(!admin_user.is_read_only());
        assert!(admin_user.has_write_permission());
        assert!(admin_user.is_admin());
    }

    #[test]
    fn test_permission_from_name() {
        assert_eq!(Permission::from_name("READ_ONLY"), Some(Permission::ReadOnly));
        assert_eq!(Permission::from_name("WRITE"), Some(Permission::Write));
        assert_eq!(Permission::from_name("ADMIN"), Some(Permission::Admin));
        assert_eq!(Permission::from_name("INVALID"), None);
    }

    #[test]
    fn test_user_ordering() {
        let mut users = vec![
            User::new("charlie", Permission::ReadOnly),
            User::new("alice", Permission::Admin),
            User::new("bob", Permission::Write),
        ];
        users.sort();
        assert_eq!(users[0].name(), "alice");
        assert_eq!(users[1].name(), "bob");
        assert_eq!(users[2].name(), "charlie");
    }
}
