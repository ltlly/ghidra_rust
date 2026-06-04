//! Repository manager for the Ghidra Server.
//!
//! Ported from `ghidra.server.RepositoryManager`.  Manages a set of
//! [`Repository`] instances under a root directory.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use super::repository::Repository;
use super::user_manager::{UserManager, Permission};
use super::ServerError;

// ---------------------------------------------------------------------------
// Naming utilities (simplified port)
// ---------------------------------------------------------------------------

/// Mangle a repository name for use as a directory name.
///
/// In Ghidra's Java code this calls `NamingUtilities.mangle()`.  The
/// Rust port uses a simple scheme: alphanumeric characters and `_` are
/// kept, all others are replaced with `_`.
pub fn mangle_name(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// Demangle a directory name back to the original repository name.
///
/// This is a best-effort reversal; since `_` is ambiguous, callers should
/// prefer the stored name when available.
pub fn demangle_name(mangled: &str) -> String {
    mangled.to_string()
}

/// Validate that a repository name contains only allowed characters.
pub fn check_name(name: &str) -> Result<(), ServerError> {
    if name.is_empty() {
        return Err(ServerError::Other("Repository name cannot be empty".into()));
    }
    if !name
        .bytes()
        .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-' || c == b'.')
    {
        return Err(ServerError::Other(format!(
            "Invalid repository name: {name}"
        )));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// RepositoryManager
// ---------------------------------------------------------------------------

/// Manages a set of repositories under a root directory.
///
/// Matches Java's `ghidra.server.RepositoryManager`.
pub struct RepositoryManager {
    root_dir: PathBuf,
    repositories: Mutex<HashMap<String, Repository>>,
    user_mgr: UserManager,
    anonymous_access_allowed: bool,
}

impl RepositoryManager {
    /// Create a new repository manager.
    ///
    /// # Arguments
    ///
    /// * `root_dir` -- directory where repositories are stored.
    /// * `enable_local_passwords` -- whether to manage local passwords.
    /// * `default_password_expiration_days` -- days until default password expires.
    /// * `anonymous_access_allowed` -- whether the server allows anonymous access.
    pub fn new(
        root_dir: PathBuf,
        enable_local_passwords: bool,
        default_password_expiration_days: i32,
        anonymous_access_allowed: bool,
    ) -> Result<Self, ServerError> {
        if !root_dir.exists() {
            fs::create_dir_all(&root_dir).map_err(|e| ServerError::Io(e.to_string()))?;
        }
        if !root_dir.is_dir() {
            return Err(ServerError::Io(format!(
                "{} is not a directory",
                root_dir.display()
            )));
        }

        let user_mgr = UserManager::new(
            root_dir.clone(),
            enable_local_passwords,
            default_password_expiration_days,
        );

        let mgr = Self {
            root_dir,
            repositories: Mutex::new(HashMap::new()),
            user_mgr,
            anonymous_access_allowed,
        };

        // Load existing repositories
        mgr.initialize()?;

        Ok(mgr)
    }

    /// Whether anonymous access is allowed.
    pub fn anonymous_access_allowed(&self) -> bool {
        self.anonymous_access_allowed
    }

    /// Return a reference to the user manager.
    pub fn user_manager(&self) -> &UserManager {
        &self.user_mgr
    }

    /// Return the root directory.
    pub fn root_dir(&self) -> &Path {
        &self.root_dir
    }

    /// Create a new repository.
    ///
    /// # Errors
    ///
    /// Returns [`ServerError::DuplicateName`] if a repository with the same
    /// name already exists, or [`ServerError::UserAccess`] if the user is
    /// not known.
    pub fn create_repository(
        &self,
        current_user: &str,
        name: &str,
    ) -> Result<(), ServerError> {
        if current_user == UserManager::ANONYMOUS_USERNAME {
            return Err(ServerError::UserAccess(
                "Anonymous user not permitted to create repository".into(),
            ));
        }
        self.validate_user(current_user)?;
        check_name(name)?;

        let mut repos = self
            .repositories
            .lock()
            .map_err(|e| ServerError::Other(e.to_string()))?;

        if repos.contains_key(name) {
            return Err(ServerError::DuplicateName(format!(
                "Repository named {name} already exists"
            )));
        }

        let dir = self.root_dir.join(mangle_name(name));
        fs::create_dir(&dir).map_err(|e| ServerError::Io(e.to_string()))?;

        let repo = Repository::new(name, dir, Some(current_user))?;
        repos.insert(name.to_string(), repo);
        Ok(())
    }

    /// Get a repository by name (with read privilege check).
    ///
    /// Returns `Ok(true)` if the repository exists and the user has access,
    /// `Ok(false)` if the repository doesn't exist.
    pub fn get_repository(
        &self,
        current_user: &str,
        name: &str,
    ) -> Result<bool, ServerError> {
        if current_user != UserManager::ANONYMOUS_USERNAME {
            self.validate_user(current_user)?;
        }
        let repos = self
            .repositories
            .lock()
            .map_err(|e| ServerError::Other(e.to_string()))?;

        if let Some(repo) = repos.get(name) {
            repo.validate_read_privilege(current_user)?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Check if a repository exists.
    pub fn repository_exists(&self, name: &str) -> bool {
        self.repositories
            .lock()
            .map(|r| r.contains_key(name))
            .unwrap_or(false)
    }

    /// Delete a repository.
    pub fn delete_repository(
        &self,
        current_user: &str,
        name: &str,
    ) -> Result<(), ServerError> {
        if current_user == UserManager::ANONYMOUS_USERNAME {
            return Err(ServerError::UserAccess(
                "Anonymous user not permitted to delete repository".into(),
            ));
        }
        self.validate_user(current_user)?;

        let mut repos = self
            .repositories
            .lock()
            .map_err(|e| ServerError::Other(e.to_string()))?;

        if let Some(repo) = repos.get(name) {
            repo.validate_admin_privilege(current_user)?;
            repo.dispose();
        }

        let dir = self.root_dir.join(mangle_name(name));
        if dir.exists() {
            fs::remove_dir_all(&dir).map_err(|e| ServerError::Io(e.to_string()))?;
        }

        repos.remove(name);
        Ok(())
    }

    /// Get the names of repositories accessible by the given user.
    pub fn get_repository_names(&self, current_user: &str) -> Vec<String> {
        let repos = match self.repositories.lock() {
            Ok(r) => r,
            Err(_) => return Vec::new(),
        };

        let mut names: Vec<String> = repos
            .values()
            .filter(|repo| {
                if current_user == UserManager::ANONYMOUS_USERNAME {
                    repo.anonymous_access_allowed()
                } else {
                    repo.get_user(current_user).is_some()
                }
            })
            .map(|repo| repo.name().to_string())
            .collect();

        names.sort();
        names
    }

    /// Get all users known to the server.
    pub fn get_all_users(&self, current_user: &str) -> Vec<String> {
        if current_user == UserManager::ANONYMOUS_USERNAME {
            return Vec::new();
        }
        self.user_mgr.get_users()
    }

    /// Dispose the manager and all repositories.
    pub fn dispose(&self) {
        if let Ok(repos) = self.repositories.lock() {
            for repo in repos.values() {
                repo.dispose();
            }
        }
    }

    // --- Private helpers ---

    /// Grant a user access to a specific repository.
    pub fn grant_user_access(
        &self,
        username: &str,
        permission: Permission,
        repo_name: &str,
    ) -> Result<(), ServerError> {
        let repos = self
            .repositories
            .lock()
            .map_err(|e| ServerError::Other(e.to_string()))?;
        if let Some(repo) = repos.get(repo_name) {
            repo.set_user_permission(username, permission)?;
        }
        Ok(())
    }

    /// Revoke a user's access to a specific repository.
    pub fn revoke_user_access(
        &self,
        username: &str,
        repo_name: &str,
    ) -> Result<(), ServerError> {
        let repos = self
            .repositories
            .lock()
            .map_err(|e| ServerError::Other(e.to_string()))?;
        if let Some(repo) = repos.get(repo_name) {
            repo.remove_user(username)?;
        }
        Ok(())
    }

    fn validate_user(&self, username: &str) -> Result<(), ServerError> {
        if !self.user_mgr.is_valid_user(username) {
            return Err(ServerError::UserAccess(format!(
                "{username} is unknown to this repository manager"
            )));
        }
        Ok(())
    }

    fn initialize(&self) -> Result<(), ServerError> {
        let names = Self::get_repository_names_from_dir(&self.root_dir);

        let mut repos = self
            .repositories
            .lock()
            .map_err(|e| ServerError::Other(e.to_string()))?;

        for name in names {
            let dir = self.root_dir.join(mangle_name(&name));
            if !dir.is_dir() {
                continue;
            }
            match Repository::new(&name, dir, None) {
                Ok(repo) => {
                    repos.insert(name, repo);
                }
                Err(_) => continue,
            }
        }

        Ok(())
    }

    /// Scan a directory for repository subdirectories and return their names.
    pub fn get_repository_names_from_dir(root: &Path) -> Vec<String> {
        let mut names = Vec::new();
        if let Ok(entries) = fs::read_dir(root) {
            for entry in entries.flatten() {
                let path = entry.path();
                if !path.is_dir() {
                    continue;
                }
                let dir_name = entry.file_name().to_string_lossy().to_string();
                if dir_name.starts_with('.') {
                    continue;
                }
                names.push(demangle_name(&dir_name));
            }
        }
        names.sort();
        names
    }

    /// Format the list of repositories to stdout.
    pub fn list_repositories(root: &Path, include_user_details: bool) {
        let names = Self::get_repository_names_from_dir(root);
        println!("\nRepositories:");
        if names.is_empty() {
            println!("   <No repositories have been created>");
            return;
        }
        for name in &names {
            let repo_dir = root.join(mangle_name(name));
            println!("  {name}");
            if include_user_details {
                let perms = Repository::get_formatted_user_permissions(&repo_dir, "    ");
                print!("{perms}");
            }
        }
    }

    /// When a user is removed from the server, remove them from all repos.
    pub fn user_removed(&self, username: &str) -> Result<(), ServerError> {
        let repos = self
            .repositories
            .lock()
            .map_err(|e| ServerError::Other(e.to_string()))?;
        for repo in repos.values() {
            let _ = repo.remove_user(username);
        }
        Ok(())
    }
}

impl Drop for RepositoryManager {
    fn drop(&mut self) {
        self.dispose();
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_repo_mgr() -> (RepositoryManager, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let mgr =
            RepositoryManager::new(dir.path().to_path_buf(), true, 0, false).unwrap();
        (mgr, dir)
    }

    #[test]
    fn test_create_and_list_repositories() {
        let (mgr, _dir) = temp_repo_mgr();
        // The user file must exist and have at least one user for the manager
        // to accept operations.
        mgr.user_manager().add_user("admin").unwrap();

        mgr.create_repository("admin", "my_repo").unwrap();
        assert!(mgr.repository_exists("my_repo"));

        let names = mgr.get_repository_names("admin");
        assert_eq!(names, vec!["my_repo"]);
    }

    #[test]
    fn test_duplicate_repository() {
        let (mgr, _dir) = temp_repo_mgr();
        mgr.user_manager().add_user("admin").unwrap();
        mgr.create_repository("admin", "repo1").unwrap();
        let result = mgr.create_repository("admin", "repo1");
        assert!(result.is_err());
    }

    #[test]
    fn test_delete_repository() {
        let (mgr, _dir) = temp_repo_mgr();
        mgr.user_manager().add_user("admin").unwrap();
        mgr.create_repository("admin", "repo1").unwrap();
        assert!(mgr.repository_exists("repo1"));

        mgr.delete_repository("admin", "repo1").unwrap();
        assert!(!mgr.repository_exists("repo1"));
    }

    #[test]
    fn test_anonymous_cannot_create() {
        let (mgr, _dir) = temp_repo_mgr();
        let result = mgr.create_repository("anonymous", "secret");
        assert!(result.is_err());
    }

    #[test]
    fn test_mangle_name() {
        assert_eq!(mangle_name("hello_world"), "hello_world");
        assert_eq!(mangle_name("hello-world"), "hello_world");
        assert_eq!(mangle_name("repo 1"), "repo_1");
    }

    #[test]
    fn test_check_name() {
        assert!(check_name("valid_repo").is_ok());
        assert!(check_name("repo-1.0").is_ok());
        assert!(check_name("").is_err());
        assert!(check_name("repo name").is_err());
    }

    #[test]
    fn test_user_removed_from_repos() {
        let (mgr, _dir) = temp_repo_mgr();
        mgr.user_manager().add_user("admin").unwrap();
        mgr.user_manager().add_user("bob").unwrap();
        mgr.create_repository("admin", "repo1").unwrap();

        // Add bob to the repository
        {
            let repos = mgr.repositories.lock().unwrap();
            let repo = repos.get("repo1").unwrap();
            repo.set_user_permission("bob", Permission::Write)
                .unwrap();
        }

        // Remove bob from server
        mgr.user_manager().remove_user("bob").unwrap();
        mgr.user_removed("bob").unwrap();

        // Bob should no longer have access
        let repos = mgr.repositories.lock().unwrap();
        let repo = repos.get("repo1").unwrap();
        assert!(repo.get_user("bob").is_none());
    }
}
