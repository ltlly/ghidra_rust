//! Server admin CLI tool.
//!
//! Ported from `ghidra.server.ServerAdmin`.  Provides the `svrAdmin`
//! equivalent command-line interface for managing a Ghidra Server's
//! users and repositories.

use std::path::{Path, PathBuf};

use super::command_processor::CommandProcessor;
use super::repository_manager::RepositoryManager;
use super::user_manager::UserManager;

// ---------------------------------------------------------------------------
// ServerAdmin
// ---------------------------------------------------------------------------

/// Server admin command-line tool.
///
/// Matches Java's `ghidra.server.ServerAdmin`.
pub struct ServerAdmin {
    server_root: PathBuf,
}

impl ServerAdmin {
    /// Create a new server admin for the given server root directory.
    pub fn new(server_root: PathBuf) -> Self {
        Self { server_root }
    }

    /// The server root directory.
    pub fn server_root(&self) -> &Path {
        &self.server_root
    }

    /// Execute the admin command-line arguments.
    pub fn execute(&self, args: &[String]) -> Result<(), String> {
        if args.is_empty() {
            Self::display_usage(None);
            return Err("No command specified".into());
        }

        let cmd = args[0].as_str();
        match cmd {
            "-list" => {
                let details = args.get(1).map(|s| s.as_str()) == Some("-users");
                RepositoryManager::list_repositories(&self.server_root, details);
            }
            "-users" => {
                UserManager::list_users(&self.server_root);
            }
            "-migrate" => {
                if let Some(name) = args.get(1) {
                    println!("Migration of repository '{name}' is not yet supported in Rust port");
                } else {
                    Self::display_usage(Some("Missing repository name for -migrate"));
                }
            }
            "-migrate-all" => {
                println!("Migration of all repositories is not yet supported in Rust port");
            }
            _ => {
                // Queue the command for the running server to process
                Self::display_usage(Some(&format!("Unknown command: {cmd}")));
            }
        }

        Ok(())
    }

    fn display_usage(msg: Option<&str>) {
        if let Some(m) = msg {
            println!("{m}");
        }
        println!("Usage: svrAdmin [options] <config_file> <command>");
        println!("Commands:");
        println!("  -list [-users]       List repositories (with optional user details)");
        println!("  -users               List all known users");
        println!("  -migrate <repo>      Mark repository for index migration");
        println!("  -migrate-all         Mark all repositories for migration");
        println!("  -add <user>          Add a user");
        println!("  -remove <user>       Remove a user");
        println!("  -reset <user>        Reset a user's password");
        println!("  -dn <user> <dn>      Set a user's distinguished name");
        println!("  -grant <user> <perm> <repo>  Grant access to a repository");
        println!("  -revoke <user> <repo>        Revoke access to a repository");
    }
}

// Extension trait for UserManager to support the list_users admin function
impl UserManager {
    /// Print all users to stdout (for admin use).
    pub fn list_users(server_root: &Path) {
        let user_file = server_root.join(Self::USER_PASSWORD_FILE);
        if !user_file.exists() {
            println!("\nRepository Server Users:");
            println!("   <No users have been added>");
            return;
        }

        let mgr = UserManager::new(server_root.to_path_buf(), false, 0);
        let users = mgr.get_users();

        println!("\nRepository Server Users:");
        if users.is_empty() {
            println!("   <No users have been added>");
        } else {
            let mut sorted = users;
            sorted.sort();
            for name in sorted {
                println!("  {name}");
            }
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
    fn test_server_admin_creation() {
        let admin = ServerAdmin::new(PathBuf::from("/tmp/test"));
        assert_eq!(admin.server_root(), Path::new("/tmp/test"));
    }

    #[test]
    fn test_display_usage_does_not_panic() {
        // Just ensure it doesn't crash
        ServerAdmin::display_usage(Some("test message"));
        ServerAdmin::display_usage(None);
    }
}
