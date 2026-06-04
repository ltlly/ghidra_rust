//! Command processor for the Ghidra Server admin interface.
//!
//! Ported from `ghidra.server.CommandProcessor`.  Processes admin
//! commands queued by the `svrAdmin` tool.

use std::fs;
use std::io::{self, BufRead, BufReader};
use std::path::Path;

use super::repository_manager::RepositoryManager;
use super::user_manager::{Permission, User};
use super::ServerError;

// ---------------------------------------------------------------------------
// Command constants
// ---------------------------------------------------------------------------

/// Add a user to the server.
pub const ADD_USER_COMMAND: &str = "-add";
/// Remove a user from the server.
pub const REMOVE_USER_COMMAND: &str = "-remove";
/// Reset a user's password.
pub const RESET_USER_COMMAND: &str = "-reset";
/// Set a user's X.500 distinguished name.
pub const SET_USER_DN_COMMAND: &str = "-dn";
/// Grant a user access to a repository.
pub const GRANT_USER_COMMAND: &str = "-grant";
/// Revoke a user's access to a repository.
pub const REVOKE_USER_COMMAND: &str = "-revoke";

/// Password option flag (applies to add and reset commands).
pub const PASSWORD_OPTION: &str = "--p";

/// Hidden directory for admin command files.
const ADMIN_CMD_DIR: &str = ".admin";

/// File extension for command files.
const COMMAND_FILE_EXT: &str = ".cmd";

// ---------------------------------------------------------------------------
// CommandProcessor
// ---------------------------------------------------------------------------

/// Processes server admin commands.
///
/// Matches Java's `ghidra.server.CommandProcessor`.
pub struct CommandProcessor;

impl CommandProcessor {
    /// Split a command string into arguments, respecting quotes.
    pub fn split_command(cmd: &str) -> Vec<String> {
        let mut args = Vec::new();
        let mut current = String::new();
        let mut in_quotes = false;

        for c in cmd.chars() {
            match c {
                '"' => in_quotes = !in_quotes,
                ' ' if !in_quotes => {
                    if !current.is_empty() {
                        args.push(current.clone());
                        current.clear();
                    }
                }
                _ => current.push(c),
            }
        }
        if !current.is_empty() {
            args.push(current);
        }
        args
    }

    /// Process any pending command files in the admin directory.
    pub fn process_commands(mgr: &RepositoryManager) -> Result<(), ServerError> {
        let cmd_dir = mgr.root_dir().join(ADMIN_CMD_DIR);
        if !cmd_dir.exists() {
            return Ok(());
        }

        let mut files: Vec<fs::DirEntry> = fs::read_dir(&cmd_dir)
            .map_err(|e| ServerError::Io(e.to_string()))?
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.path()
                    .extension()
                    .map(|ext| ext == "cmd")
                    .unwrap_or(false)
            })
            .collect();

        // Sort by modification time
        files.sort_by_key(|f| {
            f.metadata()
                .and_then(|m| m.modified())
                .unwrap_or(std::time::SystemTime::UNIX_EPOCH)
        });

        for entry in files {
            let path = entry.path();
            if let Err(e) = Self::process_command_file(mgr, &path) {
                eprintln!("Error processing command file {}: {e}", path.display());
            }
            // Remove the processed file
            let _ = fs::remove_file(&path);
        }

        Ok(())
    }

    fn process_command_file(mgr: &RepositoryManager, path: &Path) -> Result<(), ServerError> {
        let file = fs::File::open(path).map_err(|e| ServerError::Io(e.to_string()))?;
        let reader = BufReader::new(file);

        for line_result in reader.lines() {
            let line = line_result.map_err(|e| ServerError::Io(e.to_string()))?;
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            Self::process_command(mgr, line)?;
        }
        Ok(())
    }

    /// Process a single command line.
    pub fn process_command(mgr: &RepositoryManager, cmdline: &str) -> Result<(), ServerError> {
        let args = Self::split_command(cmdline);
        if args.is_empty() {
            return Ok(());
        }

        match args[0].as_str() {
            ADD_USER_COMMAND => Self::cmd_add_user(mgr, &args),
            REMOVE_USER_COMMAND => Self::cmd_remove_user(mgr, &args),
            RESET_USER_COMMAND => Self::cmd_reset_password(mgr, &args),
            SET_USER_DN_COMMAND => Self::cmd_set_dn(mgr, &args),
            GRANT_USER_COMMAND => Self::cmd_grant(mgr, &args),
            REVOKE_USER_COMMAND => Self::cmd_revoke(mgr, &args),
            _ => {
                eprintln!("Unknown command: {}", args[0]);
                Ok(())
            }
        }
    }

    fn cmd_add_user(mgr: &RepositoryManager, args: &[String]) -> Result<(), ServerError> {
        if args.len() < 2 {
            return Err(ServerError::Other(
                "Usage: -add <username> [--p <password>]".into(),
            ));
        }
        let username = &args[1];
        // Look for password option
        let password = args
            .windows(2)
            .find(|w| w[0] == PASSWORD_OPTION)
            .map(|w| w[1].as_str());

        match password {
            Some(_pwd) => {
                // In a full implementation, we'd hash the password here
                mgr.user_manager().add_user(username)?;
            }
            None => {
                mgr.user_manager().add_user(username)?;
            }
        }
        Ok(())
    }

    fn cmd_remove_user(mgr: &RepositoryManager, args: &[String]) -> Result<(), ServerError> {
        if args.len() < 2 {
            return Err(ServerError::Other(
                "Usage: -remove <username>".into(),
            ));
        }
        let username = &args[1];
        mgr.user_manager().remove_user(username)?;
        mgr.user_removed(username)?;
        Ok(())
    }

    fn cmd_reset_password(mgr: &RepositoryManager, args: &[String]) -> Result<(), ServerError> {
        if args.len() < 2 {
            return Err(ServerError::Other(
                "Usage: -reset <username>".into(),
            ));
        }
        let username = &args[1];
        mgr.user_manager().reset_password(username)?;
        Ok(())
    }

    fn cmd_set_dn(mgr: &RepositoryManager, args: &[String]) -> Result<(), ServerError> {
        if args.len() < 3 {
            return Err(ServerError::Other(
                "Usage: -dn <username> <distinguished_name>".into(),
            ));
        }
        let username = &args[1];
        let dn = &args[2];
        mgr.user_manager().set_distinguished_name(username, dn)?;
        Ok(())
    }

    fn cmd_grant(mgr: &RepositoryManager, args: &[String]) -> Result<(), ServerError> {
        if args.len() < 4 {
            return Err(ServerError::Other(
                "Usage: -grant <username> <permission> <repo_name>".into(),
            ));
        }
        let username = &args[1];
        let permission = Permission::from_name(&args[2]).ok_or_else(|| {
            ServerError::Other(format!("Invalid permission: {}", args[2]))
        })?;
        let repo_name = &args[3];

        mgr.grant_user_access(username, permission, repo_name)
    }

    fn cmd_revoke(mgr: &RepositoryManager, args: &[String]) -> Result<(), ServerError> {
        if args.len() < 3 {
            return Err(ServerError::Other(
                "Usage: -revoke <username> <repo_name>".into(),
            ));
        }
        let username = &args[1];
        let repo_name = &args[2];

        mgr.revoke_user_access(username, repo_name)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_split_command_simple() {
        let args = CommandProcessor::split_command("-add alice");
        assert_eq!(args, vec!["-add", "alice"]);
    }

    #[test]
    fn test_split_command_with_quotes() {
        let args = CommandProcessor::split_command("-dn alice \"CN=Alice,O=Example\"");
        assert_eq!(args, vec!["-dn", "alice", "CN=Alice,O=Example"]);
    }

    #[test]
    fn test_split_command_empty() {
        let args = CommandProcessor::split_command("");
        assert!(args.is_empty());
    }

    #[test]
    fn test_split_command_password() {
        let args = CommandProcessor::split_command("-add alice --p secret123");
        assert_eq!(args, vec!["-add", "alice", "--p", "secret123"]);
    }

    #[test]
    fn test_command_constants() {
        assert_eq!(ADD_USER_COMMAND, "-add");
        assert_eq!(REMOVE_USER_COMMAND, "-remove");
        assert_eq!(RESET_USER_COMMAND, "-reset");
        assert_eq!(SET_USER_DN_COMMAND, "-dn");
        assert_eq!(GRANT_USER_COMMAND, "-grant");
        assert_eq!(REVOKE_USER_COMMAND, "-revoke");
    }
}
