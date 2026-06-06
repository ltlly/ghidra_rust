//! `ShellUtils` -- shell command and path utilities.
//!
//! Ported from `ghidra.pty.ShellUtils`.

use std::path::{Path, PathBuf};

/// Utilities for shell operations.
pub struct ShellUtils;

impl ShellUtils {
    /// Get the default shell for the current platform.
    pub fn default_shell() -> String {
        if cfg!(target_os = "windows") {
            "cmd.exe".to_string()
        } else {
            std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".to_string())
        }
    }

    /// Get the shell arguments for running a command.
    pub fn shell_args(command: &str) -> Vec<String> {
        if cfg!(target_os = "windows") {
            vec!["/c".to_string(), command.to_string()]
        } else {
            vec!["-c".to_string(), command.to_string()]
        }
    }

    /// Quote a string for shell use.
    pub fn shell_quote(s: &str) -> String {
        if cfg!(target_os = "windows") {
            if s.contains(' ') || s.contains('"') {
                format!("\"{}\"", s.replace('"', "\\\""))
            } else {
                s.to_string()
            }
        } else {
            if s.is_empty()
                || s.contains(' ')
                || s.contains('"')
                || s.contains('\'')
                || s.contains('\\')
            {
                format!("'{}'", s.replace('\'', "'\\''"))
            } else {
                s.to_string()
            }
        }
    }

    /// Find an executable in PATH.
    pub fn find_in_path(name: &str) -> Option<PathBuf> {
        if let Ok(path) = std::env::var("PATH") {
            let sep = if cfg!(target_os = "windows") { ';' } else { ':' };
            for dir in path.split(sep) {
                let candidate = Path::new(dir).join(name);
                if candidate.is_file() {
                    return Some(candidate);
                }
                // On Windows, also check with common extensions
                #[cfg(target_os = "windows")]
                {
                    for ext in &[".exe", ".cmd", ".bat"] {
                        let with_ext = Path::new(dir).join(format!("{}{}", name, ext));
                        if with_ext.is_file() {
                            return Some(with_ext);
                        }
                    }
                }
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_shell() {
        let shell = ShellUtils::default_shell();
        assert!(!shell.is_empty());
    }

    #[test]
    fn test_shell_args() {
        let args = ShellUtils::shell_args("echo hello");
        assert_eq!(args.len(), 2);
        if cfg!(target_os = "windows") {
            assert_eq!(args[0], "/c");
        } else {
            assert_eq!(args[0], "-c");
        }
        assert_eq!(args[1], "echo hello");
    }

    #[test]
    fn test_shell_quote_simple() {
        let quoted = ShellUtils::shell_quote("hello");
        assert_eq!(quoted, "hello");
    }

    #[test]
    fn test_shell_quote_with_space() {
        let quoted = ShellUtils::shell_quote("hello world");
        if cfg!(target_os = "windows") {
            assert_eq!(quoted, "\"hello world\"");
        } else {
            assert_eq!(quoted, "'hello world'");
        }
    }

    #[test]
    fn test_shell_quote_empty() {
        let quoted = ShellUtils::shell_quote("");
        if cfg!(target_os = "windows") {
            assert_eq!(quoted, "");
        } else {
            assert_eq!(quoted, "''");
        }
    }

    #[test]
    fn test_find_in_path() {
        // "ls" should exist on Unix
        if cfg!(unix) {
            let result = ShellUtils::find_in_path("ls");
            assert!(result.is_some());
        }
    }

    #[test]
    fn test_find_in_path_nonexistent() {
        let result = ShellUtils::find_in_path("nonexistent_command_12345");
        assert!(result.is_none());
    }
}
