//! Shell argument parsing and generation utilities.
//!
//! Port of Ghidra's `ghidra.pty.ShellUtils`.

use std::collections::HashMap;
use std::path::Path;

/// Parser state for shell argument tokenization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ParseState {
    Normal,
    NormalEscape,
    DQuote,
    DQuoteEscape,
    SQuote,
    SQuoteEscape,
}

/// Parse a command line string into individual arguments, respecting
/// shell quoting rules (single quotes, double quotes, backslash escapes).
///
/// # Errors
///
/// Returns an error if the input contains unterminated strings or
/// incomplete escape sequences.
///
/// # Examples
///
/// ```
/// use ghidra_core::pty::shell_utils::parse_args;
///
/// let args = parse_args("echo \"hello world\" 'single'").unwrap();
/// assert_eq!(args, vec!["echo", "hello world", "single"]);
/// ```
pub fn parse_args(args: &str) -> Result<Vec<String>, String> {
    let mut result = Vec::new();
    let mut cur_arg = String::new();
    let mut state = ParseState::Normal;

    for c in args.chars() {
        match state {
            ParseState::Normal => match c {
                '\\' => state = ParseState::NormalEscape,
                '"' => state = ParseState::DQuote,
                '\'' => state = ParseState::SQuote,
                ' ' => {
                    if !cur_arg.is_empty() {
                        result.push(std::mem::take(&mut cur_arg));
                    }
                }
                _ => cur_arg.push(c),
            },
            ParseState::NormalEscape => {
                cur_arg.push(c);
                state = ParseState::Normal;
            }
            ParseState::DQuote => match c {
                '\\' => state = ParseState::DQuoteEscape,
                '"' => state = ParseState::Normal,
                _ => cur_arg.push(c),
            },
            ParseState::DQuoteEscape => {
                cur_arg.push(c);
                state = ParseState::DQuote;
            }
            ParseState::SQuote => match c {
                '\\' => state = ParseState::SQuoteEscape,
                '\'' => state = ParseState::Normal,
                _ => cur_arg.push(c),
            },
            ParseState::SQuoteEscape => {
                cur_arg.push(c);
                state = ParseState::SQuote;
            }
        }
    }

    match state {
        ParseState::Normal => {
            if !cur_arg.is_empty() {
                result.push(cur_arg);
            }
        }
        ParseState::DQuote | ParseState::SQuote => {
            return Err("Unterminated string".into());
        }
        ParseState::NormalEscape | ParseState::DQuoteEscape | ParseState::SQuoteEscape => {
            return Err("Incomplete escaped character".into());
        }
    }

    Ok(result)
}

/// Extract the filename component from a path string.
///
/// # Examples
///
/// ```
/// use ghidra_core::pty::shell_utils::remove_path;
///
/// assert_eq!(remove_path("/usr/bin/bash"), "bash");
/// assert_eq!(remove_path("bash"), "bash");
/// ```
pub fn remove_path(exec: &str) -> &str {
    Path::new(exec)
        .file_name()
        .and_then(|f| f.to_str())
        .unwrap_or(exec)
}

/// Strip the directory path from the first element of an argument list.
pub fn remove_path_from_args(args: &[String]) -> Vec<String> {
    if args.is_empty() {
        return Vec::new();
    }
    let mut copy = args.to_vec();
    copy[0] = remove_path(&args[0]).to_string();
    copy
}

/// Generate a shell command line string from an argument list.
///
/// Properly quotes arguments containing spaces or special characters.
pub fn generate_line(args: &[&str]) -> String {
    if args.is_empty() {
        return String::new();
    }
    let mut line = generate_argument(args[0]);
    for a in &args[1..] {
        line.push(' ');
        line.push_str(&generate_argument(a));
    }
    line
}

/// Quote a single argument for shell inclusion.
///
/// If the argument contains spaces, it will be wrapped in appropriate quotes.
pub fn generate_argument(a: &str) -> String {
    if a.contains(' ') {
        if a.contains('"') {
            if a.contains('\'') {
                // Both types of quotes present: escape double quotes
                format!("\"{}\"", a.replace('"', "\\\""))
            } else {
                // Only double quotes present: use single quotes
                format!("'{}'", a)
            }
        } else {
            // No double quotes present: use double quotes
            format!("\"{}\"", a)
        }
    } else {
        a.to_string()
    }
}

/// Generate a null-terminated environment block from a map.
///
/// Each entry is formatted as `KEY=VALUE\0`.
pub fn generate_env_block(env: &HashMap<String, String>) -> String {
    env.iter()
        .map(|(k, v)| format!("{}={}\0", k, v))
        .collect::<String>()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_args_simple() {
        let args = parse_args("echo hello world").unwrap();
        assert_eq!(args, vec!["echo", "hello", "world"]);
    }

    #[test]
    fn test_parse_args_double_quotes() {
        let args = parse_args("echo \"hello world\"").unwrap();
        assert_eq!(args, vec!["echo", "hello world"]);
    }

    #[test]
    fn test_parse_args_single_quotes() {
        let args = parse_args("echo 'hello world'").unwrap();
        assert_eq!(args, vec!["echo", "hello world"]);
    }

    #[test]
    fn test_parse_args_mixed_quotes() {
        let args = parse_args("cmd \"double\" 'single'").unwrap();
        assert_eq!(args, vec!["cmd", "double", "single"]);
    }

    #[test]
    fn test_parse_args_escape() {
        let args = parse_args("echo hello\\ world").unwrap();
        assert_eq!(args, vec!["echo", "hello world"]);
    }

    #[test]
    fn test_parse_args_empty() {
        let args = parse_args("").unwrap();
        assert!(args.is_empty());
    }

    #[test]
    fn test_parse_args_spaces_only() {
        let args = parse_args("   ").unwrap();
        assert!(args.is_empty());
    }

    #[test]
    fn test_parse_args_unterminated_double_quote() {
        let result = parse_args("echo \"hello");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Unterminated"));
    }

    #[test]
    fn test_parse_args_unterminated_single_quote() {
        let result = parse_args("echo 'hello");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_args_incomplete_escape() {
        let result = parse_args("echo hello\\");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Incomplete"));
    }

    #[test]
    fn test_parse_args_nested_quotes() {
        let args = parse_args("echo \"it's here\"").unwrap();
        assert_eq!(args, vec!["echo", "it's here"]);
    }

    #[test]
    fn test_remove_path() {
        assert_eq!(remove_path("/usr/bin/bash"), "bash");
        assert_eq!(remove_path("/usr/local/bin/python3"), "python3");
        assert_eq!(remove_path("bash"), "bash");
        assert_eq!(remove_path("./my_script"), "my_script");
    }

    #[test]
    fn test_remove_path_from_args() {
        let args: Vec<String> = vec!["/usr/bin/bash".into(), "-c".into(), "echo".into()];
        let result = remove_path_from_args(&args);
        assert_eq!(result, vec!["bash", "-c", "echo"]);
    }

    #[test]
    fn test_remove_path_from_args_empty() {
        let result = remove_path_from_args(&[]);
        assert!(result.is_empty());
    }

    #[test]
    fn test_generate_argument_no_spaces() {
        assert_eq!(generate_argument("hello"), "hello");
    }

    #[test]
    fn test_generate_argument_with_spaces() {
        assert_eq!(generate_argument("hello world"), "\"hello world\"");
    }

    #[test]
    fn test_generate_argument_with_double_quotes() {
        assert_eq!(generate_argument("say \"hi\""), "'say \"hi\"'");
    }

    #[test]
    fn test_generate_argument_with_both_quotes() {
        assert_eq!(
            generate_argument("it's a \"test\""),
            "\"it's a \\\"test\\\"\""
        );
    }

    #[test]
    fn test_generate_line() {
        let line = generate_line(&["echo", "hello", "world"]);
        assert_eq!(line, "echo hello world");
    }

    #[test]
    fn test_generate_line_with_spaces() {
        let line = generate_line(&["echo", "hello world"]);
        assert_eq!(line, "echo \"hello world\"");
    }

    #[test]
    fn test_generate_line_empty() {
        assert_eq!(generate_line(&[]), "");
    }

    #[test]
    fn test_generate_env_block() {
        let mut env = HashMap::new();
        env.insert("HOME".to_string(), "/root".to_string());
        env.insert("PATH".to_string(), "/usr/bin".to_string());
        let block = generate_env_block(&env);
        // Order is not guaranteed, but both entries should be present
        assert!(block.contains("HOME=/root\0"));
        assert!(block.contains("PATH=/usr/bin\0"));
    }

    #[test]
    fn test_generate_env_block_empty() {
        let env = HashMap::new();
        assert_eq!(generate_env_block(&env), "");
    }
}
