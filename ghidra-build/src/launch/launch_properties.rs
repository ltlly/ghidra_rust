//! Launch properties file parser.
//!
//! Port of `ghidra.launch.LaunchProperties`.
//!
//! Supports duplicate keys (values collected into `Vec`), `#` and `//` comments,
//! and `${ENV_VAR}` expansion.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use super::java_finder::current_platform;

/// Constant key for the `JAVA_HOME_OVERRIDE` property.
pub const JAVA_HOME_OVERRIDE: &str = "JAVA_HOME_OVERRIDE";

/// Constant key for the `VMARGS` property (all platforms).
pub const VMARGS: &str = "VMARGS";

/// Constant key for the `ENVVARS` property (all platforms).
pub const ENVVARS: &str = "ENVVARS";

/// Error type for launch properties parsing.
#[derive(Debug, thiserror::Error)]
pub enum LaunchPropertiesError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Parse error at line {line}: {message}")]
    Parse { line: usize, message: String },
}

/// Parsed launch properties with support for duplicate keys.
#[derive(Debug, Clone)]
pub struct LaunchProperties {
    properties: HashMap<String, Vec<String>>,
    file_path: PathBuf,
}

impl LaunchProperties {
    /// Load and parse a launch properties file.
    pub fn load(path: &Path) -> Result<Self, LaunchPropertiesError> {
        let content = fs::read_to_string(path)?;
        let properties = parse_properties(&content)?;
        Ok(Self {
            properties,
            file_path: path.to_path_buf(),
        })
    }

    /// Returns the path of the properties file.
    pub fn file_path(&self) -> &Path {
        &self.file_path
    }

    /// Gets the VMARGS platform-specific key for the current platform.
    fn vmargs_platform_key() -> String {
        format!("VMARGS_{}", current_platform().as_str())
    }

    /// Gets the ENVVARS platform-specific key for the current platform.
    fn envvars_platform_key() -> String {
        format!("ENVVARS_{}", current_platform().as_str())
    }

    /// Gets the Java home override directory, if specified.
    pub fn java_home_override(&self) -> Option<PathBuf> {
        self.properties
            .get(JAVA_HOME_OVERRIDE)
            .and_then(|v| v.first())
            .map(PathBuf::from)
    }

    /// Gets all VM arguments (generic + platform-specific) as a single string.
    pub fn vm_args_string(&self) -> String {
        self.vm_arg_list().join(" ")
    }

    /// Gets all VM arguments (generic + platform-specific) as a list.
    pub fn vm_arg_list(&self) -> Vec<String> {
        let mut args = Vec::new();
        if let Some(list) = self.properties.get(VMARGS) {
            args.extend(list.iter().cloned());
        }
        let platform_key = Self::vmargs_platform_key();
        if let Some(list) = self.properties.get(&platform_key) {
            args.extend(list.iter().cloned());
        }
        args
    }

    /// Gets all environment variables (generic + platform-specific) as a list.
    pub fn env_var_list(&self) -> Vec<String> {
        let mut vars = Vec::new();
        if let Some(list) = self.properties.get(ENVVARS) {
            vars.extend(list.iter().cloned());
        }
        let platform_key = Self::envvars_platform_key();
        if let Some(list) = self.properties.get(&platform_key) {
            vars.extend(list.iter().cloned());
        }
        vars
    }
}

/// Parse properties content, allowing duplicate keys.
fn parse_properties(content: &str) -> Result<HashMap<String, Vec<String>>, LaunchPropertiesError> {
    let mut map: HashMap<String, Vec<String>> = HashMap::new();

    for (i, line) in content.lines().enumerate() {
        let line_num = i + 1;
        let trimmed = line.trim();

        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with("//") {
            continue;
        }

        let equals_idx = trimmed.find('=').ok_or_else(|| LaunchPropertiesError::Parse {
            line: line_num,
            message: format!("No '=' found in line"),
        })?;

        if equals_idx == 0 {
            return Err(LaunchPropertiesError::Parse {
                line: line_num,
                message: "Empty key".to_string(),
            });
        }

        let key = trimmed[..equals_idx].trim().to_string();
        let value = expand_env_vars(trimmed[equals_idx + 1..].trim());

        let entry = map.entry(key).or_default();
        if !value.is_empty() {
            entry.push(value);
        }
    }

    Ok(map)
}

/// Expand `${VAR}` style environment variables.
fn expand_env_vars(text: &str) -> String {
    let mut result = text.to_string();
    // Use a simple approach: find each ${...} and replace
    while let Some(start) = result.find("${") {
        if let Some(end) = result[start + 2..].find('}') {
            let var_name = &result[start + 2..start + 2 + end];
            if let Ok(val) = std::env::var(var_name) {
                let placeholder = format!("${{{var_name}}}");
                result = result.replacen(&placeholder, &val, 1);
            } else {
                // Leave unexpanded
                break;
            }
        } else {
            break;
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_parse_basic() {
        let content = r#"
# comment
VMARGS=-Xmx512m
VMARGS=-Xms256m
JAVA_HOME_OVERRIDE=/opt/java17
"#;
        let props = parse_properties(content).unwrap();
        assert_eq!(props.get("VMARGS").unwrap().len(), 2);
        assert_eq!(
            props.get("JAVA_HOME_OVERRIDE").unwrap(),
            &vec!["/opt/java17".to_string()]
        );
    }

    #[test]
    fn test_comments() {
        let content = r#"
# hash comment
// double slash comment
KEY=value
"#;
        let props = parse_properties(content).unwrap();
        assert_eq!(props.len(), 1);
        assert_eq!(props.get("KEY").unwrap(), &vec!["value".to_string()]);
    }

    #[test]
    fn test_launch_properties_java_home() {
        let mut tmpfile = tempfile::NamedTempFile::new().unwrap();
        writeln!(tmpfile, "JAVA_HOME_OVERRIDE=/opt/java17").unwrap();
        let lp = LaunchProperties::load(tmpfile.path()).unwrap();
        assert_eq!(
            lp.java_home_override(),
            Some(PathBuf::from("/opt/java17"))
        );
    }

    #[test]
    fn test_empty_java_home_override() {
        let mut tmpfile = tempfile::NamedTempFile::new().unwrap();
        writeln!(tmpfile, "OTHER=value").unwrap();
        let lp = LaunchProperties::load(tmpfile.path()).unwrap();
        assert_eq!(lp.java_home_override(), None);
    }

    #[test]
    fn test_vm_args_list() {
        let mut tmpfile = tempfile::NamedTempFile::new().unwrap();
        writeln!(tmpfile, "VMARGS=-Xmx512m").unwrap();
        writeln!(tmpfile, "VMARGS=-Xms256m").unwrap();
        let lp = LaunchProperties::load(tmpfile.path()).unwrap();
        let args = lp.vm_arg_list();
        assert!(args.contains(&"-Xmx512m".to_string()));
        assert!(args.contains(&"-Xms256m".to_string()));
    }

    #[test]
    fn test_env_var_list() {
        let mut tmpfile = tempfile::NamedTempFile::new().unwrap();
        writeln!(tmpfile, "ENVVARS=FOO=bar").unwrap();
        let lp = LaunchProperties::load(tmpfile.path()).unwrap();
        let vars = lp.env_var_list();
        assert!(vars.contains(&"FOO=bar".to_string()));
    }

    #[test]
    fn test_parse_error_no_equals() {
        let result = parse_properties("badline");
        assert!(result.is_err());
    }
}
