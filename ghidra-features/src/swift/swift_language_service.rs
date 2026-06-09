//! Swift language service: toolchain detection, compiler version,
//! and language-specific analysis helpers.
//!
//! Ported from Ghidra's `SwiftLanguageService.java`.

use std::fmt;
use std::path::{Path, PathBuf};
use std::process::Command;

// ---------------------------------------------------------------------------
// Swift compiler version
// ---------------------------------------------------------------------------

/// A parsed Swift compiler version.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct SwiftVersion {
    /// Major version number.
    pub major: u32,
    /// Minor version number.
    pub minor: u32,
    /// Patch version number.
    pub patch: u32,
}

impl SwiftVersion {
    /// Create a new version.
    pub fn new(major: u32, minor: u32, patch: u32) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }

    /// Parse a version string like `"5.9.2"` or `"5.9"`.
    pub fn parse(s: &str) -> Option<Self> {
        let parts: Vec<&str> = s.trim().split('.').collect();
        if parts.len() < 2 {
            return None;
        }
        let major = parts[0].parse().ok()?;
        let minor = parts[1].parse().ok()?;
        let patch = if parts.len() > 2 {
            parts[2].parse().unwrap_or(0)
        } else {
            0
        };
        Some(Self::new(major, minor, patch))
    }

    /// Whether this version supports Swift concurrency (`async`/`await`).
    ///
    /// Swift concurrency was introduced in Swift 5.5.
    pub fn supports_concurrency(&self) -> bool {
        *self >= SwiftVersion::new(5, 5, 0)
    }

    /// Whether this version supports parameter packs (Swift 5.9+).
    pub fn supports_parameter_packs(&self) -> bool {
        *self >= SwiftVersion::new(5, 9, 0)
    }

    /// Whether this version supports noncopyable types (Swift 5.9+).
    pub fn supports_noncopyable(&self) -> bool {
        *self >= SwiftVersion::new(5, 9, 0)
    }

    /// Whether this version uses the modern `$s` mangling prefix (Swift 4+).
    pub fn uses_modern_mangling(&self) -> bool {
        *self >= SwiftVersion::new(4, 0, 0)
    }
}

impl fmt::Display for SwiftVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

// ---------------------------------------------------------------------------
// Swift toolchain
// ---------------------------------------------------------------------------

/// Information about a detected Swift toolchain installation.
#[derive(Debug, Clone)]
pub struct SwiftToolchain {
    /// Path to the Swift binary directory.
    pub bin_dir: PathBuf,
    /// Path to the Swift standard library.
    pub stdlib_dir: PathBuf,
    /// The compiler version.
    pub version: SwiftVersion,
    /// Full version string from `swift --version`.
    pub version_string: String,
    /// Target triple (e.g., `x86_64-unknown-linux-gnu`).
    pub target_triple: Option<String>,
}

impl SwiftToolchain {
    /// Attempt to detect a Swift toolchain on the system.
    ///
    /// Tries `swift --version` on the system PATH first.  If that fails,
    /// checks common installation locations.
    pub fn detect() -> Option<Self> {
        Self::detect_from_path().or_else(Self::detect_from_common_locations)
    }

    /// Try to detect from the system PATH.
    fn detect_from_path() -> Option<Self> {
        let output = Command::new("swift").arg("--version").output().ok()?;
        if !output.status.success() {
            return None;
        }
        let version_str = String::from_utf8_lossy(&output.stdout).to_string();
        let version = Self::parse_version_from_output(&version_str)?;

        let bin_output = Command::new("swift")
            .args(["-print-target-info"])
            .output()
            .ok();
        let target_triple = bin_output.and_then(|o| {
            let text = String::from_utf8_lossy(&o.stdout);
            Self::parse_target_triple(&text)
        });

        let bin_dir = Self::find_swift_bin_dir().unwrap_or_else(|| PathBuf::from("/usr/bin"));

        Some(Self {
            stdlib_dir: bin_dir
                .parent()
                .unwrap_or(Path::new("/usr"))
                .join("lib/swift"),
            bin_dir,
            version,
            version_string: version_str,
            target_triple,
        })
    }

    /// Try common installation paths.
    fn detect_from_common_locations() -> Option<Self> {
        let candidates = [
            "/usr/bin/swift",
            "/usr/local/bin/swift",
            "/opt/swift/usr/bin/swift",
            "/Library/Developer/CommandLineTools/usr/bin/swift",
        ];
        for path in &candidates {
            if Path::new(path).exists() {
                if let Ok(output) = Command::new(path).arg("--version").output() {
                    if output.status.success() {
                        let version_str = String::from_utf8_lossy(&output.stdout).to_string();
                        if let Some(version) = Self::parse_version_from_output(&version_str) {
                            let bin_dir = Path::new(path)
                                .parent()
                                .unwrap_or(Path::new("/usr/bin"))
                                .to_path_buf();
                            return Some(Self {
                                stdlib_dir: bin_dir
                                    .parent()
                                    .unwrap_or(Path::new("/usr"))
                                    .join("lib/swift"),
                                bin_dir,
                                version,
                                version_string: version_str,
                                target_triple: None,
                            });
                        }
                    }
                }
            }
        }
        None
    }

    /// Parse a version from `swift --version` output.
    ///
    /// Example input: `swift-driver version: 1.87.3 Apple Swift version 5.9.2`
    fn parse_version_from_output(output: &str) -> Option<SwiftVersion> {
        // Look for "Swift version X.Y.Z" pattern
        for line in output.lines() {
            if let Some(pos) = line.find("Swift version") {
                let rest = &line[pos + "Swift version".len()..];
                let version_str = rest.split_whitespace().next()?;
                return SwiftVersion::parse(version_str);
            }
        }
        // Fallback: look for a version-like string
        for line in output.lines() {
            for word in line.split_whitespace() {
                if let Some(v) = SwiftVersion::parse(word) {
                    if v.major >= 2 {
                        return Some(v);
                    }
                }
            }
        }
        None
    }

    /// Parse the target triple from `swift -print-target-info` JSON output.
    fn parse_target_triple(json: &str) -> Option<String> {
        // Simple extraction without a JSON dependency.
        // Looks for "target": { ... "triple": "..." }
        for line in json.lines() {
            let trimmed = line.trim();
            if trimmed.contains("\"triple\"") {
                if let Some(start) = trimmed.find('"') {
                    let rest = &trimmed[start + 1..];
                    if let Some(end) = rest.find('"') {
                        let key = &rest[..end];
                        if key == "triple" {
                            // Next quoted string is the value
                            let after_key = &rest[end + 1..];
                            if let Some(vs) = after_key.find('"') {
                                let val_start = vs + 1;
                                if let Some(ve) = after_key[val_start..].find('"') {
                                    return Some(after_key[val_start..val_start + ve].to_string());
                                }
                            }
                        }
                    }
                }
            }
        }
        None
    }

    /// Find the directory containing the `swift` binary.
    ///
    /// Checks the `PATH` environment variable for the `swift` binary.
    fn find_swift_bin_dir() -> Option<PathBuf> {
        if let Ok(path_env) = std::env::var("PATH") {
            for dir in path_env.split(':') {
                let candidate = Path::new(dir).join("swift");
                if candidate.exists() {
                    return Some(PathBuf::from(dir));
                }
            }
        }
        None
    }

    /// Get the path to `swift-demangle`.
    pub fn swift_demangle_path(&self) -> PathBuf {
        self.bin_dir.join("swift-demangle")
    }

    /// Check if `swift-demangle` is available.
    pub fn has_swift_demangle(&self) -> bool {
        self.swift_demangle_path().exists()
    }

    /// Get the Swift standard library path for the given platform.
    pub fn stdlib_path(&self, platform: &str) -> PathBuf {
        self.stdlib_dir.join(platform)
    }
}

// ---------------------------------------------------------------------------
// Swift language analysis helpers
// ---------------------------------------------------------------------------

/// Helpers for analysing Swift binaries.
pub struct SwiftLanguageService;

impl SwiftLanguageService {
    /// Detect whether a binary appears to contain Swift code by looking for
    /// characteristic section names and symbols.
    ///
    /// Returns a confidence score from 0.0 (no Swift indicators) to 1.0
    /// (definitive Swift binary).
    pub fn detect_swift_binary(section_names: &[String], symbol_names: &[String]) -> f64 {
        let mut score: f64 = 0.0;

        // Check for Swift metadata sections (strong indicator)
        let swift_sections = [
            "__swift5_fieldmd",
            "swift5_fieldmd",
            "__swift5_typeref",
            "swift5_typeref",
            "__swift5_reflstr",
            "swift5_reflstr",
            "__swift5_proto",
            "swift5_protocol_conformances",
            "__swift5_types",
            "swift5_type_metadata",
            "__swift5_assocty",
            "swift5_assocty",
            "__swift5_builtin",
            "swift5_builtin",
            "__swift5_capture",
            "swift5_capture",
            "__swift5_protos",
            "swift5_protocols",
            "__swift5_entry",
            "swift5_entry",
        ];

        let mut swift_section_count = 0;
        for sec in section_names {
            if swift_sections.iter().any(|s| *s == sec.as_str()) {
                swift_section_count += 1;
            }
        }
        if swift_section_count > 0 {
            score += 0.3_f64.min(swift_section_count as f64 * 0.1);
        }

        // Check for Swift runtime symbols
        let swift_runtime_count = symbol_names
            .iter()
            .filter(|s| super::is_swift_runtime_fn(s))
            .count();
        if swift_runtime_count > 0 {
            score += 0.3_f64.min(swift_runtime_count as f64 * 0.05);
        }

        // Check for Swift mangled symbols
        let swift_mangled_count = symbol_names
            .iter()
            .filter(|s| super::is_swift_mangled(s))
            .count();
        if swift_mangled_count > 0 {
            score += 0.4_f64.min(swift_mangled_count as f64 * 0.01);
        }

        score.min(1.0)
    }

    /// Classify a Swift symbol by its kind.
    pub fn classify_symbol(mangled: &str) -> SwiftSymbolKind {
        if !super::is_swift_mangled(mangled) {
            return SwiftSymbolKind::Other;
        }
        // After the prefix ($s, $S, _T0, etc.), the first meaningful character
        // often indicates the kind.
        let effective = if mangled.starts_with("_$s") || mangled.starts_with("_$S") {
            &mangled[3..]
        } else if mangled.starts_with("$s") || mangled.starts_with("$S") {
            &mangled[2..]
        } else if mangled.starts_with("_T0") {
            &mangled[3..]
        } else if mangled.starts_with("__T") || mangled.starts_with("_Tt") {
            &mangled[3..]
        } else {
            return SwiftSymbolKind::Other;
        };

        // Skip module name (digits followed by identifier)
        let mut chars = effective.chars();
        // Read digits
        while let Some(c) = chars.clone().next() {
            if c.is_ascii_digit() {
                chars.next();
            } else {
                break;
            }
        }
        // Read identifier chars
        while let Some(c) = chars.clone().next() {
            if c.is_ascii_alphanumeric() || c == '_' {
                chars.next();
            } else {
                break;
            }
        }
        // Now look at the operator
        let remaining: String = chars.collect();
        match remaining.chars().next() {
            Some('V') => SwiftSymbolKind::Struct,
            Some('C') => SwiftSymbolKind::Class,
            Some('O') => SwiftSymbolKind::Enum,
            Some('P') => SwiftSymbolKind::Protocol,
            Some('f') => SwiftSymbolKind::Function,
            Some('v') => SwiftSymbolKind::Variable,
            Some('i') => SwiftSymbolKind::Subscript,
            Some('a') => SwiftSymbolKind::TypeAlias,
            Some('E') => SwiftSymbolKind::Extension,
            _ => SwiftSymbolKind::Other,
        }
    }

    /// Return the list of all Swift metadata section names this service
    /// knows about.
    pub fn known_section_names() -> &'static [&'static str] {
        &[
            "__swift5_fieldmd",
            "swift5_fieldmd",
            ".sw5flmd",
            "__swift5_assocty",
            "swift5_assocty",
            ".sw5asty",
            "__swift5_builtin",
            "swift5_builtin",
            ".sw5bltn",
            "__swift5_capture",
            "swift5_capture",
            ".sw5cptr",
            "__swift5_typeref",
            "swift5_typeref",
            ".sw5tyrf",
            "__swift5_reflstr",
            "swift5_reflstr",
            ".sw5rfst",
            "__swift5_proto",
            "swift5_protocol_conformances",
            ".sw5prtc",
            "__swift5_protos",
            "swift5_protocols",
            ".sw5prt",
            "__swift5_acfuncs",
            "swift5_accessible_functions",
            ".sw5acfn",
            "__swift5_mpenum",
            "swift5_mpenum",
            ".sw5mpen",
            "__swift5_types",
            "__swift5_types2",
            "swift5_type_metadata",
            ".sw5tymd",
            "__swift5_entry",
            "swift5_entry",
            ".sw5entr",
            "__swift_ast",
            ".swift_ast",
            "swiftast",
        ]
    }
}

// ---------------------------------------------------------------------------
// Swift symbol kind
// ---------------------------------------------------------------------------

/// The kind of entity a Swift symbol represents.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SwiftSymbolKind {
    /// A struct type.
    Struct,
    /// A class type.
    Class,
    /// An enum type.
    Enum,
    /// A protocol.
    Protocol,
    /// A function or method.
    Function,
    /// A variable or property.
    Variable,
    /// A subscript.
    Subscript,
    /// A type alias.
    TypeAlias,
    /// A type extension.
    Extension,
    /// An actor type.
    Actor,
    /// A closure.
    Closure,
    /// Could not be classified.
    Other,
}

impl SwiftSymbolKind {
    /// Return a human-readable name for this kind.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Struct => "struct",
            Self::Class => "class",
            Self::Enum => "enum",
            Self::Protocol => "protocol",
            Self::Function => "function",
            Self::Variable => "variable",
            Self::Subscript => "subscript",
            Self::TypeAlias => "typealias",
            Self::Extension => "extension",
            Self::Actor => "actor",
            Self::Closure => "closure",
            Self::Other => "other",
        }
    }
}

impl fmt::Display for SwiftSymbolKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_swift_version_parse() {
        assert_eq!(
            SwiftVersion::parse("5.9.2"),
            Some(SwiftVersion::new(5, 9, 2))
        );
        assert_eq!(
            SwiftVersion::parse("5.9"),
            Some(SwiftVersion::new(5, 9, 0))
        );
        assert_eq!(SwiftVersion::parse("invalid"), None);
        assert_eq!(SwiftVersion::parse("5"), None);
    }

    #[test]
    fn test_swift_version_display() {
        let v = SwiftVersion::new(5, 9, 2);
        assert_eq!(v.to_string(), "5.9.2");
    }

    #[test]
    fn test_swift_version_ordering() {
        let a = SwiftVersion::new(5, 9, 0);
        let b = SwiftVersion::new(5, 9, 2);
        let c = SwiftVersion::new(6, 0, 0);
        assert!(a < b);
        assert!(b < c);
    }

    #[test]
    fn test_swift_version_feature_detection() {
        let v4 = SwiftVersion::new(4, 0, 0);
        assert!(v4.uses_modern_mangling());
        assert!(!v4.supports_concurrency());

        let v55 = SwiftVersion::new(5, 5, 0);
        assert!(v55.supports_concurrency());
        assert!(!v55.supports_parameter_packs());

        let v59 = SwiftVersion::new(5, 9, 0);
        assert!(v59.supports_concurrency());
        assert!(v59.supports_parameter_packs());
        assert!(v59.supports_noncopyable());
    }

    #[test]
    fn test_parse_version_from_output() {
        let output =
            "swift-driver version: 1.87.3 Apple Swift version 5.9.2 (swiftlang-5.9.2.2.11)";
        let v = SwiftToolchain::parse_version_from_output(output);
        assert_eq!(v, Some(SwiftVersion::new(5, 9, 2)));
    }

    #[test]
    fn test_parse_version_from_output_simple() {
        let output = "Apple Swift version 5.7 (swiftlang-5.7.0.127.4)";
        let v = SwiftToolchain::parse_version_from_output(output);
        assert_eq!(v, Some(SwiftVersion::new(5, 7, 0)));
    }

    #[test]
    fn test_detect_swift_binary_no_indicators() {
        let score = SwiftLanguageService::detect_swift_binary(&[], &[]);
        assert_eq!(score, 0.0);
    }

    #[test]
    fn test_detect_swift_binary_with_sections() {
        let sections = vec![
            "__swift5_fieldmd".to_string(),
            "__swift5_typeref".to_string(),
            "__swift5_reflstr".to_string(),
        ];
        let score = SwiftLanguageService::detect_swift_binary(&sections, &[]);
        assert!(score > 0.0);
        assert!(score <= 1.0);
    }

    #[test]
    fn test_detect_swift_binary_with_symbols() {
        let symbols = vec![
            "_swift_allocObject".to_string(),
            "swift_retain".to_string(),
            "$s10MyModule3fooyyF".to_string(),
        ];
        let score = SwiftLanguageService::detect_swift_binary(&[], &symbols);
        assert!(score > 0.0);
    }

    #[test]
    fn test_detect_swift_binary_full() {
        let sections = vec![
            "__swift5_fieldmd".to_string(),
            "__swift5_types".to_string(),
            "__swift5_proto".to_string(),
        ];
        let symbols = vec![
            "_swift_allocObject".to_string(),
            "swift_retain".to_string(),
            "$s10MyModule3fooyyF".to_string(),
            "$s10MyModule5PointV".to_string(),
            "$s10MyModule7MyClassC".to_string(),
        ];
        let score = SwiftLanguageService::detect_swift_binary(&sections, &symbols);
        assert!(score > 0.5);
    }

    #[test]
    fn test_classify_symbol() {
        assert_eq!(
            SwiftLanguageService::classify_symbol("$s10Module5PointV"),
            SwiftSymbolKind::Struct
        );
        assert_eq!(
            SwiftLanguageService::classify_symbol("$s10Module7MyClassC"),
            SwiftSymbolKind::Class
        );
        assert_eq!(
            SwiftLanguageService::classify_symbol("$s10Module7MyEnumO"),
            SwiftSymbolKind::Enum
        );
        assert_eq!(
            SwiftLanguageService::classify_symbol("not_mangled"),
            SwiftSymbolKind::Other
        );
    }

    #[test]
    fn test_swift_symbol_kind_name() {
        assert_eq!(SwiftSymbolKind::Struct.name(), "struct");
        assert_eq!(SwiftSymbolKind::Class.name(), "class");
        assert_eq!(SwiftSymbolKind::Function.name(), "function");
    }

    #[test]
    fn test_known_section_names() {
        let names = SwiftLanguageService::known_section_names();
        assert!(names.contains(&"__swift5_fieldmd"));
        assert!(names.contains(&"swift5_type_metadata"));
        assert!(names.len() > 30);
    }
}
