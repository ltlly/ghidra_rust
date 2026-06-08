//! PDB Program Attributes -- storage of PDB-related metadata.
//!
//! Ports Ghidra's `ghidra.app.util.pdb.PdbProgramAttributes`.

use std::fmt;

/// PDB-related attributes stored with a program.
///
/// Contains the GUID, age, signature, file path, and other metadata
/// that identifies which PDB file corresponds to a binary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PdbProgramAttributes {
    /// PDB Age as a hex string.
    pdb_age: Option<String>,
    /// PDB GUID string.
    pdb_guid: Option<String>,
    /// PDB Signature (older CodeView format).
    pdb_signature: Option<String>,
    /// Path to the PDB file.
    pdb_file: Option<String>,
    /// PDB version string (e.g., "RSDS").
    pdb_version: Option<String>,
    /// Whether the PDB has been loaded.
    pdb_loaded: bool,
    /// Whether the program has been analyzed.
    program_analyzed: bool,
    /// Path to the executable.
    executable_path: String,
}

impl PdbProgramAttributes {
    /// Create a new PdbProgramAttributes with explicit values.
    ///
    /// This is the "dummy" constructor used for testing.
    pub fn new(
        guid: Option<String>,
        age: Option<String>,
        loaded: bool,
        analyzed: bool,
        signature: Option<String>,
        file: Option<String>,
        exec_path: String,
    ) -> Self {
        Self {
            pdb_age: age,
            pdb_guid: guid,
            pdb_signature: signature,
            pdb_file: file,
            pdb_version: Some("RSDS".to_string()),
            pdb_loaded: loaded,
            program_analyzed: analyzed,
            executable_path: exec_path,
        }
    }

    /// Create a PdbProgramAttributes with all fields specified.
    pub fn with_version(
        guid: Option<String>,
        age: Option<String>,
        loaded: bool,
        analyzed: bool,
        signature: Option<String>,
        file: Option<String>,
        version: Option<String>,
        exec_path: String,
    ) -> Self {
        Self {
            pdb_age: age,
            pdb_guid: guid,
            pdb_signature: signature,
            pdb_file: file,
            pdb_version: version,
            pdb_loaded: loaded,
            program_analyzed: analyzed,
            executable_path: exec_path,
        }
    }

    /// Get the PDB Age as a hex string.
    pub fn pdb_age(&self) -> Option<&str> {
        self.pdb_age.as_deref()
    }

    /// Get the decoded integer value of the age string.
    ///
    /// Returns 0 if the age is invalid or undefined.
    pub fn pdb_age_as_int(&self) -> u32 {
        self.pdb_age
            .as_ref()
            .and_then(|s| u32::from_str_radix(s, 16).ok())
            .unwrap_or(0)
    }

    /// Get the PDB GUID string.
    pub fn pdb_guid(&self) -> Option<&str> {
        self.pdb_guid.as_deref()
    }

    /// Get the PDB Signature string.
    pub fn pdb_signature(&self) -> Option<&str> {
        self.pdb_signature.as_deref()
    }

    /// Get the decoded integer value of the signature string.
    ///
    /// Returns 0 if the signature is invalid or undefined.
    pub fn pdb_signature_as_int(&self) -> u32 {
        self.pdb_signature
            .as_ref()
            .and_then(|s| u32::from_str_radix(s, 16).ok())
            .unwrap_or(0)
    }

    /// Get the PDB file path.
    pub fn pdb_file(&self) -> Option<&str> {
        self.pdb_file.as_deref()
    }

    /// Get the PDB version string.
    pub fn pdb_version(&self) -> Option<&str> {
        self.pdb_version.as_deref()
    }

    /// Check if the PDB has been loaded.
    pub fn is_pdb_loaded(&self) -> bool {
        self.pdb_loaded
    }

    /// Get the executable path.
    pub fn executable_path(&self) -> &str {
        &self.executable_path
    }

    /// Check if the program has been analyzed.
    pub fn is_program_analyzed(&self) -> bool {
        self.program_analyzed
    }

    /// Check if this attributes instance has any PDB identification info.
    pub fn has_pdb_info(&self) -> bool {
        self.pdb_guid.is_some()
            || self.pdb_signature.is_some()
            || self.pdb_age.is_some()
    }

    /// Get a description of the PDB identity (GUID or signature + age).
    pub fn identity_description(&self) -> String {
        let mut parts = Vec::new();
        if let Some(guid) = &self.pdb_guid {
            parts.push(format!("GUID: {}", guid));
        }
        if let Some(sig) = &self.pdb_signature {
            parts.push(format!("Sig: {}", sig));
        }
        if let Some(age) = &self.pdb_age {
            parts.push(format!("Age: {}", age));
        }
        if parts.is_empty() {
            "No PDB identity".to_string()
        } else {
            parts.join(", ")
        }
    }
}

impl fmt::Display for PdbProgramAttributes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PDB [{}]", self.identity_description())
    }
}

/// Constants for PDB property keys (matching Ghidra's PdbParserConstants).
pub mod constants {
    /// PDB GUID property key.
    pub const PDB_GUID: &str = "PDB GUID";
    /// PDB Age property key.
    pub const PDB_AGE: &str = "PDB Age";
    /// PDB Loaded property key.
    pub const PDB_LOADED: &str = "PDB Loaded";
    /// PDB Signature property key.
    pub const PDB_SIGNATURE: &str = "PDB Signature";
    /// PDB File property key.
    pub const PDB_FILE: &str = "PDB File";
    /// PDB Version property key.
    pub const PDB_VERSION: &str = "PDB Version";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_attributes() {
        let attrs = PdbProgramAttributes::new(
            Some("AABBCCDD-EEFF-0011-2233-445566778899".to_string()),
            Some("1".to_string()),
            true,
            true,
            Some("12345678".to_string()),
            Some("test.pdb".to_string()),
            "/path/to/exe".to_string(),
        );

        assert_eq!(attrs.pdb_age(), Some("1"));
        assert_eq!(attrs.pdb_age_as_int(), 1);
        assert!(attrs.is_pdb_loaded());
        assert!(attrs.has_pdb_info());
    }

    #[test]
    fn test_age_parsing() {
        let attrs = PdbProgramAttributes::new(
            None,
            Some("FF".to_string()),
            false,
            false,
            None,
            None,
            String::new(),
        );
        assert_eq!(attrs.pdb_age_as_int(), 255);
    }

    #[test]
    fn test_invalid_age() {
        let attrs = PdbProgramAttributes::new(
            None,
            Some("invalid".to_string()),
            false,
            false,
            None,
            None,
            String::new(),
        );
        assert_eq!(attrs.pdb_age_as_int(), 0);
    }

    #[test]
    fn test_signature_parsing() {
        let attrs = PdbProgramAttributes::new(
            None,
            None,
            false,
            false,
            Some("DEADBEEF".to_string()),
            None,
            String::new(),
        );
        assert_eq!(attrs.pdb_signature_as_int(), 0xDEADBEEF);
    }

    #[test]
    fn test_no_pdb_info() {
        let attrs = PdbProgramAttributes::new(
            None,
            None,
            false,
            false,
            None,
            None,
            String::new(),
        );
        assert!(!attrs.has_pdb_info());
        assert_eq!(attrs.identity_description(), "No PDB identity");
    }

    #[test]
    fn test_display() {
        let attrs = PdbProgramAttributes::new(
            Some("AABB".to_string()),
            Some("1".to_string()),
            false,
            false,
            None,
            None,
            String::new(),
        );
        let s = format!("{}", attrs);
        assert!(s.contains("GUID: AABB"));
        assert!(s.contains("Age: 1"));
    }

    #[test]
    fn test_constants() {
        assert_eq!(constants::PDB_GUID, "PDB GUID");
        assert_eq!(constants::PDB_AGE, "PDB Age");
        assert_eq!(constants::PDB_LOADED, "PDB Loaded");
    }
}
