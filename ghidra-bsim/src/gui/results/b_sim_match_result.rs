//! A possible BSim function match result.
//!
//! Ports Ghidra's `ghidra.features.bsim.gui.search.results.BSimMatchResult`.

use super::b_sim_result_status::BSimResultStatus;

/// A possible BSim function match. The similarity of this function is scored
/// and denoted by `similarity`. The significance of the match is denoted by
/// `significance`.
#[derive(Debug, Clone)]
pub struct BSimMatchResult {
    /// Original queried function name.
    pub original_function_name: String,
    /// Original queried function address.
    pub original_function_address: u64,
    /// The matched (similar) function name.
    pub similar_function_name: String,
    /// The matched (similar) function address.
    pub similar_function_address: u64,
    /// Name of the executable containing the matched function.
    pub executable_name: String,
    /// URL string of the executable.
    pub executable_url: String,
    /// Architecture of the executable.
    pub architecture: String,
    /// Compiler name of the executable.
    pub compiler_name: String,
    /// MD5 hash of the executable.
    pub md5: String,
    /// Date of the executable.
    pub date: Option<String>,
    /// The similarity score (0.0 to 1.0).
    pub similarity: f64,
    /// The significance score (0.0+, no upper bound).
    pub significance: f64,
    /// Address in the program where the original function resides.
    pub address: u64,
    /// Status of this result.
    status: BSimResultStatus,
}

impl BSimMatchResult {
    /// Create a new BSim match result.
    pub fn new(
        original_function_name: String,
        original_function_address: u64,
        similar_function_name: String,
        similar_function_address: u64,
        executable_name: String,
        executable_url: String,
        architecture: String,
        compiler_name: String,
        md5: String,
        similarity: f64,
        significance: f64,
        address: u64,
    ) -> Self {
        Self {
            original_function_name,
            original_function_address,
            similar_function_name,
            similar_function_address,
            executable_name,
            executable_url,
            architecture,
            compiler_name,
            md5,
            date: None,
            similarity,
            significance,
            address,
            status: BSimResultStatus::NotApplied,
        }
    }

    /// Get the current status.
    pub fn status(&self) -> BSimResultStatus {
        self.status
    }

    /// Set the status. If setting to Ignored and the current status is
    /// NameApplied or SignatureApplied, the status is not changed.
    pub fn set_status(&mut self, status: BSimResultStatus) {
        if status == BSimResultStatus::Ignored
            && (self.status == BSimResultStatus::NameApplied
                || self.status == BSimResultStatus::SignatureApplied)
        {
            return;
        }
        self.status = status;
    }

    /// Whether a specific flag is set on the match function.
    pub fn is_flag_set(&self, flags: u32, mask: u32) -> bool {
        (flags & mask) != 0
    }

    /// Get the executable category for a given type.
    pub fn get_exe_category(&self, category_type: &str) -> Option<String> {
        // Placeholder: in a full implementation, this would look up
        // the category from the executable record's category map.
        match category_type {
            "architecture" => Some(self.architecture.clone()),
            "compiler" => Some(self.compiler_name.clone()),
            _ => None,
        }
    }

    /// Generate BSimMatchResults from similarity results.
    pub fn generate_from_results(
        results: &[(String, u64, Vec<(String, u64, f64, f64, String, String, String, String, String)>)],
    ) -> Vec<BSimMatchResult> {
        let mut match_results = Vec::new();
        for (orig_name, orig_addr, matches) in results {
            for (
                sim_name,
                sim_addr,
                sim_score,
                sig_score,
                exe_name,
                exe_url,
                arch,
                compiler,
                md5,
            ) in matches
            {
                match_results.push(BSimMatchResult::new(
                    orig_name.clone(),
                    *orig_addr,
                    sim_name.clone(),
                    *sim_addr,
                    exe_name.clone(),
                    exe_url.clone(),
                    arch.clone(),
                    compiler.clone(),
                    md5.clone(),
                    *sim_score,
                    *sig_score,
                    *orig_addr,
                ));
            }
        }
        match_results
    }
}

impl Default for BSimMatchResult {
    fn default() -> Self {
        Self {
            original_function_name: String::new(),
            original_function_address: 0,
            similar_function_name: String::new(),
            similar_function_address: 0,
            executable_name: String::new(),
            executable_url: String::new(),
            architecture: String::new(),
            compiler_name: String::new(),
            md5: String::new(),
            date: None,
            similarity: 0.0,
            significance: 0.0,
            address: 0,
            status: BSimResultStatus::NotApplied,
        }
    }
}

impl std::fmt::Display for BSimMatchResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "BSimMatchResult {}\n\texecutable: {}\n\tsimilarity: {}\n\tsignificance: {}\n\toriginal function: {}",
            self.similar_function_name,
            self.executable_name,
            self.similarity,
            self.significance,
            self.original_function_name
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_result() -> BSimMatchResult {
        BSimMatchResult::new(
            "main".to_string(),
            0x1000,
            "main_func".to_string(),
            0x2000,
            "test.exe".to_string(),
            "http://example.com/test.exe".to_string(),
            "x86".to_string(),
            "gcc".to_string(),
            "abc123".to_string(),
            0.95,
            10.0,
            0x1000,
        )
    }

    #[test]
    fn test_new() {
        let r = make_test_result();
        assert_eq!(r.original_function_name, "main");
        assert_eq!(r.similarity, 0.95);
        assert_eq!(r.significance, 10.0);
    }

    #[test]
    fn test_status_default() {
        let r = make_test_result();
        assert_eq!(r.status(), BSimResultStatus::NotApplied);
    }

    #[test]
    fn test_set_status() {
        let mut r = make_test_result();
        r.set_status(BSimResultStatus::NameApplied);
        assert_eq!(r.status(), BSimResultStatus::NameApplied);
    }

    #[test]
    fn test_set_status_ignored_when_applied() {
        let mut r = make_test_result();
        r.set_status(BSimResultStatus::NameApplied);
        r.set_status(BSimResultStatus::Ignored);
        // Should NOT change because it was already NameApplied
        assert_eq!(r.status(), BSimResultStatus::NameApplied);
    }

    #[test]
    fn test_set_status_ignored_when_not_applied() {
        let mut r = make_test_result();
        r.set_status(BSimResultStatus::Ignored);
        assert_eq!(r.status(), BSimResultStatus::Ignored);
    }

    #[test]
    fn test_display() {
        let r = make_test_result();
        let s = format!("{}", r);
        assert!(s.contains("main_func"));
        assert!(s.contains("test.exe"));
    }

    #[test]
    fn test_generate_from_results() {
        let results = vec![(
            "func_a".to_string(),
            0x1000,
            vec![(
                "func_b".to_string(),
                0x2000,
                0.9,
                5.0,
                "exe.exe".to_string(),
                "http://example.com".to_string(),
                "x86".to_string(),
                "gcc".to_string(),
                "md5hash".to_string(),
            )],
        )];
        let matches = BSimMatchResult::generate_from_results(&results);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].original_function_name, "func_a");
    }

    #[test]
    fn test_is_flag_set() {
        let r = make_test_result();
        assert!(r.is_flag_set(0b1010, 0b0010));
        assert!(!r.is_flag_set(0b1010, 0b0100));
    }

    #[test]
    fn test_exe_category() {
        let r = make_test_result();
        assert_eq!(r.get_exe_category("architecture"), Some("x86".to_string()));
        assert_eq!(r.get_exe_category("compiler"), Some("gcc".to_string()));
        assert_eq!(r.get_exe_category("unknown"), None);
    }
}
