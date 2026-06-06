//! ExeSpecifier -- identifies an executable in BSim.
//!
//! Ports `ghidra.features.bsim.query.protocol.ExeSpecifier`.

pub use super::core::ExeSpecifier;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exe_specifier_new() {
        let spec = ExeSpecifier::new("test.exe");
        assert_eq!(spec.exe_name, "test.exe");
        assert!(spec.md5.is_empty());
        assert!(!spec.is_empty());
    }

    #[test]
    fn test_exe_specifier_from_md5() {
        let spec = ExeSpecifier::from_md5("abc123");
        assert_eq!(spec.md5, "abc123");
        assert!(spec.exe_name.is_empty());
    }

    #[test]
    fn test_exe_specifier_name_with_md5() {
        let mut spec = ExeSpecifier::new("test.exe");
        spec.md5 = "abc123".to_string();
        assert_eq!(spec.exe_name_with_md5(), "test.exe abc123");
    }

    #[test]
    fn test_exe_specifier_eq_by_md5() {
        let a = ExeSpecifier::from_md5("abc");
        let b = ExeSpecifier {
            exe_name: "other".to_string(),
            md5: "abc".to_string(),
            ..Default::default()
        };
        assert_eq!(a, b);
    }

    #[test]
    fn test_exe_specifier_eq_by_name() {
        let a = ExeSpecifier::new("test.exe");
        let b = ExeSpecifier::new("test.exe");
        assert_eq!(a, b);
        let c = ExeSpecifier::new("other.exe");
        assert_ne!(a, c);
    }

    #[test]
    fn test_exe_specifier_ord() {
        let a = ExeSpecifier::new("aaa");
        let b = ExeSpecifier::new("bbb");
        assert!(a < b);
    }

    #[test]
    fn test_exe_specifier_serialization() {
        let spec = ExeSpecifier::new("test.exe");
        let json = serde_json::to_string(&spec).unwrap();
        assert!(json.contains("test.exe"));
        let back: ExeSpecifier = serde_json::from_str(&json).unwrap();
        assert_eq!(back, spec);
    }

    #[test]
    fn test_exe_specifier_is_empty() {
        assert!(ExeSpecifier::default().is_empty());
        assert!(!ExeSpecifier::new("test").is_empty());
    }

    #[test]
    fn test_exe_specifier_clone() {
        let spec = ExeSpecifier::new("test.exe");
        let cloned = spec.clone();
        assert_eq!(cloned, spec);
    }
}
