//! ChildAtom -- extends FilterAtom with child function information.
//!
//! Ports `ghidra.features.bsim.query.protocol.ChildAtom`.

pub use super::core::ChildAtom;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::query::protocol::FilterType;

    #[test]
    fn test_child_atom_basic() {
        let atom = ChildAtom::new(FilterType::HasNamedChild, "callee");
        assert_eq!(atom.child_name, "callee");
        assert!(atom.exe_name.is_none());
        assert_eq!(atom.value_string(), "callee");
    }

    #[test]
    fn test_child_atom_with_exe() {
        let mut atom = ChildAtom::new(FilterType::HasNamedChild, "callee");
        atom.exe_name = Some("libcrypto.so".to_string());
        assert_eq!(atom.value_string(), "[libcrypto.so]callee");
    }

    #[test]
    fn test_child_atom_info_string_no_exe() {
        let atom = ChildAtom::new(FilterType::HasNamedChild, "malloc");
        assert_eq!(atom.info_string(), Some("Has child malloc".to_string()));
    }

    #[test]
    fn test_child_atom_info_string_with_exe() {
        let mut atom = ChildAtom::new(FilterType::HasNamedChild, "malloc");
        atom.exe_name = Some("libc.so".to_string());
        assert_eq!(
            atom.info_string(),
            Some("Has child [libc.so]malloc".to_string())
        );
    }

    #[test]
    fn test_child_atom_info_string_empty_name() {
        let atom = ChildAtom::new(FilterType::Blank, "");
        assert!(atom.info_string().is_none());
    }

    #[test]
    fn test_child_atom_serialization() {
        let mut atom = ChildAtom::new(FilterType::HasNamedChild, "printf");
        atom.exe_name = Some("libc.so".to_string());
        let json = serde_json::to_string(&atom).unwrap();
        assert!(json.contains("printf"));
        assert!(json.contains("libc.so"));
        let back: ChildAtom = serde_json::from_str(&json).unwrap();
        assert_eq!(back.child_name, "printf");
    }

    #[test]
    fn test_child_atom_clone() {
        let atom = ChildAtom::new(FilterType::HasNamedChild, "free");
        let cloned = atom.clone();
        assert_eq!(cloned.child_name, "free");
    }
}
