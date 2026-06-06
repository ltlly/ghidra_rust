//! FilterAtom -- a single filter element for BSim queries.
//!
//! Ports `ghidra.features.bsim.query.protocol.FilterAtom`.

pub use super::core::FilterAtom;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::query::protocol::FilterType;

    #[test]
    fn test_filter_atom_validity() {
        let atom = FilterAtom::new(FilterType::ExeNameMatch, "test");
        assert!(atom.is_valid());
        let empty = FilterAtom::new(FilterType::Blank, "");
        assert!(!empty.is_valid());
    }

    #[test]
    fn test_filter_atom_info_string() {
        let atom = FilterAtom::new(FilterType::ExeNameMatch, "myexe");
        assert_eq!(atom.info_string(), Some("Executable name myexe".to_string()));
    }

    #[test]
    fn test_filter_atom_blank_info_string() {
        let atom = FilterAtom::new(FilterType::Blank, "");
        assert!(atom.info_string().is_none());
    }

    #[test]
    fn test_filter_atom_value_string() {
        let atom = FilterAtom::new(FilterType::ArchitectureMatch, "x86");
        assert_eq!(atom.value_string(), "x86");
    }

    #[test]
    fn test_filter_atom_serialization() {
        let atom = FilterAtom::new(FilterType::Md5Match, "abc123");
        let json = serde_json::to_string(&atom).unwrap();
        assert!(json.contains("abc123"));
        let back: FilterAtom = serde_json::from_str(&json).unwrap();
        assert_eq!(back.value, "abc123");
    }

    #[test]
    fn test_filter_atom_clone() {
        let atom = FilterAtom::new(FilterType::CompilerMatch, "gcc");
        let cloned = atom.clone();
        assert_eq!(cloned.value, "gcc");
    }

    #[test]
    fn test_filter_atom_various_types() {
        let types = vec![
            FilterType::ExeNameMatch,
            FilterType::ArchitectureMatch,
            FilterType::CompilerMatch,
            FilterType::Md5Match,
            FilterType::DateEarlier,
            FilterType::DateLater,
            FilterType::ExeCategory,
        ];
        for ft in types {
            let label = ft.label().to_string();
            let atom = FilterAtom::new(ft, "value");
            assert!(atom.info_string().unwrap().contains(&label));
        }
    }
}
