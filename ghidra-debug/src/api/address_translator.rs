//! Address translation between static programs and dynamic traces.
//!
//! Ported from Ghidra's `ghidra.debug.api.modules.DebuggerAddressTranslator`.

use serde::{Deserialize, Serialize};

/// A translated address from trace to program (or vice versa).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TranslatedAddress {
    /// The translated address offset.
    pub offset: u64,
    /// The program or trace ID the address belongs to.
    pub owner_id: String,
    /// Whether the translation was successful.
    pub mapped: bool,
}

impl TranslatedAddress {
    /// Create a successful translation.
    pub fn mapped(offset: u64, owner_id: impl Into<String>) -> Self {
        Self {
            offset,
            owner_id: owner_id.into(),
            mapped: true,
        }
    }

    /// Create an unmapped result.
    pub fn unmapped() -> Self {
        Self {
            offset: 0,
            owner_id: String::new(),
            mapped: false,
        }
    }
}

/// A static mapping entry relating a program address range to a trace address range.
///
/// Ported from the `DebuggerAddressTranslator` interface's mapping context.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StaticMappingEntry {
    /// The program URL.
    pub program_url: String,
    /// The program address range start.
    pub program_min: u64,
    /// The program address range end (inclusive).
    pub program_max: u64,
    /// The trace address range start.
    pub trace_min: u64,
    /// The trace address range end (inclusive).
    pub trace_max: u64,
    /// The lifespan (snap range) during which this mapping is valid.
    pub from_snap: i64,
    /// The end snap (exclusive). i64::MAX means open-ended.
    pub to_snap: i64,
}

impl StaticMappingEntry {
    /// Create a new mapping entry.
    pub fn new(
        program_url: impl Into<String>,
        program_min: u64,
        program_max: u64,
        trace_min: u64,
        trace_max: u64,
        from_snap: i64,
        to_snap: i64,
    ) -> Self {
        Self {
            program_url: program_url.into(),
            program_min,
            program_max,
            trace_min,
            trace_max,
            from_snap,
            to_snap,
        }
    }

    /// Whether this mapping contains the given program address.
    pub fn contains_program_addr(&self, addr: u64) -> bool {
        addr >= self.program_min && addr <= self.program_max
    }

    /// Whether this mapping contains the given trace address.
    pub fn contains_trace_addr(&self, addr: u64) -> bool {
        addr >= self.trace_min && addr <= self.trace_max
    }

    /// Whether this mapping is valid at the given snap.
    pub fn valid_at_snap(&self, snap: i64) -> bool {
        snap >= self.from_snap && snap < self.to_snap
    }

    /// Translate a trace address to a program address.
    pub fn trace_to_program(&self, trace_addr: u64) -> Option<u64> {
        if self.contains_trace_addr(trace_addr) {
            let offset = trace_addr - self.trace_min;
            Some(self.program_min + offset)
        } else {
            None
        }
    }

    /// Translate a program address to a trace address.
    pub fn program_to_trace(&self, program_addr: u64) -> Option<u64> {
        if self.contains_program_addr(program_addr) {
            let offset = program_addr - self.program_min;
            Some(self.trace_min + offset)
        } else {
            None
        }
    }
}

/// The address translator that manages all static mappings.
///
/// Ported from Ghidra's `DebuggerAddressTranslator` interface.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AddressTranslator {
    /// All known static mappings.
    pub mappings: Vec<StaticMappingEntry>,
}

impl AddressTranslator {
    /// Create a new empty translator.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a static mapping entry.
    pub fn add_mapping(&mut self, mapping: StaticMappingEntry) {
        self.mappings.push(mapping);
    }

    /// Translate a trace address to a program address at a given snap.
    pub fn trace_to_program(&self, trace_addr: u64, snap: i64) -> Option<TranslatedAddress> {
        for m in &self.mappings {
            if m.valid_at_snap(snap) {
                if let Some(prog_addr) = m.trace_to_program(trace_addr) {
                    return Some(TranslatedAddress::mapped(prog_addr, &m.program_url));
                }
            }
        }
        None
    }

    /// Translate a program address to a trace address at a given snap.
    pub fn program_to_trace(
        &self,
        program_url: &str,
        program_addr: u64,
        snap: i64,
    ) -> Option<TranslatedAddress> {
        for m in &self.mappings {
            if m.valid_at_snap(snap) && m.program_url == program_url {
                if let Some(trace_addr) = m.program_to_trace(program_addr) {
                    return Some(TranslatedAddress::mapped(trace_addr, "trace"));
                }
            }
        }
        None
    }

    /// Get all mappings valid at a given snap.
    pub fn mappings_at_snap(&self, snap: i64) -> Vec<&StaticMappingEntry> {
        self.mappings
            .iter()
            .filter(|m| m.valid_at_snap(snap))
            .collect()
    }

    /// Get all unique program URLs referenced by mappings.
    pub fn program_urls(&self) -> Vec<&str> {
        let mut urls: Vec<&str> = self
            .mappings
            .iter()
            .map(|m| m.program_url.as_str())
            .collect();
        urls.sort();
        urls.dedup();
        urls
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_static_mapping_entry() {
        let m = StaticMappingEntry::new("file:///prog", 0x400000, 0x400fff, 0x7fff0000, 0x7fff0fff, 0, i64::MAX);
        assert!(m.contains_program_addr(0x400000));
        assert!(m.contains_program_addr(0x400fff));
        assert!(!m.contains_program_addr(0x500000));

        assert!(m.contains_trace_addr(0x7fff0000));
        assert!(!m.contains_trace_addr(0x80000000));

        assert!(m.valid_at_snap(0));
        assert!(m.valid_at_snap(1000));
    }

    #[test]
    fn test_translation() {
        let m = StaticMappingEntry::new("prog", 0x400000, 0x400fff, 0x7fff0000, 0x7fff0fff, 0, i64::MAX);

        assert_eq!(m.trace_to_program(0x7fff0000), Some(0x400000));
        assert_eq!(m.trace_to_program(0x7fff0100), Some(0x400100));
        assert_eq!(m.trace_to_program(0x80000000), None);

        assert_eq!(m.program_to_trace(0x400000), Some(0x7fff0000));
        assert_eq!(m.program_to_trace(0x500000), None);
    }

    #[test]
    fn test_address_translator() {
        let mut t = AddressTranslator::new();
        t.add_mapping(StaticMappingEntry::new(
            "prog1", 0x400000, 0x400fff, 0x7fff0000, 0x7fff0fff, 0, 100,
        ));
        t.add_mapping(StaticMappingEntry::new(
            "prog1", 0x401000, 0x401fff, 0x7fff1000, 0x7fff1fff, 50, i64::MAX,
        ));

        // At snap 0: only first mapping
        let result = t.trace_to_program(0x7fff0000, 0);
        assert!(result.is_some());
        assert_eq!(result.unwrap().offset, 0x400000);

        // At snap 0: second mapping not yet valid
        let result = t.trace_to_program(0x7fff1000, 0);
        assert!(result.is_none());

        // At snap 60: both valid
        let mappings = t.mappings_at_snap(60);
        assert_eq!(mappings.len(), 2);

        // Program URLs
        let urls = t.program_urls();
        assert_eq!(urls.len(), 1);
        assert_eq!(urls[0], "prog1");
    }

    #[test]
    fn test_translated_address() {
        let addr = TranslatedAddress::mapped(0x400000, "prog");
        assert!(addr.mapped);
        assert_eq!(addr.offset, 0x400000);

        let addr = TranslatedAddress::unmapped();
        assert!(!addr.mapped);
    }

    #[test]
    fn test_snapped_mapping() {
        let m = StaticMappingEntry::new("prog", 0x100, 0x1ff, 0x200, 0x2ff, 10, 20);
        assert!(!m.valid_at_snap(9));
        assert!(m.valid_at_snap(10));
        assert!(m.valid_at_snap(19));
        assert!(!m.valid_at_snap(20));
    }

    #[test]
    fn test_translator_serde() {
        let mut t = AddressTranslator::new();
        t.add_mapping(StaticMappingEntry::new("prog", 0, 0xff, 0, 0xff, 0, i64::MAX));
        let json = serde_json::to_string(&t).unwrap();
        let back: AddressTranslator = serde_json::from_str(&json).unwrap();
        assert_eq!(back.mappings.len(), 1);
    }
}
