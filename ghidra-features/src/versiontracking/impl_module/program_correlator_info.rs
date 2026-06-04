//! Program correlator info implementation.

use std::fmt;

use crate::versiontracking::options::VtOptions;
use crate::versiontracking::types::VtProgramCorrelatorAddressRestrictionPreference;

/// Implementation of program correlator metadata.
///
/// Stores information about a program correlator run including
/// the correlator name, description, options, and address sets.
///
/// Corresponds to Ghidra's `ProgramCorrelatorInfoImpl` and
/// `VTProgramCorrelatorInfo` Java classes.
#[derive(Debug, Clone)]
pub struct ProgramCorrelatorInfoImpl {
    /// Correlator name
    name: String,
    /// Correlator description
    description: String,
    /// Correlator class name (fully qualified)
    class_name: String,
    /// Correlator options
    options: VtOptions,
    /// Source address set (offsets)
    source_address_set: Vec<u64>,
    /// Destination address set (offsets)
    destination_address_set: Vec<u64>,
    /// Address restriction preference
    address_restriction_preference: VtProgramCorrelatorAddressRestrictionPreference,
    /// Priority
    priority: i32,
    /// Timestamp when the correlation was run
    timestamp: u64,
}

impl ProgramCorrelatorInfoImpl {
    /// Create a new program correlator info.
    pub fn new(name: impl Into<String>, class_name: impl Into<String>) -> Self {
        let name_str = name.into();
        Self {
            description: String::new(),
            options: VtOptions::new(&name_str),
            name: name_str,
            class_name: class_name.into(),
            source_address_set: Vec::new(),
            destination_address_set: Vec::new(),
            address_restriction_preference: VtProgramCorrelatorAddressRestrictionPreference::NoPreference,
            priority: 100,
            timestamp: 0,
        }
    }

    /// Returns the correlator name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Set the correlator name.
    pub fn set_name(&mut self, name: impl Into<String>) {
        self.name = name.into();
    }

    /// Returns the correlator description.
    pub fn description(&self) -> &str {
        &self.description
    }

    /// Set the description.
    pub fn set_description(&mut self, desc: impl Into<String>) {
        self.description = desc.into();
    }

    /// Returns the class name.
    pub fn class_name(&self) -> &str {
        &self.class_name
    }

    /// Returns the options.
    pub fn options(&self) -> &VtOptions {
        &self.options
    }

    /// Returns a mutable reference to options.
    pub fn options_mut(&mut self) -> &mut VtOptions {
        &mut self.options
    }

    /// Set options.
    pub fn set_options(&mut self, options: VtOptions) {
        self.options = options;
    }

    /// Returns the source address set.
    pub fn source_address_set(&self) -> &[u64] {
        &self.source_address_set
    }

    /// Set the source address set.
    pub fn set_source_address_set(&mut self, addresses: Vec<u64>) {
        self.source_address_set = addresses;
    }

    /// Returns the destination address set.
    pub fn destination_address_set(&self) -> &[u64] {
        &self.destination_address_set
    }

    /// Set the destination address set.
    pub fn set_destination_address_set(&mut self, addresses: Vec<u64>) {
        self.destination_address_set = addresses;
    }

    /// Returns the address restriction preference.
    pub fn address_restriction_preference(&self) -> VtProgramCorrelatorAddressRestrictionPreference {
        self.address_restriction_preference
    }

    /// Set the address restriction preference.
    pub fn set_address_restriction_preference(
        &mut self,
        pref: VtProgramCorrelatorAddressRestrictionPreference,
    ) {
        self.address_restriction_preference = pref;
    }

    /// Returns the priority.
    pub fn priority(&self) -> i32 {
        self.priority
    }

    /// Set the priority.
    pub fn set_priority(&mut self, priority: i32) {
        self.priority = priority;
    }

    /// Returns the timestamp.
    pub fn timestamp(&self) -> u64 {
        self.timestamp
    }

    /// Set the timestamp.
    pub fn set_timestamp(&mut self, ts: u64) {
        self.timestamp = ts;
    }

    /// Serialize to XML string (simplified).
    pub fn to_xml(&self) -> String {
        format!(
            "<ProgramCorrelatorInfo name=\"{}\" class=\"{}\" priority=\"{}\" timestamp=\"{}\"/>",
            self.name, self.class_name, self.priority, self.timestamp
        )
    }
}

/// Fake/info-only program correlator info for display purposes.
#[derive(Debug, Clone)]
pub struct ProgramCorrelatorInfoFake {
    name: String,
    description: String,
}

impl ProgramCorrelatorInfoFake {
    /// Create a fake correlator info.
    pub fn new(name: impl Into<String>, description: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            description: description.into(),
        }
    }

    /// Returns the name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the description.
    pub fn description(&self) -> &str {
        &self.description
    }
}

impl fmt::Display for ProgramCorrelatorInfoImpl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ProgramCorrelatorInfo({}, class={}, src_addrs={}, dst_addrs={})",
            self.name,
            self.class_name,
            self.source_address_set.len(),
            self.destination_address_set.len()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_correlator_info_create() {
        let info = ProgramCorrelatorInfoImpl::new("ExactMatch", "com.ghidra.ExactMatchCorrelator");
        assert_eq!(info.name(), "ExactMatch");
        assert_eq!(info.class_name(), "com.ghidra.ExactMatchCorrelator");
        assert!(info.description().is_empty());
    }

    #[test]
    fn test_correlator_info_address_sets() {
        let mut info = ProgramCorrelatorInfoImpl::new("Test", "TestClass");
        info.set_source_address_set(vec![0x1000, 0x1100, 0x1200]);
        info.set_destination_address_set(vec![0x2000, 0x2100]);
        assert_eq!(info.source_address_set().len(), 3);
        assert_eq!(info.destination_address_set().len(), 2);
    }

    #[test]
    fn test_correlator_info_options() {
        let mut info = ProgramCorrelatorInfoImpl::new("Test", "TestClass");
        info.options_mut().set_int("min_size", 10);
        assert_eq!(info.options().get_int("min_size", 0), 10);
    }

    #[test]
    fn test_correlator_info_xml() {
        let mut info = ProgramCorrelatorInfoImpl::new("Test", "TestClass");
        info.set_priority(20);
        info.set_timestamp(1234567890);
        let xml = info.to_xml();
        assert!(xml.contains("Test"));
        assert!(xml.contains("TestClass"));
        assert!(xml.contains("20"));
    }

    #[test]
    fn test_correlator_info_fake() {
        let fake = ProgramCorrelatorInfoFake::new("Manual Match", "User-created match");
        assert_eq!(fake.name(), "Manual Match");
        assert_eq!(fake.description(), "User-created match");
    }

    #[test]
    fn test_correlator_info_display() {
        let mut info = ProgramCorrelatorInfoImpl::new("Test", "TestClass");
        info.set_source_address_set(vec![0x1000]);
        let display = format!("{}", info);
        assert!(display.contains("Test"));
        assert!(display.contains("src_addrs=1"));
    }
}
