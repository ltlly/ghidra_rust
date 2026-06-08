//! ComparisonData implementation for Data objects.
//!
//! Ported from Ghidra's `DataComparisonData` Java class in
//! `ghidra.features.base.codecompare.panel`.
//!
//! This module provides a [`ComparisonData`] implementation backed by a
//! program data element (as opposed to a function or raw address range).
//! It is used when the user selects a data element in the listing and
//! wants to compare it with another data element.
//!
//! # Key types
//!
//! - [`DataInfo`] -- lightweight representation of a data element
//! - [`DataComparisonData`] -- ComparisonData implementation for data elements

use super::{AddressSet, ComparisonData, FunctionComparisonInfo, ProgramInfo, ProgramLocation};

/// Lightweight representation of a program data element for comparison purposes.
///
/// This captures the essential information needed to describe and navigate
/// to a data element without depending on the full Ghidra Data model.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataInfo {
    /// The data type name (e.g., "int", "char[16]", "MyStruct").
    pub data_type_name: String,
    /// The label of the data element, if any.
    pub label: Option<String>,
    /// The minimum address of the data element.
    pub min_address: u64,
    /// The length of the data element in bytes.
    pub length: usize,
    /// The program containing this data element.
    pub program: ProgramInfo,
    /// Whether this data element is in an external memory block.
    pub is_external: bool,
    /// The end address of the memory block containing this data element.
    /// Used to clamp the comparison address range.
    pub block_end_address: Option<u64>,
}

impl DataInfo {
    /// Create a new DataInfo.
    pub fn new(
        data_type_name: impl Into<String>,
        min_address: u64,
        length: usize,
        program: ProgramInfo,
    ) -> Self {
        Self {
            data_type_name: data_type_name.into(),
            label: None,
            min_address,
            length,
            program,
            is_external: false,
            block_end_address: None,
        }
    }

    /// Create a new DataInfo with a label.
    pub fn with_label(
        data_type_name: impl Into<String>,
        label: impl Into<String>,
        min_address: u64,
        length: usize,
        program: ProgramInfo,
    ) -> Self {
        Self {
            data_type_name: data_type_name.into(),
            label: Some(label.into()),
            min_address,
            length,
            program,
            is_external: false,
            block_end_address: None,
        }
    }

    /// Set the block end address for address range clamping.
    pub fn with_block_end(mut self, block_end: u64) -> Self {
        self.block_end_address = Some(block_end);
        self
    }

    /// Mark this data element as external.
    pub fn as_external(mut self) -> Self {
        self.is_external = true;
        self
    }

    /// Get the display label for this data element.
    ///
    /// Returns the label if set, otherwise the address as a hex string.
    pub fn display_label(&self) -> String {
        self.label
            .clone()
            .unwrap_or_else(|| format!("0x{:x}", self.min_address))
    }

    /// Compute the end address of the data element, clamped to the block end if available.
    pub fn end_address(&self) -> u64 {
        if self.is_external {
            return self.min_address;
        }
        let raw_end = self.min_address + self.length as u64;
        match self.block_end_address {
            Some(block_end) => raw_end.min(block_end),
            None => raw_end,
        }
    }

    /// Compute the address set for this data element, taking into account
    /// the other side's length (for matching sizes).
    pub fn compute_address_set(&self, other_length: usize) -> AddressSet {
        let size = self.length.max(other_length);
        let end = if self.is_external {
            self.min_address
        } else {
            let raw_end = self.min_address + size as u64;
            match self.block_end_address {
                Some(block_end) => raw_end.min(block_end),
                None => raw_end,
            }
        };
        AddressSet::single(self.min_address, end)
    }
}

/// ComparisonData for a Data object.
///
/// This is the Rust equivalent of Ghidra's `DataComparisonData` Java class.
/// It wraps a [`DataInfo`] and implements the [`ComparisonData`] trait so that
/// data elements can be used in code comparison views.
///
/// # Example
///
/// ```rust
/// use ghidra_features::codecompare::panel::data_comparison::*;
/// use ghidra_features::codecompare::panel::*;
///
/// let program = ProgramInfo::new(1, "/project/test", "test");
/// let data = DataInfo::new("int", 0x1000, 4, program);
/// let comp_data = DataComparisonData::new(data, 4);
///
/// assert!(!comp_data.is_empty());
/// assert!(comp_data.get_function().is_none());
/// assert_eq!(comp_data.get_short_description(), "int");
/// ```
#[derive(Debug, Clone)]
pub struct DataComparisonData {
    data: DataInfo,
    /// The address set computed from this data and the other side's length.
    addresses: AddressSet,
}

impl DataComparisonData {
    /// Create a new DataComparisonData.
    ///
    /// `data` is the data element being compared.
    /// `other_length` is the length of the data element on the other side,
    /// used to ensure both sides cover the same address range size.
    pub fn new(data: DataInfo, other_length: usize) -> Self {
        let addresses = data.compute_address_set(other_length);
        Self { data, addresses }
    }

    /// Get the underlying data info.
    pub fn data_info(&self) -> &DataInfo {
        &self.data
    }

    /// Get the data type name.
    pub fn data_type_name(&self) -> &str {
        &self.data.data_type_name
    }

    /// Get the address set owned (not by reference, to avoid unimplemented in trait).
    pub fn address_set_owned(&self) -> &AddressSet {
        &self.addresses
    }
}

impl ComparisonData for DataComparisonData {
    fn get_function(&self) -> Option<&FunctionComparisonInfo> {
        None
    }

    fn get_address_set(&self) -> &AddressSet {
        &self.addresses
    }

    fn get_program(&self) -> Option<&ProgramInfo> {
        Some(&self.data.program)
    }

    fn get_description(&self) -> String {
        let label = self.data.display_label();
        let data_str = format!("<b>{}</b>", html_escape(&label));

        let prog_str = html_color(
            "#666666",
            &html_escape(&self.data.program.path),
        );
        format!("    {} in {}    ", data_str, prog_str)
    }

    fn get_short_description(&self) -> String {
        self.data.data_type_name.clone()
    }

    fn is_empty(&self) -> bool {
        false
    }

    fn get_initial_location(&self) -> Option<ProgramLocation> {
        Some(ProgramLocation::new(
            self.data.program.clone(),
            self.data.min_address,
        ))
    }
}

/// HTML helper: escape special characters.
fn html_escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// HTML helper: wrap text in a font color tag.
fn html_color(color: &str, text: &str) -> String {
    format!("<font color=\"{}\">{}</font>", color, text)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_program(id: u64, path: &str, name: &str) -> ProgramInfo {
        ProgramInfo::new(id, path, name)
    }

    fn make_data_info(
        dtype: &str,
        addr: u64,
        length: usize,
        program: ProgramInfo,
    ) -> DataInfo {
        DataInfo::new(dtype, addr, length, program)
    }

    // --- DataInfo tests ---

    #[test]
    fn test_data_info_basic() {
        let p = make_program(1, "/project/test", "test");
        let d = make_data_info("int", 0x1000, 4, p);
        assert_eq!(d.data_type_name, "int");
        assert_eq!(d.min_address, 0x1000);
        assert_eq!(d.length, 4);
        assert!(!d.is_external);
        assert!(d.label.is_none());
    }

    #[test]
    fn test_data_info_with_label() {
        let p = make_program(1, "/project/test", "test");
        let d = DataInfo::with_label("int", "myVar", 0x1000, 4, p);
        assert_eq!(d.label.as_deref(), Some("myVar"));
        assert_eq!(d.display_label(), "myVar");
    }

    #[test]
    fn test_data_info_display_label_no_label() {
        let p = make_program(1, "/project/test", "test");
        let d = make_data_info("int", 0x1000, 4, p);
        assert_eq!(d.display_label(), "0x1000");
    }

    #[test]
    fn test_data_info_end_address() {
        let p = make_program(1, "/project/test", "test");
        let d = make_data_info("int", 0x1000, 4, p);
        assert_eq!(d.end_address(), 0x1004);
    }

    #[test]
    fn test_data_info_end_address_clamped() {
        let p = make_program(1, "/project/test", "test");
        let d = make_data_info("int", 0x1000, 4, p).with_block_end(0x1002);
        assert_eq!(d.end_address(), 0x1002);
    }

    #[test]
    fn test_data_info_end_address_external() {
        let p = make_program(1, "/project/test", "test");
        let d = make_data_info("int", 0x1000, 4, p).as_external();
        assert_eq!(d.end_address(), 0x1000);
    }

    #[test]
    fn test_data_info_address_set() {
        let p = make_program(1, "/project/test", "test");
        let d = make_data_info("int", 0x1000, 4, p);
        let set = d.compute_address_set(4);
        assert_eq!(set.min_address(), Some(0x1000));
        assert_eq!(set.max_address(), Some(0x1004));
    }

    #[test]
    fn test_data_info_address_set_larger_other() {
        let p = make_program(1, "/project/test", "test");
        let d = make_data_info("int", 0x1000, 4, p);
        // Other side has 8 bytes, so we expand to match
        let set = d.compute_address_set(8);
        assert_eq!(set.max_address(), Some(0x1008));
    }

    #[test]
    fn test_data_info_address_set_clamped() {
        let p = make_program(1, "/project/test", "test");
        let d = make_data_info("int", 0x1000, 4, p).with_block_end(0x1003);
        let set = d.compute_address_set(8);
        assert_eq!(set.max_address(), Some(0x1003));
    }

    // --- DataComparisonData tests ---

    #[test]
    fn test_data_comparison_data_basic() {
        let p = make_program(1, "/project/test", "test");
        let d = make_data_info("int", 0x1000, 4, p);
        let data = DataComparisonData::new(d, 4);

        assert!(!data.is_empty());
        assert!(data.get_function().is_none());
        assert_eq!(data.get_short_description(), "int");
        assert!(data.get_program().is_some());
        assert!(data.get_initial_location().is_some());
    }

    #[test]
    fn test_data_comparison_data_description() {
        let p = make_program(1, "/project/test", "test");
        let d = DataInfo::with_label("int", "myVar", 0x1000, 4, p);
        let data = DataComparisonData::new(d, 4);
        let desc = data.get_description();
        assert!(desc.contains("myVar"));
        assert!(desc.contains("/project/test"));
    }

    #[test]
    fn test_data_comparison_data_description_no_label() {
        let p = make_program(1, "/project/test", "test");
        let d = make_data_info("int", 0x1000, 4, p);
        let data = DataComparisonData::new(d, 4);
        let desc = data.get_description();
        assert!(desc.contains("0x1000"));
    }

    #[test]
    fn test_data_comparison_data_initial_location() {
        let p = make_program(1, "/project/test", "test");
        let d = make_data_info("int", 0x1000, 4, p);
        let data = DataComparisonData::new(d, 4);
        let loc = data.get_initial_location().unwrap();
        assert_eq!(loc.address, 0x1000);
        assert_eq!(loc.program.path, "/project/test");
    }

    #[test]
    fn test_data_comparison_data_address_set() {
        let p = make_program(1, "/project/test", "test");
        let d = make_data_info("int", 0x1000, 4, p);
        let data = DataComparisonData::new(d, 8);
        let set = data.get_address_set();
        // Should use the larger of 4 and 8
        assert_eq!(set.max_address(), Some(0x1008));
    }

    #[test]
    fn test_data_comparison_data_external() {
        let p = make_program(1, "/project/test", "test");
        let d = make_data_info("int", 0, 4, p).as_external();
        let data = DataComparisonData::new(d, 4);
        assert!(!data.is_empty());
        // External data has min == max
        let set = data.get_address_set();
        assert_eq!(set.min_address(), Some(0));
    }

    #[test]
    fn test_data_comparison_data_data_info_accessor() {
        let p = make_program(1, "/project/test", "test");
        let d = make_data_info("char[16]", 0x2000, 16, p);
        let data = DataComparisonData::new(d, 16);
        assert_eq!(data.data_type_name(), "char[16]");
        assert_eq!(data.data_info().length, 16);
    }
}
