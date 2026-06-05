//! Defined strings table model.
//!
//! Ported from `ghidra.app.plugin.core.strings.DefinedStringsTableModel`.
//!
//! Provides the table model for displaying all defined string data items
//! in the program, with sorting, filtering, and column access.

use super::{DefinedStringInfo, EncodedStringFilter, StringConstraint};
use std::cmp::Ordering;

/// Column definitions for the defined strings table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DefinedStringColumn {
    Address,
    Value,
    Encoding,
    ByteLength,
    CharLength,
    Translation,
}

impl DefinedStringColumn {
    /// Get the column header text.
    pub fn header(&self) -> &'static str {
        match self {
            Self::Address => "Address",
            Self::Value => "String",
            Self::Encoding => "Encoding",
            Self::ByteLength => "Byte Length",
            Self::CharLength => "Char Length",
            Self::Translation => "Translation",
        }
    }

    /// Get all columns.
    pub fn all() -> &'static [DefinedStringColumn] {
        &[
            Self::Address,
            Self::Value,
            Self::Encoding,
            Self::ByteLength,
            Self::CharLength,
            Self::Translation,
        ]
    }
}

/// Sort configuration for the defined strings table.
#[derive(Debug, Clone)]
pub struct TableSortConfig {
    pub column: DefinedStringColumn,
    pub ascending: bool,
}

impl Default for TableSortConfig {
    fn default() -> Self {
        Self {
            column: DefinedStringColumn::Address,
            ascending: true,
        }
    }
}

/// Table model for defined strings.
#[derive(Debug)]
pub struct DefinedStringsTableModel {
    all_strings: Vec<DefinedStringInfo>,
    filtered_indices: Vec<usize>,
    filter: EncodedStringFilter,
    sort_config: TableSortConfig,
    selected: Option<usize>,
}

impl DefinedStringsTableModel {
    pub fn new() -> Self {
        Self {
            all_strings: Vec::new(),
            filtered_indices: Vec::new(),
            filter: EncodedStringFilter::default(),
            sort_config: TableSortConfig::default(),
            selected: None,
        }
    }

    pub fn set_strings(&mut self, strings: Vec<DefinedStringInfo>) {
        self.all_strings = strings;
        self.rebuild();
    }

    pub fn add_string(&mut self, info: DefinedStringInfo) {
        self.all_strings.push(info);
        self.rebuild();
    }

    pub fn total_count(&self) -> usize {
        self.all_strings.len()
    }

    pub fn filtered_count(&self) -> usize {
        self.filtered_indices.len()
    }

    pub fn get_filtered(&self, index: usize) -> Option<&DefinedStringInfo> {
        self.filtered_indices
            .get(index)
            .and_then(|&idx| self.all_strings.get(idx))
    }

    pub fn filter(&self) -> &EncodedStringFilter {
        &self.filter
    }

    pub fn filter_mut(&mut self) -> &mut EncodedStringFilter {
        &mut self.filter
    }

    pub fn set_sort(&mut self, config: TableSortConfig) {
        self.sort_config = config;
        self.rebuild();
    }

    pub fn select(&mut self, index: Option<usize>) {
        self.selected = index;
    }

    pub fn selected(&self) -> Option<&DefinedStringInfo> {
        self.selected
            .and_then(|i| self.get_filtered(i))
    }

    fn rebuild(&mut self) {
        self.filtered_indices.clear();
        for (i, info) in self.all_strings.iter().enumerate() {
            if self.filter.matches(info) {
                self.filtered_indices.push(i);
            }
        }
        let col = self.sort_config.column;
        let asc = self.sort_config.ascending;
        let strings = &self.all_strings;
        self.filtered_indices.sort_by(|&a, &b| {
            let sa = &strings[a];
            let sb = &strings[b];
            let cmp = match col {
                DefinedStringColumn::Address => sa.address.cmp(&sb.address),
                DefinedStringColumn::Value => sa.value.cmp(&sb.value),
                DefinedStringColumn::Encoding => sa.encoding.cmp(&sb.encoding),
                DefinedStringColumn::ByteLength => sa.byte_length.cmp(&sb.byte_length),
                DefinedStringColumn::CharLength => sa.char_length.cmp(&sb.char_length),
                DefinedStringColumn::Translation => {
                    sa.translation.as_deref().cmp(&sb.translation.as_deref())
                }
            };
            if asc { cmp } else { cmp.reverse() }
        });
        self.selected = None;
    }
}

impl Default for DefinedStringsTableModel {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::DefinedStringInfo;

    fn make_info(addr: u64, val: &str, enc: &str) -> DefinedStringInfo {
        DefinedStringInfo {
            address: addr,
            value: val.to_string(),
            encoding: enc.to_string(),
            byte_length: val.len() + 1,
            char_length: val.len(),
            translation: None,
            is_ascii: enc == "ASCII",
            has_encoding_error: false,
        }
    }

    #[test]
    fn test_table_model_set_strings() {
        let mut model = DefinedStringsTableModel::new();
        model.set_strings(vec![
            make_info(0x1000, "hello", "ASCII"),
            make_info(0x2000, "world", "UTF-16LE"),
        ]);
        assert_eq!(model.total_count(), 2);
        assert_eq!(model.filtered_count(), 2);
    }

    #[test]
    fn test_table_model_sort() {
        let mut model = DefinedStringsTableModel::new();
        model.set_strings(vec![
            make_info(0x2000, "b", "ASCII"),
            make_info(0x1000, "a", "ASCII"),
        ]);
        assert_eq!(model.get_filtered(0).unwrap().address, 0x1000);
        model.set_sort(TableSortConfig { column: DefinedStringColumn::Address, ascending: false });
        assert_eq!(model.get_filtered(0).unwrap().address, 0x2000);
    }

    #[test]
    fn test_table_model_filter() {
        let mut model = DefinedStringsTableModel::new();
        model.set_strings(vec![
            make_info(0x1000, "hello", "ASCII"),
            make_info(0x2000, "world", "UTF-16LE"),
        ]);
        model.filter_mut().constraints.push(StringConstraint::IsAscii);
        model.set_strings(vec![
            make_info(0x1000, "hello", "ASCII"),
            make_info(0x2000, "world", "UTF-16LE"),
        ]);
        assert_eq!(model.filtered_count(), 1);
    }

    #[test]
    fn test_column_headers() {
        assert_eq!(DefinedStringColumn::Address.header(), "Address");
        assert_eq!(DefinedStringColumn::all().len(), 6);
    }

    #[test]
    fn test_select() {
        let mut model = DefinedStringsTableModel::new();
        model.set_strings(vec![make_info(0x1000, "test", "ASCII")]);
        model.select(Some(0));
        assert!(model.selected().is_some());
        assert_eq!(model.selected().unwrap().value, "test");
    }
}
