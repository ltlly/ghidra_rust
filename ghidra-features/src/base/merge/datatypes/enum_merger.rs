//! Enum data type merger.
//!
//! Port of Ghidra's `EnumMerger`.

use super::{join_comments, DataTypeMerger, EnumEntry, MergedDataType};
use crate::base::merge::error::{DataTypeMergeError, MergeResult};

/// Merger for enum data types.
///
/// Combines two enum variants by adding new entries from the "other" version
/// into the "working" version. If an entry exists in both, the values must
/// match (otherwise a conflict error is raised), and comments are joined.
///
/// Port of Ghidra's `EnumMerger`.
pub struct EnumMerger {
    working: MergedDataType,
    other: MergedDataType,
    warnings: Vec<String>,
}

impl EnumMerger {
    /// Create a new enum merger.
    ///
    /// `dt1` is the working copy (result), `dt2` is the other version to merge in.
    pub fn new(dt1: MergedDataType, dt2: MergedDataType) -> Self {
        Self {
            working: dt1,
            other: dt2,
            warnings: Vec::new(),
        }
    }

    fn merge_size(&mut self) {
        if self.working.size < self.other.size {
            self.working.size = self.other.size;
        }
    }

    fn merge_description(&mut self) {
        if self
            .working
            .description
            .as_ref()
            .map_or(true, |d| d.trim().is_empty())
        {
            self.working.description = self.other.description.clone();
        }
    }

    fn add_value(
        &mut self,
        name: &str,
        value: i64,
        comment: Option<String>,
    ) -> MergeResult<()> {
        // Check for negative/unsigned conflict.
        // If value would conflict with existing entry range, error out.
        let conflicting = self
            .working
            .enum_entries
            .iter()
            .any(|e| e.value == value && e.name != name);
        if conflicting {
            return Err(DataTypeMergeError::new(
                "Enum conflict: one enum has negative values: one has large unsigned values",
            )
            .into());
        }
        self.working
            .enum_entries
            .push(EnumEntry::new(name, value, comment));
        Ok(())
    }
}

impl DataTypeMerger for EnumMerger {
    fn merge(&mut self) -> MergeResult<MergedDataType> {
        self.warnings.clear();
        self.merge_size();
        self.merge_description();

        let other_entries: Vec<_> = self.other.enum_entries.clone();
        for entry in &other_entries {
            if let Some(existing) = self
                .working
                .enum_entries
                .iter()
                .find(|e| e.name == entry.name)
            {
                // Entry exists in both: values must match.
                if existing.value != entry.value {
                    return Err(DataTypeMergeError::new(format!(
                        "Enums have different values for name \"{}\". {} and {}",
                        entry.name, existing.value, entry.value
                    ))
                    .into());
                }
                // Join comments.
                let joined = join_comments(existing.comment.as_deref(), entry.comment.as_deref());
                // Update in place.
                if let Some(e) = self
                    .working
                    .enum_entries
                    .iter_mut()
                    .find(|e| e.name == entry.name)
                {
                    e.comment = joined;
                }
            } else {
                // Entry only in other: add it.
                self.add_value(&entry.name, entry.value, entry.comment.clone())?;
            }
        }

        Ok(self.working.clone())
    }

    fn warnings(&self) -> &[String] {
        &self.warnings
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_enum(
        name: &str,
        size: usize,
        entries: Vec<(&str, i64, Option<&str>)>,
    ) -> MergedDataType {
        let mut dt = MergedDataType::new(name, size);
        dt.enum_entries = entries
            .into_iter()
            .map(|(n, v, c)| EnumEntry::new(n, v, c.map(|s| s.to_string())))
            .collect();
        dt
    }

    #[test]
    fn test_enum_merge_no_conflict() {
        let working = make_enum("Color", 4, vec![("RED", 0, None), ("GREEN", 1, Some("go"))]);
        let other = make_enum(
            "Color",
            4,
            vec![("BLUE", 2, Some("sky")), ("GREEN", 1, Some("grass"))],
        );
        let mut merger = EnumMerger::new(working, other);
        let result = merger.merge().unwrap();

        assert_eq!(result.enum_entries.len(), 3);
        let green = result.enum_entries.iter().find(|e| e.name == "GREEN").unwrap();
        assert_eq!(green.value, 1);
        // Comments should be joined.
        assert_eq!(green.comment.as_deref(), Some("go grass"));

        let blue = result.enum_entries.iter().find(|e| e.name == "BLUE").unwrap();
        assert_eq!(blue.value, 2);
        assert_eq!(blue.comment.as_deref(), Some("sky"));
    }

    #[test]
    fn test_enum_merge_conflicting_values() {
        let working = make_enum("Color", 4, vec![("RED", 0, None)]);
        let other = make_enum("Color", 4, vec![("RED", 5, None)]);
        let mut merger = EnumMerger::new(working, other);
        let result = merger.merge();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("different values"));
    }

    #[test]
    fn test_enum_merge_grow_size() {
        let working = make_enum("Small", 4, vec![("A", 0, None)]);
        let other = make_enum("Small", 8, vec![("B", 1, None)]);
        let mut merger = EnumMerger::new(working, other);
        let result = merger.merge().unwrap();
        assert_eq!(result.size, 8);
    }

    #[test]
    fn test_enum_merge_empty_other() {
        let working = make_enum("E", 4, vec![("A", 0, None)]);
        let other = make_enum("E", 4, vec![]);
        let mut merger = EnumMerger::new(working, other);
        let result = merger.merge().unwrap();
        assert_eq!(result.enum_entries.len(), 1);
    }
}
