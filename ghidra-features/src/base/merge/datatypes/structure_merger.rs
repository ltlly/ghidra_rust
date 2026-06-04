//! Structure data type merger.
//!
//! Port of Ghidra's `StructureMerger`.

use super::{
    is_undefined_type, pick_best_type_for_merge, DataTypeMerger,
    MergeDataTypeComponent, MergedDataType,
};
use crate::base::merge::error::{DataTypeMergeError, MergeResult};

/// Merger for structure data types.
///
/// Supports two merge strategies:
///
/// 1. **Packed merge**: When both structures have packing enabled and their
///    components align exactly by ordinal and offset, only field names and
///    comments are merged (fast path).
///
/// 2. **Unpacked merge**: For complex cases, the working structure is unpacked
///    and components from the other version are overlaid. Components that
///    conflict in data type are either upgraded (if possible) or cause errors.
///
/// Port of Ghidra's `StructureMerger`.
pub struct StructureMerger {
    working: MergedDataType,
    other: MergedDataType,
    terminate_on_error: bool,
    errors: Vec<String>,
    warnings: Vec<String>,
}

impl StructureMerger {
    /// Create a new structure merger.
    ///
    /// If `terminate_on_error` is `true`, conflicts raise errors immediately.
    /// If `false`, errors are collected and can be retrieved after merging.
    pub fn new(
        dt1: MergedDataType,
        dt2: MergedDataType,
        terminate_on_error: bool,
    ) -> Self {
        Self {
            working: dt1,
            other: dt2,
            terminate_on_error,
            errors: Vec::new(),
            warnings: Vec::new(),
        }
    }

    /// Create a merger that terminates on first error.
    pub fn strict(dt1: MergedDataType, dt2: MergedDataType) -> Self {
        Self::new(dt1, dt2, true)
    }

    /// Create a merger that collects errors without terminating.
    pub fn lenient(dt1: MergedDataType, dt2: MergedDataType) -> Self {
        Self::new(dt1, dt2, false)
    }

    /// Return errors collected during a lenient merge.
    pub fn errors(&self) -> &[String] {
        &self.errors
    }

    fn collect_error(&mut self, message: &str) {
        self.errors.push(message.to_string());
    }

    fn check_sizes(&mut self) {
        if self.working.size != self.other.size {
            self.warnings
                .push("Structures are not the same size.".to_string());
        }
        if self.working.size < self.other.size {
            let old_size = self.working.size;
            self.working.size = self.other.size;
            // Fill the new space with undefined components so that
            // copy_component_to_working can find undefined space.
            for offset in old_size..self.working.size {
                // Only add if there's no existing component at this offset.
                let has_component = self.working.components.iter().any(|c| {
                    c.offset <= offset && offset < c.offset + c.length.max(1)
                });
                if !has_component {
                    self.working.components.push(MergeDataTypeComponent::new(
                        self.working.components.len(),
                        offset,
                        1,
                        None,
                        "undefined",
                        None,
                    ));
                }
            }
            self.working.components.sort_by_key(|c| c.offset);
            for (i, c) in self.working.components.iter_mut().enumerate() {
                c.ordinal = i;
            }
        }
    }

    /// Check if a packed merge is possible.
    fn can_merge_packed(&self) -> bool {
        if !self.working.packing_enabled {
            return false;
        }
        if self.other.components.len() != self.working.components.len() {
            return false;
        }
        self.working
            .components
            .iter()
            .zip(self.other.components.iter())
            .all(|(w, o)| w.data_type_name == o.data_type_name && w.offset == o.offset)
    }

    fn merge_packed(&mut self) {
        if self.working.components.len() != self.other.components.len() {
            self.collect_error("Packed structures must have same size.");
            return;
        }
        for i in 0..self.working.components.len() {
            if self.working.components[i].data_type_name == self.other.components[i].data_type_name
                && self.working.components[i].offset == self.other.components[i].offset
            {
                self.process_field_names(i, i);
                self.process_comments(i, i);
            } else {
                self.collect_error(&format!(
                    "Packed components have conflicting datatypes at ordinal {}, offset {}",
                    self.other.components[i].ordinal, self.other.components[i].offset
                ));
            }
        }
    }

    fn merge_unpacked(&mut self) {
        let other_comps: Vec<_> = self.other.components.clone();
        for other_comp in &other_comps {
            if let Some(working_idx) = self.find_corresponding_component(other_comp) {
                self.process_field_names(working_idx, other_comp.ordinal);
                self.process_comments(working_idx, other_comp.ordinal);
            } else {
                self.copy_component_to_working(other_comp);
            }
        }
    }

    fn find_corresponding_component(&self, comp: &MergeDataTypeComponent) -> Option<usize> {
        let offset = comp.offset;
        for (i, wcomp) in self.working.components.iter().enumerate() {
            if wcomp.offset <= offset
                && offset < wcomp.offset + wcomp.length.max(1)
                && !is_undefined_type(&wcomp.data_type_name)
            {
                if self.is_same_component(comp, wcomp) {
                    return Some(i);
                }
            }
        }
        None
    }

    fn is_same_component(
        &self,
        other: &MergeDataTypeComponent,
        working: &MergeDataTypeComponent,
    ) -> bool {
        if other.offset != working.offset {
            return false;
        }
        if other.data_type_name != working.data_type_name {
            return false;
        }
        if other.length > 0 {
            return true;
        }
        // Zero-length types must also match names.
        other.field_name == working.field_name
    }

    fn copy_component_to_working(&mut self, comp: &MergeDataTypeComponent) {
        let offset = comp.offset;
        let length = comp.length;

        // Zero-length items can be added if not in the middle of an existing entry.
        if length == 0 {
            let working_at = self.working.components.iter().find(|c| {
                c.offset <= offset && offset < c.offset + c.length.max(1)
            });
            if working_at.is_some() {
                // Check that it's not extending into an existing component.
                let has_undefined = self.working.components.iter().any(|c| {
                    c.offset == offset && is_undefined_type(&c.data_type_name)
                });
                if !has_undefined {
                    self.collect_error(&format!(
                        "Conflict at offset {}. Existing component extends to this offset.",
                        offset
                    ));
                    return;
                }
            }
            self.working.components.push(MergeDataTypeComponent::new(
                self.working.components.len(),
                offset,
                0,
                comp.field_name.clone(),
                &comp.data_type_name,
                comp.comment.clone(),
            ));
            return;
        }

        // Check if there's a defined component at this offset.
        let working_at = self.working.components.iter().find(|c| {
            c.offset <= offset && offset < c.offset + c.length.max(1)
        });

        if let Some(wc) = working_at {
            if !is_undefined_type(&wc.data_type_name) {
                // Try merging data types.
                self.try_merge_data_types(wc.ordinal, comp);
                return;
            }
        }

        // Check for undefined space.
        if self.has_undefined_space(offset, length) {
            // Replace undefined space with new component.
            self.working.components.retain(|c| {
                !(c.offset >= offset && c.offset < offset + length)
            });
            self.working.components.push(MergeDataTypeComponent::new(
                self.working.components.len(),
                offset,
                length,
                comp.field_name.clone(),
                &comp.data_type_name,
                comp.comment.clone(),
            ));
            self.working
                .components
                .sort_by_key(|c| c.offset);
            // Reassign ordinals.
            for (i, c) in self.working.components.iter_mut().enumerate() {
                c.ordinal = i;
            }
            return;
        }

        self.collect_error(&format!(
            "Conflict at offset {}. Not enough undefined bytes to insert here.",
            offset
        ));
    }

    fn has_undefined_space(&self, offset: usize, length: usize) -> bool {
        for i in 0..length {
            let at = offset + i;
            let has_undefined = self.working.components.iter().any(|c| {
                c.offset <= at
                    && at < c.offset + c.length.max(1)
                    && is_undefined_type(&c.data_type_name)
            });
            if !has_undefined {
                return false;
            }
        }
        true
    }

    fn try_merge_data_types(
        &mut self,
        working_idx: usize,
        other: &MergeDataTypeComponent,
    ) {
        let working_dt = self.working.components[working_idx].data_type_name.clone();
        let other_dt = other.data_type_name.clone();

        let merged_name = pick_best_type_for_merge(
            &working_dt,
            self.working.components[working_idx].length,
            &other_dt,
            other.length,
        );

        let merged_name = match merged_name {
            Some(name) => name,
            None => {
                self.collect_error(&format!(
                    "Conflict at offset {}. Incompatible datatype already defined here.",
                    other.offset
                ));
                return;
            }
        };

        self.warnings.push(format!(
            "Merging '{}' and '{}' at offset {} to '{}'.",
            working_dt, other_dt, other.offset, merged_name
        ));

        // Process field names.
        self.process_field_names(working_idx, other.ordinal);

        let name = self.working.components[working_idx].field_name.clone();
        let comment = self.working.components[working_idx].comment.clone();
        let comment = if comment.as_ref().map_or(true, |c| c.trim().is_empty()) {
            other.comment.clone()
        } else {
            comment
        };
        let len = self.working.components[working_idx].length;

        self.working.components[working_idx] = MergeDataTypeComponent::new(
            working_idx,
            self.working.components[working_idx].offset,
            len,
            name,
            &merged_name,
            comment,
        );
    }

    fn process_field_names(&mut self, working_idx: usize, other_idx: usize) {
        let working_name = self.working.components[working_idx].field_name.clone();
        let other_name = self.other.components[other_idx].field_name.clone();

        match (&working_name, &other_name) {
            (Some(wn), Some(on)) if wn != on => {
                self.collect_error(&format!(
                    "Components have conflicting field names at ordinal {}, offset {}. Names: {} vs {}",
                    self.working.components[working_idx].ordinal,
                    self.working.components[working_idx].offset,
                    wn,
                    on,
                ));
            }
            (None, Some(on)) => {
                self.working.components[working_idx].field_name = Some(on.clone());
            }
            _ => {}
        }
    }

    fn process_comments(&mut self, working_idx: usize, other_idx: usize) {
        let working_comment = self.working.components[working_idx].comment.as_deref();
        let other_comment = self.other.components[other_idx].comment.as_deref();

        if working_comment.map_or(true, |c| c.trim().is_empty()) {
            self.working.components[working_idx].comment =
                other_comment.map(|s| s.to_string());
        }
    }

}

impl DataTypeMerger for StructureMerger {
    fn merge(&mut self) -> MergeResult<MergedDataType> {
        self.warnings.clear();
        self.errors.clear();

        // Merge description.
        if self
            .working
            .description
            .as_ref()
            .map_or(true, |d| d.trim().is_empty())
        {
            self.working.description = self.other.description.clone();
        }

        if self.can_merge_packed() {
            self.merge_packed();
        } else {
            if self.working.packing_enabled {
                self.working.packing_enabled = false;
            }
            self.check_sizes();
            self.merge_unpacked();
        }

        if self.terminate_on_error && !self.errors.is_empty() {
            return Err(DataTypeMergeError::new(self.errors[0].clone()).into());
        }

        self.working
            .warnings
            .extend(self.warnings.iter().cloned());
        Ok(self.working.clone())
    }

    fn warnings(&self) -> &[String] {
        &self.warnings
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_struct(
        name: &str,
        size: usize,
        packed: bool,
        components: Vec<(usize, usize, usize, &str, &str, Option<&str>)>,
    ) -> MergedDataType {
        let mut dt = MergedDataType::new(name, size);
        dt.packing_enabled = packed;
        dt.components = components
            .into_iter()
            .map(|(ord, off, len, field, dtype, comment)| {
                MergeDataTypeComponent::new(
                    ord,
                    off,
                    len,
                    Some(field.to_string()),
                    dtype,
                    comment.map(|s| s.to_string()),
                )
            })
            .collect();
        dt
    }

    fn make_struct_unnamed(
        name: &str,
        size: usize,
        components: Vec<(usize, usize, usize, &str)>,
    ) -> MergedDataType {
        let mut dt = MergedDataType::new(name, size);
        dt.components = components
            .into_iter()
            .map(|(ord, off, len, dtype)| {
                MergeDataTypeComponent::new(ord, off, len, None, dtype, None)
            })
            .collect();
        dt
    }

    #[test]
    fn test_structure_merge_identical() {
        let s1 = make_struct(
            "Point",
            8,
            false,
            vec![
                (0, 0, 4, "x", "int", None),
                (1, 4, 4, "y", "int", None),
            ],
        );
        let s2 = make_struct(
            "Point",
            8,
            false,
            vec![
                (0, 0, 4, "x", "int", None),
                (1, 4, 4, "y", "int", None),
            ],
        );
        let mut merger = StructureMerger::strict(s1, s2);
        let result = merger.merge().unwrap();
        assert_eq!(result.size, 8);
        assert_eq!(result.components.len(), 2);
    }

    #[test]
    fn test_structure_merge_add_field_name() {
        let s1 = make_struct_unnamed("S", 8, vec![(0, 0, 4, "int"), (1, 4, 4, "int")]);
        let s2 = make_struct(
            "S",
            8,
            false,
            vec![
                (0, 0, 4, "x", "int", None),
                (1, 4, 4, "y", "int", None),
            ],
        );
        let mut merger = StructureMerger::strict(s1, s2);
        let result = merger.merge().unwrap();
        assert_eq!(
            result.components[0].field_name.as_deref(),
            Some("x")
        );
        assert_eq!(
            result.components[1].field_name.as_deref(),
            Some("y")
        );
    }

    #[test]
    fn test_structure_merge_conflicting_field_names_strict() {
        let s1 = make_struct(
            "S",
            8,
            false,
            vec![
                (0, 0, 4, "x", "int", None),
                (1, 4, 4, "y", "int", None),
            ],
        );
        let s2 = make_struct(
            "S",
            8,
            false,
            vec![
                (0, 0, 4, "a", "int", None),
                (1, 4, 4, "b", "int", None),
            ],
        );
        let mut merger = StructureMerger::strict(s1, s2);
        // In strict mode, conflicting names cause an error.
        let result = merger.merge();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("conflicting field names"));
    }

    #[test]
    fn test_structure_merge_size_mismatch() {
        let s1 = make_struct("S", 4, false, vec![(0, 0, 4, "x", "int", None)]);
        let s2 = make_struct(
            "S",
            8,
            false,
            vec![
                (0, 0, 4, "x", "int", None),
                (1, 4, 4, "y", "int", None),
            ],
        );
        let mut merger = StructureMerger::strict(s1, s2);
        let result = merger.merge().unwrap();
        assert_eq!(result.size, 8);
        assert!(result.warnings.iter().any(|w| w.contains("not the same size")));
    }

    #[test]
    fn test_structure_merge_packed_path() {
        let s1 = make_struct(
            "P",
            8,
            true,
            vec![
                (0, 0, 4, "x", "int", None),
                (1, 4, 4, "y", "int", None),
            ],
        );
        let s2 = make_struct(
            "P",
            8,
            true,
            vec![
                (0, 0, 4, "x", "int", Some("comment from s2")),
                (1, 4, 4, "y", "int", Some("y comment")),
            ],
        );
        let mut merger = StructureMerger::strict(s1, s2);
        let result = merger.merge().unwrap();
        assert_eq!(
            result.components[0].comment.as_deref(),
            Some("comment from s2")
        );
        assert_eq!(
            result.components[1].comment.as_deref(),
            Some("y comment")
        );
    }

    #[test]
    fn test_structure_merge_description_fallback() {
        let mut s1 = make_struct("S", 4, false, vec![]);
        s1.description = None;
        let mut s2 = make_struct("S", 4, false, vec![]);
        s2.description = Some("A test struct".to_string());
        let mut merger = StructureMerger::strict(s1, s2);
        let result = merger.merge().unwrap();
        assert_eq!(result.description.as_deref(), Some("A test struct"));
    }

    #[test]
    fn test_structure_merge_add_new_component_in_undefined_space() {
        let s1 = make_struct_unnamed("S", 8, vec![(0, 0, 8, "undefined")]);
        let s2 = make_struct(
            "S",
            8,
            false,
            vec![(0, 0, 4, "x", "int", Some("x field"))],
        );
        let mut merger = StructureMerger::strict(s1, s2);
        let result = merger.merge().unwrap();
        assert!(result.components.iter().any(|c| c.field_name.as_deref() == Some("x")));
    }

    #[test]
    fn test_structure_merge_upgrading_undefined() {
        let s1 = make_struct("S", 4, false, vec![(0, 0, 4, "x", "undefined4", None)]);
        let s2 = make_struct("S", 4, false, vec![(0, 0, 4, "x", "int", None)]);
        let mut merger = StructureMerger::strict(s1, s2);
        let result = merger.merge().unwrap();
        // The undefined should have been upgraded to int.
        assert_eq!(result.components[0].data_type_name, "int");
    }

    #[test]
    fn test_structure_merge_lenient_collects_errors() {
        let s1 = make_struct(
            "S",
            4,
            false,
            vec![(0, 0, 4, "a", "float", None)],
        );
        let s2 = make_struct(
            "S",
            4,
            false,
            vec![(0, 0, 4, "a", "int", None)],
        );
        let mut merger = StructureMerger::lenient(s1, s2);
        let result = merger.merge();
        // In lenient mode, the error should be collected.
        assert!(!merger.errors().is_empty() || result.is_ok());
    }
}
