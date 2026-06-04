//! Union data type merger.
//!
//! Port of Ghidra's `UnionMerger`.

use super::{
    join_comments, pick_best_type_for_merge, DataTypeMerger, MergeDataTypeComponent,
    MergedDataType,
};
use crate::base::merge::error::{DataTypeMergeError, MergeResult};

/// Merger for union data types.
///
/// Combines two union variants by adding components from the "other" version
/// into the "working" version. Named components are matched by name first,
/// then by data type (to adopt a name for an anonymous component).
/// Unmatched named components are added as new entries.
///
/// Port of Ghidra's `UnionMerger`.
pub struct UnionMerger {
    working: MergedDataType,
    other: MergedDataType,
    warnings: Vec<String>,
}

impl UnionMerger {
    /// Create a new union merger.
    pub fn new(dt1: MergedDataType, dt2: MergedDataType) -> Self {
        Self {
            working: dt1,
            other: dt2,
            warnings: Vec::new(),
        }
    }

    fn process_named_component(&mut self, other_comp: &MergeDataTypeComponent) -> MergeResult<()> {
        let name = other_comp.field_name.as_ref().unwrap();

        // 1. Try to find a component with the same name in working.
        if let Some(result_idx) = self.find_by_name(name) {
            self.apply_same_named_component(result_idx, other_comp)?;
            return Ok(());
        }

        // 2. Try to find an unnamed component with the same data type.
        if let Some(result_idx) = self.find_unnamed_by_type(&other_comp.data_type_name) {
            self.apply_same_type_component(result_idx, other_comp);
            return Ok(());
        }

        // 3. Add as new component.
        self.working.components.push(MergeDataTypeComponent::new(
            self.working.components.len(),
            0, // Unions always start at offset 0.
            other_comp.length,
            other_comp.field_name.clone(),
            &other_comp.data_type_name,
            other_comp.comment.clone(),
        ));

        Ok(())
    }

    fn process_unnamed_component(&mut self, other_comp: &MergeDataTypeComponent) {
        if !self.has_component_with_type(&other_comp.data_type_name) {
            self.working.components.push(MergeDataTypeComponent::new(
                self.working.components.len(),
                0,
                other_comp.length,
                None,
                &other_comp.data_type_name,
                None,
            ));
        }
    }

    fn apply_same_named_component(
        &mut self,
        working_idx: usize,
        other_comp: &MergeDataTypeComponent,
    ) -> MergeResult<()> {
        let working_dt = self.working.components[working_idx].data_type_name.clone();
        let other_dt = other_comp.data_type_name.clone();
        let working_len = self.working.components[working_idx].length;

        if working_dt == other_dt {
            // Same data type: just join comments.
            let joined = join_comments(
                self.working.components[working_idx].comment.as_deref(),
                other_comp.comment.as_deref(),
            );
            self.working.components[working_idx].comment = joined;
            return Ok(());
        }

        // Different data types: try to pick the best one.
        let merged_name = pick_best_type_for_merge(
            &working_dt,
            working_len,
            &other_dt,
            other_comp.length,
        );

        if let Some(merged_name) = merged_name {
            if other_comp.length == working_len {
                let field_name = other_comp.field_name.clone();
                let comment = join_comments(
                    self.working.components[working_idx].comment.as_deref(),
                    other_comp.comment.as_deref(),
                );
                let length = other_comp.length;

                self.working.components[working_idx] = MergeDataTypeComponent::new(
                    working_idx,
                    0,
                    length,
                    field_name,
                    &merged_name,
                    comment,
                );

                self.warnings.push(format!(
                    "Merging '{}' and '{}' to '{}' for member '{}'.",
                    working_dt,
                    other_dt,
                    merged_name,
                    self.working.components[working_idx]
                        .field_name
                        .as_deref()
                        .unwrap_or("<anon>")
                ));
                return Ok(());
            }
        }

        Err(DataTypeMergeError::new(format!(
            "Unions have conflicting components named {}",
            other_comp.field_name.as_deref().unwrap_or("<anon>")
        ))
        .into())
    }

    fn apply_same_type_component(
        &mut self,
        working_idx: usize,
        other_comp: &MergeDataTypeComponent,
    ) {
        self.working.components[working_idx].field_name = other_comp.field_name.clone();
        let joined = join_comments(
            self.working.components[working_idx].comment.as_deref(),
            other_comp.comment.as_deref(),
        );
        self.working.components[working_idx].comment = joined;
    }

    fn find_by_name(&self, name: &str) -> Option<usize> {
        self.working
            .components
            .iter()
            .position(|c| c.field_name.as_deref() == Some(name))
    }

    fn find_unnamed_by_type(&self, type_name: &str) -> Option<usize> {
        self.working
            .components
            .iter()
            .position(|c| c.field_name.is_none() && c.data_type_name == type_name)
    }

    fn has_component_with_type(&self, type_name: &str) -> bool {
        self.working
            .components
            .iter()
            .any(|c| c.data_type_name == type_name)
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
}

impl DataTypeMerger for UnionMerger {
    fn merge(&mut self) -> MergeResult<MergedDataType> {
        self.warnings.clear();
        self.merge_description();

        let other_comps: Vec<_> = self.other.components.clone();
        for comp in &other_comps {
            if comp.field_name.is_some() {
                self.process_named_component(comp)?;
            } else {
                self.process_unnamed_component(comp);
            }
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

    fn make_union(
        name: &str,
        size: usize,
        components: Vec<(usize, usize, Option<&str>, &str, Option<&str>)>,
    ) -> MergedDataType {
        let mut dt = MergedDataType::new(name, size);
        dt.components = components
            .into_iter()
            .map(|(ord, len, field, dtype, comment)| {
                MergeDataTypeComponent::new(
                    ord,
                    0, // Unions are always at offset 0.
                    len,
                    field.map(|s| s.to_string()),
                    dtype,
                    comment.map(|s| s.to_string()),
                )
            })
            .collect();
        dt
    }

    #[test]
    fn test_union_merge_disjoint_named() {
        let u1 = make_union(
            "U",
            4,
            vec![(0, 4, Some("x"), "int", None)],
        );
        let u2 = make_union(
            "U",
            4,
            vec![(0, 4, Some("y"), "float", None)],
        );
        let mut merger = UnionMerger::new(u1, u2);
        let result = merger.merge().unwrap();
        assert_eq!(result.components.len(), 2);
        assert!(result
            .components
            .iter()
            .any(|c| c.field_name.as_deref() == Some("x")));
        assert!(result
            .components
            .iter()
            .any(|c| c.field_name.as_deref() == Some("y")));
    }

    #[test]
    fn test_union_merge_same_name_same_type() {
        let u1 = make_union(
            "U",
            4,
            vec![(0, 4, Some("x"), "int", Some("from u1"))],
        );
        let u2 = make_union(
            "U",
            4,
            vec![(0, 4, Some("x"), "int", Some("from u2"))],
        );
        let mut merger = UnionMerger::new(u1, u2);
        let result = merger.merge().unwrap();
        assert_eq!(result.components.len(), 1);
        assert_eq!(
            result.components[0].comment.as_deref(),
            Some("from u1 from u2")
        );
    }

    #[test]
    fn test_union_merge_same_name_different_type_upgrade() {
        let u1 = make_union("U", 4, vec![(0, 4, Some("x"), "undefined4", None)]);
        let u2 = make_union("U", 4, vec![(0, 4, Some("x"), "int", None)]);
        let mut merger = UnionMerger::new(u1, u2);
        let result = merger.merge().unwrap();
        assert_eq!(result.components.len(), 1);
        assert_eq!(result.components[0].data_type_name, "int");
        assert!(merger.warnings().iter().any(|w| w.contains("Merging")));
    }

    #[test]
    fn test_union_merge_same_name_conflict() {
        let u1 = make_union("U", 4, vec![(0, 4, Some("x"), "float", None)]);
        let u2 = make_union("U", 4, vec![(0, 4, Some("x"), "int", None)]);
        let mut merger = UnionMerger::new(u1, u2);
        let result = merger.merge();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("conflicting"));
    }

    #[test]
    fn test_union_merge_unnamed_disjoint() {
        let u1 = make_union("U", 4, vec![(0, 4, None, "int", None)]);
        let u2 = make_union("U", 4, vec![(0, 4, None, "float", None)]);
        let mut merger = UnionMerger::new(u1, u2);
        let result = merger.merge().unwrap();
        assert_eq!(result.components.len(), 2);
    }

    #[test]
    fn test_union_merge_unnamed_duplicate_type() {
        let u1 = make_union("U", 4, vec![(0, 4, None, "int", None)]);
        let u2 = make_union("U", 4, vec![(0, 4, None, "int", None)]);
        let mut merger = UnionMerger::new(u1, u2);
        let result = merger.merge().unwrap();
        assert_eq!(result.components.len(), 1);
    }

    #[test]
    fn test_union_merge_name_adopt_from_unnamed() {
        // Working has unnamed int, other has named int "x" -- should adopt the name.
        let u1 = make_union("U", 4, vec![(0, 4, None, "int", None)]);
        let u2 = make_union("U", 4, vec![(0, 4, Some("x"), "int", Some("named"))]);
        let mut merger = UnionMerger::new(u1, u2);
        let result = merger.merge().unwrap();
        // Should have one component with the adopted name.
        assert_eq!(result.components.len(), 1);
        assert_eq!(
            result.components[0].field_name.as_deref(),
            Some("x")
        );
    }

    #[test]
    fn test_union_merge_empty_other() {
        let u1 = make_union("U", 4, vec![(0, 4, Some("x"), "int", None)]);
        let u2 = make_union("U", 4, vec![]);
        let mut merger = UnionMerger::new(u1, u2);
        let result = merger.merge().unwrap();
        assert_eq!(result.components.len(), 1);
    }

    #[test]
    fn test_union_merge_description_fallback() {
        let mut u1 = make_union("U", 4, vec![]);
        u1.description = None;
        let mut u2 = make_union("U", 4, vec![]);
        u2.description = Some("A union".to_string());
        let mut merger = UnionMerger::new(u1, u2);
        let result = merger.merge().unwrap();
        assert_eq!(result.description.as_deref(), Some("A union"));
    }
}
