//! Filter table widget.
//!
//! Port of Ghidra's `GFilterTable<ROW_OBJECT>`. A composite widget that
//! combines a table view with a filter text field. In egui immediate-mode
//! style, this is rendered via [`GFilterTable::show`].

use std::collections::HashSet;

use super::row_object_table_model::RowObjectTableModel;
use super::table_filter::{AcceptAllFilter, TableFilter, TextContainsFilter};

/// A callback invoked when the selected row changes.
pub type SelectionCallback<T> = Box<dyn Fn(Option<&T>)>;

/// Composite filter-table widget for egui.
///
/// Combines a table body with a filter text input. The filter text is applied
/// as a [`TextContainsFilter`] against the row objects' `ToString`
/// representations.
pub struct GFilterTable<T: 'static + ToString + PartialEq> {
    /// The filter text entered by the user.
    filter_text: String,
    /// The set of selected view row indices.
    selected_rows: HashSet<usize>,
    /// Whether the filter field is focused.
    filter_focused: bool,
    /// Column widths (pixels).
    column_widths: Vec<f32>,
    /// The currently hovered row (for highlight).
    hovered_row: Option<usize>,
    /// Row height in pixels.
    row_height: f32,
    /// Selection callbacks.
    listeners: Vec<SelectionCallback<T>>,
    /// The sort state: which column and direction.
    sort_column: Option<(usize, bool)>, // (column_index, is_ascending)
}

impl<T: 'static + ToString + PartialEq> GFilterTable<T> {
    pub fn new() -> Self {
        Self {
            filter_text: String::new(),
            selected_rows: HashSet::new(),
            filter_focused: false,
            column_widths: Vec::new(),
            hovered_row: None,
            row_height: 22.0,
            listeners: Vec::new(),
            sort_column: None,
        }
    }

    /// Set the filter text programmatically.
    pub fn set_filter_text(&mut self, text: impl Into<String>) {
        self.filter_text = text.into();
    }

    /// Get the current filter text.
    pub fn filter_text(&self) -> &str {
        &self.filter_text
    }

    /// Set the row height.
    pub fn set_row_height(&mut self, height: f32) {
        self.row_height = height;
    }

    /// Clear all selections.
    pub fn clear_selection(&mut self) {
        self.selected_rows.clear();
    }

    /// Get the selected view row indices.
    pub fn selected_rows(&self) -> &HashSet<usize> {
        &self.selected_rows
    }

    /// Select a specific row.
    pub fn select_row(&mut self, row: usize) {
        self.selected_rows.clear();
        self.selected_rows.insert(row);
    }

    /// Add a row to the selection (multi-select).
    pub fn add_to_selection(&mut self, row: usize) {
        self.selected_rows.insert(row);
    }

    /// Toggle a row in the selection.
    pub fn toggle_selection(&mut self, row: usize) {
        if self.selected_rows.contains(&row) {
            self.selected_rows.remove(&row);
        } else {
            self.selected_rows.insert(row);
        }
    }

    /// Get the selected row objects from the model.
    pub fn get_selected_row_objects<'a, M: RowObjectTableModel<T>>(
        &self,
        model: &'a M,
    ) -> Vec<&'a T> {
        self.selected_rows
            .iter()
            .filter_map(|&row| model.get_row_object(row))
            .collect()
    }

    /// Get the first selected row object.
    pub fn get_selected_row_object<'a, M: RowObjectTableModel<T>>(
        &self,
        model: &'a M,
    ) -> Option<&'a T> {
        self.selected_rows.iter().min().and_then(|&row| model.get_row_object(row))
    }

    /// Set the sort column. Pass `None` to clear sorting.
    pub fn set_sort_column(&mut self, column: Option<usize>) {
        match column {
            Some(col) => {
                if self.sort_column.map(|(c, _)| c) == Some(col) {
                    // Toggle direction
                    if let Some((c, ascending)) = self.sort_column {
                        self.sort_column = Some((c, !ascending));
                    }
                } else {
                    self.sort_column = Some((col, true));
                }
            }
            None => self.sort_column = None,
        }
    }

    /// Get the sort column and direction.
    pub fn sort_column(&self) -> Option<(usize, bool)> {
        self.sort_column
    }

    /// Build a filter from the current filter text.
    pub fn build_filter(&self) -> Box<dyn TableFilter<T>>
    where
        T: ToString,
    {
        if self.filter_text.is_empty() {
            Box::new(AcceptAllFilter)
        } else {
            Box::new(TextContainsFilter::new(&self.filter_text))
        }
    }

    /// Get the filtered row indices from a model.
    pub fn filtered_indices<M: RowObjectTableModel<T>>(&self, model: &M) -> Vec<usize> {
        let filter = self.build_filter();
        (0..model.row_count())
            .filter(|&i| {
                model
                    .get_row_object(i)
                    .map_or(false, |obj| filter.accepts_row(obj))
            })
            .collect()
    }

    /// Add a selection listener.
    pub fn add_listener(&mut self, callback: SelectionCallback<T>) {
        self.listeners.push(callback);
    }

    /// Notify listeners of selection change.
    fn notify_selection<M: RowObjectTableModel<T>>(&self, model: &M) {
        let selected = self.get_selected_row_object(model);
        for listener in &self.listeners {
            listener(selected);
        }
    }

    /// Show the filter table using egui.
    ///
    /// This renders the filter input and table body. The `model` supplies
    /// the data, and `column_names` provides the header labels.
    pub fn show<M: RowObjectTableModel<T>>(
        &mut self,
        ui: &mut egui::Ui,
        model: &M,
        column_names: &[String],
    ) -> egui::Response {
        let available = ui.available_size();
        let filter_height = 28.0;
        let table_height = (available.y - filter_height).max(100.0);

        // Filter input
        ui.horizontal(|ui| {
            ui.label("Filter:");
            let response = ui.text_edit_singleline(&mut self.filter_text);
            if response.gained_focus() {
                self.filter_focused = true;
            }
            if response.lost_focus() {
                self.filter_focused = false;
            }
        });

        ui.separator();

        // Table header
        let _header_response = ui.horizontal(|ui| {
            for (i, name) in column_names.iter().enumerate() {
                let label = if self.sort_column.map(|(c, _)| c) == Some(i) {
                    let arrow = if self.sort_column.unwrap().1 { " ^" } else { " v" };
                    format!("{}{}", name, arrow)
                } else {
                    name.clone()
                };
                if ui.selectable_label(false, label).clicked() {
                    self.set_sort_column(Some(i));
                }
            }
        });

        // Table body
        let filtered = self.filtered_indices(model);
        egui::ScrollArea::vertical()
            .max_height(table_height)
            .show(ui, |ui| {
                for &view_row in &filtered {
                    let is_selected = self.selected_rows.contains(&view_row);
                    let is_hovered = self.hovered_row == Some(view_row);

                    let _bg_color = if is_selected {
                        ui.visuals().selection.bg_fill
                    } else if is_hovered {
                        ui.visuals().widgets.hovered.bg_fill
                    } else {
                        egui::Color32::TRANSPARENT
                    };

                    let row_response = ui.horizontal(|ui| {
                        if let Some(_row_obj) = model.get_row_object(view_row) {
                            for col in 0..model.column_count() {
                                if let Some(val) = model.get_value_at(view_row, col) {
                                    let text = format_any(&*val);
                                    let label = egui::Label::new(text);
                                    ui.add(label);
                                }
                            }
                        }
                    });

                    let rect = row_response.response.rect;
                    if ui.rect_contains_pointer(rect) {
                        self.hovered_row = Some(view_row);
                    }
                }
            });

        ui.allocate_response(available, egui::Sense::click())
    }
}

/// Format a `dyn std::any::Any` value to string for display.
fn format_any(val: &dyn std::any::Any) -> String {
    if let Some(s) = val.downcast_ref::<String>() {
        s.clone()
    } else if let Some(s) = val.downcast_ref::<&str>() {
        s.to_string()
    } else if let Some(i) = val.downcast_ref::<i32>() {
        i.to_string()
    } else if let Some(i) = val.downcast_ref::<i64>() {
        i.to_string()
    } else if let Some(i) = val.downcast_ref::<u64>() {
        i.to_string()
    } else if let Some(f) = val.downcast_ref::<f64>() {
        format!("{:.2}", f)
    } else if let Some(f) = val.downcast_ref::<f32>() {
        format!("{:.2}", f)
    } else if let Some(b) = val.downcast_ref::<bool>() {
        b.to_string()
    } else {
        "<???>".to_string()
    }
}

impl<T: 'static + ToString + PartialEq> Default for GFilterTable<T> {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::widgets::table::abstract_g_table_model::AbstractGTableModel;

    #[derive(Debug, Clone, PartialEq)]
    struct Item {
        name: String,
        value: i32,
    }

    impl ToString for Item {
        fn to_string(&self) -> String {
            format!("{}:{}", self.name, self.value)
        }
    }

    fn make_items() -> Vec<Item> {
        vec![
            Item { name: "apple".into(), value: 1 },
            Item { name: "banana".into(), value: 2 },
            Item { name: "cherry".into(), value: 3 },
        ]
    }

    #[test]
    fn test_new_filter_table() {
        let ft: GFilterTable<Item> = GFilterTable::new();
        assert!(ft.filter_text().is_empty());
        assert!(ft.selected_rows().is_empty());
        assert_eq!(ft.sort_column(), None);
    }

    #[test]
    fn test_set_filter_text() {
        let mut ft: GFilterTable<Item> = GFilterTable::new();
        ft.set_filter_text("test");
        assert_eq!(ft.filter_text(), "test");
    }

    #[test]
    fn test_selection() {
        let mut ft: GFilterTable<Item> = GFilterTable::new();
        ft.select_row(0);
        assert_eq!(ft.selected_rows().len(), 1);
        assert!(ft.selected_rows().contains(&0));

        ft.add_to_selection(2);
        assert_eq!(ft.selected_rows().len(), 2);

        ft.clear_selection();
        assert!(ft.selected_rows().is_empty());
    }

    #[test]
    fn test_toggle_selection() {
        let mut ft: GFilterTable<Item> = GFilterTable::new();
        ft.toggle_selection(1);
        assert!(ft.selected_rows().contains(&1));
        ft.toggle_selection(1);
        assert!(!ft.selected_rows().contains(&1));
    }

    #[test]
    fn test_get_selected_row_objects() {
        let mut model = AbstractGTableModel::new("Test", vec!["Name".into()]);
        model.set_data(make_items());
        let mut ft: GFilterTable<Item> = GFilterTable::new();
        ft.select_row(1);
        let selected = ft.get_selected_row_objects(&model);
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].name, "banana");
    }

    #[test]
    fn test_get_selected_row_object_first() {
        let mut model = AbstractGTableModel::new("Test", vec!["Name".into()]);
        model.set_data(make_items());
        let mut ft: GFilterTable<Item> = GFilterTable::new();
        ft.add_to_selection(2);
        ft.add_to_selection(0);
        let obj = ft.get_selected_row_object(&model).unwrap();
        // Should return the one at the lowest index
        assert_eq!(obj.name, "apple");
    }

    #[test]
    fn test_filtered_indices_no_filter() {
        let mut model = AbstractGTableModel::new("Test", vec!["Name".into()]);
        model.set_data(make_items());
        let ft: GFilterTable<Item> = GFilterTable::new();
        let indices = ft.filtered_indices(&model);
        assert_eq!(indices, vec![0, 1, 2]);
    }

    #[test]
    fn test_filtered_indices_with_filter() {
        let mut model = AbstractGTableModel::new("Test", vec!["Name".into()]);
        model.set_data(make_items());
        let mut ft: GFilterTable<Item> = GFilterTable::new();
        ft.set_filter_text("banana");
        let indices = ft.filtered_indices(&model);
        assert_eq!(indices, vec![1]);
    }

    #[test]
    fn test_filtered_indices_case_insensitive() {
        let mut model = AbstractGTableModel::new("Test", vec!["Name".into()]);
        model.set_data(make_items());
        let mut ft: GFilterTable<Item> = GFilterTable::new();
        ft.set_filter_text("APPLE");
        let indices = ft.filtered_indices(&model);
        assert_eq!(indices, vec![0]);
    }

    #[test]
    fn test_sort_column_toggle() {
        let mut ft: GFilterTable<Item> = GFilterTable::new();
        ft.set_sort_column(Some(0));
        assert_eq!(ft.sort_column(), Some((0, true)));
        ft.set_sort_column(Some(0));
        assert_eq!(ft.sort_column(), Some((0, false)));
        ft.set_sort_column(Some(1));
        assert_eq!(ft.sort_column(), Some((1, true)));
        ft.set_sort_column(None);
        assert_eq!(ft.sort_column(), None);
    }

    #[test]
    fn test_build_filter_empty() {
        let ft: GFilterTable<Item> = GFilterTable::new();
        let filter = ft.build_filter();
        assert!(filter.is_empty());
    }

    #[test]
    fn test_build_filter_text() {
        let mut ft: GFilterTable<Item> = GFilterTable::new();
        ft.set_filter_text("test");
        let filter = ft.build_filter();
        assert!(!filter.is_empty());
    }

    #[test]
    fn test_default() {
        let ft: GFilterTable<Item> = GFilterTable::default();
        assert!(ft.filter_text().is_empty());
    }
}
