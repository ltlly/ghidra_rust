//! GUI components for memory search -- ported from
//! `ghidra.features.base.memsearch.gui`.
//!
//! - [`SearchSettings`] -- immutable container for search settings
//! - [`SearchGuiModel`] -- maintains the state of all search controls
//! - [`SearchHistory`] -- manages previously used searches
//! - [`SearchMarkers`] -- manages marker sets for search results

mod settings;
mod gui_model;
mod history;
mod markers;

pub use settings::SearchSettings;
pub use gui_model::SearchGuiModel;
pub use history::SearchHistory;
pub use markers::SearchMarkers;
