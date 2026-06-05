//! Look-and-Feel management system.
//!
//! Ports Ghidra's `generic.theme.laf` package. Provides the abstract
//! [`LookAndFeelManager`] base and concrete managers for each supported
//! Swing L&F (Metal, Nimbus, Flat, GTK, Motif, Windows, Windows Classic, Mac).
//!
//! In the Rust port (egui-based), the L&F managers control theme defaults,
//! font registrations, and UIDefaults mappings rather than Swing's
//! `UIManager.setLookAndFeel`.

pub mod laf_manager;
pub mod component_font_registry;
pub mod font_non_ui_resource;
pub mod ui_defaults_mapper;
pub mod concrete_managers;
pub mod font_change_listener;
pub mod nimbus;

pub use laf_manager::LookAndFeelManager;
pub use component_font_registry::ComponentFontRegistry;
pub use font_non_ui_resource::FontNonUiResource;
pub use ui_defaults_mapper::UiDefaultsMapper;
pub use concrete_managers::*;
pub use nimbus::{SelectedTreePainter, NimbusLafManager, PaintContext, PaintInsets, CacheMode};
