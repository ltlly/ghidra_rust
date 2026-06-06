//! Data plugin -- ported from `ghidra.app.plugin.core.data`.
//!
//! Provides the [`DataPlugin`] and all associated actions for creating,
//! editing, cycling, and managing data types in the listing display.
//!
//! # Modules
//!
//! | Rust module     | Java class(es)                                   |
//! |-----------------|--------------------------------------------------|
//! | `plugin`        | `DataPlugin`                                     |
//! | `actions`       | `DataAction`, `ChooseDataTypeAction`, etc.       |
//! | `actions_ext`   | `PointerDataAction`, `VoidDataAction`, etc.      |
//! | `settings`      | `DataSettingsDialog`, `DataTypeSettingsDialog`   |
//! | `dialogs`       | `CreateStructureDialog`, `EditDataFieldDialog`   |

pub mod plugin;
pub mod actions;
pub mod actions_ext;
pub mod settings;
pub mod dialogs;
pub mod recently_used;
pub mod rename_dialog;

pub use plugin::*;
pub use actions::*;
pub use actions_ext::*;
pub use settings::*;
pub use dialogs::*;
