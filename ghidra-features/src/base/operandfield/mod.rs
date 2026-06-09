//! Operand field display and interaction.
//!
//! Ported from Ghidra's `ghidra.app.util.viewer.field.OperandFieldHelper`,
//! `OperandFieldFactory`, and associated operand field plugin code in
//! `ghidra.app.plugin.core`.
//!
//! This module provides:
//! - [`OperandFieldHelper`] -- display options and rendering logic for
//!   operand fields (word wrap, underline, separator spacing, etc.)
//! - [`OperandFieldPlugin`] -- plugin managing operand field actions
//!   (set equate, remove equate, set label, follow reference, edit, copy)
//! - [`OperandFieldAction`] -- enum of available operand field actions
//! - [`OperandFieldContext`] -- context for determining action enablement
//! - [`UnderlineChoice`] -- underline display policy
//! - [`OperandFieldDisplayOptions`] -- configurable display settings
//! - [`OperandFieldElement`] -- a single rendered element in an operand field
//! - [`OperandFieldResult`] -- accumulates rendered elements for display
//! - [`OpInfo`] -- operand representation info for a single operand
//! - [`OpRepElement`] -- a single element in an operand representation list
//! - [`OperandKind`] -- classification of operand element types
//! - [`OperandLocationInfo`] -- location info for click-to-program-location
//!
//! # Architecture
//!
//! The module separates display configuration ([`OperandFieldHelper`]) from
//! action management ([`OperandFieldPlugin`]). The helper handles rendering
//! options and element classification; the plugin handles action enablement,
//! callbacks, and location resolution.
//!
//! # Sub-modules
//!
//! - [`operand_field_helper`] -- display options, element types, rendering helpers
//! - [`operand_field_plugin`] -- plugin logic, actions, context, enablement

pub mod operand_field_helper;
pub mod operand_field_plugin;

pub use operand_field_helper::{
    OperandFieldDisplayOptions, OperandFieldElement, OperandFieldHelper, OperandFieldResult,
    OperandKind, OperandLocationInfo, OpInfo, OpRepElement, UnderlineChoice,
};
pub use operand_field_plugin::{
    get_enabled_actions, is_copy_operand_enabled, is_edit_operand_enabled,
    is_follow_reference_enabled, is_remove_equate_enabled, is_set_equate_enabled,
    is_set_operand_label_enabled, OperandFieldAction, OperandFieldContext, OperandFieldPlugin,
};
