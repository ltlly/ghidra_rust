//! Listing field factories and text fields -- ported from
//! `ghidra.app.util.viewer.field`.
//!
//! Provides the field rendering framework for the code browser listing.
//!
//! - [`FieldFactory`] -- base for all field factories that generate display fields
//! - [`ListingTextField`] -- a text field in the listing display
//! - [`Annotation`] -- an annotation within a field (comments, labels, etc.)
//! - [`BrowserCodeUnitFormat`] -- format options for code unit display

pub mod field_factory;
pub mod listing_text_field;
pub mod annotation;
pub mod browser_code_unit_format;
pub mod annotated_string_handler;
pub mod address_field_factory;
pub mod mnemonic_field_factory;
pub mod operand_field_factory;

pub use field_factory::FieldFactory;
pub use listing_text_field::ListingTextField;
pub use annotation::{Annotation, AnnotationType};
pub use browser_code_unit_format::BrowserCodeUnitFormat;
pub use annotated_string_handler::AnnotatedStringHandler;
pub use address_field_factory::AddressFieldFactory;
pub use mnemonic_field_factory::MnemonicFieldFactory;
pub use operand_field_factory::OperandFieldFactory;
