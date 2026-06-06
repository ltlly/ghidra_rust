//! Listing viewer framework -- ported from
//! `ghidra.app.util.viewer`.
//!
//! Provides the field rendering framework for the code browser listing display.
//!
//! - [`field`] -- field factories and text fields (Address, Mnemonic, Operand, etc.)
//! - [`format`] -- field format models managing layout and ordering
//! - [`listingpanel`] -- the main listing panel for displaying code
//! - [`multilisting`] -- synchronized side-by-side listings
//! - [`options`] -- display options for the listing
//! - [`proxy`] -- lazy data proxies for field rendering
//! - [`util`] -- utility functions for text layout

pub mod field;
pub mod format;
pub mod listingpanel;
pub mod multilisting;
pub mod options;
pub mod proxy;
pub mod util;

// Re-export commonly used types
pub use field::{
    FieldFactory, ListingTextField, Annotation, AnnotationType,
    BrowserCodeUnitFormat, AnnotatedStringHandler,
    AddressFieldFactory, MnemonicFieldFactory, OperandFieldFactory,
};
pub use format::FieldFormatModel;
pub use listingpanel::{ListingPanel, AddressBasedPanelView};
pub use multilisting::MultiListingPanel;
pub use options::ListingOptions;
pub use proxy::ProxyObj;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_field_format_model_with_factories() {
        let mut model = FieldFormatModel::new("Listing");
        model.add_factory(Box::new(AddressFieldFactory::new()));
        model.add_factory(Box::new(MnemonicFieldFactory::new()));
        model.add_factory(Box::new(OperandFieldFactory::new()));
        assert_eq!(model.num_factories(), 3);
        assert_eq!(
            model.factory_names(),
            vec!["Address", "Mnemonic", "Operands"]
        );
    }

    #[test]
    fn test_listing_panel_navigation() {
        let mut panel = ListingPanel::new();
        panel.set_program("test.exe");
        panel.go_to(0x401000);
        assert_eq!(panel.current_address(), Some(0x401000));
    }

    #[test]
    fn test_listing_options_variants() {
        let opts_min = ListingOptions::minimal();
        assert!(opts_min.condensed);

        let opts_verbose = ListingOptions::verbose();
        assert!(opts_verbose.show_bytes);
    }

    #[test]
    fn test_field_with_annotation() {
        let mut field = ListingTextField::new_single_line("Mnemonic", "mov eax, ebx", 100, 80);
        field.add_annotation(Annotation::highlight(0, 3, (255, 255, 0)));
        assert_eq!(field.text(), "mov eax, ebx");
        assert_eq!(field.start_x(), 100);
        assert_eq!(field.annotations().len(), 1);
    }

    #[test]
    fn test_proxy_workflow() {
        let mut proxy = ProxyObj::<String>::new(0x401000);
        assert!(!proxy.has_value());
        proxy.set("push ebp".to_string());
        assert!(proxy.has_value());
        assert_eq!(proxy.get(), Some(&"push ebp".to_string()));
    }

    #[test]
    fn test_multi_listing() {
        let mut panel = MultiListingPanel::new("Original", "Modified");
        assert!(panel.is_synchronized());
        panel.set_synchronized(false);
        assert!(!panel.is_synchronized());
    }

    #[test]
    fn test_util_wrap_text() {
        let lines = util::wrap_text("Hello World How Are You", 10);
        assert!(lines.len() > 1);
        for line in &lines {
            assert!(line.len() <= 10);
        }
    }

    #[test]
    fn test_browser_code_unit_format() {
        let fmt = BrowserCodeUnitFormat::default();
        assert_eq!(fmt.format_address(0x401000), "0x00401000");
        assert_eq!(fmt.format_label("main", Some("libc")), "libc::main");
    }

    #[test]
    fn test_annotated_string() {
        use crate::viewer::field::annotated_string_handler::BasicAnnotatedString;
        let mut s = BasicAnnotatedString::new("Hello");
        s.add_annotation(Annotation::color_change(0, 5, (255, 0, 0)));
        assert_eq!(s.color_at(2), Some((255, 0, 0)));
    }
}
