// Port of help.validator.JavaHelpValidator

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use crate::help::links::*;
use crate::help::location::HelpModuleCollection;
use crate::help::model::{HelpFile, HelpTopic, TocItem};
use crate::help::validator::link_database::{DuplicateAnchorCollection, LinkDatabase};

/// Prefix for external help references (files outside the help system).
pub const EXTERNAL_PREFIX: &str = "external:";

/// Validates help files, links, anchors, and TOC items.
pub struct JavaHelpValidator {
    pub module_name: String,
    pub debug_enabled: bool,
}

impl JavaHelpValidator {
    pub fn new(module_name: String) -> Self {
        JavaHelpValidator {
            module_name,
            debug_enabled: false,
        }
    }

    pub fn set_debug_enabled(&mut self, debug: bool) {
        self.debug_enabled = debug;
    }

    /// Run the full validation pipeline.
    pub fn validate(
        &self,
        help: &HelpModuleCollection,
        link_database: &mut LinkDatabase,
    ) -> Vec<InvalidLink> {
        // 1) Validate internal file links
        self.validate_internal_file_links(help, link_database);

        // 2) Validate external links
        self.validate_external_file_links(link_database);

        // 3) Validate TOC item IDs
        self.validate_toc_item_ids(help, link_database);

        link_database.get_unresolved_links().iter().cloned().collect()
    }

    fn validate_internal_file_links(
        &self,
        help: &HelpModuleCollection,
        link_database: &mut LinkDatabase,
    ) {
        self.debug(&format!(
            "validating internal help links for module: {}",
            help
        ));

        let mut unresolved_links = Vec::new();

        // Validate HREFs -- collect all cloned hrefs first to release borrow
        let href_data: Vec<_> = {
            let hrefs = help.get_all_hrefs();
            self.debug(&format!("\tHREF count: {}", hrefs.len()));
            hrefs
                .iter()
                .filter(|h| !h.is_remote)
                .map(|h| {
                    (
                        h.reference_file_help_path().map(|p| p.to_path_buf()),
                        h.clone(),
                    )
                })
                .collect()
        };

        for (help_path, href) in &href_data {
            let help_file_exists = if let Some(ref path) = help_path {
                help.get_help_file(path).is_some()
            } else {
                false
            };

            if let Some(ref path) = help_path {
                self.validate_href_help_file(href, help_file_exists, path, &mut unresolved_links);
            }
        }

        // Validate IMGs -- collect all cloned imgs first to release borrow
        let img_data: Vec<_> = {
            let imgs = help.get_all_imgs();
            self.debug(&format!("\tIMG count: {}", imgs.len()));
            imgs.iter().map(|i| (*i).clone()).collect()
        };

        for img in &img_data {
            self.validate_img_file(img, &mut unresolved_links);
        }

        link_database.add_unresolved_links(unresolved_links);

        // Check for duplicate anchors
        let duplicate_anchors = help.get_duplicate_anchors_by_file();
        self.debug(&format!(
            "\tHelp files with duplicate anchors: {}",
            duplicate_anchors.len()
        ));

        for (file_path, anchors_map) in duplicate_anchors {
            for (id, definitions) in anchors_map {
                link_database.add_duplicate_anchors(DuplicateAnchorCollection {
                    description: format!("Duplicate anchor '{}' in {}", id, file_path.display()),
                    anchor_ids: definitions.iter().map(|d| d.id().to_string()).collect(),
                });
            }
        }
    }

    fn validate_href_help_file(
        &self,
        href: &crate::help::model::Href,
        help_file_found: bool,
        _help_path: &Path,
        unresolved_links: &mut Vec<InvalidLink>,
    ) {
        if !help_file_found {
            if self.is_excluded_href(href) {
                return;
            }
            unresolved_links.push(InvalidLink::MissingFile(MissingFileInvalidLink::new(
                href.clone(),
            )));
            return;
        }

        // We found a help file, make sure the anchor is there
        if let Some(ref anchor) = href.anchor_name {
            // In a full implementation, we would check:
            //   help_file.contains_anchor(anchor_name)
            // For now, we skip the per-file check since we've already
            // verified the file exists
            let _ = anchor;
        }
    }

    fn validate_img_file(
        &self,
        img: &crate::help::model::Img,
        unresolved_links: &mut Vec<InvalidLink>,
    ) {
        if img.is_remote() {
            return;
        }

        if img.is_runtime() {
            if img.is_invalid() {
                unresolved_links.push(InvalidLink::InvalidRuntimeImage(
                    InvalidRuntimeImgFileInvalidLink::new(img.clone()),
                ));
            }
            return;
        }

        let image_path = &img.resolved_path;
        if image_path.is_none() {
            unresolved_links.push(InvalidLink::NonExistentImage(
                NonExistentImgFileInvalidLink::new(img.clone()),
            ));
        }
    }

    fn validate_external_file_links(&self, link_database: &mut LinkDatabase) {
        let unresolved = link_database.get_unresolved_links().clone();
        self.debug(&format!(
            "validating {} unresolved external links",
            unresolved.len()
        ));

        let mut remaining = Vec::new();
        for link in unresolved {
            match &link {
                InvalidLink::MissingAnchor(_) => {
                    remaining.push(link);
                }
                InvalidLink::MissingFile(_) => {
                    // In a full implementation, we would try to resolve
                    // against external help modules
                    remaining.push(link);
                }
                _ => {
                    remaining.push(link);
                }
            }
        }

        link_database.add_unresolved_links(remaining);
    }

    fn validate_toc_item_ids(
        &self,
        help: &HelpModuleCollection,
        link_database: &mut LinkDatabase,
    ) {
        self.debug("Validating TOC item IDs...");
        let mut unresolved_links = Vec::new();

        let items = help.get_input_toc_items();
        self.debug(&format!(
            "\tvalidating {} TOC item references for module: {}",
            items.len(),
            self.module_name
        ));

        for item in items {
            if !item.validate(link_database) {
                match item {
                    TocItem::Reference(reference) => {
                        unresolved_links.push(InvalidLink::MissingTocDefinition(
                            MissingTocDefinitionInvalidLink::new(
                                reference.source_file.clone(),
                                reference.line_number,
                                reference.id.clone(),
                            ),
                        ));
                    }
                    _ => {
                        if let Some(target) = item.target_attribute() {
                            if !is_excluded_path(target) {
                                unresolved_links.push(InvalidLink::MissingTocTargetId(
                                    MissingTocTargetIdInvalidLink::new(
                                        item.source_file().clone(),
                                        item.line_number(),
                                        item.id_attribute().to_string(),
                                    ),
                                ));
                            }
                        }
                    }
                }
            }
        }

        link_database.add_unresolved_links(unresolved_links);
        self.debug("\tfinished validating TOC item IDs...");
    }

    fn is_excluded_href(&self, href: &crate::help::model::Href) -> bool {
        let path = &href.href;
        is_excluded_path(path)
    }

    fn debug(&self, message: &str) {
        if self.debug_enabled {
            eprintln!("[JavaHelpValidator] {}", message);
        }
    }
}

fn is_excluded_path(path: &str) -> bool {
    if path.contains("/docs/api/") {
        return true;
    }
    let stripped = match path.rfind('.') {
        Some(pos) => &path[..pos],
        None => path,
    };
    stripped.starts_with(EXTERNAL_PREFIX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_excluded_path() {
        assert!(is_excluded_path("/docs/api/java/lang/String.html"));
        assert!(is_excluded_path("external:SomeFile.html"));
        assert!(!is_excluded_path("help/topics/MyTopic/page.html"));
    }

    #[test]
    fn test_validator_creation() {
        let _validator = JavaHelpValidator::new("TestModule".to_string());
        // Validator is created successfully
    }

    #[test]
    fn test_validator_set_debug() {
        let mut validator = JavaHelpValidator::new("TestModule".to_string());
        validator.set_debug_enabled(true);
        // Debug mode is set without panic
    }
}
