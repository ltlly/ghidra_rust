//! PEF constants ported from Ghidra's `PefConstants.java`.

/// Well-known PEF section name constants.
pub struct PefConstants;

impl PefConstants {
    /// Transition vector section.
    pub const TVECT: &'static str = ".TVect";
    /// Import section.
    pub const IMPORT: &'static str = ".import";
    /// Termination section.
    pub const TERM: &'static str = ".term";
    /// Initialization section.
    pub const INIT: &'static str = ".init";
    /// Main entry section.
    pub const MAIN: &'static str = ".main";
    /// Table of contents section.
    pub const TOC: &'static str = ".toc";
    /// Glue section.
    pub const GLUE: &'static str = ".glue";

    /// Default base address for PEF images.
    pub const BASE_ADDRESS: u64 = 0x10000000;
}
