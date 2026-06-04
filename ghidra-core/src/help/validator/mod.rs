// Help framework: validation (ported from help.validator Java package)

pub(crate) mod link_database;
pub(crate) mod anchor_manager;
pub(crate) mod java_help_validator;

pub use link_database::LinkDatabase;
pub use anchor_manager::AnchorManager;
pub use java_help_validator::JavaHelpValidator;
