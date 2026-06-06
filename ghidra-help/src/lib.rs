//! Ghidra Help -- Online help system framework.
//!
//! Ports Ghidra's `Framework/Help` Java package into Rust. Provides:
//!
//! - **`HelpService`** trait: Display help by object, URL, or location.
//! - **`DefaultHelpService`**: No-op fallback when help is unavailable.
//! - **`Help`**: Global accessor for the active `HelpService`.
//! - **`HelpDescriptor`**: Trait for objects that self-describe for help.
//! - **`HelpBuildUtils`**: Build and validate help topic trees.
//! - **`PathKey`**: Table-of-contents path key.
//! - **`HelpSet`**: Help set description (`.hs` file equivalent).
//! - **`validator`**: Link and anchor validation for help HTML files.
//!
//! # Architecture
//!
//! ```text
//! ┌──────────────────────────────────────────┐
//! │            HelpService (trait)            │
//! │  register, show, clear, query help       │
//! └──────────────────────────────────────────┘
//!     │                    │
//!     ▼                    ▼
//! ┌─────────────┐  ┌─────────────────────────┐
//! │DefaultHelp  │  │ Help (global accessor)  │
//! │Service      │  │ HelpBuildUtils          │
//! └─────────────┘  │ validator::             │
//!                  │  links, model, location │
//!                  └─────────────────────────┘
//! ```

pub mod default_help_service;
pub mod help;
pub mod help_build_utils;
pub mod help_descriptor;
pub mod help_location;
pub mod help_service;
pub mod help_set;
pub mod path_key;
pub mod validator;

// Re-export key types
pub use default_help_service::DefaultHelpService;
pub use help::Help;
pub use help_build_utils::HelpBuildUtils;
pub use help_descriptor::HelpDescriptor;
pub use help_location::{DynamicHelpLocation, HelpLocation};
pub use help_service::HelpService;
pub use help_set::HelpSet;
pub use path_key::PathKey;
pub use validator::JavaHelpValidator;
