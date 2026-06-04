//! Launch support infrastructure.
//!
//! Port of Ghidra's `ghidra.launch` package.
//!
//! Provides Java version parsing, Java installation discovery across platforms,
//! launch properties parsing, and application configuration management.

pub mod app_config;
pub mod java_finder;
pub mod java_version;
pub mod launch_properties;

pub use app_config::{AppConfig, AppConfigError};
pub use java_finder::{
    JavaFilter, JavaFinder, LinuxJavaFinder, MacJavaFinder, Platform, WindowsJavaFinder,
    create_java_finder, current_platform,
};
pub use java_version::{JavaVersion, ParseVersionError};
pub use launch_properties::{LaunchProperties, LaunchPropertiesError, JAVA_HOME_OVERRIDE, VMARGS, ENVVARS};
