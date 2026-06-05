//! DBTraceMain - main trace database implementation.
//!
//! Ported from Ghidra's `ghidra.trace.database.DBTrace`.

use serde::{Deserialize, Serialize};

/// Database configuration for a trace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceDatabaseConfig {
    /// The base language ID.
    pub language_id: String,
    /// The base compiler spec ID.
    pub compiler_spec_id: String,
    /// The trace name.
    pub name: String,
    /// Date created (epoch millis).
    pub date_created: i64,
    /// Executable path, if known.
    pub executable_path: Option<String>,
    /// Platform name, if known.
    pub platform: Option<String>,
}

impl TraceDatabaseConfig {
    /// Create a new database configuration.
    pub fn new(
        language_id: impl Into<String>,
        compiler_spec_id: impl Into<String>,
        name: impl Into<String>,
    ) -> Self {
        Self {
            language_id: language_id.into(),
            compiler_spec_id: compiler_spec_id.into(),
            name: name.into(),
            date_created: 0,
            executable_path: None,
            platform: None,
        }
    }

    /// Set the executable path.
    pub fn with_executable(mut self, path: impl Into<String>) -> Self {
        self.executable_path = Some(path.into());
        self
    }

    /// Set the platform.
    pub fn with_platform(mut self, platform: impl Into<String>) -> Self {
        self.platform = Some(platform.into());
        self
    }
}

/// Constants for trace database.
pub mod constants {
    /// Chunk size for database storage.
    pub const CHUNK_SIZE: usize = 4096;

    /// Database time interval for event coalescing (ms).
    pub const DB_TIME_INTERVAL: u64 = 500;

    /// Database buffer size for write coalescing.
    pub const DB_BUFFER_SIZE: usize = 1000;

    /// Options category for trace information.
    pub const TRACE_INFO: &str = "Trace Information";

    /// Options key for name.
    pub const NAME_KEY: &str = "Name";

    /// Options key for date created.
    pub const DATE_CREATED_KEY: &str = "Date Created";

    /// Options key for base language.
    pub const BASE_LANGUAGE_KEY: &str = "Base Language";

    /// Options key for base compiler.
    pub const BASE_COMPILER_KEY: &str = "Base Compiler";

    /// Options key for platform.
    pub const PLATFORM_KEY: &str = "Platform";

    /// Options key for executable path.
    pub const EXECUTABLE_PATH_KEY: &str = "Executable Location";

    /// Options key for emulator cache version.
    pub const EMU_CACHE_VERSION_KEY: &str = "Emulator Cache Version";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_database_config() {
        let config = TraceDatabaseConfig::new(
            "x86:LE:64:default",
            "default",
            "test.trace",
        )
        .with_executable("/bin/test")
        .with_platform("linux");

        assert_eq!(config.language_id, "x86:LE:64:default");
        assert_eq!(config.executable_path.as_deref(), Some("/bin/test"));
        assert_eq!(config.platform.as_deref(), Some("linux"));
    }

    #[test]
    fn test_constants() {
        assert_eq!(constants::CHUNK_SIZE, 4096);
        assert_eq!(constants::DB_TIME_INTERVAL, 500);
    }
}
