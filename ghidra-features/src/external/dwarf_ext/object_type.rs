//! ObjectType -- type of external debug object.
//!
//! Ported from `ghidra.app.util.bin.format.dwarf.external.ObjectType`.

/// Specifies the type of a debug object that can be fetched from a
/// [`DebugInfoProvider`](super::DebugInfoProvider).
///
/// The debuginfod protocol distinguishes between debug info files (`.debug`),
/// the original executable, and source files.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ObjectType {
    /// A debug info file (typically a `.debug` ELF containing DWARF).
    DebugInfo,
    /// The original executable binary.
    Executable,
    /// A source file referenced by the debug info.
    Source,
}

impl ObjectType {
    /// Returns the lowercase path segment used in debuginfod URLs and
    /// directory structures (e.g. `"debuginfo"`, `"executable"`, `"source"`).
    pub fn path_string(self) -> &'static str {
        match self {
            ObjectType::DebugInfo => "debuginfo",
            ObjectType::Executable => "executable",
            ObjectType::Source => "source",
        }
    }
}

impl std::fmt::Display for ObjectType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.path_string())
    }
}

impl std::str::FromStr for ObjectType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "debuginfo" => Ok(ObjectType::DebugInfo),
            "executable" => Ok(ObjectType::Executable),
            "source" => Ok(ObjectType::Source),
            _ => Err(format!("Unknown ObjectType: {}", s)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_path_string() {
        assert_eq!(ObjectType::DebugInfo.path_string(), "debuginfo");
        assert_eq!(ObjectType::Executable.path_string(), "executable");
        assert_eq!(ObjectType::Source.path_string(), "source");
    }

    #[test]
    fn test_display() {
        assert_eq!(ObjectType::DebugInfo.to_string(), "debuginfo");
        assert_eq!(ObjectType::Executable.to_string(), "executable");
    }

    #[test]
    fn test_from_str() {
        assert_eq!("debuginfo".parse::<ObjectType>().unwrap(), ObjectType::DebugInfo);
        assert_eq!("DEBUGINFO".parse::<ObjectType>().unwrap(), ObjectType::DebugInfo);
        assert_eq!("executable".parse::<ObjectType>().unwrap(), ObjectType::Executable);
        assert_eq!("source".parse::<ObjectType>().unwrap(), ObjectType::Source);
        assert!("unknown".parse::<ObjectType>().is_err());
    }
}
