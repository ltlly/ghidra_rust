//! Generic help topic constants.
//!
//! Ported from `ghidra.app.util.GenericHelpTopics` in
//! `Ghidra/Framework/Project/src/main/java/ghidra/app/util/GenericHelpTopics.java`.

/// Help Topic for "About."
pub const ABOUT: &str = "About";

/// Name of options for the help topic for the front end (Project Window).
pub const FRONT_END: &str = "FrontEndPlugin";

/// Help Topic for the glossary.
pub const GLOSSARY: &str = "Glossary";

/// Help for Intro topics.
pub const INTRO: &str = "Intro";

/// Help Topic for the project repository.
pub const REPOSITORY: &str = "Repository";

/// Help Topic for the version control.
pub const VERSION_CONTROL: &str = "VersionControl";

/// Help Topic for tools.
///
/// Note: In the Java source this delegates to `ToolConstants.TOOL_HELP_TOPIC`.
/// The canonical value is `"Tool"`.
pub const TOOL: &str = "Tool";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generic_help_topics_constants() {
        assert_eq!(ABOUT, "About");
        assert_eq!(FRONT_END, "FrontEndPlugin");
        assert_eq!(GLOSSARY, "Glossary");
        assert_eq!(INTRO, "Intro");
        assert_eq!(REPOSITORY, "Repository");
        assert_eq!(VERSION_CONTROL, "VersionControl");
        assert_eq!(TOOL, "Tool");
    }
}
