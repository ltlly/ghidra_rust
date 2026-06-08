// Help framework: help building (ported from help.GHelpBuilder, JavaHelpFilesBuilder,
// JavaHelpSetBuilder, HelpBuildUtils Java classes)

use std::fs;
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};

use crate::help::location::HelpModuleCollection;
use crate::help::validator::link_database::LinkDatabase;
use crate::help::validator::JavaHelpValidator;

/// Constants for file name suffixes.
const TOC_OUTPUT_FILE_APPENDIX: &str = "_TOC.xml";
const MAP_OUTPUT_FILE_APPENDIX: &str = "_map.xml";
const HELP_SET_OUTPUT_FILE_APPENDIX: &str = "_HelpSet.hs";
const _HELP_SEARCH_DIRECTORY_APPENDIX: &str = "_JavaHelpSearch";

const _HELP_TOPICS_ROOT_PATH: &str = "help/topics";

// ---------------------------------------------------------------------------
// GHelpBuilder -- the main build orchestrator
// ---------------------------------------------------------------------------

/// Configuration for the help builder.
#[derive(Debug, Clone)]
pub struct HelpBuilderConfig {
    pub output_directory: PathBuf,
    pub module_name: String,
    pub dependency_help_paths: Vec<PathBuf>,
    pub generated_dependency_help_paths: Vec<PathBuf>,
    pub help_input_directories: Vec<PathBuf>,
    pub debug_enabled: bool,
    pub ignore_invalid: bool,
    pub exit_on_error: bool,
}

impl HelpBuilderConfig {
    pub fn new(output_directory: PathBuf, module_name: String) -> Self {
        HelpBuilderConfig {
            output_directory,
            module_name,
            dependency_help_paths: Vec::new(),
            generated_dependency_help_paths: Vec::new(),
            help_input_directories: Vec::new(),
            debug_enabled: false,
            ignore_invalid: false,
            exit_on_error: false,
        }
    }
}

/// Build result containing validation messages and success status.
#[derive(Debug)]
pub struct BuildResult {
    pub message: String,
    pub failed: bool,
}

impl BuildResult {
    pub fn success(message: String) -> Self {
        BuildResult {
            message,
            failed: false,
        }
    }

    pub fn failure(message: String) -> Self {
        BuildResult {
            message,
            failed: true,
        }
    }
}

/// The main help builder that validates and generates help output files.
pub struct GHelpBuilder {
    config: HelpBuilderConfig,
}

impl GHelpBuilder {
    pub fn new(config: HelpBuilderConfig) -> Self {
        GHelpBuilder { config }
    }

    /// Parse command-line arguments and create a config.
    pub fn parse_args(args: &[String]) -> Result<HelpBuilderConfig, String> {
        let mut output_dir = None;
        let mut module_name = None;
        let mut help_inputs = Vec::new();
        let mut dep_paths = Vec::new();
        let mut gen_dep_paths = Vec::new();
        let mut debug = false;
        let mut ignore_invalid = false;

        let mut i = 0;
        while i < args.len() {
            match args[i].as_str() {
                "-o" => {
                    i += 1;
                    output_dir = args.get(i).map(PathBuf::from);
                }
                "-n" => {
                    i += 1;
                    module_name = args.get(i).cloned();
                }
                "-hp" => {
                    i += 1;
                    if let Some(hp) = args.get(i) {
                        dep_paths = hp.split(':').map(PathBuf::from).collect();
                    }
                }
                "-hpg" => {
                    i += 1;
                    if let Some(hp) = args.get(i) {
                        gen_dep_paths = hp.split(':').map(PathBuf::from).collect();
                    }
                }
                "-debug" => debug = true,
                "-ignoreinvalid" => ignore_invalid = true,
                opt if opt.starts_with('-') => {
                    return Err(format!("Unknown option: {}", opt));
                }
                input => {
                    help_inputs.push(PathBuf::from(input));
                }
            }
            i += 1;
        }

        let output_dir = output_dir.ok_or("Missing output directory: -o")?;
        let module_name = module_name.ok_or("Missing module name: -n")?;

        if help_inputs.is_empty() {
            return Err("Must specify at least one input directory".to_string());
        }

        Ok(HelpBuilderConfig {
            output_directory: output_dir,
            module_name,
            dependency_help_paths: dep_paths,
            generated_dependency_help_paths: gen_dep_paths,
            help_input_directories: help_inputs,
            debug_enabled: debug,
            ignore_invalid,
            exit_on_error: false,
        })
    }

    /// Run the build process.
    pub fn build(&self) -> BuildResult {
        // Collect all help
        let mut all_help = self.config.help_input_directories.clone();
        all_help.extend(self.config.dependency_help_paths.iter().cloned());

        let mut collection = match HelpModuleCollection::from_directories(&all_help) {
            Ok(c) => c,
            Err(e) => return BuildResult::failure(format!("Failed to collect help: {}", e)),
        };

        let mut link_database = LinkDatabase::new(&mut collection);

        // Validate
        let invalid_links = {
            let mut v = JavaHelpValidator::new(self.config.module_name.clone());
            if self.config.debug_enabled {
                v.set_debug_enabled(true);
            }
            v.validate(&collection, &mut link_database)
        };

        if !invalid_links.is_empty() || !link_database.get_duplicate_anchors().is_empty() {
            let mut message = String::new();
            if !invalid_links.is_empty() {
                message.push_str(&format!(
                    "[JavaHelpValidator] - Found the following {} invalid links:\n",
                    invalid_links.len()
                ));
                for link in &invalid_links {
                    message.push_str(&format!(
                        "Module {} - {}\n\n",
                        self.config.module_name, link
                    ));
                }
            }
            if !link_database.get_duplicate_anchors().is_empty() {
                message.push_str(&format!(
                    "[JavaHelpValidator] - Found the following {} topic(s) with duplicate anchor definitions:\n",
                    link_database.get_duplicate_anchors().len()
                ));
                for collection in link_database.get_duplicate_anchors() {
                    message.push_str(&format!("{}\n\n", collection));
                }
            }

            if self.config.ignore_invalid {
                log::warn!("{}", message);
            } else {
                return BuildResult::failure(message);
            }
        }

        // Build JavaHelp files
        if let Err(e) = self.build_java_help_files(&mut collection, &link_database) {
            return BuildResult::failure(format!("Error building help files: {}", e));
        }

        BuildResult::success(format!(
            "Finished building help for module: {}",
            self.config.module_name
        ))
    }

    fn build_java_help_files(
        &self,
        collection: &mut HelpModuleCollection,
        _link_database: &LinkDatabase,
    ) -> Result<(), String> {
        let output_dir = &self.config.output_directory;
        fs::create_dir_all(output_dir)
            .map_err(|e| format!("Failed to create output directory: {}", e))?;

        // Generate map file
        self.generate_map_file(output_dir, collection)?;

        // Generate help set file
        self.generate_help_set_file(output_dir)?;

        Ok(())
    }

    fn generate_map_file(
        &self,
        output_dir: &Path,
        collection: &mut HelpModuleCollection,
    ) -> Result<(), String> {
        let map_file = output_dir.join(format!("{}{}", self.config.module_name, MAP_OUTPUT_FILE_APPENDIX));
        log::info!("Generating map file: {}", map_file.display());

        let file = fs::File::create(&map_file)
            .map_err(|e| format!("Failed to create map file: {}", e))?;
        let mut writer = BufWriter::new(file);

        writeln!(writer, "<?xml version='1.0' encoding='ISO-8859-1' ?>").unwrap();
        writeln!(writer, "<!doctype MAP public \"-//Sun Microsystems Inc.//DTD JavaHelp Map Version 1.0//EN\">").unwrap();
        writeln!(writer, "<!-- Auto-generated: Do Not Edit -->").unwrap();
        writeln!(writer, "<map version=\"1.0\">").unwrap();

        let anchors = collection.get_all_anchor_definitions();
        for anchor in anchors {
            let help_path = anchor.help_path();
            let updated_path = self.relativize(&help_path);
            writeln!(
                writer,
                "  <mapID target=\"{}\" url=\"{}\"/>",
                anchor.id(),
                updated_path
            )
            .unwrap();
        }

        writeln!(writer, "</map>").unwrap();
        Ok(())
    }

    fn relativize(&self, anchor_target: &str) -> String {
        if Path::new(anchor_target).is_absolute() {
            return anchor_target.to_string();
        }

        if !anchor_target.starts_with("help") {
            return anchor_target.to_string();
        }

        // Strip the leading "help/" component
        if let Some(pos) = anchor_target.find('/') {
            let relative = &anchor_target[pos + 1..];
            return relative.replace('\\', "/");
        }

        anchor_target.to_string()
    }

    fn generate_help_set_file(&self, output_dir: &Path) -> Result<(), String> {
        let help_set_file = output_dir.join(format!(
            "{}{}",
            self.config.module_name, HELP_SET_OUTPUT_FILE_APPENDIX
        ));
        let map_file_name = format!("{}{}", self.config.module_name, MAP_OUTPUT_FILE_APPENDIX);
        let toc_file_name = format!("{}{}", self.config.module_name, TOC_OUTPUT_FILE_APPENDIX);

        JavaHelpSetBuilder::write_help_set_file(
            &help_set_file,
            &self.config.module_name,
            &map_file_name,
            &toc_file_name,
        )
    }
}

// ---------------------------------------------------------------------------
// JavaHelpSetBuilder
// ---------------------------------------------------------------------------

struct JavaHelpSetBuilder;

impl JavaHelpSetBuilder {
    fn write_help_set_file(
        help_set_file: &Path,
        module_name: &str,
        map_file_name: &str,
        toc_file_name: &str,
    ) -> Result<(), String> {
        let file = fs::File::create(help_set_file)
            .map_err(|e| format!("Failed to create help set file: {}", e))?;
        let mut writer = BufWriter::new(file);

        // Header
        writeln!(writer, "<?xml version='1.0' encoding='ISO-8859-1' ?>").unwrap();
        writeln!(writer, "<!DOCTYPE helpset PUBLIC \"-//Sun Microsystems Inc.//DTD JavaHelp HelpSet Version 2.0//EN\" \"http://java.sun.com/products/javahelp/helpset_2_0.dtd\">").unwrap();
        writeln!(writer).unwrap();
        writeln!(writer, "<!-- HelpSet auto-generated -->").unwrap();
        writeln!(writer, "<helpset version=\"2.0\">").unwrap();
        writeln!(writer, "\t<title>{} HelpSet</title>", module_name).unwrap();

        // Maps entry
        writeln!(writer, "\t<maps>").unwrap();
        writeln!(
            writer,
            "\t\t<mapref location=\"{}\" />",
            map_file_name
        )
        .unwrap();
        writeln!(writer, "\t</maps>").unwrap();

        // TOC entry
        writeln!(writer, "\t<view mergetype=\"javax.help.UniteAppendMerge\">").unwrap();
        writeln!(writer, "\t\t<name>TOC</name>").unwrap();
        writeln!(writer, "\t\t<label>Ghidra Table of Contents</label>").unwrap();
        writeln!(
            writer,
            "\t\t<type>help.CustomTOCView</type>"
        )
        .unwrap();
        writeln!(writer, "\t\t<data>{}</data>", toc_file_name).unwrap();
        writeln!(writer, "\t</view>").unwrap();

        // Search entry
        writeln!(writer, "\t<view>").unwrap();
        writeln!(writer, "\t\t<name>Search</name>").unwrap();
        writeln!(writer, "\t\t<label>Search for Keywords</label>").unwrap();
        writeln!(
            writer,
            "\t\t<type>help.CustomSearchView</type>"
        )
        .unwrap();
        writeln!(writer, "\t</view>").unwrap();

        // Favorites entry
        writeln!(writer, "\t<view>").unwrap();
        writeln!(writer, "\t\t<name>Favorites</name>").unwrap();
        writeln!(writer, "\t\t<label>Ghidra Favorites</label>").unwrap();
        writeln!(
            writer,
            "\t\t<type>help.CustomFavoritesView</type>"
        )
        .unwrap();
        writeln!(writer, "\t</view>").unwrap();

        writeln!(writer, "</helpset>").unwrap();
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// HelpBuildUtils (port of static utility methods)
// ---------------------------------------------------------------------------

/// Utility functions for the help build system.
pub mod build_utils {
    use std::path::PathBuf;

    use regex::Regex;
    use std::sync::LazyLock;

    static HREF_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r#""(\.\./[^/.]+/[^/.]+\.html*(#[^"]+)*)""#).unwrap()
    });

    static STYLE_CLASS_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r#"(?i)class\s*=\s*"(\w+)""#).unwrap()
    });

    /// Find the actual module file for the given relative path.
    pub fn find_module_file(module_dirs: &[PathBuf], relative_path: &str) -> Option<PathBuf> {
        for dir in module_dirs {
            let file = dir.join(relative_path);
            if file.exists() {
                return Some(file);
            }
        }
        None
    }

    /// Fix relative links in a help HTML file.
    pub fn fix_links_in_file(file_contents: &str) -> Option<String> {
        if !HREF_PATTERN.is_match(file_contents) {
            return None;
        }

        let result = HREF_PATTERN.replace_all(file_contents, |caps: &regex::Captures| {
            let href_text = &caps[1];
            let updated = resolve_link(href_text);
            format!("\"{}\"", updated)
        });

        Some(result.into_owned())
    }

    /// Fix CSS class names to lowercase.
    pub fn fix_style_sheet_class_names(file_contents: &str) -> Option<String> {
        if !STYLE_CLASS_PATTERN.is_match(file_contents) {
            return None;
        }

        let result =
            STYLE_CLASS_PATTERN.replace_all(file_contents, |caps: &regex::Captures| {
                let class_name = &caps[1];
                if contains_upper_case(class_name) {
                    format!("class=\"{}\"", class_name.to_lowercase())
                } else {
                    caps[0].to_string()
                }
            });

        Some(result.into_owned())
    }

    fn resolve_link(link_text: &str) -> String {
        if link_text.starts_with(HELP_TOPICS_ROOT_PATH) {
            return link_text.to_string();
        }

        let parts: Vec<&str> = link_text.split('/').collect();
        if parts.len() != 3 || parts[0] != ".." {
            return link_text.to_string();
        }

        format!("{}/{}/{}", HELP_TOPICS_ROOT_PATH, parts[1], parts[2])
    }

    fn contains_upper_case(s: &str) -> bool {
        s.chars().any(|c| c.is_uppercase())
    }

    /// Check if a URI string represents a remote resource.
    pub fn is_remote(uri_string: &str) -> bool {
        if uri_string.starts_with("http://")
            || uri_string.starts_with("https://")
            || uri_string.starts_with("ftp://")
        {
            return true;
        }
        if uri_string.contains("://") {
            return !uri_string.starts_with("file:");
        }
        false
    }

    const HELP_TOPICS_ROOT_PATH: &str = "help/topics";

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn test_fix_links_in_file() {
            // Regex matches: "../<module>/<file>.html" (exactly 2 segments after ../)
            let input = "href=\"../OtherModule/page.html\"";
            let result = fix_links_in_file(input);
            assert!(result.is_some(), "fix_links_in_file should match relative .html links");
            let result = result.unwrap();
            assert!(
                result.contains("help/topics/OtherModule/page.html"),
                "Should convert ../OtherModule/page.html to help/topics/OtherModule/page.html, got: {}",
                result
            );
        }

        #[test]
        fn test_fix_links_no_change() {
            let input = r#"<a href="help/topics/Foo/bar.html">Link</a>"#;
            let result = fix_links_in_file(input);
            // No relative links to fix
            assert!(result.is_none());
        }

        #[test]
        fn test_fix_style_sheet_class_names() {
            let input = r#"<div class="MyClassName">Content</div>"#;
            let result = fix_style_sheet_class_names(input);
            assert!(result.is_some());
            assert!(result.unwrap().contains("class=\"myclassname\""));
        }

        #[test]
        fn test_fix_style_sheet_class_names_no_change() {
            let input = r#"<div class="lowercase">Content</div>"#;
            let result = fix_style_sheet_class_names(input);
            // No uppercase to fix
            assert!(result.is_none() || result.unwrap().contains("class=\"lowercase\""));
        }

        #[test]
        fn test_is_remote() {
            assert!(is_remote("http://example.com"));
            assert!(is_remote("https://example.com/img.png"));
            assert!(!is_remote("file:///tmp/test.html"));
            assert!(!is_remote("images/icon.png"));
        }

        #[test]
        fn test_contains_upper_case() {
            assert!(contains_upper_case("MyClass"));
            assert!(!contains_upper_case("lowercase"));
            assert!(!contains_upper_case("123"));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_help_builder_config() {
        let config = HelpBuilderConfig::new(
            PathBuf::from("/output"),
            "TestModule".to_string(),
        );
        assert_eq!(config.module_name, "TestModule");
        assert!(!config.debug_enabled);
    }

    #[test]
    fn test_build_result() {
        let r = BuildResult::success("OK".to_string());
        assert!(!r.failed);
        assert_eq!(r.message, "OK");

        let r = BuildResult::failure("Error".to_string());
        assert!(r.failed);
    }

    #[test]
    fn test_relativize() {
        let config = HelpBuilderConfig::new(
            PathBuf::from("/output"),
            "Test".to_string(),
        );
        let builder = GHelpBuilder::new(config);

        assert_eq!(
            builder.relativize("help/topics/MyTopic/page.html"),
            "topics/MyTopic/page.html"
        );
        assert_eq!(
            builder.relativize("/absolute/path.html"),
            "/absolute/path.html"
        );
    }

    #[test]
    fn test_java_help_set_builder() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("TestModule_HelpSet.hs");
        let result = JavaHelpSetBuilder::write_help_set_file(
            &path,
            "TestModule",
            "TestModule_map.xml",
            "TestModule_TOC.xml",
        );
        assert!(result.is_ok());
        assert!(path.exists());

        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("TestModule"));
        assert!(content.contains("TestModule_map.xml"));
        assert!(content.contains("TestModule_TOC.xml"));
    }

    #[test]
    fn test_parse_args() {
        let args: Vec<String> = vec![
            "-o".into(),
            "/output".into(),
            "-n".into(),
            "MyModule".into(),
            "-debug".into(),
            "/input".into(),
        ];
        let config = GHelpBuilder::parse_args(&args);
        assert!(config.is_ok());
        let config = config.unwrap();
        assert_eq!(config.output_directory, PathBuf::from("/output"));
        assert_eq!(config.module_name, "MyModule");
        assert!(config.debug_enabled);
        assert_eq!(config.help_input_directories.len(), 1);
    }

    #[test]
    fn test_parse_args_missing_output() {
        let args: Vec<String> = vec!["-n".into(), "M".into(), "/input".into()];
        let config = GHelpBuilder::parse_args(&args);
        assert!(config.is_err());
    }

    #[test]
    fn test_parse_args_missing_name() {
        let args: Vec<String> = vec!["-o".into(), "/output".into(), "/input".into()];
        let config = GHelpBuilder::parse_args(&args);
        assert!(config.is_err());
    }
}
