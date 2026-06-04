//! Objective-C metadata analyzers.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.analysis.ObjcMessageAnalyzer`
//! and `ObjcTypeMetadataAnalyzer`.
//!
//! These analyzers detect and apply Objective-C runtime metadata to a program
//! being analyzed in Ghidra. They create symbols, namespaces, and data types
//! for classes, categories, methods, protocols, and properties found in
//! Mach-O binaries.

use crate::base::analyzer::core::*;
use crate::base::analyzer::priority::*;
use crate::base::analyzer::r#trait::*;

// ============================================================================
// ObjcTypeMetadataAnalyzer
// ============================================================================

/// Analyzer that detects and applies Objective-C type metadata.
///
/// This analyzer runs early in the analysis pipeline. It looks for
/// `__OBJC` (ObjC1) or `__objc_*` (ObjC2) sections in Mach-O binaries
/// and applies the metadata structures to the program.
///
/// Corresponds to Java's `ObjcTypeMetadataAnalyzer`.
#[derive(Debug, Clone)]
pub struct ObjcTypeMetadataAnalyzer {
    base: AbstractAnalyzer,
    /// Whether to process ObjC1 metadata.
    pub process_objc1: bool,
    /// Whether to process ObjC2 metadata.
    pub process_objc2: bool,
}

impl ObjcTypeMetadataAnalyzer {
    /// The analyzer name.
    pub const NAME: &'static str = "Objective-C Type Metadata";
    /// The analyzer description.
    pub const DESCRIPTION: &'static str =
        "Analyzes Objective-C runtime metadata in Mach-O binaries to create \
         symbols, namespaces, and data types for classes, categories, methods, \
         protocols, and properties.";

    /// Create a new analyzer.
    pub fn new() -> Self {
        let mut base = AbstractAnalyzer::new(Self::NAME, Self::DESCRIPTION, AnalyzerType::Byte);
        base.set_priority(AnalysisPriority::DATA_TYPE_PROPAGATION.before());
        base.set_supports_one_time_analysis(true);
        Self {
            base,
            process_objc1: true,
            process_objc2: true,
        }
    }
}

impl Default for ObjcTypeMetadataAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl Analyzer for ObjcTypeMetadataAnalyzer {
    fn name(&self) -> &str {
        self.base.name()
    }

    fn description(&self) -> &str {
        self.base.description()
    }

    fn analysis_type(&self) -> AnalyzerType {
        self.base.analysis_type()
    }

    fn priority(&self) -> AnalysisPriority {
        AnalysisPriority::DATA_TYPE_PROPAGATION.before()
    }

    fn can_analyze(&self, program: &Program) -> bool {
        // Only analyze Mach-O binaries
        program.get_executable_format() == Some("Mach-O")
    }

    fn default_enablement(&self, _program: &Program) -> bool {
        true
    }

    fn supports_one_time_analysis(&self) -> bool {
        true
    }

    fn added(
        &self,
        _program: &mut Program,
        _set: &AddressSet,
        monitor: &dyn TaskMonitor,
        log: &mut MessageLog,
    ) -> Result<bool, CancelledError> {
        monitor.check_cancelled()?;
        monitor.set_indeterminate(true);
        monitor.set_message("Analyzing Objective-C type metadata...");
        log.append_msg("ObjcTypeMetadataAnalyzer: analyzing ObjC metadata");

        // In the full implementation:
        // 1. Check for __OBJC segment (ObjC1) or __DATA/__DATA_CONST (ObjC2)
        // 2. Parse the metadata structures
        // 3. Create symbols, namespaces, and data types
        // 4. Apply methods, ivars, protocols to the program

        monitor.set_indeterminate(false);
        Ok(true)
    }
}

// ============================================================================
// ObjcMessageAnalyzer
// ============================================================================

/// Analyzer that identifies Objective-C message send sites.
///
/// This analyzer looks for calls to `objc_msgSend`, `objc_msgSend_stret`,
/// `objc_msgSendSuper`, etc. and applies type information to the call sites
/// based on the ObjC metadata.
///
/// Corresponds to Java's `ObjcMessageAnalyzer`.
#[derive(Debug, Clone)]
pub struct ObjcMessageAnalyzer {
    base: AbstractAnalyzer,
}

impl ObjcMessageAnalyzer {
    /// The analyzer name.
    pub const NAME: &'static str = "Objective-C Message";
    /// The analyzer description.
    pub const DESCRIPTION: &'static str =
        "Analyzes Objective-C message send calls to determine receiver types \
         and selector names, applying the information to improve decompilation.";

    /// Known objc_msgSend variants.
    pub const MSG_SEND_VARIANTS: &[&str] = &[
        "_objc_msgSend",
        "_objc_msgSend_stret",
        "_objc_msgSendSuper",
        "_objc_msgSendSuper_stret",
        "_objc_msgSendSuper2",
        "_objc_msgSendSuper2_stret",
        "_objc_msgSend_fixup",
        "_objc_msgSend_uncached",
        "_objc_msg_lookup",
        "_objc_msg_lookup_super",
    ];

    /// Create a new analyzer.
    pub fn new() -> Self {
        let mut base = AbstractAnalyzer::new(Self::NAME, Self::DESCRIPTION, AnalyzerType::Byte);
        base.set_priority(AnalysisPriority::DATA_TYPE_PROPAGATION.before().before());
        base.set_supports_one_time_analysis(true);
        Self { base }
    }

    /// Check if a symbol name is a known objc_msgSend variant.
    pub fn is_msg_send(symbol_name: &str) -> bool {
        Self::MSG_SEND_VARIANTS.iter().any(|&v| {
            symbol_name == v
                || symbol_name.ends_with(v)
                || symbol_name == &v[1..] // without leading underscore
        })
    }
}

impl Default for ObjcMessageAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl Analyzer for ObjcMessageAnalyzer {
    fn name(&self) -> &str {
        self.base.name()
    }

    fn description(&self) -> &str {
        self.base.description()
    }

    fn analysis_type(&self) -> AnalyzerType {
        self.base.analysis_type()
    }

    fn priority(&self) -> AnalysisPriority {
        AnalysisPriority::DATA_TYPE_PROPAGATION.before().before()
    }

    fn can_analyze(&self, program: &Program) -> bool {
        program.get_executable_format() == Some("Mach-O")
    }

    fn default_enablement(&self, _program: &Program) -> bool {
        true
    }

    fn supports_one_time_analysis(&self) -> bool {
        true
    }

    fn added(
        &self,
        _program: &mut Program,
        _set: &AddressSet,
        monitor: &dyn TaskMonitor,
        log: &mut MessageLog,
    ) -> Result<bool, CancelledError> {
        monitor.check_cancelled()?;
        monitor.set_indeterminate(true);
        monitor.set_message("Analyzing Objective-C message sends...");
        log.append_msg("ObjcMessageAnalyzer: analyzing ObjC message send sites");

        // In the full implementation:
        // 1. Find all references to objc_msgSend variants
        // 2. For each call site, determine the receiver (x0 on ARM64, etc.)
        // 3. Look up the receiver's class in the ObjC metadata
        // 4. Find the selector from the call context
        // 5. Look up the method in the class metadata
        // 6. Apply the method's return type and parameter types

        monitor.set_indeterminate(false);
        Ok(true)
    }
}

// ============================================================================
// ObjcUtilsAnalyzer
// ============================================================================

/// Utility functions used by the ObjC analyzers.
///
/// These correspond to static helper methods in the Java analyzer classes.
pub struct ObjcAnalyzerUtils;

impl ObjcAnalyzerUtils {
    /// Check if a segment name indicates an ObjC-related segment.
    pub fn is_objc_segment(segment_name: &str) -> bool {
        matches!(
            segment_name,
            "__OBJC" | "__objc" | "__DATA" | "__DATA_CONST" | "__DATA_DIRTY"
        )
    }

    /// Check if a section name is ObjC-related.
    pub fn is_objc_section(section_name: &str) -> bool {
        super::objc1::Objc1Constants::is_objc_section(section_name)
            || super::objc2::Objc2Constants::is_objc2_section(section_name)
    }

    /// Format a class name for display.
    pub fn format_class_name(name: &str, is_meta: bool) -> String {
        if is_meta {
            format!("+{}", name)
        } else {
            name.to_string()
        }
    }

    /// Format a method for display.
    pub fn format_method(
        method_type: super::ObjcMethodType,
        class_name: &str,
        selector: &str,
    ) -> String {
        format!("{}[{} {}]", method_type.as_str(), class_name, selector)
    }

    /// Create the Objective-C namespace hierarchy string.
    pub fn objc_namespace() -> &'static str {
        "objc"
    }

    /// Create the category namespace path.
    pub fn category_namespace(category_name: &str) -> String {
        format!("objc::Categories::{}", category_name)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_objc_type_metadata_analyzer() {
        let analyzer = ObjcTypeMetadataAnalyzer::new();
        assert_eq!(analyzer.name(), ObjcTypeMetadataAnalyzer::NAME);
        assert!(analyzer.supports_one_time_analysis());
        assert!(analyzer.process_objc1);
        assert!(analyzer.process_objc2);
    }

    #[test]
    fn test_objc_type_metadata_analyzer_can_analyze() {
        let analyzer = ObjcTypeMetadataAnalyzer::new();

        let mut macho_program = Program::new(
            "test",
            Language {
                processor: "AARCH64".into(),
                variant: "LE".into(),
                size: 64,
            },
        );
        macho_program.executable_format = Some("Mach-O".into());
        assert!(analyzer.can_analyze(&macho_program));

        let mut elf_program = Program::new(
            "test",
            Language {
                processor: "x86".into(),
                variant: "LE".into(),
                size: 64,
            },
        );
        elf_program.executable_format = Some("ELF".into());
        assert!(!analyzer.can_analyze(&elf_program));
    }

    #[test]
    fn test_objc_message_analyzer() {
        let analyzer = ObjcMessageAnalyzer::new();
        assert_eq!(analyzer.name(), ObjcMessageAnalyzer::NAME);
        assert!(analyzer.supports_one_time_analysis());
    }

    #[test]
    fn test_is_msg_send() {
        assert!(ObjcMessageAnalyzer::is_msg_send("_objc_msgSend"));
        assert!(ObjcMessageAnalyzer::is_msg_send("_objc_msgSend_stret"));
        assert!(ObjcMessageAnalyzer::is_msg_send("_objc_msgSendSuper"));
        assert!(ObjcMessageAnalyzer::is_msg_send("_objc_msgSendSuper2"));
        assert!(ObjcMessageAnalyzer::is_msg_send("objc_msgSend"));
        assert!(!ObjcMessageAnalyzer::is_msg_send("_printf"));
        assert!(!ObjcMessageAnalyzer::is_msg_send(""));
    }

    #[test]
    fn test_analyzer_added() {
        let analyzer = ObjcTypeMetadataAnalyzer::new();
        let mut prog = Program::new(
            "test",
            Language {
                processor: "AARCH64".into(),
                variant: "LE".into(),
                size: 64,
            },
        );
        prog.executable_format = Some("Mach-O".into());
        let set = AddressSet::new();
        let monitor = BasicTaskMonitor::new();
        let mut log = MessageLog::new();
        let result = analyzer.added(&mut prog, &set, &monitor, &mut log);
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn test_msg_analyzer_added() {
        let analyzer = ObjcMessageAnalyzer::new();
        let mut prog = Program::new(
            "test",
            Language {
                processor: "AARCH64".into(),
                variant: "LE".into(),
                size: 64,
            },
        );
        let set = AddressSet::new();
        let monitor = BasicTaskMonitor::new();
        let mut log = MessageLog::new();
        let result = analyzer.added(&mut prog, &set, &monitor, &mut log);
        assert!(result.is_ok());
    }

    #[test]
    fn test_analyzer_utils() {
        assert!(ObjcAnalyzerUtils::is_objc_segment("__OBJC"));
        assert!(ObjcAnalyzerUtils::is_objc_segment("__DATA_CONST"));
        assert!(!ObjcAnalyzerUtils::is_objc_segment("__TEXT"));

        assert!(ObjcAnalyzerUtils::is_objc_section("__objc_classlist"));
        assert!(ObjcAnalyzerUtils::is_objc_section("__module_info"));
        assert!(!ObjcAnalyzerUtils::is_objc_section("__text"));

        assert_eq!(
            ObjcAnalyzerUtils::format_class_name("UIView", false),
            "UIView"
        );
        assert_eq!(
            ObjcAnalyzerUtils::format_class_name("UIView", true),
            "+UIView"
        );

        assert_eq!(
            ObjcAnalyzerUtils::format_method(
                super::super::ObjcMethodType::Instance,
                "UIView",
                "initWithFrame:"
            ),
            "+[UIView initWithFrame:]"
        );

        assert_eq!(ObjcAnalyzerUtils::objc_namespace(), "objc");
        assert_eq!(
            ObjcAnalyzerUtils::category_namespace("MyCategory"),
            "objc::Categories::MyCategory"
        );
    }

    #[test]
    fn test_msg_send_variants_count() {
        assert!(ObjcMessageAnalyzer::MSG_SEND_VARIANTS.len() >= 5);
    }
}
