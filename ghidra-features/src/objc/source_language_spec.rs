//! Objective-C source language specification extensions.
//!
//! Ported from Ghidra's `ObjcSourceLanguageSpecExtension`, `ObjcSourceLanguage`,
//! and `MachoObjcSourceLanguage` Java classes.
//!
//! These provide source language identification and spec extension rules
//! for Objective-C programs in Ghidra.

/// Objective-C source language specification extension.
///
/// Provides calling convention and register mapping rules for
/// Objective-C message send stubs.
///
/// Corresponds to Java's `ObjcSourceLanguageSpecExtension`.
#[derive(Debug, Clone)]
pub struct ObjcSourceLanguageSpecExtension {
    /// The compatible source language ID.
    pub source_language_id: String,
    /// The name of the `__objc_msgSend_stub` calling convention.
    pub msgsend_stub_convention: String,
    /// Extension rules loaded from configuration.
    pub rules: Vec<SpecExtensionRule>,
}

/// A specification extension rule.
///
/// Defines how to map a calling convention or register set for
/// a specific Objective-C pattern.
#[derive(Debug, Clone)]
pub struct SpecExtensionRule {
    /// The rule name.
    pub name: String,
    /// The calling convention this rule applies to.
    pub calling_convention: String,
    /// The description of the rule.
    pub description: String,
}

impl ObjcSourceLanguageSpecExtension {
    /// The Objective-C message send stub calling convention name.
    pub const OBJC_MSGSEND_STUBS: &'static str = "__objc_msgSend_stub";

    /// The compatible source language identifier.
    pub const OBJC_LANGUAGE_ID: &'static str = "Objective-C";

    /// Create a new spec extension.
    pub fn new() -> Self {
        Self {
            source_language_id: Self::OBJC_LANGUAGE_ID.to_string(),
            msgsend_stub_convention: Self::OBJC_MSGSEND_STUBS.to_string(),
            rules: Vec::new(),
        }
    }

    /// Get the compatible source language ID.
    pub fn get_compatible_source_language(&self) -> &str {
        &self.source_language_id
    }

    /// Get the spec extension rules.
    pub fn get_spec_extension_rules(&self) -> &[SpecExtensionRule] {
        &self.rules
    }

    /// Add a rule.
    pub fn add_rule(&mut self, rule: SpecExtensionRule) {
        self.rules.push(rule);
    }

    /// Load default Objective-C spec extension rules.
    ///
    /// In Ghidra, these would be loaded from `extensions.json` in the module's data directory.
    pub fn load_default_rules(&mut self) {
        self.rules.push(SpecExtensionRule {
            name: "objc_msgSend_stub".to_string(),
            calling_convention: Self::OBJC_MSGSEND_STUBS.to_string(),
            description: "Calling convention for Objective-C message send stubs. \
                          The receiver is in x0, selector in x1, and remaining arguments \
                          in x2-x7 (ARM64)."
                .to_string(),
        });

        self.rules.push(SpecExtensionRule {
            name: "objc_msgSend_stret_stub".to_string(),
            calling_convention: "__objc_msgSend_stret_stub".to_string(),
            description: "Calling convention for Objective-C stret message send stubs. \
                          The struct return buffer pointer is in x8, receiver in x0, \
                          selector in x1 (ARM64)."
                .to_string(),
        });

        self.rules.push(SpecExtensionRule {
            name: "objc_msgSendSuper_stub".to_string(),
            calling_convention: "__objc_msgSendSuper_stub".to_string(),
            description: "Calling convention for Objective-C super message send stubs."
                .to_string(),
        });
    }
}

impl Default for ObjcSourceLanguageSpecExtension {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// MachoObjcSourceLanguage -- Mach-O specific Objective-C language
// ============================================================================

/// A Mach-O specific Objective-C source language.
///
/// Identifies Objective-C programs in Mach-O format with specific
/// ABI characteristics.
///
/// Corresponds to Java's `MachoObjcSourceLanguage`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachoObjcSourceLanguage {
    /// The language identifier.
    pub id: String,
    /// The processor name (e.g., "AARCH64", "x86").
    pub processor: String,
    /// Whether this is a 64-bit language.
    pub is_64bit: bool,
}

impl MachoObjcSourceLanguage {
    /// The Mach-O Objective-C language ID prefix.
    pub const MACHO_OBJC_PREFIX: &'static str = "Mach-O:ObjC";

    /// Create a new Mach-O Objective-C source language for ARM64.
    pub fn arm64() -> Self {
        Self {
            id: format!("{}:AARCH64", Self::MACHO_OBJC_PREFIX),
            processor: "AARCH64".to_string(),
            is_64bit: true,
        }
    }

    /// Create a new Mach-O Objective-C source language for x86-64.
    pub fn x86_64() -> Self {
        Self {
            id: format!("{}:x86-64", Self::MACHO_OBJC_PREFIX),
            processor: "x86".to_string(),
            is_64bit: true,
        }
    }

    /// Create a new Mach-O Objective-C source language for ARM32.
    pub fn arm32() -> Self {
        Self {
            id: format!("{}:ARM", Self::MACHO_OBJC_PREFIX),
            processor: "ARM".to_string(),
            is_64bit: false,
        }
    }

    /// Create a new Mach-O Objective-C source language for x86-32.
    pub fn x86_32() -> Self {
        Self {
            id: format!("{}:x86", Self::MACHO_OBJC_PREFIX),
            processor: "x86".to_string(),
            is_64bit: false,
        }
    }

    /// The language identifier.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// The processor name.
    pub fn processor(&self) -> &str {
        &self.processor
    }

    /// Whether this is a 64-bit language.
    pub fn is_64bit(&self) -> bool {
        self.is_64bit
    }

    /// Get the pointer size in bytes.
    pub fn pointer_size(&self) -> usize {
        if self.is_64bit { 8 } else { 4 }
    }
}

// ============================================================================
// ObjcCallingConvention -- ObjC-specific calling conventions
// ============================================================================

/// Objective-C calling conventions.
///
/// These describe how arguments are passed in Objective-C method calls
/// for different architectures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ObjcCallingConvention {
    /// Standard Objective-C message send (ARM64).
    ///
    /// x0 = receiver, x1 = selector, x2-x7 = arguments.
    MsgSend,
    /// Stret variant (ARM64).
    ///
    /// x8 = struct return buffer, x0 = receiver, x1 = selector.
    MsgSendStret,
    /// Super message send (ARM64).
    MsgSendSuper,
    /// Super stret (ARM64).
    MsgSendSuperStret,
    /// Standard Objective-C message send (x86-64).
    ///
    /// rdi = receiver, rsi = selector, rdx, rcx, r8, r9 = arguments.
    MsgSendX86_64,
    /// Stret variant (x86-64).
    ///
    /// rax = struct return buffer, rdi = receiver, rsi = selector.
    MsgSendStretX86_64,
}

impl ObjcCallingConvention {
    /// Get the name of this calling convention.
    pub fn name(&self) -> &'static str {
        match self {
            Self::MsgSend => "_objc_msgSend",
            Self::MsgSendStret => "_objc_msgSend_stret",
            Self::MsgSendSuper => "_objc_msgSendSuper",
            Self::MsgSendSuperStret => "_objc_msgSendSuper_stret",
            Self::MsgSendX86_64 => "_objc_msgSend",
            Self::MsgSendStretX86_64 => "_objc_msgSend_stret",
        }
    }

    /// Get the register containing the receiver.
    pub fn receiver_register(&self, is_64bit: bool) -> &'static str {
        match self {
            Self::MsgSend | Self::MsgSendStret | Self::MsgSendSuper | Self::MsgSendSuperStret => {
                "x0"
            }
            Self::MsgSendX86_64 | Self::MsgSendStretX86_64 => "rdi",
        }
    }

    /// Get the register containing the selector.
    pub fn selector_register(&self, is_64bit: bool) -> &'static str {
        match self {
            Self::MsgSend | Self::MsgSendStret | Self::MsgSendSuper | Self::MsgSendSuperStret => {
                "x1"
            }
            Self::MsgSendX86_64 | Self::MsgSendStretX86_64 => "rsi",
        }
    }

    /// Get the first argument register.
    pub fn first_arg_register(&self) -> &'static str {
        match self {
            Self::MsgSend | Self::MsgSendStret | Self::MsgSendSuper | Self::MsgSendSuperStret => {
                "x2"
            }
            Self::MsgSendX86_64 | Self::MsgSendStretX86_64 => "rdx",
        }
    }

    /// Whether this convention uses a struct return buffer.
    pub fn uses_stret(&self) -> bool {
        matches!(
            self,
            Self::MsgSendStret
                | Self::MsgSendSuperStret
                | Self::MsgSendStretX86_64
        )
    }

    /// Get the struct return buffer register (if applicable).
    pub fn stret_register(&self) -> Option<&'static str> {
        match self {
            Self::MsgSendStret | Self::MsgSendSuperStret => Some("x8"),
            Self::MsgSendStretX86_64 => Some("rax"),
            _ => None,
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_spec_extension_new() {
        let ext = ObjcSourceLanguageSpecExtension::new();
        assert_eq!(
            ext.get_compatible_source_language(),
            ObjcSourceLanguageSpecExtension::OBJC_LANGUAGE_ID
        );
        assert_eq!(
            ext.msgsend_stub_convention,
            ObjcSourceLanguageSpecExtension::OBJC_MSGSEND_STUBS
        );
        assert!(ext.get_spec_extension_rules().is_empty());
    }

    #[test]
    fn test_spec_extension_default_rules() {
        let mut ext = ObjcSourceLanguageSpecExtension::new();
        ext.load_default_rules();
        assert_eq!(ext.get_spec_extension_rules().len(), 3);
        assert_eq!(ext.get_spec_extension_rules()[0].name, "objc_msgSend_stub");
    }

    #[test]
    fn test_spec_extension_add_rule() {
        let mut ext = ObjcSourceLanguageSpecExtension::new();
        ext.add_rule(SpecExtensionRule {
            name: "test".to_string(),
            calling_convention: "test_cc".to_string(),
            description: "test rule".to_string(),
        });
        assert_eq!(ext.get_spec_extension_rules().len(), 1);
    }

    #[test]
    fn test_macho_objc_source_language_arm64() {
        let lang = MachoObjcSourceLanguage::arm64();
        assert_eq!(lang.processor(), "AARCH64");
        assert!(lang.is_64bit());
        assert_eq!(lang.pointer_size(), 8);
        assert!(lang.id().contains("AARCH64"));
    }

    #[test]
    fn test_macho_objc_source_language_x86_64() {
        let lang = MachoObjcSourceLanguage::x86_64();
        assert_eq!(lang.processor(), "x86");
        assert!(lang.is_64bit());
        assert_eq!(lang.pointer_size(), 8);
    }

    #[test]
    fn test_macho_objc_source_language_arm32() {
        let lang = MachoObjcSourceLanguage::arm32();
        assert_eq!(lang.processor(), "ARM");
        assert!(!lang.is_64bit());
        assert_eq!(lang.pointer_size(), 4);
    }

    #[test]
    fn test_macho_objc_source_language_x86_32() {
        let lang = MachoObjcSourceLanguage::x86_32();
        assert_eq!(lang.processor(), "x86");
        assert!(!lang.is_64bit());
        assert_eq!(lang.pointer_size(), 4);
    }

    #[test]
    fn test_calling_convention_names() {
        assert_eq!(ObjcCallingConvention::MsgSend.name(), "_objc_msgSend");
        assert_eq!(
            ObjcCallingConvention::MsgSendStret.name(),
            "_objc_msgSend_stret"
        );
        assert_eq!(
            ObjcCallingConvention::MsgSendSuper.name(),
            "_objc_msgSendSuper"
        );
    }

    #[test]
    fn test_calling_convention_registers() {
        let cc = ObjcCallingConvention::MsgSend;
        assert_eq!(cc.receiver_register(true), "x0");
        assert_eq!(cc.selector_register(true), "x1");
        assert_eq!(cc.first_arg_register(), "x2");
        assert!(!cc.uses_stret());
        assert!(cc.stret_register().is_none());

        let stret = ObjcCallingConvention::MsgSendStret;
        assert!(stret.uses_stret());
        assert_eq!(stret.stret_register(), Some("x8"));
    }

    #[test]
    fn test_calling_convention_x86_64() {
        let cc = ObjcCallingConvention::MsgSendX86_64;
        assert_eq!(cc.receiver_register(true), "rdi");
        assert_eq!(cc.selector_register(true), "rsi");
        assert_eq!(cc.first_arg_register(), "rdx");

        let stret = ObjcCallingConvention::MsgSendStretX86_64;
        assert!(stret.uses_stret());
        assert_eq!(stret.stret_register(), Some("rax"));
    }
}
