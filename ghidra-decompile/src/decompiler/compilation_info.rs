//! Compilation information for decompiled functions.
//!
//! Port of compilation-related types from Ghidra's decompiler framework.
//! Captures metadata about how a function was compiled, which the decompiler
//! uses for accurate recovery.

use serde::{Deserialize, Serialize};

/// Information about the compiler and compilation environment.
///
/// Port of compiler metadata that Ghidra tracks per-function.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompilationInfo {
    /// The compiler ID (e.g., "gcc", "msvc", "clang").
    pub compiler_id: String,
    /// The target architecture (e.g., "x86", "x86_64", "ARM").
    pub architecture: String,
    /// Compiler version string (e.g., "gcc 11.2.0").
    pub compiler_version: String,
    /// The calling convention used (e.g., "cdecl", "stdcall", "fastcall").
    pub calling_convention: String,
    /// Whether position-independent code was used.
    pub pic: bool,
    /// Whether stack protection (-fstack-protector) was enabled.
    pub stack_protection: bool,
    /// Optimization level (0-3, or -1 if unknown).
    pub optimization_level: i8,
    /// Whether debug info was present.
    pub has_debug_info: bool,
    /// The source language (e.g., "c", "c++", "rust", "go").
    pub source_language: String,
    /// Target OS (e.g., "linux", "windows", "macos").
    pub target_os: String,
    /// Target ABI (e.g., "SystemV", "Windows").
    pub target_abi: String,
}

impl Default for CompilationInfo {
    fn default() -> Self {
        Self {
            compiler_id: String::new(),
            architecture: String::new(),
            compiler_version: String::new(),
            calling_convention: String::new(),
            pic: false,
            stack_protection: false,
            optimization_level: -1,
            has_debug_info: false,
            source_language: String::new(),
            target_os: String::new(),
            target_abi: String::new(),
        }
    }
}

impl CompilationInfo {
    /// Create a new CompilationInfo with minimal fields.
    pub fn new(
        compiler_id: impl Into<String>,
        architecture: impl Into<String>,
    ) -> Self {
        Self {
            compiler_id: compiler_id.into(),
            architecture: architecture.into(),
            ..Default::default()
        }
    }

    /// Set the calling convention.
    pub fn with_calling_convention(mut self, cc: impl Into<String>) -> Self {
        self.calling_convention = cc.into();
        self
    }

    /// Set the optimization level.
    pub fn with_optimization_level(mut self, level: i8) -> Self {
        self.optimization_level = level;
        self
    }

    /// Set the source language.
    pub fn with_source_language(mut self, lang: impl Into<String>) -> Self {
        self.source_language = lang.into();
        self
    }

    /// Set the target OS.
    pub fn with_target_os(mut self, os: impl Into<String>) -> Self {
        self.target_os = os.into();
        self
    }

    /// Set whether PIC is used.
    pub fn with_pic(mut self, pic: bool) -> Self {
        self.pic = pic;
        self
    }

    /// Set whether stack protection is used.
    pub fn with_stack_protection(mut self, sp: bool) -> Self {
        self.stack_protection = sp;
        self
    }

    /// Set whether debug info is present.
    pub fn with_debug_info(mut self, debug: bool) -> Self {
        self.has_debug_info = debug;
        self
    }

    /// Whether the source language is C++.
    pub fn is_cpp(&self) -> bool {
        self.source_language == "c++" || self.source_language == "cpp"
    }

    /// Whether the source language is Rust.
    pub fn is_rust(&self) -> bool {
        self.source_language == "rust"
    }

    /// Whether the target is 64-bit.
    pub fn is_64_bit(&self) -> bool {
        self.architecture.contains("64")
            || self.architecture.contains("x86_64")
            || self.architecture.contains("aarch64")
    }

    /// Create a typical GCC/Linux x86_64 compilation info.
    pub fn gcc_linux_x86_64() -> Self {
        Self::new("gcc", "x86_64")
            .with_calling_convention("SystemV")
            .with_source_language("c")
            .with_target_os("linux")
    }

    /// Create a typical MSVC/Windows x64 compilation info.
    pub fn msvc_windows_x64() -> Self {
        Self::new("msvc", "x86_64")
            .with_calling_convention("fastcall")
            .with_source_language("c")
            .with_target_os("windows")
    }

    /// Create a typical Clang/macOS ARM64 compilation info.
    pub fn clang_macos_arm64() -> Self {
        Self::new("clang", "aarch64")
            .with_calling_convention("SystemV")
            .with_source_language("c")
            .with_target_os("macos")
    }
}

/// The calling convention strategy used by a function.
///
/// Port of Ghidra's calling convention metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CallingConvention {
    /// C calling convention (x86).
    CDecl,
    /// Standard calling convention (x86).
    StdCall,
    /// Fast calling convention (x86).
    FastCall,
    /// System V ABI (x86_64/Linux/macOS).
    SystemV,
    /// Microsoft x64 calling convention.
    MicrosoftX64,
    /// ARM AAPCS.
    ArmAapcs,
    /// ARM AAPCS VFP.
    ArmAapcsVfp,
    /// MIPS o32.
    MipsO32,
    /// PowerPC System V.
    PpcSysV,
    /// Compiler-managed (detected automatically).
    CompilerManaged,
    /// Unknown or custom convention.
    Unknown,
}

impl CallingConvention {
    /// Get the name of this calling convention.
    pub fn name(&self) -> &'static str {
        match self {
            CallingConvention::CDecl => "cdecl",
            CallingConvention::StdCall => "stdcall",
            CallingConvention::FastCall => "fastcall",
            CallingConvention::SystemV => "SystemV",
            CallingConvention::MicrosoftX64 => "MicrosoftX64",
            CallingConvention::ArmAapcs => "aapcs",
            CallingConvention::ArmAapcsVfp => "aapcs-vfp",
            CallingConvention::MipsO32 => "o32",
            CallingConvention::PpcSysV => "ppc-sysv",
            CallingConvention::CompilerManaged => "__compiler",
            CallingConvention::Unknown => "unknown",
        }
    }

    /// Parse a calling convention from its name.
    pub fn from_name(name: &str) -> Self {
        match name.to_lowercase().as_str() {
            "cdecl" | "c" => CallingConvention::CDecl,
            "stdcall" => CallingConvention::StdCall,
            "fastcall" => CallingConvention::FastCall,
            "systemv" | "sysv" | "system_v" => CallingConvention::SystemV,
            "microsoftx64" | "ms_x64" => CallingConvention::MicrosoftX64,
            "aapcs" => CallingConvention::ArmAapcs,
            "aapcs-vfp" | "aapcs_vfp" => CallingConvention::ArmAapcsVfp,
            "o32" | "mipso32" => CallingConvention::MipsO32,
            "ppc-sysv" | "ppcsysv" => CallingConvention::PpcSysV,
            "__compiler" | "compilermanaged" => CallingConvention::CompilerManaged,
            _ => CallingConvention::Unknown,
        }
    }

    /// Whether this convention passes arguments on the stack.
    pub fn is_stack_based(&self) -> bool {
        matches!(self, CallingConvention::CDecl | CallingConvention::StdCall)
    }

    /// Whether this convention passes arguments in registers.
    pub fn is_register_based(&self) -> bool {
        matches!(
            self,
            CallingConvention::FastCall
                | CallingConvention::SystemV
                | CallingConvention::MicrosoftX64
                | CallingConvention::ArmAapcs
                | CallingConvention::ArmAapcsVfp
        )
    }
}

impl Default for CallingConvention {
    fn default() -> Self {
        Self::Unknown
    }
}

impl std::fmt::Display for CallingConvention {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compilation_info_default() {
        let info = CompilationInfo::default();
        assert!(info.compiler_id.is_empty());
        assert!(!info.is_cpp());
        assert!(!info.is_rust());
    }

    #[test]
    fn test_compilation_info_builder() {
        let info = CompilationInfo::new("gcc", "x86_64")
            .with_calling_convention("SystemV")
            .with_source_language("c++")
            .with_optimization_level(2)
            .with_target_os("linux")
            .with_pic(true);

        assert_eq!(info.compiler_id, "gcc");
        assert_eq!(info.architecture, "x86_64");
        assert!(info.is_cpp());
        assert!(info.is_64_bit());
        assert!(info.pic);
        assert_eq!(info.optimization_level, 2);
    }

    #[test]
    fn test_compilation_info_presets() {
        let gcc = CompilationInfo::gcc_linux_x86_64();
        assert_eq!(gcc.compiler_id, "gcc");
        assert_eq!(gcc.target_os, "linux");
        assert!(gcc.is_64_bit());

        let msvc = CompilationInfo::msvc_windows_x64();
        assert_eq!(msvc.compiler_id, "msvc");
        assert_eq!(msvc.target_os, "windows");

        let clang = CompilationInfo::clang_macos_arm64();
        assert_eq!(clang.compiler_id, "clang");
        assert!(clang.is_64_bit());
    }

    #[test]
    fn test_compilation_info_rust() {
        let info = CompilationInfo::new("rustc", "x86_64")
            .with_source_language("rust");
        assert!(info.is_rust());
        assert!(!info.is_cpp());
    }

    #[test]
    fn test_calling_convention_names() {
        assert_eq!(CallingConvention::CDecl.name(), "cdecl");
        assert_eq!(CallingConvention::SystemV.name(), "SystemV");
        assert_eq!(CallingConvention::MicrosoftX64.name(), "MicrosoftX64");
    }

    #[test]
    fn test_calling_convention_from_name() {
        assert_eq!(CallingConvention::from_name("cdecl"), CallingConvention::CDecl);
        assert_eq!(CallingConvention::from_name("SystemV"), CallingConvention::SystemV);
        assert_eq!(CallingConvention::from_name("stdcall"), CallingConvention::StdCall);
        assert_eq!(CallingConvention::from_name("unknown_cc"), CallingConvention::Unknown);
    }

    #[test]
    fn test_calling_convention_properties() {
        assert!(CallingConvention::CDecl.is_stack_based());
        assert!(!CallingConvention::CDecl.is_register_based());
        assert!(CallingConvention::SystemV.is_register_based());
        assert!(!CallingConvention::SystemV.is_stack_based());
    }

    #[test]
    fn test_calling_convention_display() {
        assert_eq!(format!("{}", CallingConvention::FastCall), "fastcall");
    }

    #[test]
    fn test_compilation_info_serialization() {
        let info = CompilationInfo::gcc_linux_x86_64();
        let json = serde_json::to_string(&info).unwrap();
        let back: CompilationInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(back.compiler_id, "gcc");
        assert_eq!(back.target_os, "linux");
    }
}
