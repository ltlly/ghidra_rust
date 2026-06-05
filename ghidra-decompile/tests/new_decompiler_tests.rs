//! Integration tests for newly ported decompiler modules.
//!
//! Tests the validator expansion, compilation info, find dialog extension,
//! and clang bit-field token types.

use ghidra_decompile::decompiler::clang_bitfield_token::{ClangBitFieldToken, SyntaxType};
use ghidra_decompile::decompiler::compilation_info::{CallingConvention, CompilationInfo};
use ghidra_decompile::decompiler::decompiler_find_dialog_ext::{
    DecompilerFindMatch, DecompilerFindOptions, DecompilerFindResults, DecompilerSearchMode,
};
use ghidra_decompile::validator::decompiler_validator::{
    AggregateValidator, CCodeValidator, CallConventionValidator, DecompilerParameterIdValidator,
    ParameterInfo, SyntaxTreeValidator,
};
use ghidra_decompile::validator::{run_all_validators, ConsistencyValidator, ValidationResult};

// ===========================================================================
// ClangBitFieldToken tests
// ===========================================================================

#[test]
fn test_bitfield_token_basic() {
    let bf = ClangBitFieldToken::new("flags", 0, 7, "unsigned char", 8, 0x1000);
    assert_eq!(bf.bit_size(), 8);
    assert_eq!(bf.bit_mask(), 0xFF);
}

#[test]
fn test_bitfield_token_middle_bits() {
    let bf = ClangBitFieldToken::new("mode", 8, 11, "unsigned int", 32, 0x2000);
    assert_eq!(bf.bit_size(), 4);
    assert_eq!(bf.bit_mask(), 0xF00);
}

#[test]
fn test_bitfield_token_extract() {
    let bf = ClangBitFieldToken::new("val", 4, 7, "unsigned char", 8, 0);
    assert_eq!(bf.extract_value(0x5A), 0x5);
    assert_eq!(bf.extract_value(0xFF), 0xF);
}

#[test]
fn test_bitfield_token_insert() {
    let bf = ClangBitFieldToken::new("val", 4, 7, "unsigned char", 8, 0);
    let result = bf.insert_value(0x00, 0xA);
    assert_eq!(result, 0xA0);
    // Insert preserves other bits
    let result2 = bf.insert_value(0x0F, 0xA);
    assert_eq!(result2, 0xAF);
}

#[test]
fn test_bitfield_syntax_type_variants() {
    assert_eq!(SyntaxType::Default, SyntaxType::Default);
    assert_ne!(SyntaxType::Keyword, SyntaxType::Variable);
}

#[test]
fn test_bitfield_full_width() {
    let bf = ClangBitFieldToken::new("all", 0, 63, "unsigned long", 64, 0);
    assert_eq!(bf.bit_mask(), u64::MAX);
    assert_eq!(bf.bit_size(), 64);
}

// ===========================================================================
// CompilationInfo tests
// ===========================================================================

#[test]
fn test_compilation_info_builder_chain() {
    let info = CompilationInfo::new("gcc", "ARM")
        .with_calling_convention("aapcs")
        .with_source_language("c")
        .with_target_os("linux")
        .with_optimization_level(2)
        .with_stack_protection(true)
        .with_debug_info(true)
        .with_pic(true);

    assert_eq!(info.compiler_id, "gcc");
    assert_eq!(info.architecture, "ARM");
    assert!(info.pic);
    assert!(info.stack_protection);
    assert!(info.has_debug_info);
    assert_eq!(info.optimization_level, 2);
}

#[test]
fn test_compilation_info_presets() {
    let gcc = CompilationInfo::gcc_linux_x86_64();
    assert!(gcc.is_64_bit());
    assert!(!gcc.is_cpp());

    let msvc = CompilationInfo::msvc_windows_x64();
    assert_eq!(msvc.calling_convention, "fastcall");

    let clang = CompilationInfo::clang_macos_arm64();
    assert!(clang.is_64_bit());
    assert_eq!(clang.target_os, "macos");
}

#[test]
fn test_compilation_info_serialization_roundtrip() {
    let info = CompilationInfo::new("rustc", "x86_64")
        .with_source_language("rust")
        .with_target_os("linux");

    let json = serde_json::to_string(&info).unwrap();
    let back: CompilationInfo = serde_json::from_str(&json).unwrap();
    assert!(back.is_rust());
    assert!(!back.is_cpp());
    assert_eq!(back.target_os, "linux");
}

#[test]
fn test_calling_convention_properties() {
    assert!(CallingConvention::CDecl.is_stack_based());
    assert!(CallingConvention::StdCall.is_stack_based());
    assert!(!CallingConvention::SystemV.is_stack_based());
    assert!(CallingConvention::SystemV.is_register_based());
    assert!(CallingConvention::FastCall.is_register_based());
    assert!(CallingConvention::ArmAapcs.is_register_based());
}

#[test]
fn test_calling_convention_from_name_roundtrip() {
    let conventions = [
        CallingConvention::CDecl,
        CallingConvention::StdCall,
        CallingConvention::FastCall,
        CallingConvention::SystemV,
        CallingConvention::MicrosoftX64,
        CallingConvention::ArmAapcs,
    ];
    for cc in &conventions {
        let name = cc.name();
        let back = CallingConvention::from_name(name);
        assert_eq!(*cc, back, "Roundtrip failed for {}", name);
    }
}

// ===========================================================================
// DecompilerFindOptions tests
// ===========================================================================

#[test]
fn test_find_options_plain_text() {
    let opts = DecompilerFindOptions::new("return");
    assert!(opts.matches("    return 0;"));
    assert!(!opts.matches("    break;"));
}

#[test]
fn test_find_options_case_insensitive() {
    let opts = DecompilerFindOptions::new("RETURN").case_sensitive(false);
    assert!(opts.matches("return 0;"));
    assert!(opts.matches("RETURN 0;"));
}

#[test]
fn test_find_options_regex() {
    let opts = DecompilerFindOptions::new(r"int\s+\w+\(").regex(true);
    assert!(opts.matches("int main("));
    assert!(opts.matches("int foo_bar("));
    assert!(!opts.matches("void main("));
}

#[test]
fn test_find_match_coordinates() {
    let m = DecompilerFindMatch::new(
        10,
        5,
        "main",
        DecompilerSearchMode::DecompiledCode,
    );
    assert_eq!(m.line, 10);
    assert_eq!(m.column, 5);
    assert_eq!(m.end_column(), 9);
    assert_eq!(m.text, "main");
}

#[test]
fn test_find_results_navigation() {
    let mut results = DecompilerFindResults::new();
    assert_eq!(results.match_count(), 0);
    assert!(results.current_match().is_none());

    results.add_match(DecompilerFindMatch::new(0, 0, "a", DecompilerSearchMode::DecompiledCode));
    results.add_match(DecompilerFindMatch::new(1, 0, "b", DecompilerSearchMode::DecompiledCode));
    results.add_match(DecompilerFindMatch::new(2, 0, "c", DecompilerSearchMode::DecompiledCode));

    assert_eq!(results.match_count(), 3);
    assert_eq!(results.current_match().unwrap().text, "a");

    results.next();
    assert_eq!(results.current_match().unwrap().text, "b");

    results.next();
    assert_eq!(results.current_match().unwrap().text, "c");

    results.next(); // wraps to first
    assert_eq!(results.current_match().unwrap().text, "a");

    results.previous(); // wraps to last
    assert_eq!(results.current_match().unwrap().text, "c");
}

#[test]
fn test_search_mode_variants() {
    let modes = [
        DecompilerSearchMode::DecompiledCode,
        DecompilerSearchMode::FunctionName,
        DecompilerSearchMode::VariableName,
        DecompilerSearchMode::Comment,
        DecompilerSearchMode::TypeName,
    ];
    assert_eq!(modes.len(), 5);
    assert_eq!(
        DecompilerSearchMode::default(),
        DecompilerSearchMode::DecompiledCode
    );
}

// ===========================================================================
// Validator tests
// ===========================================================================

#[test]
fn test_parameter_id_validator_with_real_params() {
    let validator = DecompilerParameterIdValidator::new()
        .with_param_range(2, 5)
        .with_stack_warnings(true);

    let params = vec![
        ParameterInfo::new("argc", "int", "RDI", 0),
        ParameterInfo::new("argv", "char**", "RSI", 1),
        ParameterInfo::new("envp", "char**", "RDX", 2),
    ];

    let result = validator.validate_params(&params);
    assert!(result.passed, "Expected pass: {:?}", result.errors);
    assert!(result.warnings.is_empty()); // All register-based
}

#[test]
fn test_parameter_id_validator_stack_param_warning() {
    let validator = DecompilerParameterIdValidator::new()
        .with_stack_warnings(true);

    let params = vec![
        ParameterInfo::new("a", "int", "RDI", 0),
        ParameterInfo::new("b", "long", "Stack[0x8]", 1),
    ];

    let result = validator.validate_params(&params);
    assert!(result.passed);
    assert!(!result.warnings.is_empty());
    assert!(result.warnings[0].contains("stack"));
}

#[test]
fn test_c_code_validator_various_inputs() {
    let validator = CCodeValidator::new();

    // Valid C code
    let result = validator.validate_source("int main() {\n  return 0;\n}\n");
    assert!(result.passed);

    // Empty code
    let result = validator.validate_source("");
    assert!(!result.passed);

    // Unmatched braces
    let result = validator.validate_source("int main() {");
    assert!(!result.passed);

    // Unmatched parentheses
    let result = validator.validate_source("int main( {");
    assert!(!result.passed);

    // Undefined types (warning, not error)
    let result = validator.validate_source("undefined foo() { return 0; }");
    assert!(result.passed);
    assert!(!result.warnings.is_empty());
}

#[test]
fn test_syntax_tree_validator_various_cases() {
    let validator = SyntaxTreeValidator::new();

    // Normal tree
    let result = validator.validate_tree(50, 10, true);
    assert!(result.passed);

    // No root
    let result = validator.validate_tree(50, 10, false);
    assert!(!result.passed);

    // Empty tree
    let result = validator.validate_tree(0, 0, true);
    assert!(!result.passed);

    // Very deep tree (warning)
    let result = validator.validate_tree(100, 600, true);
    assert!(result.passed);
    assert!(!result.warnings.is_empty());
}

#[test]
fn test_aggregate_validator() {
    let mut agg = AggregateValidator::new();
    agg.add(Box::new(CCodeValidator::new()));
    agg.add(Box::new(SyntaxTreeValidator::new()));
    agg.add(Box::new(CallConventionValidator::new()));

    let results = agg.validate_all(0x1000);
    assert_eq!(results.len(), 3);
    assert!(results.iter().all(|r| r.passed));
}

#[test]
fn test_run_all_validators_expanded() {
    let validators: Vec<&dyn ghidra_decompile::validator::DecompilerValidator> = vec![
        &ConsistencyValidator,
        &ghidra_decompile::validator::DataTypeValidator,
        &ghidra_decompile::validator::VariableReferenceValidator,
    ];

    let results = run_all_validators(&validators, 0x401000);
    assert_eq!(results.len(), 3);
    assert!(results.iter().all(|r| r.passed));

    // Check that all have correct validator names
    for result in &results {
        assert!(!result.validator_name.is_empty());
    }
}

#[test]
fn test_validation_result_chaining() {
    let result = ValidationResult::pass("Test")
        .with_warning("warning 1")
        .with_warning("warning 2");
    assert!(result.passed);
    assert_eq!(result.warnings.len(), 2);
    assert!(result.errors.is_empty());
}
