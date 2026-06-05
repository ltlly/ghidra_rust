//! Integration tests for the Decompiler module ported from Ghidra's Java
//! Features/Decompiler package.

use ghidra_decompile::decompiler::*;
use ghidra_decompile::validator as top_validator;

// ============================================================================
// Clang AST types
// ============================================================================

#[test]
fn test_clang_node_arena() {
    let arena = ClangNodeArena::new();
    let _ = arena;
}

#[test]
fn test_syntax_type_variants() {
    let t = SyntaxType::from_i32(0);
    assert_eq!(t, SyntaxType::Keyword);
    let t = SyntaxType::from_i32(99);
    assert_eq!(t, SyntaxType::Default);
}

// ============================================================================
// DecompileOptions
// ============================================================================

#[test]
fn test_decompile_options_default() {
    let opts = DecompileOptions::default();
    let _ = opts;
}

// ============================================================================
// DecompInterface
// ============================================================================

#[test]
fn test_decomp_interface_new() {
    let iface = DecompInterface::new();
    let _ = iface;
}

// ============================================================================
// DecompileResults
// ============================================================================

#[test]
fn test_decompile_results_types() {
    let arena = ClangNodeArena::new();
    let mut arena2 = ClangNodeArena::new();
    let root = arena2.alloc(ClangNodeKind::TokenGroup(ClangTokenGroupData::default()));
    let results = DecompileResults::success(0x1000, Some("main".to_string()), root, arena2);
    assert!(results.decompile_completed());
    assert_eq!(results.function_entry, 0x1000);
}

// ============================================================================
// DecompileException
// ============================================================================

#[test]
fn test_decompile_exception() {
    let e = DecompileException::new("process", "timeout");
    assert!(format!("{}", e).contains("timeout"));
}

// ============================================================================
// Parallel decompilation
// ============================================================================

#[test]
fn test_parallel_basic() {
    let functions = vec![
        DecompilerMapFunction::new(0x1000),
        DecompilerMapFunction::new(0x2000),
    ];
    let results = ParallelDecompiler::decompile_batch(&functions, |f| {
        Ok(format!("fn_{}", f.entry_point))
    });
    assert_eq!(results.len(), 2);
}

// ============================================================================
// Validators (from top-level validator module)
// ============================================================================

#[test]
fn test_validator_result_pass() {
    let result = top_validator::ValidationResult::pass("TestValidator");
    assert!(result.passed);
    assert!(result.errors.is_empty());
}

#[test]
fn test_validator_result_fail() {
    let result = top_validator::ValidationResult::fail("TestValidator", "type mismatch");
    assert!(!result.passed);
    assert_eq!(result.errors.len(), 1);
}

// ============================================================================
// Post-analysis validators (from decompiler::validator module)
// ============================================================================

#[test]
fn test_decompiler_validator_new() {
    use ghidra_decompile::decompiler::validator::DecompilerValidator;
    let v = DecompilerValidator::new();
    assert_eq!(v.functions_processed, 0);
    assert_eq!(v.functions_with_errors, 0);
}

#[test]
fn test_decompiler_validator_with_timeout() {
    use ghidra_decompile::decompiler::validator::DecompilerValidator;
    let v = DecompilerValidator::new().with_timeout(120);
    assert_eq!(v.timeout_secs, 120);
}

#[test]
fn test_decompiler_validator_process_results_success() {
    use ghidra_decompile::decompiler::validator::{DecompilerValidator, ConditionStatus};
    let mut v = DecompilerValidator::new();
    let results = vec![
        DecompilerResult::success(DecompilerMapFunction::new(0x1000), ()),
        DecompilerResult::success(DecompilerMapFunction::new(0x2000), ()),
    ];
    let result = v.process_results(&results);
    assert_eq!(result.status, ConditionStatus::Passed);
    assert_eq!(v.functions_processed, 2);
    assert_eq!(v.functions_with_errors, 0);
}

#[test]
fn test_decompiler_validator_process_results_with_errors() {
    use ghidra_decompile::decompiler::validator::{DecompilerValidator, ConditionStatus};
    let mut v = DecompilerValidator::new();
    let mut func = DecompilerMapFunction::new(0x1000);
    func.name = Some("bad_func".to_string());
    let results = vec![
        DecompilerResult::success(DecompilerMapFunction::new(0x2000), ()),
        DecompilerResult::error(func, "decompile failed".to_string()),
    ];
    let result = v.process_results(&results);
    assert_eq!(result.status, ConditionStatus::Warning);
    assert_eq!(v.functions_processed, 2);
    assert_eq!(v.functions_with_errors, 1);
    assert!(result.message.contains("bad_func"));
}

#[test]
fn test_parameter_id_validator_new() {
    use ghidra_decompile::decompiler::validator::DecompilerParameterIDValidator;
    let v = DecompilerParameterIDValidator::new();
    assert_eq!(v.min_percent_threshold, 1);
}

#[test]
fn test_parameter_id_validator_below_threshold() {
    use ghidra_decompile::decompiler::validator::{DecompilerParameterIDValidator, ConditionStatus, PostAnalysisValidator};
    let mut v = DecompilerParameterIDValidator::new().with_threshold(10);
    v.set_counts(5, 100);
    let result = v.do_run();
    assert_eq!(result.status, ConditionStatus::Warning);
}

#[test]
fn test_parameter_id_validator_above_threshold() {
    use ghidra_decompile::decompiler::validator::{DecompilerParameterIDValidator, ConditionStatus, PostAnalysisValidator};
    let mut v = DecompilerParameterIDValidator::new().with_threshold(1);
    v.set_counts(50, 100);
    let result = v.do_run();
    assert_eq!(result.status, ConditionStatus::Passed);
}

// ============================================================================
// Component types
// ============================================================================

#[test]
fn test_token_highlight_colors_default() {
    let colors = TokenHighlightColors::default();
    let _ = colors;
}

#[test]
fn test_token_highlights() {
    let highlights = TokenHighlights::new();
    assert!(highlights.is_empty());
}

// ============================================================================
// Actions
// ============================================================================

#[test]
fn test_action_category() {
    use actions::ActionCategory;
    assert_ne!(ActionCategory::Navigation, ActionCategory::Editing);
}

#[test]
fn test_constant_format() {
    use actions::ConstantFormat;
    assert_ne!(ConstantFormat::Hex, ConstantFormat::Decimal);
}

// ============================================================================
// Find dialog types
// ============================================================================

#[test]
fn test_decompiler_find_dialog() {
    let dialog = DecompilerFindDialog::new();
    let _ = dialog;
}

#[test]
fn test_overlay_message_painter() {
    let painter = OverlayMessagePainter::new("test message");
    let _ = painter;
}

// ============================================================================
// Clipboard provider
// ============================================================================

#[test]
fn test_decompiler_clipboard_provider() {
    let provider = DecompilerClipboardProvider::new();
    let _ = provider;
}

// ============================================================================
// ConcurrentQ
// ============================================================================

#[test]
fn test_decompiler_concurrent_q() {
    let _q = DecompilerConcurrentQ::<String, String>::new(4);
}

// ============================================================================
// Disposer
// ============================================================================

#[test]
fn test_dispose_state_variants() {
    assert_eq!(DisposeState::NotDisposed, DisposeState::default());
    assert_ne!(DisposeState::DisposedOnTimeout, DisposeState::NotDisposed);
}

// ============================================================================
// DecompileDebug
// ============================================================================

#[test]
fn test_decompile_debug() {
    let debug = DecompileDebug::new();
    let _ = debug;
}

// ============================================================================
// FillOutStructure
// ============================================================================

#[test]
fn test_fill_out_structure_helper() {
    let helper = FillOutStructureHelper::new(0x1000);
    let _ = helper;
}

// ============================================================================
// CppExporter
// ============================================================================

#[test]
fn test_cpp_export_options() {
    let opts = CppExportOptions::default();
    let _ = opts;
}

// ============================================================================
// Markup parser
// ============================================================================

#[test]
fn test_markup_parser_exists() {
    // MarkupParser is accessible
    let _ = std::any::type_name::<MarkupParser>();
}

// ============================================================================
// Token iterator
// ============================================================================

#[test]
fn test_token_iterator_empty() {
    let mut arena = ClangNodeArena::new();
    let root = arena.alloc(ClangNodeKind::TokenGroup(ClangTokenGroupData::default()));
    let iter = TokenIterator::from_group(&arena, root, true);
    assert_eq!(iter.count(), 0);
}

// ============================================================================
// PrettyPrinter
// ============================================================================

#[test]
fn test_pretty_printer_type() {
    let _ = std::any::type_name::<PrettyPrinter>();
}

// ============================================================================
// Decompiler initializer
// ============================================================================

#[test]
fn test_decompiler_initializer() {
    let _ = DecompilerInitializer::new();
}

// ============================================================================
// Location memento
// ============================================================================

#[test]
fn test_decompiler_location_memento() {
    let memento = DecompilerLocationMemento::new(0x1000);
    let _ = memento;
}

// ============================================================================
// Decompiler plugin
// ============================================================================

#[test]
fn test_decompiler_action_context_type() {
    use ghidra_core::addr::Address;
    let ctx = DecompilerActionContext::new(Address::new(0x1000));
    assert_eq!(ctx.function_entry, Address::new(0x1000));
}

// ============================================================================
// ConcurrentQ callback
// ============================================================================

#[test]
fn test_q_result_success() {
    let result = QResult::success("input".to_string(), "output".to_string());
    assert!(result.result.is_ok());
}

#[test]
fn test_q_result_error() {
    let result: QResult<String, String> = QResult::failure("input".to_string(), "test error");
    assert!(!result.is_success());
}
