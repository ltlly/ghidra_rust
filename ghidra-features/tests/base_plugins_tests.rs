//! Integration tests for the newly ported Ghidra Features/Base plugin modules.
//!
//! These tests exercise the cross-module interactions and verify that the
//! ported plugin models compile and function correctly end-to-end.

use ghidra_core::Address;
use ghidra_features::instructionsearch::{InstructionSearchApi, MaskContainer, MaskSettings};
use ghidra_features::instructionsearch::utils::InstructionSearchUtils;
use ghidra_features::bookmark::{BookmarkManager, BookmarkNavigator, BookmarkType};
use ghidra_features::calltree::{CallTreeBuilder, CallTreeDirection, CallTreeEdgeType, FunctionRef};
use ghidra_features::reachability::{ReachabilityAnalyzer, ReachabilityGraph, FRVertex};
use ghidra_features::fallthrough::FallThroughModel;
use ghidra_features::label::{LabelInfo, LabelManager, LabelScope, LabelValidator};
use ghidra_features::memory::{MemoryBlockInfo, MemoryBlockPermission, MemoryBlockType, MemoryMapModel};
use ghidra_features::reloc::{Relocation, RelocationFixupModel, RelocationType};
use ghidra_features::disassembler::DisassemblerModel;
use ghidra_features::assembler::{AssemblerModel, AssemblyInstruction};
use ghidra_features::scalartable::{ScalarCategory, ScalarEntry, ScalarTableModel};
use ghidra_features::stackeditor::{StackEditorModel, StackVariableEntry};
use ghidra_features::sourcefilestable::{SourceFileEntry, SourceFilesTableModel};
use ghidra_features::module::ProgramTreeModel;
use ghidra_features::clipboard::ClipboardManager;
use ghidra_features::clear::{ClearModel, ClearOperation, ClearType};
use ghidra_features::select::{AddressSet, SelectionModel};
use ghidra_features::highlight::{HighlightColor, HighlightManager};
use ghidra_features::flowarrow::{FlowArrow, FlowArrowModel, FlowArrowType};
use ghidra_features::colorizer::{ColorizerMode, ColorizerModel};
use ghidra_features::comments_plugin::CommentsModel;
use ghidra_features::commentwindow::{CommentEntry, CommentWindowModel};
use ghidra_features::printing::PrintModel;
use ghidra_features::misc::{AddressDisplayFormat, ImportType};
use ghidra_features::hover::{HoverElementType, HoverInfo, HoverModel};
use ghidra_features::help::{HelpLocation, HelpModel, HelpTopic};
use ghidra_features::check::{ValidationCheck, ValidationModel, ValidationResult, ValidationSeverity};
use ghidra_features::data_plugin::{DataAction, DataPluginModel};

// ==========================================================================
// Instruction Search integration
// ==========================================================================

#[test]
fn test_instruction_search_end_to_end() {
    let api = InstructionSearchApi::new();

    // Parse a hex pattern with wildcards
    let mc = InstructionSearchApi::parse_hex_pattern("48 89 .. 00").unwrap();
    assert_eq!(mc.mask, vec![0xFF, 0xFF, 0x00, 0xFF]);

    // Search for it in a buffer
    // Pattern "48 89 .. 00" requires 4th byte to be 0x00
    let memory = vec![0x00, 0x48, 0x89, 0xD8, 0x00, 0x00, 0x48, 0x89, 0xC3, 0x00];
    let results = api.search_bytes(&mc, &memory, 0x1000, true);
    // Should match at offset 1 (48 89 D8 00) and offset 6 (48 89 C3 00)
    assert_eq!(results.len(), 2);
    assert_eq!(results[0], Address::new(0x1001));
    assert_eq!(results[1], Address::new(0x1006));

    // Convert to YARA format
    let yara = InstructionSearchApi::to_yara_hex_string(&mc);
    assert_eq!(yara, "48 89 [..] 00");
}

// ==========================================================================
// Bookmark integration
// ==========================================================================

#[test]
fn test_bookmark_with_navigation() {
    let mut mgr = BookmarkManager::new();
    let bt = BookmarkType::info();
    mgr.set_bookmark(Address::new(0x1000), &bt, "entry point");
    mgr.set_bookmark(Address::new(0x2000), &bt, "important call");
    mgr.set_bookmark(Address::new(0x4000), &bt, "return");

    let nav = BookmarkNavigator::new(BookmarkType::info(), &mgr);
    assert_eq!(nav.count(), 3);
    assert_eq!(nav.get_next(Address::new(0x1000)), Some(Address::new(0x2000)));
    assert_eq!(nav.get_next(Address::new(0x2000)), Some(Address::new(0x4000)));
    assert_eq!(nav.get_previous(Address::new(0x4000)), Some(Address::new(0x2000)));
}

// ==========================================================================
// Calltree + Reachability integration
// ==========================================================================

#[test]
fn test_calltree_and_reachability_combined() {
    // Build a call tree
    let mut builder = CallTreeBuilder::new();
    builder.add_function(FunctionRef::new("main", Address::new(0x1000)));
    builder.add_function(FunctionRef::new("process", Address::new(0x2000)));
    builder.add_function(FunctionRef::new("helper", Address::new(0x3000)));
    builder.add_call(Address::new(0x1000), Address::new(0x2000), CallTreeEdgeType::Call);
    builder.add_call(Address::new(0x2000), Address::new(0x3000), CallTreeEdgeType::Call);

    let tree = builder.build_outgoing(Address::new(0x1000), 10);
    assert_eq!(tree.root.name, "main");
    assert_eq!(tree.unique_function_count, 3);

    // Also build a reachability graph
    let mut graph = ReachabilityGraph::new();
    graph.add_vertex(FRVertex::new("main", Address::new(0x1000)));
    graph.add_vertex(FRVertex::new("process", Address::new(0x2000)));
    graph.add_vertex(FRVertex::new("helper", Address::new(0x3000)));
    graph.add_edge(Address::new(0x1000), Address::new(0x2000));
    graph.add_edge(Address::new(0x2000), Address::new(0x3000));

    assert!(graph.is_reachable(Address::new(0x1000), Address::new(0x3000)));
    let path = graph.shortest_path(Address::new(0x1000), Address::new(0x3000)).unwrap();
    assert_eq!(path.path_length, 2);
}

// ==========================================================================
// Label + Fallthrough integration
// ==========================================================================

#[test]
fn test_label_and_fallthrough_workflow() {
    let mut label_mgr = LabelManager::new();
    label_mgr.add_label(LabelInfo::primary("start", Address::new(0x1000)));
    label_mgr.add_label(LabelInfo::local("loop", Address::new(0x1010)));

    assert_eq!(label_mgr.get_label_name(Address::new(0x1000)), Some("start"));
    assert!(LabelValidator::is_valid_label_name("valid_label_001"));

    let mut ft_model = FallThroughModel::new();
    ft_model.register_instruction(Address::new(0x1000), Some(Address::new(0x1004)));
    ft_model.register_instruction(Address::new(0x1004), Some(Address::new(0x1008)));

    ft_model.set_fallthrough(Address::new(0x1000), Address::new(0x1010));
    assert!(ft_model.is_overridden(Address::new(0x1000)));
    ft_model.clear_fallthrough(Address::new(0x1000));
    assert!(!ft_model.is_overridden(Address::new(0x1000)));
}

// ==========================================================================
// Memory + Relocation integration
// ==========================================================================

#[test]
fn test_memory_and_relocation_workflow() {
    let mut mem = MemoryMapModel::new();
    mem.add_block(MemoryBlockInfo::new(
        ".text",
        Address::new(0x401000),
        Address::new(0x401FFF),
        MemoryBlockType::Initialized,
    ))
    .unwrap();

    let mut reloc = RelocationFixupModel::new();
    reloc.add_relocation(Relocation::new(
        Address::new(0x401000),
        RelocationType::Absolute,
        0x402000,
    ));

    // Apply base change
    reloc.apply_image_base_change(0x400000, 0x500000);
    let r = reloc.table().get(Address::new(0x401000)).unwrap();
    assert_eq!(r.original_value, 0x502000);
}

// ==========================================================================
// Assembler + Disassembler integration
// ==========================================================================

#[test]
fn test_assembler_disassembler_roundtrip() {
    let mut assembler = AssemblerModel::new("x86:LE:64");
    assembler.add_instruction(AssemblyInstruction::new(
        "nop",
        vec![0x90],
        Address::new(0x1000),
    ));
    assembler.add_instruction(AssemblyInstruction::new(
        "ret",
        vec![0xC3],
        Address::new(0x1001),
    ));

    let bytes = assembler.get_bytes();
    assert_eq!(bytes, vec![0x90, 0xC3]);

    let mut disasm = DisassemblerModel::new();
    disasm.record_instruction(Address::new(0x1000), 1);
    disasm.record_instruction(Address::new(0x1001), 1);

    assert!(disasm.is_disassembled(Address::new(0x1000)));
    assert_eq!(disasm.get_instruction_length(Address::new(0x1000)), Some(1));
    assert_eq!(
        disasm.get_next_instruction_address(Address::new(0x1000)),
        Some(Address::new(0x1001))
    );
}

// ==========================================================================
// Data Plugin + Scalar Table integration
// ==========================================================================

#[test]
fn test_data_and_scalar_integration() {
    let mut data_model = DataPluginModel::new();
    data_model
        .create_data(Address::new(0x1000), DataAction::DWord, 4)
        .unwrap();
    data_model
        .create_data(Address::new(0x1004), DataAction::Byte, 1)
        .unwrap();

    let mut scalar_model = ScalarTableModel::new();
    scalar_model.add_entry(ScalarEntry::new(0x42, Address::new(0x1000), 0, 4));
    scalar_model.add_entry(ScalarEntry::new(0x42, Address::new(0x1004), 0, 1));

    assert_eq!(data_model.item_count(), 2);
    assert_eq!(scalar_model.entry_count(), 2);
    assert_eq!(scalar_model.unique_value_count(), 1);
}

// ==========================================================================
// Selection + Highlight + Clipboard integration
// ==========================================================================

#[test]
fn test_selection_highlight_clipboard_workflow() {
    let mut sel = SelectionModel::new();
    let mut set = AddressSet::new();
    set.add_range(Address::new(0x1000), Address::new(0x100F));
    sel.set_selection(set);
    assert!(sel.has_selection());

    let mut highlight = HighlightManager::new();
    highlight.set_highlight(Address::new(0x1004), HighlightColor::yellow());
    assert!(highlight.is_highlighted(Address::new(0x1004)));

    let mut clipboard = ClipboardManager::new();
    clipboard.copy_bytes(Address::new(0x1000), Address::new(0x1003), vec![0x48, 0x89, 0xD8, 0xC3]);
    let entry = clipboard.peek().unwrap();
    assert_eq!(entry.as_hex(), "48 89 D8 C3");
}

// ==========================================================================
// Module/Fragment + Source Files integration
// ==========================================================================

#[test]
fn test_program_tree_and_source_files() {
    let mut tree = ProgramTreeModel::new();
    let root = tree.create_module("root", None);
    tree.add_fragment(".text", root, Address::new(0x1000), Address::new(0x1FFF));
    tree.add_fragment(".data", root, Address::new(0x2000), Address::new(0x2FFF));

    let mut src = SourceFilesTableModel::new();
    let mut e = SourceFileEntry::new("/src/main.c");
    e.language = "C".into();
    e.code_unit_count = 200;
    src.add_entry(e);

    assert_eq!(tree.get_fragments().len(), 2);
    assert_eq!(src.entry_count(), 1);
}

// ==========================================================================
// Validation + Help integration
// ==========================================================================

#[test]
fn test_validation_and_help() {
    let mut model = ValidationModel::new();
    model.add_check(ValidationCheck::new("MemoryCheck", "Checks for memory overlaps"));
    model.add_result(
        ValidationResult::new("MemoryCheck", ValidationSeverity::Warning, "Minor issue")
            .with_address(Address::new(0x1000)),
    );
    assert_eq!(model.warning_count(), 1);

    let mut help = HelpModel::new();
    help.register_topic(HelpTopic {
        id: "MemoryCheck".into(),
        name: "Memory Check Help".into(),
        content: "Checks for memory block overlaps...".into(),
        children: Vec::new(),
    });
    let topic = help.get_topic("MemoryCheck").unwrap();
    assert_eq!(topic.name, "Memory Check Help");

    let loc = HelpLocation::new("MemoryPlugin", "help.html").with_anchor("memory-check");
    assert_eq!(loc.anchor.as_deref(), Some("memory-check"));
}

// ==========================================================================
// Utility integration
// ==========================================================================

#[test]
fn test_misc_utilities() {
    assert_eq!(ImportType::Elf.display_name(), "ELF");
    assert_eq!(AddressDisplayFormat::Hex.format(0xFF), "0xFF");
    assert_eq!(AddressDisplayFormat::Decimal.format(255), "255");

    // InstructionSearchUtils
    assert!(InstructionSearchUtils::is_hex("4889"));
    assert!(InstructionSearchUtils::is_binary("01001000"));
    assert!(InstructionSearchUtils::contains_on_bit(&[0x00, 0x01]));
    assert_eq!(InstructionSearchUtils::to_binary_string(0x48), "01001000");
}
