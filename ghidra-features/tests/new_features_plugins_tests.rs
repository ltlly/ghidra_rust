//! Integration tests for the remaining Features/Base plugin modules ported from Java.
//!
//! These tests exercise the new Rust modules that correspond to
//! `ghidra.app.util.opinion`, `ghidra.program.util`, `ghidra.util.bytesearch`,
//! `ghidra.util.table`, and `ghidra.app.util.xml`.

use ghidra_features::app_util_opinion::*;
use ghidra_features::base::analyzer::{Address, AddressRange, AddressSet, Function, Language, Program};
use ghidra_features::loader::framework::*;
use ghidra_features::program_util::*;
use ghidra_features::table_util::*;
use ghidra_features::util_bytesearch::*;
use ghidra_features::app_util_xml::*;

// ===========================================================================
// LoaderService / LoaderMap integration tests
// ===========================================================================

#[test]
fn test_loader_service_elf_detection() {
    let mut data = vec![0u8; 64];
    data[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
    data[4] = 2; // ELFCLASS64
    data[5] = 1; // ELFDATA2LSB

    let map = LoaderService::get_supported_load_specs(&data);
    assert!(!map.is_empty());
    assert!(map.contains_loader("Executable and Linking Format (ELF)"));
}

#[test]
fn test_loader_service_mz_detection() {
    let mut data = vec![0u8; 256];
    data[0] = 0x4D;
    data[1] = 0x5A;
    // No PE header

    let map = LoaderService::get_supported_load_specs(&data);
    assert!(map.contains_loader("Old-style DOS Executable (MZ)"));
}

#[test]
fn test_loader_service_no_match() {
    let data = vec![0u8; 16];
    let map = LoaderService::get_supported_load_specs(&data);
    assert!(map.is_empty());
}

#[test]
fn test_loader_map_flat_specs() {
    let mut map = LoaderMap::new();
    map.insert("ELF", vec![
        LoadSpec::with_unknown_language("ELF", 0x400000, true),
        LoadSpec::with_unknown_language("ELF", 0, false),
    ]);
    map.insert("PE", vec![
        LoadSpec::with_unknown_language("PE", 0x10000, true),
    ]);

    let all = map.all_specs();
    assert_eq!(all.len(), 3);

    // Verify sorted by loader name (BTreeMap)
    let names = map.loader_names();
    assert_eq!(names[0], "ELF");
    assert_eq!(names[1], "PE");
}

#[test]
fn test_loader_service_all_names() {
    let names = LoaderService::get_all_loader_names();
    assert!(names.len() >= 8);
    assert!(names.iter().any(|n| n.contains("ELF")));
    assert!(names.iter().any(|n| n.contains("PE")));
    assert!(names.iter().any(|n| n.contains("Raw Binary")));
}

// ===========================================================================
// BinaryRawLoader integration tests
// ===========================================================================

#[test]
fn test_binary_raw_loader_full_workflow() {
    let loader = BinaryRawLoader;
    assert_eq!(loader.tier(), LoaderTier::UntargetedLoader);
    assert_eq!(loader.tier_priority(), 100);
    assert!(loader.should_apply_processor_labels());

    let specs = loader.find_supported_load_specs();
    assert_eq!(specs.len(), 1);
    assert!(specs[0].requires_language_compiler_spec);

    let opts = BinaryRawLoader::default_options(4096);
    assert!(BinaryRawLoader::validate_options(&opts, 4096).is_ok());
}

// ===========================================================================
// DefLoader integration tests
// ===========================================================================

#[test]
fn test_def_loader_full_workflow() {
    let loader = DefLoader;
    let data = b"LIBRARY MyLib\nEXPORTS\n  Func1 @1\n  Func2 @2 DATA\n";

    assert!(DefLoader::is_def(data));
    assert_eq!(loader.tier(), LoaderTier::GenericTargetLoader);

    let specs = loader.find_supported_load_specs(data);
    assert_eq!(specs.len(), 1);

    let exports = DefLoader::parse_exports(data);
    assert_eq!(exports.len(), 2);
    assert_eq!(exports[0].name, "Func1");
    assert_eq!(exports[0].ordinal, Some(1));
    assert!(exports[1].is_data);
}

// ===========================================================================
// DBG / GDT / GZF loader integration tests
// ===========================================================================

#[test]
fn test_gdt_gzf_magic_detection() {
    let mut data = vec![0u8; 64];
    data[0..4].copy_from_slice(b"GDB\0");
    assert!(GdtLoader::is_gdt(&data));
    assert!(GzfLoader::is_gzf(&data));
}

#[test]
fn test_dbg_loader_rejects_non_dbg() {
    assert!(!DbgLoader::is_dbg(&[0u8; 64]));
    assert!(!DbgLoader::is_dbg(&[0x7f, b'E', b'L', b'F']));
}

#[test]
fn test_separate_debug_header_roundtrip() {
    let mut data = vec![0u8; 64];
    data[0..4].copy_from_slice(&0x4944_4D50u32.to_le_bytes()); // 'PMDB' = IMAGE_SEPARATE_DEBUG_SIGNATURE
    data[4..6].copy_from_slice(&0x8664u16.to_le_bytes()); // x86_64

    let header = SeparateDebugHeader::parse(&data).unwrap();
    assert_eq!(header.machine_name(), "x86_64");
}

// ===========================================================================
// AddressSetPartitioner integration tests
// ===========================================================================

#[test]
fn test_partitioner_complex_split() {
    let mut set = AddressSet::new();
    set.add_range(AddressRange::new(Address::new(0x1000), Address::new(0x2FFF)));

    let partitions = vec![Address::new(0x1500), Address::new(0x2000), Address::new(0x2800)];
    let range_data = std::collections::HashMap::new(); // empty for simplicity
    let partitioner = AddressSetPartitioner::new(&set, &range_data, &partitions);

    assert_eq!(partitioner.len(), 4);
    assert_eq!(partitioner.ranges()[0].start.offset, 0x1000);
    assert_eq!(partitioner.ranges()[0].end.offset, 0x14FF);
    assert_eq!(partitioner.ranges()[1].start.offset, 0x1500);
    assert_eq!(partitioner.ranges()[1].end.offset, 0x1FFF);
    assert_eq!(partitioner.ranges()[2].start.offset, 0x2000);
    assert_eq!(partitioner.ranges()[2].end.offset, 0x27FF);
    assert_eq!(partitioner.ranges()[3].start.offset, 0x2800);
    assert_eq!(partitioner.ranges()[3].end.offset, 0x2FFF);
}

// ===========================================================================
// Program utility integration tests
// ===========================================================================

#[test]
fn test_program_diff_full_workflow() {
    let mut prog_a = Program::new("a", Language { processor: "x86".into(), variant: "LE".into(), size: 64 });
    let mut prog_b = Program::new("b", Language { processor: "x86".into(), variant: "LE".into(), size: 64 });

    // Different symbols
    prog_a.symbols.insert(Address::new(0x1000), "main".into());
    prog_b.symbols.insert(Address::new(0x1000), "entry".into());

    // Different functions
    prog_a.function_manager.functions.insert(
        Address::new(0x1000),
        Function { name: Some("main".into()), entry_point: Address::new(0x1000), body: AddressSet::new(), is_external: false, is_thunk: false, is_inline: false, has_noreturn: false, call_fixup: None },
    );
    // prog_b has no functions

    let mut addr_set = AddressSet::new();
    addr_set.add(Address::new(0x1000));

    let report = ProgramDiff::full_diff(&prog_a, &prog_b, &addr_set);
    assert!(!report.is_empty());
    assert!(report.get_category_set(DiffCategory::Labels).is_some());
    assert!(report.get_category_set(DiffCategory::Functions).is_some());
}

#[test]
fn test_memory_diff_partial_overlap() {
    let mut prog_a = Program::new("a", Language { processor: "x86".into(), variant: "LE".into(), size: 64 });
    let mut prog_b = Program::new("b", Language { processor: "x86".into(), variant: "LE".into(), size: 64 });

    prog_a.memory.add_range(AddressRange::new(Address::new(0x1000), Address::new(0x1FFF)));
    prog_b.memory.add_range(AddressRange::new(Address::new(0x1800), Address::new(0x27FF)));

    let mut addr_set = AddressSet::new();
    addr_set.add_range(AddressRange::new(Address::new(0), Address::new(0xFFFF)));

    let diff = MemoryDiff::new(&prog_a, &prog_b, &addr_set);
    assert!(!diff.is_identical());
    assert!(diff.only_in_a().contains(&Address::new(0x1000)));
    assert!(!diff.only_in_a().contains(&Address::new(0x1800)));
    assert!(diff.only_in_b().contains(&Address::new(0x2000)));
    assert!(diff.in_both().contains(&Address::new(0x1800)));
}

#[test]
fn test_string_searcher_comprehensive() {
    let searcher = StringSearcher::new(4);
    let data = b"test\x00short\x00\x00another_string\x00ab\x00";

    let results = searcher.search(data, Address::new(0x10000));
    // Should find "test" (4 chars), "another_string" (14 chars), "short" (5 chars)
    assert!(results.len() >= 2);
    for result in &results {
        assert!(result.value.len() >= 4);
        assert!(result.address.offset >= 0x10000);
    }
}

#[test]
fn test_symbolic_propagator_comprehensive() {
    let mut prop = SymbolicPropagator::new();

    // Set up values
    prop.propagate_constant(Address::new(0x1000), Address::new(0x100F), "RAX", 0);
    prop.set_register_value(Address::new(0x1000), "RBX", 42);
    prop.set_register_value(Address::new(0x1004), "RAX", 100); // overwrite within range

    // Verify
    assert_eq!(prop.get_register_value(Address::new(0x1000), "RAX"), Some(0));
    assert_eq!(prop.get_register_value(Address::new(0x1004), "RAX"), Some(100));
    assert_eq!(prop.get_register_value(Address::new(0x1008), "RAX"), Some(0));
    assert_eq!(prop.get_register_value(Address::new(0x1000), "RBX"), Some(42));
}

#[test]
fn test_address_translator_roundtrip() {
    let translator = DefaultAddressTranslator::new(0x1000, 0x8000_0000);

    let original = Address::new(0x1500);
    let translated = translator.translate(original);
    assert_eq!(translated.offset, 0x8000_0500);

    let back = translator.reverse_translate(translated);
    assert_eq!(back.offset, original.offset);
}

#[test]
fn test_program_merge_filter_custom() {
    let mut filter = ProgramMergeFilter::new();
    filter.set_action(DiffCategory::Labels, MergeAction::Add);
    filter.set_action(DiffCategory::Functions, MergeAction::Replace);
    filter.set_action(DiffCategory::Bookmarks, MergeAction::Remove);

    assert!(filter.should_merge(DiffCategory::Labels));
    assert!(filter.should_merge(DiffCategory::Functions));
    assert!(!filter.should_merge(DiffCategory::Bookmarks)); // Remove doesn't count as "merge"
    assert!(!filter.should_merge(DiffCategory::Comments)); // Default is Skip
}

// ===========================================================================
// Byte pattern search integration tests
// ===========================================================================

#[test]
fn test_byte_pattern_x86_function_prologue() {
    // x86-64 function prologues: push rbp; mov rbp, rsp (55 48 89 E5)
    let pattern = BytePattern::from_bytes(&[0x55, 0x48, 0x89, 0xE5]);

    let mut data = vec![0x90; 256]; // NOPs
    data[100..104].copy_from_slice(&[0x55, 0x48, 0x89, 0xE5]);
    data[200..204].copy_from_slice(&[0x55, 0x48, 0x89, 0xE5]);

    let results = ByteSearcher::find_all(&pattern, &data, 0);
    assert_eq!(results.len(), 2);
    assert_eq!(results[0].offset, 100);
    assert_eq!(results[1].offset, 200);
}

#[test]
fn test_byte_pattern_with_mask() {
    // Match any instruction starting with 0x8B (mov r32, r/m32)
    // followed by any ModR/M byte
    let pattern = BytePattern::new(&[0x8B, 0x00], &[0xFF, 0x00]);

    let data = vec![0x8B, 0xC5, 0x8B, 0xD8, 0x90, 0x8B, 0xEC];
    let results = ByteSearcher::find_all(&pattern, &data, 0);
    assert_eq!(results.len(), 3);
}

#[test]
fn test_byte_pattern_hex_string_complex() {
    let pattern = BytePattern::from_hex_string("E8 ?? ?? ?? ?? 83 C4").unwrap();
    // call rel32; add esp, imm8

    let mut data = vec![0x90; 32];
    data[5..12].copy_from_slice(&[0xE8, 0x10, 0x00, 0x00, 0x00, 0x83, 0xC4]);

    let result = ByteSearcher::find_first(&pattern, &data, 0);
    assert!(result.is_some());
    assert_eq!(result.unwrap().offset, 5);
}

#[test]
fn test_ditted_bit_sequence_instruction_pattern() {
    // Match a subset of x86 instructions: any byte, then 0xC3 (ret)
    let dbs = DittedBitSequence::new(
        vec![0x00, 0xC3],
        vec![0x00, 0xFF],
        16,
    );

    let data_ok = vec![0x90, 0xC3];
    assert!(dbs.matches(&data_ok));

    let data_bad = vec![0x90, 0xC2];
    assert!(!dbs.matches(&data_bad));
}

// ===========================================================================
// Table model integration tests
// ===========================================================================

#[test]
fn test_address_table_model_full_workflow() {
    let mut model = AddressBasedTableModel::new(vec!["Symbol", "Address", "Type", "Size"]);

    // Add data
    model.add_row(Address::new(0x401000), vec!["main".into(), "0x401000".into(), "Function".into(), "256".into()]);
    model.add_row(Address::new(0x401200), vec!["helper".into(), "0x401200".into(), "Function".into(), "128".into()]);
    model.add_row(Address::new(0x402000), vec!["global_data".into(), "0x402000".into(), "Label".into(), "64".into()]);

    assert_eq!(model.row_count(), 3);
    assert_eq!(model.column_count(), 4);

    // Sort by address
    model.sort_by_address();
    assert_eq!(model.get_address(0), Some(Address::new(0x401000)));

    // Get address set
    let set = model.address_set();
    assert_eq!(set.num_addresses(), 3);

    // Find rows at address
    let rows = model.find_rows_at(Address::new(0x401200));
    assert_eq!(rows.len(), 1);
}

#[test]
fn test_filtered_table_navigation() {
    let mut model = AddressBasedTableModel::new(vec!["Name", "Address"]);
    for i in 0..100 {
        model.add_row(
            Address::new(0x1000 + i * 0x100),
            vec![format!("func_{:02x}", i), format!("0x{:x}", 0x1000 + i * 0x100)],
        );
    }

    let mut table = GhidraFilterTable::new(model);

    // Filter for functions starting with "func_1"
    table.set_filter("func_1");
    // Should match: func_10, func_11, func_12, ..., func_1f, func_1 (21 total)
    assert!(table.filtered_row_count() > 10);
    assert!(table.is_filtered());

    // Find by address
    table.clear_filter();
    assert!(!table.is_filtered());
    assert_eq!(table.filtered_row_count(), 100);

    let row = table.find_row_by_address(Address::new(0x1500));
    assert!(row.is_some());
}

// ===========================================================================
// XML parsing integration tests
// ===========================================================================

#[test]
fn test_xml_program_representation() {
    let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<program name="test.exe" arch="x86:LE:64:default" image_base="0x400000">
    <memory>
        <block name=".text" start="0x401000" length="0x1000" read="true" execute="true"/>
        <block name=".data" start="0x402000" length="0x500" read="true" write="true"/>
    </memory>
    <functions>
        <function name="main" entry="0x401000" size="256"/>
        <function name="helper" entry="0x401100" size="128"/>
    </functions>
</program>"#;

    let doc = XmlPullParser::new(xml).parse().unwrap();
    assert_eq!(doc.tag_name, "program");
    assert_eq!(doc.attr("name"), Some("test.exe"));
    assert_eq!(doc.attr_as_u64("image_base"), Some(0x400000));

    let memory = doc.child("memory").unwrap();
    let blocks = memory.children_with_tag("block");
    assert_eq!(blocks.len(), 2);
    assert_eq!(blocks[0].attr("name"), Some(".text"));
    assert_eq!(blocks[0].attr_as_bool("execute"), Some(true));

    let functions = doc.find_by_path("functions").unwrap();
    assert_eq!(functions.children.len(), 2);
}

#[test]
fn test_xml_writer_roundtrip() {
    let mut root = XmlElement::new("program");
    root.set_attr("name", "test.exe");

    let mut block = XmlElement::new("block");
    block.set_attr("name", ".text");
    block.set_attr("start", "0x401000");
    root.add_child(block);

    let xml = root.to_xml();

    // Parse and verify
    let doc = XmlPullParser::new(&xml).parse().unwrap();
    assert_eq!(doc.attr("name"), Some("test.exe"));
    assert_eq!(doc.child("block").unwrap().attr("start"), Some("0x401000"));
}

#[test]
fn test_xml_attributes_builder() {
    let mut attrs = XmlAttributes::new();
    attrs.add("name", "section");
    attrs.add_u64("offset", 0xDEAD_BEEF);
    attrs.add_bool("enabled", true);

    let map = attrs.to_map();
    assert_eq!(map.len(), 3);
    assert_eq!(map.get("offset").unwrap(), "0xdeadbeef");
    assert_eq!(map.get("enabled").unwrap(), "true");
}

// ===========================================================================
// LibraryHints integration tests
// ===========================================================================

#[test]
fn test_library_hints_workflow() {
    let mut hints = LibraryHints::new();

    hints.add_hint(LibraryHint {
        library_name: "libc.so.6".into(),
        preferred_path: Some("/usr/lib".into()),
        lcs: Some(LanguageCompilerSpecPair::new("x86:LE:64:default", "default")),
        search_paths: vec!["/lib".into(), "/usr/lib/x86_64-linux-gnu".into()],
    });

    hints.add_hint(LibraryHint {
        library_name: "kernel32.dll".into(),
        preferred_path: Some("C:\\Windows\\System32".into()),
        lcs: None,
        search_paths: vec![],
    });

    assert_eq!(hints.len(), 2);

    let libc = hints.find_hint("libc.so.6").unwrap();
    assert_eq!(libc.search_paths.len(), 2);
    assert!(libc.lcs.is_some());

    assert!(hints.find_hint("missing.so").is_none());
}

// ===========================================================================
// Cross-module integration tests
// ===========================================================================

#[test]
fn test_combined_loader_and_program_utility() {
    // Create a program and set up its memory
    let mut program = Program::new("test.exe", Language {
        processor: "x86".into(),
        variant: "LE".into(),
        size: 64,
    });
    program.memory.add_range(AddressRange::new(Address::new(0x401000), Address::new(0x401FFF)));

    // Add functions
    program.function_manager.functions.insert(
        Address::new(0x401000),
        Function {
            name: Some("main".into()),
            entry_point: Address::new(0x401000),
            body: AddressSet::from_range(AddressRange::new(Address::new(0x401000), Address::new(0x4010FF))),
            is_external: false, is_thunk: false, is_inline: false, has_noreturn: false, call_fixup: None,
        },
    );

    // Verify using program utilities
    assert!(ProgramMemoryUtil::has_memory(&program));
    assert_eq!(FunctionUtility::function_count(&program), 1);
    assert!(FunctionUtility::is_function_start(&program, Address::new(0x401000)));
    assert_eq!(
        FunctionUtility::get_function_containing(&program, Address::new(0x401050)),
        Some("main".into())
    );

    // Use symbolic propagator
    let mut prop = SymbolicPropagator::new();
    prop.set_register_value(Address::new(0x401000), "RSP", 0x7FFF0000);
    assert_eq!(prop.get_register_value(Address::new(0x401000), "RSP"), Some(0x7FFF0000));

    // Search for byte patterns
    let pattern = BytePattern::from_bytes(&[0x55, 0x48, 0x89, 0xE5]);
    let data = vec![0x90, 0x55, 0x48, 0x89, 0xE5, 0x90];
    let result = ByteSearcher::find_first(&pattern, &data, 0);
    assert!(result.is_some());

    // Build a table model for the program
    let mut table = AddressBasedTableModel::new(vec!["Function", "Entry", "Size"]);
    table.add_row(Address::new(0x401000), vec!["main".into(), "0x401000".into(), "256".into()]);

    let mut filter = GhidraFilterTable::new(table);
    filter.set_filter("main");
    assert_eq!(filter.filtered_row_count(), 1);
    assert_eq!(filter.get_filtered_address(0), Some(Address::new(0x401000)));
}
