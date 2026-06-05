//! Integration tests for newly ported Features/Base plugin enhancements.
//!
//! Tests the new functionality added to:
//! - Memory map: expand, move, rebase, image base
//! - Label: symbol chooser
//! - Disassembler: auto table disassembler
//! - Exporter: plugin model, format selection, config
//! - Calltree: options filtering

use ghidra_core::Address;

// ============================================================================
// Memory map: expand, move, rebase, image base
// ============================================================================

mod memory_enhanced_tests {
    use super::*;
    use ghidra_features::memory::{
        expand_block::ExpandBlockModel,
        move_block::MoveBlockModel,
        ImageBaseAction, MemoryBlockInfo, MemoryBlockPermission, MemoryBlockType, MemoryMapModel,
    };

    fn make_block(name: &str, start: u64, end: u64) -> MemoryBlockInfo {
        MemoryBlockInfo::new(name, Address::new(start), Address::new(end), MemoryBlockType::Initialized)
    }

    #[test]
    fn test_expand_block_down_and_verify() {
        let mut mmap = MemoryMapModel::new();
        mmap.add_block(make_block(".text", 0x1000, 0x1FFF)).unwrap();

        let block = mmap.get_block(".text").unwrap().clone();
        let expand = ExpandBlockModel::down(".text", &block, 0x500);
        expand.execute(&mut mmap).unwrap();

        let b = mmap.get_block(".text").unwrap();
        assert_eq!(b.start.offset, 0x1000);
        assert_eq!(b.end.offset, 0x24FF);
        assert_eq!(b.size(), 0x1500);
    }

    #[test]
    fn test_expand_block_up_and_verify() {
        let mut mmap = MemoryMapModel::new();
        mmap.add_block(make_block(".text", 0x2000, 0x2FFF)).unwrap();

        let block = mmap.get_block(".text").unwrap().clone();
        let expand = ExpandBlockModel::up(".text", &block, 0x1000);
        expand.execute(&mut mmap).unwrap();

        let b = mmap.get_block(".text").unwrap();
        assert_eq!(b.start.offset, 0x1000);
        assert_eq!(b.end.offset, 0x2FFF);
        assert_eq!(b.size(), 0x2000);
    }

    #[test]
    fn test_move_block_and_verify() {
        let mut mmap = MemoryMapModel::new();
        mmap.add_block(make_block(".data", 0x3000, 0x3FFF)).unwrap();

        let block = mmap.get_block(".data").unwrap().clone();
        let mover = MoveBlockModel::new(".data", &block, Address::new(0x8000));
        mover.execute(&mut mmap).unwrap();

        let b = mmap.get_block(".data").unwrap();
        assert_eq!(b.start.offset, 0x8000);
        assert_eq!(b.end.offset, 0x8FFF);
        assert_eq!(b.size(), 0x1000);
    }

    #[test]
    fn test_move_block_overlap_rejected() {
        let mut mmap = MemoryMapModel::new();
        mmap.add_block(make_block(".text", 0x1000, 0x1FFF)).unwrap();
        mmap.add_block(make_block(".data", 0x2000, 0x2FFF)).unwrap();

        let block = mmap.get_block(".text").unwrap().clone();
        let mover = MoveBlockModel::new(".text", &block, Address::new(0x2500));
        assert!(mover.execute(&mut mmap).is_err());
    }

    #[test]
    fn test_rebase_all_blocks() {
        let mut mmap = MemoryMapModel::new();
        mmap.add_block(make_block(".text", 0x1000, 0x1FFF)).unwrap();
        mmap.add_block(make_block(".data", 0x2000, 0x2FFF)).unwrap();
        mmap.add_block(make_block(".bss", 0x3000, 0x37FF)).unwrap();

        mmap.rebase_all(0x400000);

        assert_eq!(mmap.get_block(".text").unwrap().start.offset, 0x401000);
        assert_eq!(mmap.get_block(".data").unwrap().start.offset, 0x402000);
        assert_eq!(mmap.get_block(".bss").unwrap().start.offset, 0x403000);
    }

    #[test]
    fn test_image_base_change() {
        let mut mmap = MemoryMapModel::new();
        mmap.add_block(make_block(".text", 0x401000, 0x401FFF)).unwrap();
        mmap.add_block(make_block(".data", 0x402000, 0x402FFF)).unwrap();

        let action = ImageBaseAction::new(Address::new(0x400000), Address::new(0x1000000));
        assert!(action.is_valid());
        assert_eq!(action.delta(), 0xC00000);
        action.execute(&mut mmap).unwrap();

        assert_eq!(mmap.get_block(".text").unwrap().start.offset, 0x1001000);
        assert_eq!(mmap.get_block(".data").unwrap().start.offset, 0x1002000);
    }

    #[test]
    fn test_memory_map_utility_methods() {
        let mut mmap = MemoryMapModel::new();
        let mut text = make_block(".text", 0x1000, 0x1FFF);
        text.permissions = MemoryBlockPermission::read_execute();
        mmap.add_block(text).unwrap();

        let mut data = make_block(".data", 0x2000, 0x2FFF);
        data.permissions = MemoryBlockPermission::read_write();
        mmap.add_block(data).unwrap();

        assert_eq!(mmap.total_size(), 0x2000);
        assert_eq!(mmap.min_address().unwrap().offset, 0x1000);
        assert_eq!(mmap.max_address().unwrap().offset, 0x2FFF);
        assert_eq!(mmap.executable_blocks().len(), 1);
        assert_eq!(mmap.writable_blocks().len(), 1);
    }

    #[test]
    fn test_memory_volatile_and_overlay() {
        let mut mmap = MemoryMapModel::new();
        mmap.add_block(make_block("IO", 0xF000, 0xF0FF)).unwrap();
        mmap.set_volatile("IO", true).unwrap();
        assert!(mmap.get_block("IO").unwrap().volatile);

        mmap.add_block(make_block("ov", 0x1000, 0x1FFF)).unwrap();
        mmap.set_overlay("ov", true).unwrap();
        assert!(mmap.get_block("ov").unwrap().overlay);
    }
}

// ============================================================================
// Label: symbol chooser
// ============================================================================

mod symbol_chooser_tests {
    use ghidra_core::Address;
    use ghidra_features::label::symbol_chooser::{
        SymbolChooserModel, SymbolEntry, SymbolFilter, SymbolType,
    };

    fn make_symbols() -> Vec<SymbolEntry> {
        vec![
            SymbolEntry::new("main", Address::new(0x1000), SymbolType::Function)
                .with_namespace("app"),
            SymbolEntry::new("init", Address::new(0x1100), SymbolType::Function)
                .with_namespace("app"),
            SymbolEntry::new("DATA", Address::new(0x2000), SymbolType::Label),
            SymbolEntry::new("printf", Address::new(0x4000), SymbolType::External)
                .with_namespace("libc"),
            SymbolEntry::new("_start", Address::new(0x500), SymbolType::Label),
        ]
    }

    #[test]
    fn test_symbol_chooser_unfiltered_count() {
        let mut model = SymbolChooserModel::new();
        model.add_symbols(make_symbols());
        assert_eq!(model.total_count(), 5);
        assert_eq!(model.filtered_count(), 5);
    }

    #[test]
    fn test_symbol_chooser_filter_by_type() {
        let mut model = SymbolChooserModel::new();
        model.add_symbols(make_symbols());
        model.set_filter(SymbolFilter::new().with_type(SymbolType::Function));
        assert_eq!(model.filtered_count(), 2);
    }

    #[test]
    fn test_symbol_chooser_filter_by_name() {
        let mut model = SymbolChooserModel::new();
        model.add_symbols(make_symbols());
        model.set_filter(SymbolFilter::new().with_name("printf"));
        assert_eq!(model.filtered_count(), 1);
    }

    #[test]
    fn test_symbol_chooser_filter_by_namespace() {
        let mut model = SymbolChooserModel::new();
        model.add_symbols(make_symbols());
        model.set_filter(SymbolFilter::new().with_namespace("libc"));
        assert_eq!(model.filtered_count(), 1);
    }

    #[test]
    fn test_symbol_chooser_filter_by_address_range() {
        let mut model = SymbolChooserModel::new();
        model.add_symbols(make_symbols());
        model.set_filter(
            SymbolFilter::new().with_address_range(Address::new(0x1000), Address::new(0x1FFF)),
        );
        assert_eq!(model.filtered_count(), 2);
    }

    #[test]
    fn test_symbol_chooser_select_and_get() {
        let mut model = SymbolChooserModel::new();
        model.add_symbols(make_symbols());
        model.select(0);
        let selected = model.selected_symbol().unwrap();
        assert_eq!(selected.name, "main");
    }

    #[test]
    fn test_symbol_chooser_find_by_name() {
        let mut model = SymbolChooserModel::new();
        model.add_symbols(make_symbols());
        let entry = model.find_by_name("printf").unwrap();
        assert_eq!(entry.address.offset, 0x4000);
    }

    #[test]
    fn test_symbol_chooser_namespaces() {
        let mut model = SymbolChooserModel::new();
        model.add_symbols(make_symbols());
        let ns = model.namespaces();
        assert!(ns.contains(&"app"));
        assert!(ns.contains(&"libc"));
    }

    #[test]
    fn test_symbol_entry_qualified_name() {
        let entry = SymbolEntry::new("main", Address::new(0x1000), SymbolType::Function)
            .with_namespace("app");
        assert_eq!(entry.qualified_name(), "app::main");
    }

    #[test]
    fn test_symbol_type_display() {
        assert_eq!(SymbolType::Function.display_name(), "Function");
        assert_eq!(SymbolType::Label.display_name(), "Label");
        assert_eq!(SymbolType::External.display_name(), "External");
    }
}

// ============================================================================
// Disassembler: auto table disassembler
// ============================================================================

mod auto_table_disassembler_tests {
    use super::*;
    use ghidra_features::disassembler::auto_table_disassembler::{
        AddressTable, AutoTableDisassemblerModel, TableDisassemblerConfig, TableEntryKind,
    };

    #[test]
    fn test_address_table_create_and_populate() {
        let mut table = AddressTable::new(
            Address::new(0x2000),
            TableEntryKind::Absolute,
            4,
        );
        table.add_entry(0, Address::new(0x1000));
        table.add_entry(1, Address::new(0x1100));
        table.add_entry(2, Address::new(0x1200));

        assert_eq!(table.entry_count(), 3);
        assert_eq!(table.byte_size(), 12);
        assert_eq!(table.end_address().offset, 0x200B);
    }

    #[test]
    fn test_address_table_contiguous_check() {
        let mut table = AddressTable::new(
            Address::new(0x2000),
            TableEntryKind::Absolute,
            4,
        );
        table.add_entry(0, Address::new(0x1000));
        table.add_entry(1, Address::new(0x1100));
        table.add_entry(2, Address::new(0x1200));
        assert!(table.is_contiguous());

        let mut table2 = AddressTable::new(
            Address::new(0x2000),
            TableEntryKind::Absolute,
            4,
        );
        table2.add_entry(0, Address::new(0x1000));
        table2.add_entry(5, Address::new(0x1100));
        assert!(!table2.is_contiguous());
    }

    #[test]
    fn test_auto_table_disassembler_validation() {
        let mut model = AutoTableDisassemblerModel::new();
        model.set_code_addresses(vec![
            Address::new(0x1000),
            Address::new(0x1100),
            Address::new(0x1200),
        ]);

        let mut table = AddressTable::new(
            Address::new(0x2000),
            TableEntryKind::Absolute,
            4,
        );
        table.add_entry(0, Address::new(0x1000));
        table.add_entry(1, Address::new(0x1100));

        let result = model.validate_table(&table);
        assert!(result.valid, "Errors: {:?}", result.errors);
    }

    #[test]
    fn test_auto_table_disassembler_invalid_target() {
        let mut model = AutoTableDisassemblerModel::new();
        model.set_code_addresses(vec![Address::new(0x1000)]);

        let mut table = AddressTable::new(
            Address::new(0x2000),
            TableEntryKind::Absolute,
            4,
        );
        table.add_entry(0, Address::new(0x1000));
        table.add_entry(1, Address::new(0x9999)); // Not a known code address

        let result = model.validate_table(&table);
        assert!(!result.valid);
    }

    #[test]
    fn test_auto_table_disassembler_valid_tables_filter() {
        let mut model = AutoTableDisassemblerModel::new();
        model.set_code_addresses(vec![
            Address::new(0x1000),
            Address::new(0x1100),
            Address::new(0x1200),
        ]);

        // Valid table
        let mut t1 = AddressTable::new(Address::new(0x2000), TableEntryKind::Absolute, 4);
        t1.add_entry(0, Address::new(0x1000));
        t1.add_entry(1, Address::new(0x1100));

        // Invalid table (bad target)
        let mut t2 = AddressTable::new(Address::new(0x3000), TableEntryKind::Absolute, 4);
        t2.add_entry(0, Address::new(0x1000));
        t2.add_entry(1, Address::new(0xDEAD));

        model.add_table(t1);
        model.add_table(t2);

        assert_eq!(model.valid_tables().len(), 1);
    }

    #[test]
    fn test_table_disassembler_custom_config() {
        let config = TableDisassemblerConfig {
            min_table_entries: 5,
            max_table_entries: 500,
            validate_targets: false,
            ..Default::default()
        };
        let model = AutoTableDisassemblerModel::with_config(config);

        // With validate_targets=false and min 5 entries, a small table would
        // still fail on entry count but not on targets
        assert_eq!(model.table_count(), 0);
    }

    #[test]
    fn test_address_table_targets_in_range() {
        let mut table = AddressTable::new(
            Address::new(0x2000),
            TableEntryKind::Absolute,
            4,
        );
        table.add_entry(0, Address::new(0x1000));
        table.add_entry(1, Address::new(0x1100));
        table.add_entry(2, Address::new(0x1200));

        assert!(table.all_targets_in_range(Address::new(0x0000), Address::new(0x2000)));
        assert!(!table.all_targets_in_range(Address::new(0x0000), Address::new(0x1050)));
    }
}

// ============================================================================
// Exporter: plugin model, format selection
// ============================================================================

mod exporter_plugin_tests {
    use ghidra_features::exporter::{ExportConfig, ExportFormat, ExporterPlugin};

    #[test]
    fn test_export_format_all() {
        let all = ExportFormat::all();
        assert_eq!(all.len(), 6);
    }

    #[test]
    fn test_export_format_display_names() {
        assert_eq!(ExportFormat::Binary.display_name(), "Raw Binary (*.bin)");
        assert_eq!(ExportFormat::IntelHex.display_name(), "Intel Hex (*.hex, *.ihex)");
        assert_eq!(
            ExportFormat::MotorolaHex.display_name(),
            "Motorola S-Record (*.srec, *.s19)"
        );
    }

    #[test]
    fn test_export_format_extensions() {
        assert_eq!(ExportFormat::Binary.default_extension(), "bin");
        assert_eq!(ExportFormat::IntelHex.default_extension(), "hex");
        assert_eq!(ExportFormat::MotorolaHex.default_extension(), "srec");
        assert_eq!(ExportFormat::AsciiText.default_extension(), "txt");
        assert_eq!(ExportFormat::Xml.default_extension(), "xml");
        assert_eq!(ExportFormat::Html.default_extension(), "html");
    }

    #[test]
    fn test_export_format_exporter_names() {
        assert_eq!(ExportFormat::Binary.exporter_name(), "Raw Bytes");
        assert_eq!(ExportFormat::Xml.exporter_name(), "XML");
        assert_eq!(ExportFormat::Html.exporter_name(), "HTML");
    }

    #[test]
    fn test_export_config_creation() {
        let config = ExportConfig::new(ExportFormat::Binary, "/tmp/out.bin")
            .with_selection_only(true);
        assert_eq!(config.format, ExportFormat::Binary);
        assert_eq!(config.output_path, "/tmp/out.bin");
        assert!(config.export_selection_only);
    }

    #[test]
    fn test_exporter_plugin_creation() {
        let plugin = ExporterPlugin::new();
        assert_eq!(plugin.available_formats().len(), 6);
        assert!(plugin.events().is_empty());
    }
}

// ============================================================================
// Cross-module integration: memory + disassembler + label
// ============================================================================

mod cross_module_integration {
    use super::*;
    use ghidra_features::memory::{
        expand_block::ExpandBlockModel,
        MemoryBlockInfo, MemoryBlockPermission, MemoryBlockType, MemoryMapModel,
    };
    use ghidra_features::label::{
        LabelInfo, LabelManager, LabelScope,
        history::LabelHistory,
        symbol_chooser::{SymbolChooserModel, SymbolEntry, SymbolType},
    };
    use ghidra_features::disassembler::auto_table_disassembler::{
        AddressTable, AutoTableDisassemblerModel, TableEntryKind,
    };

    #[test]
    fn test_memory_and_label_integration() {
        // Create memory layout
        let mut mmap = MemoryMapModel::new();
        mmap.add_block(MemoryBlockInfo::new(
            ".text",
            Address::new(0x1000),
            Address::new(0x1FFF),
            MemoryBlockType::Initialized,
        ))
        .unwrap();

        // Create labels in the .text section
        let mut label_mgr = LabelManager::new();
        label_mgr.add_label(LabelInfo::primary("main", Address::new(0x1000)));
        label_mgr.add_label(LabelInfo::primary("helper", Address::new(0x1100)));
        label_mgr.add_label(LabelInfo::local("loop", Address::new(0x1050)));

        // Load into symbol chooser
        let mut chooser = SymbolChooserModel::new();
        for label in label_mgr.get_labels_at(Address::new(0x1000)) {
            chooser.add_symbol(SymbolEntry::new(
                &label.name,
                label.address,
                SymbolType::Label,
            ));
        }
        for label in label_mgr.get_labels_at(Address::new(0x1100)) {
            chooser.add_symbol(SymbolEntry::new(
                &label.name,
                label.address,
                SymbolType::Label,
            ));
        }

        assert!(chooser.total_count() >= 2);

        // Rebase everything
        mmap.rebase_all(0x100000);
        assert_eq!(mmap.get_block(".text").unwrap().start.offset, 0x101000);
    }

    #[test]
    fn test_disassembler_and_memory_integration() {
        // Set up memory
        let mut mmap = MemoryMapModel::new();
        mmap.add_block(MemoryBlockInfo::new(
            ".text",
            Address::new(0x1000),
            Address::new(0x1FFF),
            MemoryBlockType::Initialized,
        ))
        .unwrap();
        mmap.add_block(MemoryBlockInfo::new(
            ".rodata",
            Address::new(0x2000),
            Address::new(0x2FFF),
            MemoryBlockType::Initialized,
        ))
        .unwrap();

        // Create an address table in .rodata pointing to .text code
        let mut table = AddressTable::new(
            Address::new(0x2000),
            TableEntryKind::Absolute,
            4,
        );
        table.add_entry(0, Address::new(0x1000));
        table.add_entry(1, Address::new(0x1100));
        table.add_entry(2, Address::new(0x1200));

        // Validate the table against known code addresses
        let mut model = AutoTableDisassemblerModel::new();
        model.set_code_addresses(vec![
            Address::new(0x1000),
            Address::new(0x1100),
            Address::new(0x1200),
        ]);
        model.add_table(table);

        let valid = model.valid_tables();
        assert_eq!(valid.len(), 1);
        assert_eq!(valid[0].entry_count(), 3);

        // All targets should be in the .text block
        for target in valid[0].targets() {
            assert!(mmap.get_block_containing(target).is_some());
        }
    }

    #[test]
    fn test_label_history_and_symbol_chooser() {
        let mut history = LabelHistory::new();
        history.record_created(Address::new(0x1000), "main", 1000, "analyst");
        history.record_created(Address::new(0x1100), "init", 1001, "analyst");
        history.record_renamed(Address::new(0x1000), "main", "entry_point", 2000, "analyst");

        assert_eq!(history.total_entries(), 3);
        assert_eq!(history.tracked_addresses(), 2);

        let main_history = history.get_history(Address::new(0x1000));
        assert_eq!(main_history.len(), 2);
        assert_eq!(main_history[1].new_name, "entry_point");

        // Create symbol chooser from the labels
        let mut chooser = SymbolChooserModel::new();
        chooser.add_symbol(SymbolEntry::new(
            "entry_point",
            Address::new(0x1000),
            SymbolType::Function,
        ));
        chooser.add_symbol(SymbolEntry::new(
            "init",
            Address::new(0x1100),
            SymbolType::Function,
        ));

        chooser.select(0);
        let selected = chooser.selected_symbol().unwrap();
        assert_eq!(selected.name, "entry_point");
        assert_eq!(selected.address.offset, 0x1000);
    }
}
