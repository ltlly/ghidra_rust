//! Integration tests for the Exporter Plugin module.
//!
//! Tests the ExporterDialogModel, FrontEndExportAction, ToolExportAction,
//! ExportResult, and ValidationStatus ported from Ghidra's
//! `ghidra.app.plugin.core.exporter` Java package (ExporterPlugin.java
//! and ExporterDialog.java).

use ghidra_features::exporter::*;
use ghidra_features::loader::framework::MessageLog as LoaderMessageLog;

// ============================================================================
// ExportResult integration tests
// ============================================================================

#[test]
fn test_export_result_success_lifecycle() {
    let mut result = ExportResult::success("/tmp/output.bin", 4096, "Raw Binary (*.bin)");
    assert!(result.success);
    assert_eq!(result.output_path, "/tmp/output.bin");
    assert_eq!(result.output_size, 4096);
    assert_eq!(result.format_name, "Raw Binary (*.bin)");
    assert!(!result.exported_domain_file);

    result.exported_domain_file = true;
    assert!(result.exported_domain_file);

    result.add_message("Exported 4096 bytes from 2 memory blocks");
    result.add_message("No warnings");
    assert_eq!(result.messages.len(), 2);

    let summary = result.summary();
    assert!(summary.contains("/tmp/output.bin"));
    assert!(summary.contains("4096"));
    assert!(summary.contains("Raw Binary"));
    assert!(summary.contains("Exported 4096 bytes"));
    assert!(summary.contains("No warnings"));
}

#[test]
fn test_export_result_failure_with_messages() {
    let mut result = ExportResult::failure("/tmp/out.bin", "Intel Hex");
    assert!(!result.success);
    result.add_message("Address space exceeds 32-bit limit");
    let summary = result.summary();
    assert!(summary.contains("Address space exceeds 32-bit"));
    assert!(result.to_string().contains("failed"));
}

// ============================================================================
// ValidationStatus integration tests
// ============================================================================

#[test]
fn test_validation_status_full_lifecycle() {
    // Start with no format
    let status = ValidationStatus::NoFormatSelected;
    assert!(!status.is_valid());
    assert!(!status.is_warning());
    assert!(status.message().is_some());
    assert!(status.to_string().contains("format"));

    // Add format, no output file
    let status = ValidationStatus::NoOutputFile;
    assert!(!status.is_valid());
    assert!(status.to_string().contains("destination"));

    // Output is directory
    let status = ValidationStatus::OutputIsDirectory;
    assert!(!status.is_valid());

    // Read-only
    let status = ValidationStatus::OutputReadOnly;
    assert!(!status.is_valid());

    // XML warning (still valid)
    let status = ValidationStatus::XmlLossyWarning;
    assert!(status.is_valid());
    assert!(status.is_warning());
    assert!(status.message().unwrap().contains("XML is lossy"));

    // SARIF warning
    let status = ValidationStatus::SarifLossyWarning;
    assert!(status.is_valid());
    assert!(status.is_warning());

    // Overwrite warning
    let status = ValidationStatus::OverwriteWarning("/tmp/out.bin exists".into());
    assert!(status.is_valid());
    assert!(status.is_warning());

    // No applicable exporters
    let status = ValidationStatus::NoApplicableExporters;
    assert!(!status.is_valid());
    assert!(status.to_string().contains("No available exporters"));

    // Custom error
    let status = ValidationStatus::Error("Disk full".into());
    assert!(!status.is_valid());
    assert!(status.to_string().contains("Disk full"));
}

// ============================================================================
// ExporterDialogModel integration tests
// ============================================================================

#[test]
fn test_dialog_model_complete_workflow() {
    let mut dialog = ExporterDialogModel::new("malware_sample.exe");
    assert_eq!(dialog.domain_file_name(), "malware_sample.exe");
    assert!(!dialog.is_front_end_mode());

    // Set format
    dialog.set_format(ExportFormat::IntelHex);
    assert_eq!(dialog.selected_format(), Some(ExportFormat::IntelHex));

    // Set output path
    dialog.set_output_path("/tmp/malware_sample.hex");
    assert_eq!(dialog.output_path(), "/tmp/malware_sample.hex");

    // Validate (should be valid)
    let status = dialog.validate();
    assert!(status.is_valid(), "Expected valid, got: {}", status);

    // Execute export
    let prog = make_test_program();
    let mem = make_test_memory();
    let mut output = Vec::new();
    let mut log = LoaderMessageLog::new();

    let result = dialog.execute_export(&prog, Some(&mem), &mut output, &mut log);
    assert!(result.success);
    assert!(!output.is_empty());

    // Verify Intel HEX output format
    let text = String::from_utf8(output).unwrap();
    assert!(text.starts_with(":"));
    assert!(text.contains(":00000001FF"));

    // Verify events were recorded
    let events = dialog.events();
    assert!(events.len() >= 3); // format change, export started, export completed
}

#[test]
fn test_dialog_model_front_end_workflow() {
    let mut dialog = ExporterDialogModel::new_front_end("archive.gzf");
    assert!(dialog.is_front_end_mode());

    // Front-end mode: no selection checkbox
    dialog.set_has_selection(true);
    dialog.set_format(ExportFormat::Binary);
    assert!(!dialog.should_enable_selection_checkbox());

    dialog.set_output_path("/tmp/archive.bin");
    let status = dialog.validate();
    assert!(status.is_valid());
}

#[test]
fn test_dialog_model_domain_object_lifecycle() {
    let mut dialog = ExporterDialogModel::new("test.elf");
    dialog.set_format(ExportFormat::Binary);
    dialog.set_output_path("/tmp/out.bin");

    // Case 1: Domain object was supplied (already open)
    dialog.set_domain_object_supplied(true);
    let prog = make_test_program();
    let mem = make_test_memory();
    let mut output = Vec::new();
    let mut log = LoaderMessageLog::new();
    let result = dialog.execute_export(&prog, Some(&mem), &mut output, &mut log);
    assert!(result.success);
    assert!(!result.exported_domain_file);

    // Case 2: Domain file export (not opened)
    dialog.set_domain_object_supplied(false);
    let mut output2 = Vec::new();
    let mut log2 = LoaderMessageLog::new();
    let result2 = dialog.execute_export(&prog, Some(&mem), &mut output2, &mut log2);
    assert!(result2.success);
    assert!(result2.exported_domain_file);
}

#[test]
fn test_dialog_model_option_validation_comprehensive() {
    let mut dialog = ExporterDialogModel::new("test.elf");

    // Set up Intel HEX options
    dialog.set_format(ExportFormat::IntelHex);
    dialog.set_options(vec![
        ExportOption {
            name: "Record Size".into(),
            option_type: ExportOptionType::Integer,
            default_value: ExportOptionValue::Integer(16),
            description: Some("Number of data bytes per HEX record (max 255)".into()),
        },
        ExportOption {
            name: "Include Header".into(),
            option_type: ExportOptionType::Boolean,
            default_value: ExportOptionValue::Boolean(true),
            description: Some("Include header record".into()),
        },
        ExportOption {
            name: "Endianness".into(),
            option_type: ExportOptionType::Choice(vec!["Little".into(), "Big".into()]),
            default_value: ExportOptionValue::String("Little".into()),
            description: Some("Byte order".into()),
        },
    ]);

    // Valid integer option
    assert!(dialog
        .validate_option("Record Size", &ExportOptionValue::Integer(32))
        .is_ok());

    // Negative integer
    assert!(dialog
        .validate_option("Record Size", &ExportOptionValue::Integer(-1))
        .is_err());

    // Valid boolean option
    assert!(dialog
        .validate_option("Include Header", &ExportOptionValue::Boolean(false))
        .is_ok());

    // Valid choice
    assert!(dialog
        .validate_option("Endianness", &ExportOptionValue::String("Big".into()))
        .is_ok());

    // Invalid choice
    assert!(dialog
        .validate_option("Endianness", &ExportOptionValue::String("Middle".into()))
        .is_err());

    // Type mismatch
    assert!(dialog
        .validate_option("Include Header", &ExportOptionValue::String("yes".into()))
        .is_err());

    // Unknown option
    assert!(dialog
        .validate_option("NonExistent", &ExportOptionValue::Boolean(true))
        .is_err());
}

#[test]
fn test_dialog_model_output_path_extension_handling() {
    let mut dialog = ExporterDialogModel::new("program.exe");

    dialog.set_format(ExportFormat::Binary);
    assert_eq!(dialog.default_output_filename(), "program.exe.bin");

    // Already has extension
    dialog.set_output_path("/tmp/program.bin");
    assert_eq!(dialog.output_path_with_extension(), "/tmp/program.bin");

    // Missing extension
    dialog.set_output_path("/tmp/program");
    assert_eq!(dialog.output_path_with_extension(), "/tmp/program.bin");

    // Case insensitive
    dialog.set_output_path("/tmp/program.BIN");
    assert_eq!(dialog.output_path_with_extension(), "/tmp/program.BIN");

    // No format selected
    let mut dialog2 = ExporterDialogModel::new("test");
    dialog2.set_output_path("/tmp/test");
    assert_eq!(dialog2.output_path_with_extension(), "/tmp/test");

    // Empty path
    dialog.set_output_path("");
    assert_eq!(dialog.output_path_with_extension(), "");
}

#[test]
fn test_dialog_model_selection_checkbox_logic() {
    let mut dialog = ExporterDialogModel::new("test.elf");

    // No selection, no format
    assert!(!dialog.should_enable_selection_checkbox());

    // Has selection but no format
    dialog.set_has_selection(true);
    assert!(!dialog.should_enable_selection_checkbox());

    // Has selection and format (Binary supports address-restricted export)
    dialog.set_format(ExportFormat::Binary);
    assert!(dialog.should_enable_selection_checkbox());

    // Front-end mode disables it
    let mut fe_dialog = ExporterDialogModel::new_front_end("test.elf");
    fe_dialog.set_has_selection(true);
    fe_dialog.set_format(ExportFormat::Binary);
    assert!(!fe_dialog.should_enable_selection_checkbox());

    // Selection lost
    dialog.set_has_selection(false);
    assert!(!dialog.should_enable_selection_checkbox());
}

// ============================================================================
// FrontEndExportAction integration tests
// ============================================================================

#[test]
fn test_front_end_action_standard_context() {
    let action = FrontEndExportAction::new();

    // Standard: one program file selected
    let ctx = ProjectDataContext::new()
        .with_file(DomainFileInfo::new("my_program.elf", "ghidra.program.model.listing.Program"));
    assert!(action.is_enabled_for_context(&ctx));
    let file = action.get_selected_file(&ctx).unwrap();
    assert_eq!(file.name, "my_program.elf");
    assert_eq!(file.content_type, "ghidra.program.model.listing.Program");
}

#[test]
fn test_front_end_action_various_disabled_contexts() {
    let action = FrontEndExportAction::new();

    // Empty selection
    let ctx = ProjectDataContext::new();
    assert!(!action.is_enabled_for_context(&ctx));

    // Multiple files
    let ctx = ProjectDataContext::new()
        .with_file(DomainFileInfo::new("a.exe", "Program"))
        .with_file(DomainFileInfo::new("b.exe", "Program"));
    assert!(!action.is_enabled_for_context(&ctx));

    // Folder selected alongside file
    let ctx = ProjectDataContext::new()
        .with_file(DomainFileInfo::new("test.elf", "Program"))
        .with_folder("/MyFolder");
    assert!(!action.is_enabled_for_context(&ctx));

    // Folder link selected
    let ctx = ProjectDataContext::new()
        .with_file(DomainFileInfo::new_link("linked.elf", "Program", true));
    assert!(!action.is_enabled_for_context(&ctx));
}

#[test]
fn test_front_end_action_file_link_allowed() {
    let action = FrontEndExportAction::new();

    // File link (not folder link) should be allowed
    let ctx = ProjectDataContext::new()
        .with_file(DomainFileInfo::new_link("linked_program.elf", "Program", false));
    assert!(action.is_enabled_for_context(&ctx));
}

// ============================================================================
// ToolExportAction tests
// ============================================================================

#[test]
fn test_tool_action_menu_integration() {
    let action = ToolExportAction::new();

    assert_eq!(action.name, "Export Program");
    assert_eq!(action.menu_path, vec!["&File", "Export Program..."]);
    assert_eq!(action.menu_group, "Import Export");
    assert_eq!(action.menu_sub_group, "z");
    assert!(action.description.contains("exports a program"));
    assert!(action.help_topic.is_some());
    assert_eq!(action.help_topic.as_ref().unwrap().help_set, "ExporterPlugin");
    assert_eq!(action.help_topic.as_ref().unwrap().topic, "Export");
}

// ============================================================================
// Cross-module integration: all export formats through dialog model
// ============================================================================

#[test]
fn test_all_export_formats_through_dialog_model() {
    let prog = make_test_program();
    let mem = make_test_memory();

    for format in ExportFormat::all() {
        let mut dialog = ExporterDialogModel::new("test_binary");
        dialog.set_format(*format);
        dialog.set_output_path(format!("/tmp/test.{}", format.default_extension()));
        dialog.set_domain_object_supplied(true);

        let mut output = Vec::new();
        let mut log = LoaderMessageLog::new();
        let result = dialog.execute_export(&prog, Some(&mem), &mut output, &mut log);

        assert!(
            result.success,
            "Export failed for format {}: {:?}",
            format.display_name(),
            result.messages
        );
        assert!(
            !output.is_empty(),
            "Empty output for format {}",
            format.display_name()
        );
        assert_eq!(result.format_name, format.display_name());
    }
}

#[test]
fn test_dialog_model_registry_access() {
    let mut dialog = ExporterDialogModel::new("test.elf");

    // Access registry
    let names = dialog.registry().exporter_names();
    assert!(names.contains(&"Raw Bytes"));
    assert!(names.contains(&"Intel Hex"));
    assert!(names.contains(&"Motorola Hex"));
    assert!(names.contains(&"XML"));
    assert!(names.contains(&"HTML"));
    assert!(names.contains(&"Ascii Text"));

    // Register a custom exporter via mutable access
    dialog.registry_mut().register(Box::new(BinaryExporter::new()));
    assert_eq!(dialog.registry().exporter_names().len(), 7); // 6 defaults + 1 custom
}

// ============================================================================
// Helpers
// ============================================================================

fn make_test_program() -> ghidra_features::base::analyzer::Program {
    use ghidra_features::base::analyzer::{Address, AddressRange, Language, Program};

    let lang = Language {
        processor: "x86".into(),
        variant: "LE".into(),
        size: 64,
    };
    let mut prog = Program::new("test_binary", lang);
    prog.image_base = 0x400000;
    prog.memory
        .add_range(AddressRange::new(Address::new(0x400000), Address::new(0x40001F)));
    prog.symbols.insert(Address::new(0x400000), "_start".into());
    prog.symbols.insert(Address::new(0x400010), "main".into());
    prog
}

fn make_test_memory() -> MemoryModel {
    use ghidra_features::base::analyzer::Address;

    let mut mem = MemoryModel::new();
    for i in 0u8..32 {
        mem.set_byte(&Address::new(0x400000 + i as u64), i);
    }
    mem
}
