//! Integration tests for newly added Features/Base plugin types.
//!
//! Covers:
//! - Module-specific table row mappers (function, comment, data, scalar, source, relocation)
//! - ValidateProgramDialog model
//! - DataRefEdge attribute access
//! - Cross-module type interactions

use ghidra_features::table_mapper::*;
use ghidra_features::validator::*;

// ============================================================================
// Table Row Mapper integration tests
// ============================================================================

mod table_mapper_integration {
    use super::*;

    #[test]
    fn test_function_workflow() {
        // Create a function row object and map it through all applicable mappers
        let func = FunctionRowObject::new(
            "process_input",
            "0x08048000",
            "cdecl",
            "int process_input(char *buf, int len)",
        );

        // Address mapping
        let addr = FunctionRowObjectToAddressRowMapper.map(&func).unwrap();
        assert_eq!(addr, "0x08048000");

        // ProgramLocation mapping
        let loc = FunctionRowObjectToProgramLocationRowMapper.map(&func).unwrap();
        assert_eq!(loc, "0x08048000");

        // Identity mapping preserves all data
        let identity = FunctionRowObjectToFunctionRowMapper.map(&func).unwrap();
        assert_eq!(identity.name, "process_input");
        assert_eq!(identity.signature, "int process_input(char *buf, int len)");
    }

    #[test]
    fn test_comment_workflow() {
        // Create comment objects of different types
        let eol_comment = CommentRowObject::new("0x1000", "loop counter", "EOL");
        let pre_comment = CommentRowObject::new("0x1004", "function prologue", "Pre");
        let post_comment = CommentRowObject::new("0x1008", "epilogue begins", "Post");
        let plate_comment = CommentRowObject::new("0x2000", "=== MAIN ===", "Plate");

        // All comment types should map to addresses
        assert_eq!(
            CommentRowObjectToAddressRowMapper.map(&eol_comment).unwrap(),
            "0x1000"
        );
        assert_eq!(
            CommentRowObjectToAddressRowMapper.map(&pre_comment).unwrap(),
            "0x1004"
        );
        assert_eq!(
            CommentRowObjectToAddressRowMapper.map(&post_comment).unwrap(),
            "0x1008"
        );
        assert_eq!(
            CommentRowObjectToAddressRowMapper.map(&plate_comment).unwrap(),
            "0x2000"
        );

        // ProgramLocation mapping
        assert_eq!(
            CommentRowObjectToProgramLocationRowMapper
                .map(&plate_comment)
                .unwrap(),
            "0x2000"
        );
    }

    #[test]
    fn test_data_workflow() {
        let int_data = DataRowObject::new("0x3000", "int", "42");
        let ptr_data = DataRowObject::new("0x3004", "pointer", "0x8048000");
        let str_data = DataRowObject::new("0x3008", "string[16]", "\"hello world\"");

        assert_eq!(
            DataRowObjectToAddressRowMapper.map(&int_data).unwrap(),
            "0x3000"
        );
        assert_eq!(
            DataRowObjectToAddressRowMapper.map(&ptr_data).unwrap(),
            "0x3004"
        );
        assert_eq!(
            DataRowObjectToAddressRowMapper.map(&str_data).unwrap(),
            "0x3008"
        );
    }

    #[test]
    fn test_scalar_workflow() {
        // Small scalar (8-bit)
        let small = ScalarRowObject::new("0x4000", 0xFF, 8);
        assert_eq!(
            ScalarRowObjectToAddressRowMapper.map(&small).unwrap(),
            "0x4000"
        );

        // Large scalar (32-bit)
        let large = ScalarRowObject::new("0x4004", 0xDEADBEEF, 32);
        assert_eq!(
            ScalarRowObjectToAddressRowMapper.map(&large).unwrap(),
            "0x4004"
        );

        // 64-bit scalar
        let huge = ScalarRowObject::new("0x4008", 0xFFFFFFFFFFFFFFFF, 64);
        assert_eq!(
            ScalarRowObjectToProgramLocationRowMapper
                .map(&huge)
                .unwrap(),
            "0x4008"
        );
    }

    #[test]
    fn test_source_map_workflow() {
        let entry_with_line = SourceMapEntryRowObject::new("main.c", "0x5000", Some(42));
        let entry_no_line = SourceMapEntryRowObject::new("utils.h", "0x5100", None);

        assert_eq!(
            SourceMapEntryToAddressRowMapper
                .map(&entry_with_line)
                .unwrap(),
            "0x5000"
        );
        assert_eq!(
            SourceMapEntryToAddressRowMapper
                .map(&entry_no_line)
                .unwrap(),
            "0x5100"
        );

        assert_eq!(
            SourceMapEntryToProgramLocationRowMapper
                .map(&entry_with_line)
                .unwrap(),
            "0x5000"
        );
    }

    #[test]
    fn test_relocation_workflow() {
        let abs_reloc = RelocationRowObject::new("0x6000", "ABSOLUTE", 0x08048000);
        let rel_reloc = RelocationRowObject::new("0x6004", "RELATIVE", 0x00001000);

        assert_eq!(
            RelocationToAddressRowMapper.map(&abs_reloc).unwrap(),
            "0x6000"
        );
        assert_eq!(
            RelocationToAddressRowMapper.map(&rel_reloc).unwrap(),
            "0x6004"
        );
    }

    #[test]
    fn test_all_mappers_have_unique_names() {
        let names = vec![
            FunctionRowObjectToAddressRowMapper.name().to_string(),
            FunctionRowObjectToProgramLocationRowMapper
                .name()
                .to_string(),
            FunctionRowObjectToFunctionRowMapper.name().to_string(),
            CommentRowObjectToAddressRowMapper.name().to_string(),
            CommentRowObjectToProgramLocationRowMapper.name().to_string(),
            DataRowObjectToAddressRowMapper.name().to_string(),
            DataRowObjectToProgramLocationRowMapper.name().to_string(),
            ScalarRowObjectToAddressRowMapper.name().to_string(),
            ScalarRowObjectToProgramLocationRowMapper.name().to_string(),
            SourceMapEntryToAddressRowMapper.name().to_string(),
            SourceMapEntryToProgramLocationRowMapper.name().to_string(),
            RelocationToAddressRowMapper.name().to_string(),
        ];

        // All names should be unique
        let mut sorted = names.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(names.len(), sorted.len(), "All mapper names should be unique");
    }

    #[test]
    fn test_mappers_are_not_one_to_many() {
        // All our mappers should be one-to-one
        assert!(!FunctionRowObjectToAddressRowMapper.is_one_to_many());
        assert!(!CommentRowObjectToAddressRowMapper.is_one_to_many());
        assert!(!DataRowObjectToAddressRowMapper.is_one_to_many());
        assert!(!ScalarRowObjectToAddressRowMapper.is_one_to_many());
        assert!(!SourceMapEntryToAddressRowMapper.is_one_to_many());
        assert!(!RelocationToAddressRowMapper.is_one_to_many());
    }
}

// ============================================================================
// ValidateProgramDialog integration tests
// ============================================================================

mod validator_dialog_integration {
    use super::*;

    #[test]
    fn test_dialog_full_workflow() {
        let mut dialog = ValidateProgramDialog::new("Validate ELF Binary");

        // Configure validators
        assert_eq!(dialog.validators().len(), 6);
        dialog.set_validator_enabled("External Reference Validator", false);
        assert_eq!(dialog.enabled_validators().len(), 5);

        // Set options
        dialog.set_auto_apply_fixes(true);
        assert!(dialog.auto_apply_fixes());

        // Accept dialog
        dialog.accept();
        assert!(dialog.is_accepted());

        // Simulate validation results
        let mut result = ValidationResult::new();
        result.add_message(ValidationMessage::new(
            ValidationSeverity::Error,
            "Dangling reference at 0x401000",
            "Memory Reference Validator",
        ));
        result.add_message(ValidationMessage::new(
            ValidationSeverity::Warning,
            "Unresolved external: printf",
            "Cross-Reference Validator",
        ));
        result.add_message(ValidationMessage::with_address(
            ValidationSeverity::Critical,
            "Overlapping data definitions",
            "Defined Data Validator",
            0x402000,
        ));
        result.elapsed_ms = 150;

        dialog.set_result(result);

        // Verify results
        let result = dialog.result().unwrap();
        assert_eq!(result.error_count(), 2); // Error + Critical
        assert_eq!(result.warning_count(), 1);
        assert_eq!(result.messages().len(), 3);
        assert!(!result.is_clean());
        assert!(!result.aborted);

        // Verify summary
        let summary = dialog.result_summary().unwrap();
        assert!(summary.contains("2 errors"));
        assert!(summary.contains("1 warnings"));
        assert!(summary.contains("3 total messages"));
    }

    #[test]
    fn test_dialog_serialization_roundtrip() {
        let mut dialog = ValidateProgramDialog::new("Test");
        dialog.set_auto_apply_fixes(true);
        dialog.accept();

        // Serialize to JSON
        let json = serde_json::to_string(&dialog).unwrap();
        assert!(json.contains("auto_apply_fixes"));

        // Deserialize
        let restored: ValidateProgramDialog = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.title(), "Test");
        assert!(restored.auto_apply_fixes());
        assert!(restored.is_accepted());
        assert_eq!(restored.validators().len(), 6);
    }

    #[test]
    fn test_validation_result_serialization() {
        let mut result = ValidationResult::new();
        result.add_message(ValidationMessage::with_address(
            ValidationSeverity::Error,
            "test error",
            "test source",
            0x1000,
        ));

        let json = serde_json::to_string(&result).unwrap();
        let restored: ValidationResult = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.messages().len(), 1);
        assert_eq!(restored.messages()[0].address, Some(0x1000));
    }

    #[test]
    fn test_dialog_enable_disable_all() {
        let mut dialog = ValidateProgramDialog::new("Test");

        // Disable all
        dialog.set_all_enabled(false);
        assert!(dialog.enabled_validators().is_empty());

        // Enable all
        dialog.set_all_enabled(true);
        assert_eq!(dialog.enabled_validators().len(), 6);

        // Disable one
        dialog.set_validator_enabled("Memory Reference Validator", false);
        assert_eq!(dialog.enabled_validators().len(), 5);
        assert!(!dialog
            .enabled_validators()
            .contains(&"Memory Reference Validator"));
    }

    #[test]
    fn test_validator_entry_threshold() {
        let mut entry = ValidatorEntry::new("Test", "Description");
        assert!(entry.enabled);
        assert_eq!(entry.severity_threshold, ValidationSeverity::Warning);

        entry.severity_threshold = ValidationSeverity::Error;
        assert_eq!(entry.severity_threshold, ValidationSeverity::Error);
    }

    #[test]
    fn test_validation_severity_ordering_comprehensive() {
        // Test all ordering relationships
        assert!(ValidationSeverity::Info < ValidationSeverity::Warning);
        assert!(ValidationSeverity::Warning < ValidationSeverity::Error);
        assert!(ValidationSeverity::Error < ValidationSeverity::Critical);

        // Test is_problem
        assert!(!ValidationSeverity::Info.is_problem());
        assert!(ValidationSeverity::Warning.is_problem());
        assert!(ValidationSeverity::Error.is_problem());
        assert!(ValidationSeverity::Critical.is_problem());

        // Test display names
        assert_eq!(ValidationSeverity::Info.display_name(), "Info");
        assert_eq!(ValidationSeverity::Warning.display_name(), "Warning");
        assert_eq!(ValidationSeverity::Error.display_name(), "Error");
        assert_eq!(ValidationSeverity::Critical.display_name(), "Critical");
    }

    #[test]
    fn test_result_max_messages() {
        let mut result = ValidationResult::new();
        for i in 0..MAX_MESSAGES + 100 {
            result.add_message(ValidationMessage::new(
                ValidationSeverity::Info,
                format!("message {}", i),
                "test",
            ));
        }
        assert!(result.aborted);
        assert_eq!(result.messages().len(), MAX_MESSAGES);
    }
}

// ============================================================================
// Cross-module integration tests
// ============================================================================

mod cross_module_integration {
    use super::*;
    use ghidra_features::base::checksums::{
        Adler32Algorithm, BasicChecksum, ChecksumAlgorithm, ChecksumBitSize, ChecksumOptions,
        Crc16Algorithm, Crc16CcittAlgorithm, Crc32Algorithm, DigestChecksum, DigestType,
    };

    #[test]
    fn test_checksum_algorithms_exist() {
        // Verify all named checksum algorithms are accessible
        let basic8 = BasicChecksum::new(ChecksumBitSize::Bits8);
        let basic16 = BasicChecksum::new(ChecksumBitSize::Bits16);
        let basic32 = BasicChecksum::new(ChecksumBitSize::Bits32);
        let crc16 = Crc16Algorithm::new();
        let crc16ccitt = Crc16CcittAlgorithm::new();
        let crc32 = Crc32Algorithm::new();
        let adler = Adler32Algorithm::new();
        let md5 = DigestChecksum::new(DigestType::Md5);
        let sha1 = DigestChecksum::new(DigestType::Sha1);
        let sha256 = DigestChecksum::new(DigestType::Sha256);

        let opts = ChecksumOptions::default();
        let data = b"Hello, World!";

        // All should produce non-empty results
        assert!(!basic8.compute(data, &opts).is_empty());
        assert!(!basic16.compute(data, &opts).is_empty());
        assert!(!basic32.compute(data, &opts).is_empty());
        assert!(!crc16.compute(data, &opts).is_empty());
        assert!(!crc16ccitt.compute(data, &opts).is_empty());
        assert!(!crc32.compute(data, &opts).is_empty());
        assert!(!adler.compute(data, &opts).is_empty());
        assert!(!md5.compute(data, &opts).is_empty());
        assert!(!sha1.compute(data, &opts).is_empty());
        assert!(!sha256.compute(data, &opts).is_empty());
    }

    #[test]
    fn test_calltree_with_mappers() {
        use ghidra_features::calltree::*;
        use ghidra_core::Address;

        // Build a call tree
        let mut builder = CallTreeBuilder::new();
        builder.add_function(FunctionRef::new("main", Address::new(0x1000)));
        builder.add_function(FunctionRef::new("process", Address::new(0x2000)));
        builder.add_call(Address::new(0x1000), Address::new(0x2000), CallTreeEdgeType::Call);

        let tree = builder.build_outgoing(Address::new(0x1000), 10);
        assert_eq!(tree.root.name, "main");
        assert_eq!(tree.root.children.len(), 1);

        // Create a function row object from the tree data
        let func = FunctionRowObject::new(
            &tree.root.name,
            "0x1000",
            "cdecl",
            "int main()",
        );
        let addr = FunctionRowObjectToAddressRowMapper.map(&func).unwrap();
        assert_eq!(addr, "0x1000");
    }

    #[test]
    fn test_hover_with_scalar_mapper() {
        use ghidra_features::hover::*;
        use ghidra_core::Address;

        let mut model = HoverModel::new();
        let scalar = ScalarRowObject::new("0x401000", 0x41, 8); // 'A'

        // Map scalar to address
        let addr_str = ScalarRowObjectToAddressRowMapper.map(&scalar).unwrap();
        assert_eq!(addr_str, "0x401000");

        // Add hover info at that address
        model.add_entry(HoverInfo::new(
            HoverElementType::Variable,
            Address::new(0x401000),
            "Scalar: 0x41 ('A')",
        ));
        assert_eq!(model.count(), 1);

        // Verify hover
        let entries = model.get_hover_at(Address::new(0x401000));
        assert_eq!(entries.len(), 1);
        assert!(entries[0].display_text.contains("0x41"));
    }
}
