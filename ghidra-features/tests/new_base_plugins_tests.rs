//! Integration tests for the newly ported top-level feature modules:
//! `console`, `function`, `references`, and `register`.
//!
//! These modules re-export from `base::*` and add feature-level types.

// ===========================================================================
// Console module tests
// ===========================================================================

#[cfg(test)]
mod console_tests {
    use ghidra_features::console::*;

    #[test]
    fn test_console_buffer_new() {
        let buf = ConsoleBuffer::new(500);
        assert_eq!(buf.max_size(), 500);
        assert!(buf.is_empty());
        assert_eq!(buf.len(), 0);
    }

    #[test]
    fn test_console_buffer_default_capacity() {
        let buf = ConsoleBuffer::default();
        assert_eq!(buf.max_size(), 10000);
    }

    #[test]
    fn test_console_buffer_add_info() {
        let mut buf = ConsoleBuffer::new(100);
        buf.add_info("analysis", "Starting auto-analysis");
        assert_eq!(buf.len(), 1);
        assert_eq!(buf.error_count(), 0);
    }

    #[test]
    fn test_console_buffer_add_error() {
        let mut buf = ConsoleBuffer::new(100);
        buf.add_error("loader", "Failed to parse header");
        assert_eq!(buf.len(), 1);
        assert_eq!(buf.error_count(), 1);
    }

    #[test]
    fn test_console_buffer_add_warning() {
        let mut buf = ConsoleBuffer::new(100);
        buf.add_warning("analyzer", "Suspicious code pattern");
        assert_eq!(buf.warning_count(), 1);
    }

    #[test]
    fn test_console_buffer_mixed_messages() {
        let mut buf = ConsoleBuffer::new(100);
        buf.add_info("s", "info1");
        buf.add_error("s", "error1");
        buf.add_warning("s", "warn1");
        buf.add_info("s", "info2");
        assert_eq!(buf.len(), 4);
        assert_eq!(buf.error_count(), 1);
        assert_eq!(buf.warning_count(), 1);
    }

    #[test]
    fn test_console_buffer_ring_eviction() {
        let mut buf = ConsoleBuffer::new(5);
        for i in 0..10 {
            buf.add_info("s", format!("msg{}", i));
        }
        assert_eq!(buf.len(), 5);
        let first = buf.iter().next().unwrap();
        assert_eq!(first.text, "msg5"); // msg0-msg4 evicted
    }

    #[test]
    fn test_console_buffer_filter_by_source() {
        let mut buf = ConsoleBuffer::new(100);
        buf.add_info("script", "a");
        buf.add_info("plugin", "b");
        buf.add_error("script", "c");
        let script_msgs = buf.messages_by_source("script");
        assert_eq!(script_msgs.len(), 2);
        let plugin_msgs = buf.messages_by_source("plugin");
        assert_eq!(plugin_msgs.len(), 1);
    }

    #[test]
    fn test_console_buffer_filter_by_type() {
        let mut buf = ConsoleBuffer::new(100);
        buf.add_info("s", "a");
        buf.add_error("s", "b");
        buf.add_info("s", "c");
        buf.add_warning("s", "d");
        assert_eq!(buf.messages_by_type(ConsoleMessageType::Info).len(), 2);
        assert_eq!(buf.messages_by_type(ConsoleMessageType::Error).len(), 1);
        assert_eq!(buf.messages_by_type(ConsoleMessageType::Warning).len(), 1);
    }

    #[test]
    fn test_console_buffer_last_n() {
        let mut buf = ConsoleBuffer::new(100);
        for i in 0..20 {
            buf.add_info("s", format!("line{}", i));
        }
        let last5 = buf.last_n(5);
        assert_eq!(last5.len(), 5);
        assert_eq!(last5[0].text, "line15");
        assert_eq!(last5[4].text, "line19");
    }

    #[test]
    fn test_console_buffer_last_n_more_than_available() {
        let mut buf = ConsoleBuffer::new(100);
        buf.add_info("s", "only_one");
        let last10 = buf.last_n(10);
        assert_eq!(last10.len(), 1);
    }

    #[test]
    fn test_console_buffer_to_text() {
        let mut buf = ConsoleBuffer::new(100);
        buf.add_info("loader", "binary loaded");
        buf.add_error("analyzer", "crash detected");
        let text = buf.to_text();
        assert!(text.contains("[INFO] loader: binary loaded"));
        assert!(text.contains("[ERROR] analyzer: crash detected"));
    }

    #[test]
    fn test_console_buffer_clear() {
        let mut buf = ConsoleBuffer::new(100);
        buf.add_info("s", "a");
        buf.add_info("s", "b");
        assert_eq!(buf.len(), 2);
        buf.clear();
        assert!(buf.is_empty());
        assert_eq!(buf.error_count(), 0);
    }

    #[test]
    fn test_console_message_format_variants() {
        let info = ConsoleMessage::new("s", "text", ConsoleMessageType::Info);
        assert_eq!(info.format(), "[INFO] s: text");

        let err = ConsoleMessage::new("s", "text", ConsoleMessageType::Error);
        assert_eq!(err.format(), "[ERROR] s: text");

        let warn = ConsoleMessage::new("s", "text", ConsoleMessageType::Warning);
        assert_eq!(warn.format(), "[WARN] s: text");
    }

    #[test]
    fn test_console_message_type_display() {
        assert_eq!(format!("{}", ConsoleMessageType::Info), "INFO");
        assert_eq!(format!("{}", ConsoleMessageType::Error), "ERROR");
        assert_eq!(format!("{}", ConsoleMessageType::Warning), "WARN");
    }

    #[test]
    fn test_console_message_type_default() {
        assert_eq!(ConsoleMessageType::default(), ConsoleMessageType::Info);
    }

    #[test]
    fn test_reexported_code_completion() {
        let cc = CodeCompletion::new("int main()", Some("main"));
        // Verify the type is accessible through the re-export
        let _ = cc;
    }

    #[test]
    fn test_reexported_console_word() {
        let word = ConsoleWord::new("analysis", 0, 8);
        let _ = word;
    }
}

// ===========================================================================
// Function module tests
// ===========================================================================

#[cfg(test)]
mod function_tests {
    use ghidra_features::function::*;

    #[test]
    fn test_function_tag_new() {
        let tag = FunctionTag::new("critical".to_string(), "High priority function".to_string());
        assert_eq!(tag.name(), "critical");
        assert_eq!(tag.description(), "High priority function");
        assert!(!tag.is_auto_created());
        assert_eq!(tag.id, 0);
    }

    #[test]
    fn test_function_tag_in_memory() {
        let tag = FunctionTag::in_memory("temp_tag".to_string());
        assert_eq!(tag.name(), "temp_tag");
        assert!(tag.description().is_empty());
    }

    #[test]
    fn test_function_tag_setters() {
        let mut tag = FunctionTag::new("old".to_string(), "desc".to_string());
        tag.set_name("new_name".to_string());
        tag.set_description("new description".to_string());
        tag.set_auto_created(true);
        assert_eq!(tag.name(), "new_name");
        assert_eq!(tag.description(), "new description");
        assert!(tag.is_auto_created());
    }

    #[test]
    fn test_function_tag_row_object() {
        let tag = FunctionTag::new("entry".to_string(), "".to_string());
        let row = FunctionTagRowObject::new(tag, 15);
        assert_eq!(row.name(), "entry");
        assert_eq!(row.function_count(), 15);
    }

    #[test]
    fn test_param_info_builder_minimal() {
        let param = ParamInfoBuilder::new(0, "x").build();
        assert_eq!(param.ordinal(), 0);
        assert_eq!(param.name(), "x");
        assert_eq!(param.data_type_name(), "undefined");
        assert!(!param.is_auto_parameter());
        assert!(!param.is_custom_storage());
    }

    #[test]
    fn test_param_info_builder_full() {
        let param = ParamInfoBuilder::new(2, "buffer")
            .data_type_name("char *")
            .auto_parameter()
            .custom_storage()
            .build();
        assert_eq!(param.ordinal(), 2);
        assert_eq!(param.name(), "buffer");
        assert_eq!(param.data_type_name(), "char *");
        assert!(param.is_auto_parameter());
        assert!(param.is_custom_storage());
    }

    #[test]
    fn test_function_editor_state_default() {
        let state = FunctionEditorState::default();
        assert!(!state.is_inline);
        assert!(!state.is_no_return);
        assert!(!state.is_varargs);
        assert!(state.calling_convention.is_none());
        assert!(state.call_fixup.is_none());
        assert!(!state.commit_signature);
    }

    #[test]
    fn test_function_editor_state_with_values() {
        let state = FunctionEditorState {
            is_inline: true,
            is_no_return: false,
            is_varargs: true,
            calling_convention: Some("thiscall".to_string()),
            call_fixup: Some("__stdcall".to_string()),
            commit_signature: true,
        };
        assert!(state.is_inline);
        assert!(state.is_varargs);
        assert_eq!(state.calling_convention.as_deref(), Some("thiscall"));
        assert_eq!(state.call_fixup.as_deref(), Some("__stdcall"));
        assert!(state.commit_signature);
    }

    #[test]
    fn test_stack_depth_change_event() {
        let event = StackDepthChangeEvent::new(0x400000, -8, Some(0));
        assert_eq!(event.address, 0x400000);
        assert_eq!(event.new_depth, -8);
        assert_eq!(event.old_depth, Some(0));
    }

    #[test]
    fn test_stack_depth_change_event_no_old() {
        let event = StackDepthChangeEvent::new(0x1000, -4, None);
        assert_eq!(event.old_depth, None);
    }

    #[test]
    fn test_reexported_function_tag_from_base() {
        // The function module also re-exports base::function::FunctionTag
        // (which is the same type as the top-level FunctionTag).
        // Verify both paths work.
        let tag = FunctionTag::in_memory("test".to_string());
        assert_eq!(tag.name(), "test");
    }
}

// ===========================================================================
// References module tests
// ===========================================================================

#[cfg(test)]
mod references_tests {
    use ghidra_features::references::*;

    #[test]
    fn test_reference_edit_state_memory() {
        let state = ReferenceEditState::new(EditPanelType::Memory);
        assert!(state.is_memory_panel());
        assert!(!state.is_stack_panel());
        assert!(!state.is_register_panel());
        assert!(!state.is_external_panel());
        assert!(!state.is_edit_mode);
        assert!(state.source_address.is_none());
        assert!(state.operand_index.is_none());
    }

    #[test]
    fn test_reference_edit_state_stack() {
        let state = ReferenceEditState::new(EditPanelType::Stack);
        assert!(state.is_stack_panel());
    }

    #[test]
    fn test_reference_edit_state_register() {
        let state = ReferenceEditState::new(EditPanelType::Register);
        assert!(state.is_register_panel());
    }

    #[test]
    fn test_reference_edit_state_external() {
        let state = ReferenceEditState::new(EditPanelType::External);
        assert!(state.is_external_panel());
    }

    #[test]
    fn test_reference_edit_state_with_address() {
        let mut state = ReferenceEditState::new(EditPanelType::Memory);
        state.is_edit_mode = true;
        state.source_address = Some(0x400000);
        state.operand_index = Some(1);
        assert!(state.is_edit_mode);
        assert_eq!(state.source_address, Some(0x400000));
        assert_eq!(state.operand_index, Some(1));
    }

    #[test]
    fn test_offset_table_dialog_model_defaults() {
        let model = OffsetTableDialogModel::new();
        assert!(model.base_address().is_none());
        assert!(!model.use_label_base());
        assert!(model.base_label().is_none());
        assert!(model.is_word_aligned());
        assert_eq!(model.pointer_size(), 4);
        assert!(!model.is_sign_extend());
    }

    #[test]
    fn test_offset_table_dialog_model_setters() {
        let mut model = OffsetTableDialogModel::new();
        model.set_base_address(0x10000);
        model.set_pointer_size(8);
        model.set_sign_extend(true);
        model.set_word_aligned(false);
        assert_eq!(model.base_address(), Some(0x10000));
        assert_eq!(model.pointer_size(), 8);
        assert!(model.is_sign_extend());
        assert!(!model.is_word_aligned());
    }

    #[test]
    fn test_offset_table_dialog_model_label_based() {
        let mut model = OffsetTableDialogModel::new();
        model.set_use_label_base(true);
        model.set_base_label("_GLOBAL_OFFSET_TABLE_".to_string());
        assert!(model.use_label_base());
        assert_eq!(model.base_label(), Some("_GLOBAL_OFFSET_TABLE_"));
    }

    #[test]
    fn test_offset_table_dialog_model_validate_no_base() {
        let model = OffsetTableDialogModel::new();
        let result = model.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Base address is required"));
    }

    #[test]
    fn test_offset_table_dialog_model_validate_with_address() {
        let mut model = OffsetTableDialogModel::new();
        model.set_base_address(0x400000);
        assert!(model.validate().is_ok());
    }

    #[test]
    fn test_offset_table_dialog_model_validate_label_empty() {
        let mut model = OffsetTableDialogModel::new();
        model.set_use_label_base(true);
        let result = model.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Base label is required"));
    }

    #[test]
    fn test_offset_table_dialog_model_validate_label_with_value() {
        let mut model = OffsetTableDialogModel::new();
        model.set_use_label_base(true);
        model.set_base_label("GOT".to_string());
        assert!(model.validate().is_ok());
    }

    #[test]
    fn test_offset_table_dialog_model_validate_bad_pointer_size() {
        let mut model = OffsetTableDialogModel::new();
        model.set_base_address(0x400000);

        model.set_pointer_size(0);
        assert!(model.validate().is_err());

        model.set_pointer_size(9);
        assert!(model.validate().is_err());

        model.set_pointer_size(4);
        assert!(model.validate().is_ok());

        model.set_pointer_size(8);
        assert!(model.validate().is_ok());
    }

    #[test]
    fn test_instruction_panel_state_default() {
        let state = InstructionPanelState::new();
        assert!(!state.has_instruction());
        assert!(!state.has_selected_operand());
        assert!(state.address.is_none());
        assert_eq!(state.operand_count, 0);
        assert!(!state.has_fall_through);
        assert!(!state.operand_has_references);
    }

    #[test]
    fn test_instruction_panel_state_with_instruction() {
        let mut state = InstructionPanelState::new();
        state.address = Some(0x401000);
        state.operand_count = 3;
        state.selected_operand = Some(1);
        state.has_fall_through = true;
        state.operand_has_references = true;
        assert!(state.has_instruction());
        assert!(state.has_selected_operand());
    }

    #[test]
    fn test_edit_panel_type_all_variants() {
        // Verify all panel types are accessible
        let types = [
            EditPanelType::Memory,
            EditPanelType::Stack,
            EditPanelType::Register,
            EditPanelType::External,
        ];
        assert_eq!(types.len(), 4);
    }
}

// ===========================================================================
// Register module tests
// ===========================================================================

#[cfg(test)]
mod register_tests {
    use ghidra_features::register::*;
    use ghidra_core::addr::Address;

    #[test]
    fn test_register_manager_provider_state_new() {
        let state = RegisterManagerProviderState::new();
        assert!(!state.show_default_values);
        assert!(state.filter_to_program_registers);
        assert!(!state.follow_location);
        assert!(state.selected_register.is_none());
        assert_eq!(state.x, 0);
        assert_eq!(state.y, 0);
        assert_eq!(state.width, 600);
        assert_eq!(state.height, 400);
        assert_eq!(state.divider_location, 200);
    }

    #[test]
    fn test_register_manager_provider_state_has_selected_register() {
        let mut state = RegisterManagerProviderState::new();
        assert!(!state.has_selected_register());
        state.selected_register = Some("EAX".to_string());
        assert!(state.has_selected_register());
    }

    #[test]
    fn test_register_value_edit_model_new() {
        let model = RegisterValueEditModel::new("RAX".to_string());
        assert_eq!(model.register_name(), "RAX");
        assert_eq!(model.value(), 0);
        assert_eq!(model.bit_size(), 32);
        assert!(model.start_address().is_none());
        assert!(model.end_address().is_none());
        assert!(!model.apply_to_selection());
        assert!(!model.clear_value());
        assert!(!model.is_modified());
    }

    #[test]
    fn test_register_value_edit_model_set_value() {
        let mut model = RegisterValueEditModel::new("EAX".to_string());
        model.set_value(0xDEADBEEF);
        assert_eq!(model.value(), 0xDEADBEEF);
        assert!(model.is_modified());
    }

    #[test]
    fn test_register_value_edit_model_bit_size() {
        let mut model = RegisterValueEditModel::new("AL".to_string());
        model.set_bit_size(8);
        assert_eq!(model.bit_size(), 8);
    }

    #[test]
    fn test_register_value_edit_model_address_range() {
        let mut model = RegisterValueEditModel::new("EAX".to_string());
        model.set_address_range(0x1000, 0x2000);
        assert_eq!(model.start_address(), Some(0x1000));
        assert_eq!(model.end_address(), Some(0x2000));
    }

    #[test]
    fn test_register_value_edit_model_apply_to_selection() {
        let mut model = RegisterValueEditModel::new("EAX".to_string());
        model.set_apply_to_selection(true);
        assert!(model.apply_to_selection());
    }

    #[test]
    fn test_register_value_edit_model_clear() {
        let mut model = RegisterValueEditModel::new("EAX".to_string());
        model.set_clear_value(true);
        assert!(model.clear_value());
    }

    #[test]
    fn test_register_value_edit_model_validate_empty_name() {
        let model = RegisterValueEditModel::new("".to_string());
        assert!(model.validate().is_err());
    }

    #[test]
    fn test_register_value_edit_model_validate_zero_bit_size() {
        let mut model = RegisterValueEditModel::new("EAX".to_string());
        model.set_bit_size(0);
        assert!(model.validate().is_err());
    }

    #[test]
    fn test_register_value_edit_model_validate_value_too_large_8bit() {
        let mut model = RegisterValueEditModel::new("AL".to_string());
        model.set_bit_size(8);
        model.set_value(0x1FF); // 511 > 255
        assert!(model.validate().is_err());
    }

    #[test]
    fn test_register_value_edit_model_validate_value_ok_8bit() {
        let mut model = RegisterValueEditModel::new("AL".to_string());
        model.set_bit_size(8);
        model.set_value(0xFF);
        assert!(model.validate().is_ok());
    }

    #[test]
    fn test_register_value_edit_model_validate_32bit() {
        let mut model = RegisterValueEditModel::new("EAX".to_string());
        model.set_bit_size(32);
        model.set_value(0xFFFFFFFF);
        assert!(model.validate().is_ok());
    }

    #[test]
    fn test_register_value_edit_model_validate_64bit() {
        let mut model = RegisterValueEditModel::new("RAX".to_string());
        model.set_bit_size(64);
        model.set_value(u64::MAX);
        assert!(model.validate().is_ok());
    }

    #[test]
    fn test_register_value_edit_model_validate_clear_bypasses_range() {
        let mut model = RegisterValueEditModel::new("AL".to_string());
        model.set_bit_size(8);
        model.set_value(u64::MAX);
        model.set_clear_value(true);
        // Clear mode bypasses value range validation
        assert!(model.validate().is_ok());
    }

    #[test]
    fn test_register_value_edit_model_validate_bad_range() {
        let mut model = RegisterValueEditModel::new("EAX".to_string());
        model.set_address_range(0x2000, 0x1000);
        assert!(model.validate().is_err());
    }

    #[test]
    fn test_register_value_edit_model_validate_good_range() {
        let mut model = RegisterValueEditModel::new("EAX".to_string());
        model.set_address_range(0x1000, 0x2000);
        assert!(model.validate().is_ok());
    }

    #[test]
    fn test_register_transition_state_default() {
        let state = RegisterTransitionState::new();
        assert!(!state.is_active());
        assert!(state.click_address.is_none());
        assert!(state.click_register.is_none());
        assert!(state.current_value.is_none());
        assert!(!state.is_dragging);
    }

    #[test]
    fn test_register_transition_state_lifecycle() {
        let mut state = RegisterTransitionState::new();

        // Start a transition
        state.start(0x400000, "EAX".to_string(), Some(42));
        assert!(state.is_active());
        assert_eq!(state.click_address, Some(0x400000));
        assert_eq!(state.click_register, Some("EAX".to_string()));
        assert_eq!(state.current_value, Some(42));
        assert!(!state.is_dragging);

        // Begin drag
        state.begin_drag();
        assert!(state.is_dragging);

        // End drag
        state.end();
        assert!(!state.is_dragging);
        // Still active until cleared
        assert!(state.is_active());
    }

    #[test]
    fn test_reexported_register_value_range() {
        let range = RegisterValueRange::new(
            Address::new(0x1000),
            Address::new(0x2000),
            0xFF,
            false,
        );
        assert_eq!(range.start_address(), Address::new(0x1000));
        assert_eq!(range.end_address(), Address::new(0x2000));
        assert_eq!(range.value(), 0xFF);
        assert!(!range.is_default());
    }

    #[test]
    fn test_reexported_register_value_range_contains() {
        let range = RegisterValueRange::new(
            Address::new(0x1000),
            Address::new(0x2000),
            0x42,
            false,
        );
        assert!(range.contains(&Address::new(0x1500)));
        assert!(!range.contains(&Address::new(0x3000)));
    }

    #[test]
    fn test_reexported_register_value_range_size() {
        let range = RegisterValueRange::new(
            Address::new(0x1000),
            Address::new(0x2000),
            0,
            false,
        );
        assert_eq!(range.size(), 0x1001);
    }
}

// ===========================================================================
// Cross-module integration tests
// ===========================================================================

#[cfg(test)]
mod integration_tests {
    use ghidra_features::console::*;
    use ghidra_features::function::*;
    use ghidra_features::references::*;
    use ghidra_features::register::*;

    #[test]
    fn test_console_and_function_together() {
        // Simulate a workflow: log function operations
        let mut console = ConsoleBuffer::new(1000);

        let tag = FunctionTag::new("analyzed".to_string(), "Function has been analyzed".to_string());
        console.add_info("analyzer", format!("Tagging function with '{}'", tag.name()));

        let param = ParamInfoBuilder::new(0, "argc")
            .data_type_name("int")
            .build();
        console.add_info("analyzer", format!("Parameter: {} ({})", param.name(), param.data_type_name()));

        assert_eq!(console.len(), 2);
        assert_eq!(console.error_count(), 0);
    }

    #[test]
    fn test_references_and_register_together() {
        // Simulate a workflow: edit references with register values
        let mut ref_state = ReferenceEditState::new(EditPanelType::Register);
        ref_state.source_address = Some(0x400000);
        ref_state.operand_index = Some(0);

        let mut reg_model = RegisterValueEditModel::new("EAX".to_string());
        reg_model.set_value(0x400000);
        reg_model.set_address_range(0x400000, 0x400000);

        assert!(reg_model.validate().is_ok());
        assert!(ref_state.is_register_panel());
    }

    #[test]
    fn test_function_editor_state_serialization() {
        let state = FunctionEditorState {
            is_inline: true,
            calling_convention: Some("fastcall".to_string()),
            ..Default::default()
        };
        let json = serde_json::to_string(&state).unwrap();
        let restored: FunctionEditorState = serde_json::from_str(&json).unwrap();
        assert!(restored.is_inline);
        assert_eq!(restored.calling_convention.as_deref(), Some("fastcall"));
    }

    #[test]
    fn test_register_value_edit_model_serialization() {
        let mut model = RegisterValueEditModel::new("RAX".to_string());
        model.set_value(42);
        model.set_bit_size(64);
        let json = serde_json::to_string(&model).unwrap();
        let restored: RegisterValueEditModel = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.register_name(), "RAX");
        assert_eq!(restored.value(), 42);
        assert_eq!(restored.bit_size(), 64);
    }

    #[test]
    fn test_console_buffer_serialization() {
        let mut buf = ConsoleBuffer::new(100);
        buf.add_info("s", "test");
        buf.add_error("s", "err");
        let json = serde_json::to_string(&buf).unwrap();
        let restored: ConsoleBuffer = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.len(), 2);
        assert_eq!(restored.error_count(), 1);
    }

    #[test]
    fn test_offset_table_dialog_model_serialization() {
        let mut model = OffsetTableDialogModel::new();
        model.set_base_address(0x10000);
        model.set_pointer_size(4);
        let json = serde_json::to_string(&model).unwrap();
        let restored: OffsetTableDialogModel = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.base_address(), Some(0x10000));
        assert_eq!(restored.pointer_size(), 4);
    }

    #[test]
    fn test_function_tag_serialization() {
        let tag = FunctionTag::new("important".to_string(), "desc".to_string());
        let json = serde_json::to_string(&tag).unwrap();
        let restored: FunctionTag = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.name(), "important");
        assert_eq!(restored.description(), "desc");
    }

    #[test]
    fn test_console_message_serialization() {
        let msg = ConsoleMessage::new("s", "test msg", ConsoleMessageType::Warning);
        let json = serde_json::to_string(&msg).unwrap();
        let restored: ConsoleMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.text, "test msg");
        assert_eq!(restored.msg_type, ConsoleMessageType::Warning);
    }

    #[test]
    fn test_register_transition_state_serialization() {
        let mut state = RegisterTransitionState::new();
        state.start(0x400000, "EAX".to_string(), Some(42));
        let json = serde_json::to_string(&state).unwrap();
        let restored: RegisterTransitionState = serde_json::from_str(&json).unwrap();
        assert!(restored.is_active());
        assert_eq!(restored.click_address, Some(0x400000));
    }

    #[test]
    fn test_stack_depth_change_event_serialization() {
        let event = StackDepthChangeEvent::new(0x400000, -8, Some(0));
        let json = serde_json::to_string(&event).unwrap();
        let restored: StackDepthChangeEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.address, 0x400000);
        assert_eq!(restored.new_depth, -8);
    }

    #[test]
    fn test_instruction_panel_state_serialization() {
        let mut state = InstructionPanelState::new();
        state.address = Some(0x400000);
        state.operand_count = 2;
        state.selected_operand = Some(0);
        state.has_fall_through = true;
        let json = serde_json::to_string(&state).unwrap();
        let restored: InstructionPanelState = serde_json::from_str(&json).unwrap();
        assert!(restored.has_instruction());
        assert_eq!(restored.operand_count, 2);
        assert!(restored.has_fall_through);
    }
}
