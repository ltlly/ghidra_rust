//! Ghidra Rust - Auto-analysis framework.
//!
//! Ported from the Ghidra Java analysis subsystem.
pub mod core;
pub mod priority;
pub mod r#trait;
pub mod scheduler;
pub mod manager;
pub mod analyzers;

pub use core::*;
pub use priority::*;
pub use r#trait::*;
pub use scheduler::*;
pub use manager::*;
pub use analyzers::*;

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_program() -> Program {
        let lang = Language { processor: "x86".into(), variant: "LE".into(), size: 64 };
        let mut prog = Program::new("test", lang);
        prog.image_base = 0x400000;
        prog.memory.add_range(AddressRange::new(Address::new(0x400000), Address::new(0x500000)));
        prog
    }
    fn make_arm_program() -> Program { Program::new("arm_test", Language { processor: "ARM".into(), variant: "LE".into(), size: 32 }) }

    #[test] fn test_address_operations() { let a = Address::new(0x1000); assert_eq!(a.add(8), Address::new(0x1008)); assert_eq!(a.to_string(), "0x00001000"); }
    #[test] fn test_address_space() { let a = Address::in_space(2, 0x1000); assert_eq!(a.to_string(), "2:0x00001000"); }
    #[test] fn test_address_range() { let r = AddressRange::new(Address::new(0x1000), Address::new(0x10FF)); assert_eq!(r.len(), 256); assert!(r.contains(&Address::new(0x1050))); }
    #[test] fn test_address_set() { let mut s = AddressSet::new(); s.add(Address::new(0x1000)); s.add(Address::new(0x1001)); assert_eq!(s.num_addresses(), 2); }
    #[test] fn test_address_set_delete() { let mut s = AddressSet::from_range(AddressRange::new(Address::new(0x1000), Address::new(0x2000))); let d = AddressSet::from_range(AddressRange::new(Address::new(0x1500), Address::new(0x1600))); s.delete(&d); assert_eq!(s.num_addresses(), 0x500 + 0xA00); }
    #[test] fn test_address_set_intersect() { let s1 = AddressSet::from_range(AddressRange::new(Address::new(0x1000), Address::new(0x2000))); let s2 = AddressSet::from_range(AddressRange::new(Address::new(0x1800), Address::new(0x2800))); assert_eq!(s1.intersect(&s2).num_addresses(), 0x801); }
    #[test] fn test_address_set_union() { let s1 = AddressSet::from_range(AddressRange::new(Address::new(0x1000), Address::new(0x1500))); let s2 = AddressSet::from_range(AddressRange::new(Address::new(0x1400), Address::new(0x2000))); assert_eq!(s1.union(&s2).num_addresses(), 0x1001); }
    #[test] fn test_address_iterator() { let s = AddressSet::from_range(AddressRange::new(Address::new(0x1000), Address::new(0x1004))); let a: Vec<_> = s.get_addresses(true).collect(); assert_eq!(a.len(), 5); assert_eq!(a[4], Address::new(0x1004)); }
    #[test] fn test_priority_ordering() { assert!(AnalysisPriority::FORMAT_ANALYSIS < AnalysisPriority::BLOCK_ANALYSIS); assert!(AnalysisPriority::BLOCK_ANALYSIS < AnalysisPriority::DISASSEMBLY); assert!(AnalysisPriority::LOW_PRIORITY > AnalysisPriority::DATA_TYPE_PROPAGATION); }
    #[test] fn test_before_after() { let b = AnalysisPriority::REFERENCE_ANALYSIS; assert!(b.before() < b); assert!(b < b.after()); }
    #[test] fn test_analyzer_type_display() { assert_eq!(AnalyzerType::Byte.to_string(), "Byte Analyzer"); assert_eq!(AnalyzerType::Data.to_string(), "Data Analyzer"); }
    #[test] fn test_task_monitor() { let m = BasicTaskMonitor::new(); assert!(!m.is_cancelled()); m.cancel(); assert!(m.is_cancelled()); m.clear_cancelled(); assert!(!m.is_cancelled()); }
    #[test] fn test_task_monitor_progress() { let m = BasicTaskMonitor::new(); m.initialize(100); assert_eq!(m.get_maximum(), 100); m.increment_progress(50); assert_eq!(m.get_progress(), 50); m.set_message("test"); assert_eq!(m.get_message(), "test"); }
    #[test] fn test_flow_type() { assert!(FlowType::Call.is_call()); assert!(FlowType::ConditionalJump.is_jump()); assert!(FlowType::Return.is_terminal()); assert!(FlowType::Fallthrough.has_fallthrough()); }
    #[test] fn test_data_is_pointer() { let d = Data { address: Address::new(0), length: 4, data_type_name: "pointer".into() }; assert!(d.is_pointer()); let d2 = Data { address: Address::new(0), length: 4, data_type_name: "dword".into() }; assert!(!d2.is_pointer()); }
    #[test] fn test_function_manager() { let m = FunctionManager::default(); assert!(m.get_functions(true).next().is_none()); }
    #[test] fn test_listing_instructions() { let mut l = Listing::default(); l.instructions.insert(Address::new(0x1000), Instruction { address: Address::new(0x1000), length: 3, mnemonic: "mov".into(), flow_type: FlowType::Fallthrough, fall_through: Some(Address::new(0x1003)), flows: vec![], num_operands: 2 }); assert_eq!(l.num_instructions(), 1); let s = AddressSet::from_range(AddressRange::new(Address::new(0x1000), Address::new(0x2000))); let instrs: Vec<_> = l.get_instructions(&s, true).collect(); assert_eq!(instrs.len(), 1); }
    #[test] fn test_listing_containing() { let mut l = Listing::default(); l.instructions.insert(Address::new(0x1000), Instruction { address: Address::new(0x1000), length: 5, mnemonic: "call".into(), flow_type: FlowType::Call, fall_through: Some(Address::new(0x1005)), flows: vec![], num_operands: 1 }); assert!(l.get_instruction_containing(&Address::new(0x1002)).is_some()); assert!(l.get_instruction_containing(&Address::new(0x1005)).is_none()); }
    #[test] fn test_message_log() { let mut l = MessageLog::new(); assert!(l.is_empty()); l.append_msg("test"); l.append_msg("test2"); assert_eq!(l.len(), 2); l.clear(); assert!(l.is_empty()); }
    #[test] fn test_program_bookmarks() { let mut p = make_test_program(); p.set_bookmark(Address::new(0x401000), BookmarkType::Analysis, "Test", "msg"); assert_eq!(p.bookmarks.len(), 1); }
    #[test] fn test_language_props() { let l = Language { processor: "x86".into(), variant: "LE".into(), size: 64 }; assert_eq!(l.default_pointer_size(), 8); assert!(!l.is_segmented()); }
    #[test] fn test_option_values() { assert_eq!(AnalysisOptionValue::Bool(true), AnalysisOptionValue::Bool(true)); assert_ne!(AnalysisOptionValue::Bool(true), AnalysisOptionValue::Bool(false)); }
    #[test] fn test_abstract_analyzer() { let mut a = AbstractAnalyzer::new("Test", "desc", AnalyzerType::Byte); a.set_priority(AnalysisPriority::CODE_ANALYSIS); assert_eq!(a.name(), "Test"); assert_eq!(a.priority(), AnalysisPriority::CODE_ANALYSIS); }
    #[test] fn test_mgr_creation() { let m = AutoAnalysisManager::new(make_test_program()); assert!(!m.is_analyzing()); assert!(m.is_enabled()); }
    #[test] fn test_add_analyzer() { let mut m = AutoAnalysisManager::new(make_test_program()); m.add_analyzer(Box::new(FunctionStartAnalyzer::new())); m.add_analyzer(Box::new(CodeBoundaryAnalyzer::new())); assert_eq!(m.num_analyzers(), 2); }
    #[test] fn test_find_analyzer() { let mut m = AutoAnalysisManager::new(make_test_program()); m.add_analyzer(Box::new(FunctionStartAnalyzer::new())); assert!(m.get_analyzer("Function Start Analyzer").is_some()); assert!(m.get_analyzer("Nope").is_none()); }
    #[test] fn test_run_empty() { let mut m = AutoAnalysisManager::new(make_test_program()); let r = m.run_analysis(&BasicTaskMonitor::new()).unwrap(); assert_eq!(r.tasks_executed, 0); assert!(!r.was_cancelled); }
    #[test] fn test_run_with_analyzers() { let mut m = AutoAnalysisManager::new(make_test_program()); m.add_analyzer(Box::new(FunctionStartAnalyzer::new())); m.add_analyzer(Box::new(CodeBoundaryAnalyzer::new())); m.add_analyzer(Box::new(DataReferenceAnalyzer::new())); let b = AddressRange::new(Address::new(0x401000), Address::new(0x402000)); m.block_added(&AddressSet::from_range(b)); let r = m.run_analysis(&BasicTaskMonitor::new()).unwrap(); assert!(r.tasks_executed >= 2); }
    #[test] fn test_cancellation() { let mut m = AutoAnalysisManager::new(make_test_program()); m.add_analyzer(Box::new(FunctionStartAnalyzer::new())); let mon = BasicTaskMonitor::new(); mon.cancel(); assert!(m.run_analysis(&mon).is_err()); }
    #[test] fn test_ignore_changes() { let mut m = AutoAnalysisManager::new(make_test_program()); m.add_analyzer(Box::new(FunctionStartAnalyzer::new())); m.set_ignore_changes(true); let b = AddressRange::new(Address::new(0x401000), Address::new(0x402000)); m.block_added(&AddressSet::from_range(b)); let r = m.run_analysis(&BasicTaskMonitor::new()).unwrap(); assert_eq!(r.tasks_executed, 0); }
    #[test] fn test_cancel_queued() { let mut m = AutoAnalysisManager::new(make_test_program()); m.add_analyzer(Box::new(FunctionStartAnalyzer::new())); let b = AddressRange::new(Address::new(0x401000), Address::new(0x402000)); m.block_added(&AddressSet::from_range(b)); m.cancel_queued_tasks(); let r = m.run_analysis(&BasicTaskMonitor::new()).unwrap(); assert_eq!(r.tasks_executed, 0); }
    #[test] fn test_external_added() { let mut m = AutoAnalysisManager::new(make_test_program()); m.add_analyzer(Box::new(FunctionStartAnalyzer::new())); m.external_added(Some(Address::in_space(Address::EXTERNAL_SPACE, 1))); m.external_added(None); }
    #[test] fn test_event_notifications() { let mut m = AutoAnalysisManager::new(make_test_program()); let s = AddressSet::from_range(AddressRange::new(Address::new(0x401000), Address::new(0x402000))); m.block_added(&s); m.code_defined(Address::new(0x401000)); m.code_defined_set(&s); m.data_defined(&s); m.function_defined(Address::new(0x401000)); m.function_defined_set(&s); m.function_modifier_changed(Address::new(0x401000)); m.function_modifier_changed_set(&s); m.function_signature_changed(Address::new(0x401000)); m.function_signature_changed_set(&s); }
    #[test] fn test_protected_locations() { let mut m = AutoAnalysisManager::new(make_test_program()); m.set_protected_location(Address::new(0x401000)); assert!(m.protected_locations().contains(&Address::new(0x401000))); }
    #[test] fn test_re_analyze() { let mut m = AutoAnalysisManager::new(make_test_program()); m.add_analyzer(Box::new(FunctionStartAnalyzer::new())); m.re_analyze_all(None); let r = m.run_analysis(&BasicTaskMonitor::new()).unwrap(); assert!(!r.was_cancelled); }
    #[test] fn test_function_start_analyzer() { let a = FunctionStartAnalyzer::new(); assert_eq!(a.name(), "Function Start Analyzer"); assert_eq!(a.analysis_type(), AnalyzerType::Byte); assert!(a.can_analyze(&make_test_program())); }
    #[test] fn test_code_boundary_analyzer() { let a = CodeBoundaryAnalyzer::new(); assert_eq!(a.name(), "Code Boundary Analyzer"); assert!(a.can_analyze(&make_test_program())); }
    #[test] fn test_data_reference_analyzer() { let a = DataReferenceAnalyzer::new(); assert_eq!(a.name(), "Reference"); assert!(a.supports_one_time_analysis()); let a2 = DataReferenceAnalyzer::new().with_string_creation(false); assert!(!a2.create_ascii_strings); }
    #[test] fn test_stack_variable_analyzer() { let a = StackVariableAnalyzer::new(); assert_eq!(a.name(), "Stack"); assert_eq!(a.analysis_type(), AnalyzerType::Function); }
    #[test] fn test_constant_reference_analyzer() { let a = ConstantReferenceAnalyzer::new(); assert_eq!(a.processor_name(), "Basic"); let x86 = ConstantReferenceAnalyzer::with_processor("x86"); assert!(x86.name().contains("x86")); }
    #[test] fn test_constant_evaluator() { let e = ConstantPropagationContextEvaluator::new(true); let p = make_test_program(); assert!(!e.evaluate_constant(0, &p)); assert!(!e.evaluate_constant(0xFFFFFFFF, &p)); assert!(e.evaluate_constant(0x401000, &p)); }
    #[test] fn test_switch_analyzer() { let a = SwitchAnalyzer::new(); assert_eq!(a.name(), "Switch Table Analyzer"); }
    #[test] fn test_arm_thumb_analyzer() { let a = ARMThumbAnalyzer::new(); assert!(!a.can_analyze(&make_test_program())); assert!(a.can_analyze(&make_arm_program())); }
    #[test] fn test_no_return_known() { let a = NoReturnKnownAnalyzer::new(); assert_eq!(a.name(), "Non-Returning Functions - Known"); assert_eq!(a.analysis_type(), AnalyzerType::Byte); }
    #[test] fn test_no_return_discovered() { let a = NoReturnDiscoveredAnalyzer::new(); assert_eq!(a.name(), "Non-Returning Functions - Discovered"); assert!(a.supports_one_time_analysis()); assert_eq!(a.evidence_threshold, 3); }
    #[test] fn test_scalar_operand() { let a = ScalarOperandAnalyzer::new(); assert_eq!(a.name(), "Scalar Operand References"); }
    #[test] fn test_data_operand_ref() { let a = DataOperandReferenceAnalyzer::new(); assert_eq!(a.name(), "Data Reference"); assert_eq!(a.analysis_type(), AnalyzerType::Data); }
    #[test] fn test_ext_symbol_resolver() { let a = ExternalSymbolResolverAnalyzer::new(); assert_eq!(a.name(), "External Symbol Resolver"); assert!(!a.can_analyze(&make_test_program())); let mut elf = make_test_program(); elf.executable_format = Some("ELF".into()); assert!(a.can_analyze(&elf)); }
    #[test] fn test_source_language() { let a = SourceLanguageAnalyzer::new(); assert_eq!(a.name(), "Source Language Support"); }
    #[test] fn test_apply_data_archive() { let a = ApplyDataArchiveAnalyzer::new(); assert_eq!(a.name(), "Apply Data Archives"); assert_eq!(a.archive_chooser, ArchiveChooserMode::AutoDetect); }
    #[test] fn test_dwarf_analyzer() { let a = DWARFAnalyzer::new(); assert_eq!(a.name(), "DWARF"); assert!(a.supports_one_time_analysis()); }
    #[test] fn test_embedded_media() { let a = EmbeddedMediaAnalyzer::new(); assert_eq!(a.name(), "Embedded Media"); assert!(a.signatures.iter().any(|s| s.name == "PNG")); assert!(a.signatures.iter().any(|s| s.name == "JPEG")); }
    #[test] fn test_register_context() { let mut b = RegisterContextBuilder::new_bit("TMode"); assert!(!b.is_value_known()); b.set_value(Address::new(0x1000), 1); assert!(b.is_value_known()); assert!(b.value_equals(1)); b.set_value_unknown(Address::new(0x2000)); assert!(!b.is_value_known()); assert_eq!(b.value_history().len(), 2); }
    #[test] fn test_register_tracker() { let mut t = RegisterContextTracker::new(); t.track_bit_register("TMode"); t.track_register("ISA", 0xFF); assert!(!t.is_known("TMode")); t.set_value("TMode", Address::new(0x1000), 1); assert!(t.is_known("TMode")); assert_eq!(t.get_value("TMode"), Some(1)); assert_eq!(t.register_names().len(), 2); }
    #[test] fn test_segmented_convention() { assert_eq!(SegmentedCallingConventionAnalyzer::classify_return_opcode(0xC3), SegmentedCallingConvention::Near); assert_eq!(SegmentedCallingConventionAnalyzer::classify_return_opcode(0xCB), SegmentedCallingConvention::Far); assert_eq!(SegmentedCallingConventionAnalyzer::classify_return_opcode(0xCF), SegmentedCallingConvention::Interrupt); }
    #[test] fn test_segmented_analyzer() { let a = SegmentedCallingConventionAnalyzer::new(); assert_eq!(a.name(), "Segmented X86 Calling Conventions"); assert_eq!(a.analysis_type(), AnalyzerType::Function); assert!(!a.can_analyze(&make_test_program())); }
    #[test] fn test_display_impls() { assert_eq!(Address::new(0xDEADBEEF).to_string(), "0xdeadbeef"); assert!(AnalysisPriority::REFERENCE_ANALYSIS.to_string().contains("REFERENCE")); assert_eq!(CancelledError.to_string(), "analysis cancelled by user"); }
    #[test] fn test_analysis_options_default() { let o = AnalysisOptions::default(); assert_eq!(o.max_iterations, 100); assert_eq!(o.timeout_ms, 300_000); assert!(o.print_task_times); }
    #[test] fn test_full_workflow() {
        let mut prog = make_test_program(); prog.memory_blocks.push(MemoryBlock { name: ".text".into(), start: Address::new(0x401000), size: 0x1000, is_read: true, is_write: false, is_execute: true, is_initialized: true });
        let mut m = AutoAnalysisManager::new(prog);
        m.add_analyzer(Box::new(FunctionStartAnalyzer::new())); m.add_analyzer(Box::new(CodeBoundaryAnalyzer::new())); m.add_analyzer(Box::new(DataReferenceAnalyzer::new())); m.add_analyzer(Box::new(ConstantReferenceAnalyzer::new())); m.add_analyzer(Box::new(NoReturnKnownAnalyzer::new())); m.add_analyzer(Box::new(EmbeddedMediaAnalyzer::new()));
        let text = AddressSet::from_range(AddressRange::new(Address::new(0x401000), Address::new(0x402000)));
        m.block_added(&text); m.code_defined_set(&text);
        let r = m.run_analysis(&BasicTaskMonitor::new()).unwrap();
        assert!(!r.was_cancelled); assert!(r.tasks_executed > 0);
        m.re_analyze_all(None);
        let r2 = m.run_analysis(&BasicTaskMonitor::new()).unwrap();
        assert!(!r2.was_cancelled);
    }
    #[derive(Debug, Clone, Default)]
    pub struct StoredAnalyzerTimes { task_times: std::collections::HashMap<String, u64> }
    impl StoredAnalyzerTimes {
        pub fn new() -> Self { Self::default() }
        pub fn add_time(&mut self, n: &str, t: u64) { *self.task_times.entry(n.to_string()).or_insert(0) += t; }
        pub fn get_time(&self, n: &str) -> Option<u64> { self.task_times.get(n).copied() }
        pub fn get_total_time(&self) -> u64 { self.task_times.values().sum() }
        pub fn get_task_names(&self) -> Vec<&str> { let mut n: Vec<&str> = self.task_times.keys().map(|s| s.as_str()).collect(); n.sort(); n }
        pub fn is_empty(&self) -> bool { self.task_times.is_empty() }
        pub fn clear(&mut self) { self.task_times.clear(); }
    }
    #[test] fn test_stored_times() { let mut t = StoredAnalyzerTimes::new(); assert!(t.is_empty()); t.add_time("A", 100); t.add_time("A", 50); t.add_time("B", 200); assert_eq!(t.get_time("A"), Some(150)); assert_eq!(t.get_total_time(), 350); assert_eq!(t.get_task_names(), vec!["A", "B"]); }
}
