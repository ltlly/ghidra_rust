//! Comprehensive integration tests for the Debug modules ported from
//! Ghidra's Debugger, Debugger-api, and Framework-TraceModeling.
//!
//! These tests verify the key types and traits ported from the Java source:
//! - Content handler types (Framework-TraceModeling)
//! - Address factory types (Framework-TraceModeling)
//! - Data view types (Framework-TraceModeling)
//! - Overlay space types (Framework-TraceModeling)
//! - Export types (Debugger)
//! - Service interfaces (Debugger-api)
//! - Model types (Framework-TraceModeling)

#[cfg(test)]
mod tests {
    use crate::model::{Lifespan, TraceExecutionState, TraceBreakpointKind, TraceMemoryState,
        DirectModelContentHandler, LinkModelContentHandler, ModelContentHandler, ModelContentError, ModelContentType,
        ModelAddressSpaceDesc, ModelAddressSpaceType, ModelTraceAddressFactory,
        ModelCodeUnitsView, ViewDataConfig, ViewDataEntry, ViewCodeUnitType, ViewReferenceInfo, ViewReferenceType,
        TraceOverlaySpace, TraceOverlayManager,
    };
    use crate::services::*;
    use crate::api::breakpoint::LogicalBreakpoint;

    // =========================================================================
    // Content handler tests
    // =========================================================================

    #[test]
    fn test_content_handler_direct() {
        let handler = DirectModelContentHandler;
        assert_eq!(handler.content_type(), ModelContentType::Direct);
        let meta = handler.metadata("test.db").unwrap();
        assert_eq!(meta.content_type, ModelContentType::Direct);
        assert!(!meta.linked);
        assert!(meta.uri.is_some());
    }

    #[test]
    fn test_content_handler_link() {
        let handler = LinkModelContentHandler::new("/linked/trace.db");
        assert_eq!(handler.content_type(), ModelContentType::Linked);
        let meta = handler.metadata("source").unwrap();
        assert!(meta.linked);
        assert_eq!(meta.uri.as_deref(), Some("/linked/trace.db"));
        // Linked content should be read-only
        assert!(handler.write_content("dest", b"data").is_err());
    }

    #[test]
    fn test_content_type_variants() {
        assert_ne!(ModelContentType::Direct, ModelContentType::Linked);
        assert_ne!(ModelContentType::Linked, ModelContentType::Temporary);
    }

    #[test]
    fn test_content_error_display() {
        let err = ModelContentError::NotFound("trace.db".into());
        assert!(err.to_string().contains("trace.db"));
        let err = ModelContentError::ReadOnly("link".into());
        assert!(err.to_string().contains("Read-only"));
    }

    // =========================================================================
    // Address factory tests
    // =========================================================================

    #[test]
    fn test_model_address_space_desc() {
        let ram = ModelAddressSpaceDesc::ram("ram", 8, false);
        assert_eq!(ram.name, "ram");
        assert!(ram.is_memory_space());
        assert!(!ram.is_register_space());
        assert!(!ram.is_overlay());
        assert_eq!(ram.max_address(), u64::MAX);
    }

    #[test]
    fn test_model_address_space_register() {
        let reg = ModelAddressSpaceDesc::register("register", 8);
        assert!(reg.is_register_space());
        assert!(!reg.is_memory_space());
    }

    #[test]
    fn test_model_address_space_overlay() {
        let ovl = ModelAddressSpaceDesc::overlay("CODE", 8, false, 0x10000);
        assert!(ovl.is_overlay());
        assert!(ovl.is_memory_space());
        assert_eq!(ovl.physical_size, Some(0x10000));
    }

    #[test]
    fn test_model_address_space_max() {
        assert_eq!(ModelAddressSpaceDesc::ram("r1", 1, false).max_address(), 0xFF);
        assert_eq!(ModelAddressSpaceDesc::ram("r2", 2, false).max_address(), 0xFFFF);
        assert_eq!(ModelAddressSpaceDesc::ram("r4", 4, false).max_address(), 0xFFFF_FFFF);
    }

    #[test]
    fn test_model_trace_address_factory() {
        let mut factory = ModelTraceAddressFactory::new();
        assert!(factory.is_empty());

        let id1 = factory.add_space(ModelAddressSpaceDesc::ram("ram", 8, false));
        let id2 = factory.add_space(ModelAddressSpaceDesc::register("register", 8));
        assert_eq!(factory.len(), 2);
        assert_ne!(id1, id2);

        assert!(factory.has_space("ram"));
        assert!(!factory.has_space("unknown"));
        assert!(factory.default_space().is_some());
        assert!(factory.register_space().is_some());
    }

    #[test]
    fn test_model_trace_address_factory_presets() {
        let x86 = ModelTraceAddressFactory::x86_64();
        assert!(x86.has_space("ram"));
        assert!(x86.has_space("register"));

        let arm = ModelTraceAddressFactory::aarch64();
        assert!(arm.has_space("ram"));
    }

    #[test]
    fn test_model_address_space_type_variants() {
        assert_ne!(ModelAddressSpaceType::Ram, ModelAddressSpaceType::Register);
        assert_ne!(ModelAddressSpaceType::Overlay, ModelAddressSpaceType::Unique);
        assert_ne!(ModelAddressSpaceType::Constant, ModelAddressSpaceType::Stack);
    }

    // =========================================================================
    // Data view tests
    // =========================================================================

    #[test]
    fn test_view_data_config() {
        let config = ViewDataConfig::new("ram", 0)
            .with_range(0x1000, 0x2000)
            .with_undefined(true);
        assert_eq!(config.space_name, "ram");
        assert_eq!(config.snap, 0);
        assert_eq!(config.min_offset, 0x1000);
        assert!(config.include_undefined);
    }

    #[test]
    fn test_model_code_units_view() {
        let config = ViewDataConfig::new("ram", 0);
        let mut view = ModelCodeUnitsView::new(config);

        view.push_entry(ViewDataEntry {
            offset: 0x1000,
            unit_type: ViewCodeUnitType::Instruction,
            size: 4,
            data_type: None,
            bytes: vec![0x55, 0x48, 0x89, 0xe5],
            display: "PUSH RBP".into(),
            references: vec![],
        });

        view.push_entry(ViewDataEntry {
            offset: 0x1004,
            unit_type: ViewCodeUnitType::DefinedData,
            size: 4,
            data_type: Some("dword".into()),
            bytes: vec![0x01, 0x00, 0x00, 0x00],
            display: "1".into(),
            references: vec![],
        });

        view.push_entry(ViewDataEntry {
            offset: 0x1008,
            unit_type: ViewCodeUnitType::UndefinedData,
            size: 1,
            data_type: None,
            bytes: vec![0x00],
            display: "??".into(),
            references: vec![],
        });

        assert_eq!(view.len(), 3);
        assert!(!view.is_empty());
        assert!(view.entry_at(0x1000).is_some());
        assert!(view.entry_at(0x3000).is_none());
        assert_eq!(view.instructions().len(), 1);
        assert_eq!(view.defined_data().len(), 1);
        assert_eq!(view.undefined_data().len(), 1);
    }

    #[test]
    fn test_view_code_unit_type_variants() {
        assert_ne!(ViewCodeUnitType::Instruction, ViewCodeUnitType::DefinedData);
        assert_ne!(ViewCodeUnitType::UndefinedData, ViewCodeUnitType::Comment);
        assert_ne!(ViewCodeUnitType::CompositeField, ViewCodeUnitType::ArrayElement);
    }

    #[test]
    fn test_view_reference_type_variants() {
        assert_ne!(ViewReferenceType::Read, ViewReferenceType::Write);
        assert_ne!(ViewReferenceType::Flow, ViewReferenceType::Call);
        assert_ne!(ViewReferenceType::Call, ViewReferenceType::Indirect);
    }

    // =========================================================================
    // Service interface tests
    // =========================================================================

    #[test]
    fn test_trace_manager_service_trait() {
        struct TestTraceManager {
            traces: Vec<String>,
            active: usize,
        }

        impl TraceInfo for String {
            fn key(&self) -> i64 { 0 }
            fn name(&self) -> &str { self }
            fn is_active(&self) -> bool { false }
        }

        impl TraceManagerService for TestTraceManager {
            fn active_trace(&self) -> Option<&dyn TraceInfo> {
                self.traces.get(self.active).map(|s| s as &dyn TraceInfo)
            }
            fn open_trace(&mut self, _: i64) -> Result<(), String> {
                self.traces.push("new".into());
                Ok(())
            }
            fn close_trace(&mut self, _: i64) -> Result<(), String> {
                self.traces.pop();
                Ok(())
            }
            fn activate_trace(&mut self, _: i64) -> Result<(), String> {
                self.active = 0;
                Ok(())
            }
            fn open_traces(&self) -> Vec<&dyn TraceInfo> {
                self.traces.iter().map(|s| s as &dyn TraceInfo).collect()
            }
        }

        let mut svc = TestTraceManager { traces: vec![], active: 0 };
        assert!(svc.open_traces().is_empty());
        svc.open_trace(1).unwrap();
        assert_eq!(svc.open_traces().len(), 1);
    }

    #[test]
    fn test_breakpoint_service_trait() {
        struct TestBpService {
            bps: Vec<LogicalBreakpoint>,
        }

        impl LogicalBreakpointService for TestBpService {
            fn breakpoints(&self) -> Vec<&LogicalBreakpoint> { self.bps.iter().collect() }
            fn breakpoint_at(&self, offset: u64) -> Option<&LogicalBreakpoint> {
                self.bps.iter().find(|bp| bp.offset == offset)
            }
            fn add_breakpoint(&mut self, bp: LogicalBreakpoint) -> Result<(), String> {
                self.bps.push(bp);
                Ok(())
            }
            fn delete_breakpoint(&mut self, offset: u64) -> Result<(), String> {
                let before = self.bps.len();
                self.bps.retain(|bp| bp.offset != offset);
                if self.bps.len() < before { Ok(()) } else { Err("Not found".into()) }
            }
            fn toggle_breakpoint(&mut self, _: u64, _: bool) -> Result<(), String> { Ok(()) }
        }

        let mut svc = TestBpService { bps: vec![] };
        svc.add_breakpoint(LogicalBreakpoint::new(0x400000, "0x400000")).unwrap();
        assert_eq!(svc.breakpoints().len(), 1);
        assert!(svc.breakpoint_at(0x400000).is_some());
        assert!(svc.breakpoint_at(0x500000).is_none());

        svc.delete_breakpoint(0x400000).unwrap();
        assert!(svc.breakpoints().is_empty());
    }

    #[test]
    fn test_emulation_service_trait() {
        struct TestEmuSvc { running: bool }

        impl EmulationService for TestEmuSvc {
            fn start_emulation(&mut self, _: i64) -> Result<(), String> {
                self.running = true;
                Ok(())
            }
            fn stop_emulation(&mut self, _: i64) -> Result<(), String> {
                self.running = false;
                Ok(())
            }
            fn is_emulating(&self, _: i64) -> bool { self.running }
            fn step_emulation(&mut self, _: i64, _: u64) -> Result<(), String> {
                if self.running { Ok(()) } else { Err("Not emulating".into()) }
            }
        }

        let mut svc = TestEmuSvc { running: false };
        assert!(!svc.is_emulating(0));
        svc.start_emulation(0).unwrap();
        assert!(svc.is_emulating(0));
        svc.step_emulation(0, 1).unwrap();
        svc.stop_emulation(0).unwrap();
        assert!(!svc.is_emulating(0));
        assert!(svc.step_emulation(0, 1).is_err());
    }

    #[test]
    fn test_control_service_trait() {
        struct TestCtrl { connected: bool }

        impl DebuggerControlService for TestCtrl {
            fn active_target(&self) -> Option<i64> {
                if self.connected { Some(1) } else { None }
            }
            fn connect(&mut self, _: i64) -> Result<(), String> {
                self.connected = true;
                Ok(())
            }
            fn disconnect(&mut self) -> Result<(), String> {
                self.connected = false;
                Ok(())
            }
            fn is_connected(&self) -> bool { self.connected }
        }

        let mut svc = TestCtrl { connected: false };
        assert!(!svc.is_connected());
        svc.connect(1).unwrap();
        assert!(svc.is_connected());
        svc.disconnect().unwrap();
        assert!(!svc.is_connected());
    }

    #[test]
    fn test_mapping_proposal_struct() {
        let proposal = MappingProposal {
            program_min: 0,
            program_max: 0x1000,
            trace_min: 0x400000,
            trace_max: 0x401000,
            confidence: 0.95,
        };
        assert_eq!(proposal.confidence, 0.95);
        assert_eq!(proposal.program_max, 0x1000);
    }

    #[test]
    fn test_target_info_struct() {
        let info = TargetInfo {
            target_type: "gdb".into(),
            display_name: "GDB Remote".into(),
            supports_launch: true,
            supports_attach: true,
        };
        assert!(info.supports_launch);
        assert!(info.supports_attach);
    }

    // =========================================================================
    // Model type tests
    // =========================================================================

    #[test]
    fn test_lifespan_basics() {
        let span = Lifespan::span(0, 100);
        assert!(span.contains(50));
        assert!(!span.contains(200));
        assert_eq!(span.lmin(), 0);
        assert_eq!(span.lmax(), 100);
    }

    #[test]
    fn test_lifespan_at() {
        let span = Lifespan::at(42);
        assert!(span.contains(42));
        assert!(!span.contains(43));
    }

    #[test]
    fn test_lifespan_since() {
        let span = Lifespan::since(10);
        assert!(span.contains(0));
        assert!(span.contains(10));
        assert!(!span.contains(11));
    }

    #[test]
    fn test_trace_execution_state() {
        assert_eq!(TraceExecutionState::Stopped, TraceExecutionState::Stopped);
        assert_ne!(TraceExecutionState::Stopped, TraceExecutionState::Running);
    }

    #[test]
    fn test_trace_breakpoint_kind() {
        use std::collections::BTreeSet;
        let mut kinds = BTreeSet::new();
        kinds.insert(TraceBreakpointKind::SwExecute);
        kinds.insert(TraceBreakpointKind::HwExecute);
        assert!(kinds.contains(&TraceBreakpointKind::SwExecute));
        assert!(kinds.contains(&TraceBreakpointKind::HwExecute));
    }

    #[test]
    fn test_trace_memory_state() {
        assert_eq!(TraceMemoryState::Known, TraceMemoryState::Known);
        assert_ne!(TraceMemoryState::Known, TraceMemoryState::Unknown);
    }

    // =========================================================================
    // Overlay tests
    // =========================================================================

    #[test]
    fn test_overlay_space_creation() {
        let overlay = TraceOverlaySpace::new("CODE", "ram", 0x400000, 0x10000);
        assert_eq!(overlay.name, "CODE");
        assert_eq!(overlay.base_space_name, "ram");
        assert!(overlay.contains(0x400100));
        assert!(!overlay.contains(0x300000));
    }

    #[test]
    fn test_overlay_manager() {
        let mut mgr = TraceOverlayManager::new();
        assert_eq!(mgr.count(), 0);

        mgr.add_overlay(TraceOverlaySpace::new("OVL1", "ram", 0x400000, 0x1000));
        mgr.add_overlay(TraceOverlaySpace::new("OVL2", "ram", 0x500000, 0x1000));
        assert_eq!(mgr.count(), 2);

        assert!(mgr.find_by_name("OVL1").is_some());
        assert!(mgr.find_by_name("UNKNOWN").is_none());
    }

    // =========================================================================
    // Export types tests (from plugin module)
    // =========================================================================

    #[test]
    fn test_export_format_variants() {
        use crate::plugin::ExportFormat;
        assert_eq!(ExportFormat::Ascii.to_string(), "ASCII");
        assert_eq!(ExportFormat::Binary.to_string(), "Binary");
        assert_eq!(ExportFormat::Html.to_string(), "HTML");
        assert_eq!(ExportFormat::IntelHex.to_string(), "Intel HEX");
        assert_eq!(ExportFormat::Xml.to_string(), "XML");
    }

    #[test]
    fn test_export_config() {
        use crate::plugin::{ExportFormat, TraceExportConfig};
        let config = TraceExportConfig::ascii(0x400000, 0x400fff, 0);
        assert_eq!(config.format, ExportFormat::Ascii);
        assert_eq!(config.range_size(), 0x1000);
    }

    #[test]
    fn test_format_intel_hex_record() {
        use crate::plugin::format_intel_hex;
        let data = [0xDE, 0xAD, 0xBE, 0xEF];
        let record = format_intel_hex(0x1000, &data, 0x00);
        assert!(record.starts_with(':'));
        assert_eq!(&record[1..3], "04");
        assert_eq!(&record[3..7], "1000");
    }

    #[test]
    fn test_format_hex_dump() {
        use crate::plugin::format_hex_dump;
        let data = b"Hello";
        let dump = format_hex_dump(0x1000, data, 16);
        assert!(dump.contains("1000"));
        assert!(dump.contains("48"));
        assert!(dump.contains("Hello"));
    }

    #[test]
    fn test_format_trace_xml() {
        use crate::plugin::format_trace_xml;
        let data = vec![0xCA, 0xFE];
        let xml = format_trace_xml(0x400000, &data);
        assert!(xml.contains("<?xml"));
        assert!(xml.contains("trace-dump"));
    }

    // =========================================================================
    // Plugin event tests
    // =========================================================================

    #[test]
    fn test_trace_activated_event() {
        use crate::plugin::{TraceActivatedEvent, ActivationCause};
        let event = TraceActivatedEvent::new("trace1");
        assert_eq!(event.trace_id, "trace1");
    }

    #[test]
    fn test_trace_location_event() {
        use crate::plugin::TraceLocationEvent;
        let event = TraceLocationEvent::new("trace1", 0x400000)
            .with_space("ram");
        assert_eq!(event.offset, 0x400000);
        assert_eq!(event.space.as_deref(), Some("ram"));
    }

    #[test]
    fn test_transaction_coalescer() {
        use crate::plugin::TransactionCoalescer;
        let mut coalescer = TransactionCoalescer::new("t1");
        coalescer.begin();
        assert!(coalescer.is_open());
        coalescer.record("op1");
        coalescer.record("op2");
        assert_eq!(coalescer.pending_count(), 2);
        let ops = coalescer.end();
        assert_eq!(ops.len(), 2);
        assert!(!coalescer.is_open());
    }

    // =========================================================================
    // Cross-module integration tests
    // =========================================================================

    #[test]
    fn test_address_factory_with_overlay() {
        let mut factory = ModelTraceAddressFactory::new();
        factory.add_space(ModelAddressSpaceDesc::ram("ram", 8, false));
        factory.add_space(ModelAddressSpaceDesc::overlay("CODE", 8, false, 0x100000));

        assert!(factory.has_space("ram"));
        assert!(factory.has_space("CODE"));

        let code_space = factory.get_space("CODE").unwrap();
        assert!(code_space.is_overlay());

        let mut overlay_mgr = TraceOverlayManager::new();
        overlay_mgr.add_overlay(TraceOverlaySpace::new("CODE", "ram", 0x400000, 0x100000));
        assert!(overlay_mgr.find_by_name("CODE").is_some());
    }

    #[test]
    fn test_data_view_with_references() {
        let config = ViewDataConfig::new("ram", 0);
        let mut view = ModelCodeUnitsView::new(config);

        view.push_entry(ViewDataEntry {
            offset: 0x1000,
            unit_type: ViewCodeUnitType::Instruction,
            size: 5,
            data_type: None,
            bytes: vec![0xe8, 0x00, 0x00, 0x00, 0x00],
            display: "CALL 0x1005".into(),
            references: vec![ViewReferenceInfo {
                ref_type: ViewReferenceType::Call,
                from_offset: 0x1000,
                from_space: "ram".into(),
                label: Some("main".into()),
            }],
        });

        assert_eq!(view.len(), 1);
        let entry = view.entry_at(0x1000).unwrap();
        assert_eq!(entry.references.len(), 1);
        assert_eq!(entry.references[0].ref_type, ViewReferenceType::Call);
    }

    #[test]
    fn test_content_handler_with_address_factory() {
        let handler = DirectModelContentHandler;
        let mut factory = ModelTraceAddressFactory::new();
        factory.add_space(ModelAddressSpaceDesc::ram("ram", 8, false));

        // Simulate reading content and creating spaces
        let meta = handler.metadata("trace.db").unwrap();
        assert!(!meta.linked);

        let ram_space = factory.default_space().unwrap();
        assert_eq!(ram_space.name, "ram");
    }

    #[test]
    fn test_multiple_services_integration() {
        // Test that multiple service types work together
        struct MockTraceInfo { key_val: i64, name_val: String, active: bool }
        impl TraceInfo for MockTraceInfo {
            fn key(&self) -> i64 { self.key_val }
            fn name(&self) -> &str { &self.name_val }
            fn is_active(&self) -> bool { self.active }
        }

        let info = MockTraceInfo {
            key_val: 42,
            name_val: "test_trace".into(),
            active: true,
        };
        assert_eq!(info.key(), 42);
        assert_eq!(info.name(), "test_trace");
        assert!(info.is_active());
    }

    #[test]
    fn test_full_debug_module_coverage() {
        // Verify all major module types are accessible
        let _span = Lifespan::span(0, 10);
        let _state = TraceExecutionState::Stopped;
        let _kind = TraceBreakpointKind::SwExecute;
        let _mem_state = TraceMemoryState::Known;

        // Address factory
        let mut factory = ModelTraceAddressFactory::new();
        factory.add_space(ModelAddressSpaceDesc::ram("ram", 8, false));
        assert!(!factory.is_empty());

        // Data views
        let config = ViewDataConfig::new("ram", 0);
        let view = ModelCodeUnitsView::new(config);
        assert!(view.is_empty());

        // Content handler
        let handler = DirectModelContentHandler;
        let _meta = handler.metadata("test").unwrap();

        // Overlay
        let mut mgr = TraceOverlayManager::new();
        mgr.add_overlay(TraceOverlaySpace::new("X", "ram", 0, 0x1000));
        assert_eq!(mgr.count(), 1);
    }
}
