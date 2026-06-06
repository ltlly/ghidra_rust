//! Comprehensive coverage tests for the Ghidra Debug Rust port.

use ghidra_debug::model::Lifespan;
use ghidra_debug::target::KeyPath;

#[cfg(test)]
mod framework_tests {
    use ghidra_debug::framework::byte_cache::ByteCache;

    #[test]
    fn test_byte_cache_creation() {
        let cache = ByteCache::new();
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn test_byte_cache_put_get() {
        let mut cache = ByteCache::new();
        cache.put(0, 0x48);
        cache.put(1, 0x65);
        assert_eq!(cache.get(0), Some(0x48));
        assert_eq!(cache.get(1), Some(0x65));
        assert_eq!(cache.get(2), None);
    }

    #[test]
    fn test_byte_cache_contains() {
        let mut cache = ByteCache::new();
        cache.put(100, 0xFF);
        assert!(cache.contains(100));
        assert!(!cache.contains(101));
    }

    #[test]
    fn test_byte_cache_put_bytes() {
        let mut cache = ByteCache::new();
        cache.put_bytes(0x1000, &[0x48, 0x65, 0x6C, 0x6C, 0x6F]);
        assert_eq!(cache.get(0x1000), Some(0x48));
        assert_eq!(cache.get(0x1004), Some(0x6F));
    }

    #[test]
    fn test_byte_cache_get_bytes() {
        let mut cache = ByteCache::new();
        cache.put_bytes(0, &[1, 2, 3, 4, 5]);
        let mut buf = [0u8; 5];
        let n = cache.get_bytes(0, &mut buf);
        assert_eq!(n, 5);
        assert_eq!(buf, [1, 2, 3, 4, 5]);
    }

    #[test]
    fn test_byte_cache_from_bytes() {
        let cache = ByteCache::from_bytes(0x1000, &[0xAA, 0xBB, 0xCC]);
        assert_eq!(cache.get(0x1000), Some(0xAA));
        assert_eq!(cache.get(0x1002), Some(0xCC));
    }

    #[test]
    fn test_byte_cache_remove() {
        let mut cache = ByteCache::new();
        cache.put(0, 0x42);
        assert_eq!(cache.remove(0), Some(0x42));
        assert_eq!(cache.get(0), None);
    }

    #[test]
    fn test_byte_cache_get_or() {
        let mut cache = ByteCache::new();
        cache.put(0, 0x42);
        assert_eq!(cache.get_or(0, 0x00), 0x42);
        assert_eq!(cache.get_or(1, 0xFF), 0xFF);
    }
}

#[cfg(test)]
mod lifespan_tests {
    use super::*;
    use ghidra_debug::model::is_scratch;

    #[test]
    fn test_lifespan_span() {
        let span = Lifespan::span(0, 10);
        assert_eq!(span.lmin(), 0);
        assert_eq!(span.lmax(), 10);
    }

    #[test]
    fn test_lifespan_at() {
        let span = Lifespan::at(5);
        assert_eq!(span.lmin(), 5);
        assert_eq!(span.lmax(), 5);
    }

    #[test]
    fn test_lifespan_since() {
        let span = Lifespan::since(10);
        assert_eq!(span.lmin(), 0);
        assert_eq!(span.lmax(), 10);
    }

    #[test]
    fn test_lifespan_contains() {
        let span = Lifespan::span(5, 15);
        assert!(span.contains(5));
        assert!(span.contains(10));
        assert!(span.contains(15));
        assert!(!span.contains(4));
        assert!(!span.contains(16));
    }

    #[test]
    fn test_lifespan_is_empty() {
        let span = Lifespan::span(5, 5);
        assert!(!span.is_empty());
    }

    #[test]
    fn test_lifespan_scratch() {
        assert!(is_scratch(-1));
        assert!(is_scratch(i64::MIN));
        assert!(!is_scratch(0));
        assert!(!is_scratch(100));
    }

    #[test]
    fn test_lifespan_intersection() {
        let a = Lifespan::span(0, 10);
        let b = Lifespan::span(5, 15);
        let intersection = a.intersect(&b);
        assert_eq!(intersection.lmin(), 5);
        assert_eq!(intersection.lmax(), 10);
    }

    #[test]
    fn test_lifespan_intersects() {
        let a = Lifespan::span(0, 10);
        let b = Lifespan::span(5, 15);
        assert!(a.intersects(&b));
        let c = Lifespan::span(20, 30);
        assert!(!a.intersects(&c));
    }

    #[test]
    fn test_lifespan_now_on() {
        let span = Lifespan::now_on(42);
        assert_eq!(span.lmin(), 42);
    }
}

#[cfg(test)]
mod breakpoint_kind_tests {
    use ghidra_debug::model::TraceBreakpointKind;

    #[test]
    fn test_breakpoint_kind_variants() {
        let kinds = [
            TraceBreakpointKind::Read, TraceBreakpointKind::Write,
            TraceBreakpointKind::HwExecute, TraceBreakpointKind::SwExecute,
        ];
        for kind in &kinds {
            assert!(!format!("{:?}", kind).is_empty());
        }
    }

    #[test]
    fn test_breakpoint_kind_encoding_char() {
        assert_eq!(TraceBreakpointKind::Read.encoding_char(), 'R');
        assert_eq!(TraceBreakpointKind::Write.encoding_char(), 'W');
        assert_eq!(TraceBreakpointKind::HwExecute.encoding_char(), 'X');
        assert_eq!(TraceBreakpointKind::SwExecute.encoding_char(), 'x');
    }

    #[test]
    fn test_breakpoint_kind_from_char() {
        assert_eq!(TraceBreakpointKind::from_char('R'), Some(TraceBreakpointKind::Read));
        assert_eq!(TraceBreakpointKind::from_char('W'), Some(TraceBreakpointKind::Write));
        assert_eq!(TraceBreakpointKind::from_char('?'), None);
    }

    #[test]
    fn test_breakpoint_kind_equality() {
        assert_eq!(TraceBreakpointKind::Read, TraceBreakpointKind::Read);
        assert_ne!(TraceBreakpointKind::Read, TraceBreakpointKind::Write);
    }
}

#[cfg(test)]
mod key_path_tests {
    use super::*;

    #[test]
    fn test_key_path_creation() {
        let path = KeyPath::new(vec!["root".to_string(), "child".to_string()]);
        assert_eq!(path.size(), 2);
        assert!(!path.is_root());
    }

    #[test]
    fn test_key_path_root() {
        let path = KeyPath::new(vec![]);
        assert!(path.is_root());
        assert_eq!(path.size(), 0);
    }

    #[test]
    fn test_key_path_of() {
        let path = KeyPath::of(&["process", "thread", "register"]);
        assert_eq!(path.size(), 3);
        assert_eq!(path.get(0), Some("process"));
        assert_eq!(path.last(), Some("register"));
    }

    #[test]
    fn test_key_path_parse() {
        let path = KeyPath::parse("process/1/thread/2");
        assert!(path.size() >= 1);
    }
}

#[cfg(test)]
mod isf_tests {
    use ghidra_debug::isf::types::{IsfBuiltIn, IsfComposite, IsfEnum};

    #[test]
    fn test_isf_built_in_creation() {
        let t = IsfBuiltIn::new(1, "uint32", 4);
        assert_eq!(t.name, "uint32");
        assert_eq!(t.size, 4);
    }

    #[test]
    fn test_isf_composite_creation() {
        let c = IsfComposite::new(2, "my_struct", 16);
        assert_eq!(c.name, "my_struct");
        assert_eq!(c.size, 16);
    }

    #[test]
    fn test_isf_enum_creation() {
        let e = IsfEnum::new(3, "my_enum", 4);
        assert_eq!(e.name, "my_enum");
        assert_eq!(e.size, 4);
    }
}

#[cfg(test)]
mod taint_tests {
    use ghidra_debug::taint_analysis::model::{TaintMark, TaintSet};

    #[test]
    fn test_taint_mark_creation() {
        let mark = TaintMark::new("input");
        assert_eq!(mark.name, "input");
    }

    #[test]
    fn test_taint_set_of() {
        let marks = vec![
            TaintMark::new("a"), TaintMark::new("b"), TaintMark::new("c"),
        ];
        let set = TaintSet::of(marks);
        assert_eq!(set.len(), 3);
        assert!(!set.is_empty());
    }

    #[test]
    fn test_taint_set_parse() {
        let set = TaintSet::parse("a,b,c");
        assert!(set.len() >= 1);
    }

    #[test]
    fn test_taint_set_union() {
        let a = TaintSet::of(vec![TaintMark::new("x")]);
        let b = TaintSet::of(vec![TaintMark::new("y")]);
        let union = a.union(&b);
        assert_eq!(union.len(), 2);
    }

    #[test]
    fn test_taint_set_intersection() {
        let a = TaintSet::of(vec![TaintMark::new("common"), TaintMark::new("a_only")]);
        let b = TaintSet::of(vec![TaintMark::new("common"), TaintMark::new("b_only")]);
        let intersection = a.intersection(&b);
        assert_eq!(intersection.len(), 1);
    }

    #[test]
    fn test_taint_mark_with_tags() {
        let mark = TaintMark::with_tags("source", vec!["external", "user_input"]);
        assert_eq!(mark.name, "source");
        assert!(!mark.tags.is_empty());
    }
}

#[cfg(test)]
mod stack_tests {
    use ghidra_debug::stack::{
        Sym, SymArithmetic, SymState, UnwindWarning, UnwindWarningKind, UnwindWarningSet,
    };
    use ghidra_debug::stack::unwind_info::ReturnLocation;

    #[test]
    fn test_sym_variants() {
        let opaque = Sym::opaque();
        assert!(opaque.is_opaque());
        let constant = Sym::constant(42);
        assert!(constant.is_const());
        assert_eq!(constant.as_const_value(), Some(42));
    }

    #[test]
    fn test_sym_equality() {
        let a = Sym::opaque();
        let b = Sym::opaque();
        assert_eq!(a, b);
        let c = Sym::constant(0);
        assert_ne!(a, c);
    }

    #[test]
    fn test_sym_add() {
        let a = Sym::constant(10);
        let b = Sym::constant(20);
        let sum = a.add("RSP", &b);
        assert_eq!(sum.as_const_value(), Some(30));
    }

    #[test]
    fn test_sym_sub() {
        let a = Sym::constant(50);
        let b = Sym::constant(20);
        let diff = a.sub("RSP", &b);
        assert_eq!(diff.as_const_value(), Some(30));
    }

    #[test]
    fn test_sym_arithmetic_opaque() {
        let a = Sym::opaque();
        let b = Sym::constant(5);
        let result = a.add("RSP", &b);
        assert!(result.is_opaque());
    }

    #[test]
    fn test_sym_state_creation() {
        let arith = SymArithmetic::new("RSP", false);
        let state = SymState::new(arith);
        assert!(state.stack.entries().is_empty());
        assert!(state.registers.entries().is_empty());
        assert!(state.unique.entries().is_empty());
    }

    #[test]
    fn test_return_location_variants() {
        let stack = ReturnLocation::Stack { offset: -8, size: 8 };
        let register = ReturnLocation::Register {
            name: "LR".into(), mask: u64::MAX,
        };
        let unknown = ReturnLocation::Unknown;
        assert!(matches!(stack, ReturnLocation::Stack { .. }));
        assert!(matches!(register, ReturnLocation::Register { .. }));
        assert!(matches!(unknown, ReturnLocation::Unknown));
    }

    #[test]
    fn test_unwind_warning_variants() {
        let warnings = [
            UnwindWarningKind::NoReturnPath,
            UnwindWarningKind::OpaqueReturnPath,
            UnwindWarningKind::AnalysisError,
        ];
        for w in &warnings {
            assert!(!format!("{:?}", w).is_empty());
        }
    }

    #[test]
    fn test_unwind_warning_set() {
        let mut set = UnwindWarningSet::new();
        assert!(set.is_empty());
        set.add(UnwindWarning::custom("No unwind data for function"));
        assert_eq!(set.len(), 1);
    }
}

#[cfg(test)]
mod platform_opinion_integration_tests {
    use ghidra_debug::plugin::platform_opinion::{create_default_registry, OpinionContext};

    #[test]
    fn test_registry_all_backends() {
        let registry = create_default_registry();
        assert_eq!(registry.len(), 3);
    }

    #[test]
    fn test_registry_gdb_x86_64() {
        let registry = create_default_registry();
        let ctx = OpinionContext::new()
            .with_debugger_type("gdb")
            .with_architecture("x86_64")
            .with_pointer_size(8);
        let best = registry.best_opinion(&ctx);
        assert!(best.is_some());
        let opinion = best.unwrap();
        assert!(opinion.language_id.contains("x86"));
        assert!(opinion.language_id.contains("64"));
    }

    #[test]
    fn test_registry_gdb_arm() {
        let registry = create_default_registry();
        let ctx = OpinionContext::new()
            .with_debugger_type("gdb")
            .with_architecture("armv7l")
            .with_pointer_size(4);
        let opinions = registry.get_opinions(&ctx);
        assert!(!opinions.is_empty());
        assert!(opinions[0].language_id.contains("ARM"));
    }

    #[test]
    fn test_registry_lldb_aarch64() {
        let registry = create_default_registry();
        let ctx = OpinionContext::new()
            .with_debugger_type("lldb")
            .with_architecture("aarch64")
            .with_pointer_size(8);
        let opinions = registry.get_opinions(&ctx);
        assert!(!opinions.is_empty());
        assert!(opinions[0].language_id.contains("AARCH64"));
    }

    #[test]
    fn test_registry_frida() {
        let registry = create_default_registry();
        let ctx = OpinionContext::new()
            .with_debugger_type("frida")
            .with_architecture("x86_64")
            .with_pointer_size(8);
        let opinions = registry.get_opinions(&ctx);
        assert!(!opinions.is_empty());
    }

    #[test]
    fn test_registry_no_match() {
        let registry = create_default_registry();
        let ctx = OpinionContext::new()
            .with_debugger_type("unknown")
            .with_architecture("unknown");
        let opinions = registry.get_opinions(&ctx);
        assert!(opinions.is_empty());
    }
}

#[cfg(test)]
mod export_integration_tests {
    use ghidra_debug::plugin::trace_exporters::{
        TraceViewAsciiExporter, TraceViewIntelHexExporter,
        TraceViewXmlExporter, IntelHexRecord,
    };
    use ghidra_debug::plugin::trace_export_formats::{BinaryExporter, HtmlExporter};

    #[test]
    fn test_ascii_hex_dump() {
        let data = vec![0x48, 0x65, 0x6C, 0x6C, 0x6F];
        let dump = TraceViewAsciiExporter::export_hex_dump(0x1000, &data);
        assert!(dump.contains("1000"));
        assert!(dump.contains("48 65 6c 6c 6f"));
        assert!(dump.contains("|Hello|"));
    }

    #[test]
    fn test_intel_hex_round_trip() {
        let data = vec![0xAA, 0xBB, 0xCC, 0xDD];
        let hex = TraceViewIntelHexExporter::export(0x1000, &data);
        let mut parsed_data = Vec::new();
        for line in hex.lines() {
            if line.starts_with(':') && line.len() > 10 {
                let record = TraceViewIntelHexExporter::parse_record(line).unwrap();
                assert!(record.verify_checksum());
                if record.is_data() {
                    parsed_data.extend_from_slice(&record.data);
                }
            }
        }
        assert_eq!(parsed_data, data);
    }

    #[test]
    fn test_html_export() {
        let exporter = HtmlExporter::new();
        let data = vec![0x90, 0xCC, 0x00, 0x01];
        let html = exporter.export(0x400000, &data);
        assert!(html.contains("<!DOCTYPE html>"));
        assert!(html.contains("<table>"));
    }

    #[test]
    fn test_xml_export() {
        let xml = TraceViewXmlExporter::export_bytes(0x1000, &[0x01, 0x02, 0x03]);
        assert!(xml.contains("<?xml"));
        assert!(xml.contains("trace-dump"));
    }

    #[test]
    fn test_binary_export_header() {
        let exporter = BinaryExporter::new().include_header(true);
        let data = vec![0x01, 0x02, 0x03, 0x04];
        let result = exporter.export(&data);
        assert!(result.len() > data.len());
        assert_eq!(&result[0..4], b"GHTR");
    }

    #[test]
    fn test_intel_hex_record() {
        let record = IntelHexRecord {
            byte_count: 2, address: 0x0000, record_type: 0x00,
            data: vec![0x12, 0x34], checksum: 0xBA,
        };
        assert!(record.is_data());
        assert!(!record.is_eof());
    }
}

#[cfg(test)]
mod gui_data_model_tests {
    use ghidra_debug::plugin::{
        LogLevel, ConsoleColumn, CopyDirection, ControlActionKind,
        PcodeStepperOpType, StepperState, DebuggerRegion,
        DisconnectMode, SettingValue, MemviewBoxType, MemviewZoomAction,
    };

    #[test]
    fn test_log_level_variants() {
        let levels = [
            LogLevel::Trace, LogLevel::Debug, LogLevel::Info,
            LogLevel::Warn, LogLevel::Error,
        ];
        for level in &levels {
            assert!(!format!("{:?}", level).is_empty());
        }
    }

    #[test]
    fn test_log_level_ordering() {
        assert!(LogLevel::Trace < LogLevel::Debug);
        assert!(LogLevel::Debug < LogLevel::Info);
        assert!(LogLevel::Info < LogLevel::Warn);
        assert!(LogLevel::Warn < LogLevel::Error);
    }

    #[test]
    fn test_console_column_variants() {
        let columns = [
            ConsoleColumn::Icon, ConsoleColumn::Source,
            ConsoleColumn::Message, ConsoleColumn::Actions,
        ];
        for col in &columns {
            assert!(!format!("{:?}", col).is_empty());
        }
    }

    #[test]
    fn test_copy_direction() {
        assert_ne!(CopyDirection::ProgramToTrace, CopyDirection::TraceToProgram);
    }

    #[test]
    fn test_control_action_kind() {
        let kinds = [
            ControlActionKind::Resume, ControlActionKind::StepInto,
            ControlActionKind::StepOver, ControlActionKind::StepOut,
        ];
        for kind in &kinds {
            assert!(!format!("{:?}", kind).is_empty());
        }
    }

    #[test]
    fn test_pcode_stepper_op_type() {
        let ops = [
            PcodeStepperOpType::Normal, PcodeStepperOpType::Branch,
            PcodeStepperOpType::Call, PcodeStepperOpType::Memory,
            PcodeStepperOpType::Register,
        ];
        for op in &ops {
            assert!(!format!("{:?}", op).is_empty());
        }
    }

    #[test]
    fn test_stepper_state() {
        let states = [
            StepperState::Idle, StepperState::Stepping,
            StepperState::Running, StepperState::Paused,
        ];
        for state in &states {
            assert!(!format!("{:?}", state).is_empty());
        }
    }

    #[test]
    fn test_debugger_region() {
        let region = DebuggerRegion::new(0x400000, 0x500000, ".text");
        assert_eq!(region.min_address, 0x400000);
        assert_eq!(region.max_address, 0x500000);
    }

    #[test]
    fn test_disconnect_mode_variants() {
        let modes = [
            DisconnectMode::Kill, DisconnectMode::Detach,
            DisconnectMode::KillAndRestart,
        ];
        for mode in &modes {
            assert!(!format!("{:?}", mode).is_empty());
        }
    }

    #[test]
    fn test_setting_value_types() {
        let values = [
            SettingValue::Bool(true),
            SettingValue::Int(42),
            SettingValue::String("test".into()),
        ];
        for val in &values {
            assert!(!format!("{:?}", val).is_empty());
        }
    }

    #[test]
    fn test_memview_box_type() {
        let types = [
            MemviewBoxType::Unknown, MemviewBoxType::Known,
            MemviewBoxType::Written, MemviewBoxType::Read,
            MemviewBoxType::Error,
        ];
        for t in &types {
            assert!(!format!("{:?}", t).is_empty());
        }
    }

    #[test]
    fn test_memview_zoom_action() {
        let actions = [
            MemviewZoomAction::ZoomInAddress, MemviewZoomAction::ZoomOutAddress,
            MemviewZoomAction::ZoomInTime, MemviewZoomAction::ZoomOutTime,
        ];
        for action in &actions {
            assert!(!format!("{:?}", action).is_empty());
        }
    }
}

#[cfg(test)]
mod service_interface_tests {
    use ghidra_debug::services::EmulationDefiniteResult;

    #[test]
    fn test_emulation_definite_result_snapshot() {
        let result = EmulationDefiniteResult { snapshot: 5 };
        assert_eq!(result.snapshot, 5);
    }
}

#[cfg(test)]
mod target_model_tests {
    use ghidra_debug::target::{KeyPath, PathMatcher, PathPattern};

    #[test]
    fn test_path_pattern_creation() {
        let pattern = PathPattern::new(KeyPath::of(&["process", "*", "thread"]));
        // Pattern should be constructable
        assert!(!format!("{:?}", pattern).is_empty());
    }

    #[test]
    fn test_path_matcher_from_patterns() {
        let matcher = PathMatcher::from_patterns(&[
            PathPattern::new(KeyPath::of(&["process", "*", "thread"])),
        ]);
        // Matcher should be constructable
        assert!(!format!("{:?}", matcher).is_empty());
    }
}

#[cfg(test)]
mod bookmark_tests {
    use ghidra_debug::model::{Lifespan, TraceBookmark, TraceBookmarkType};

    #[test]
    fn test_bookmark_type_variants() {
        let types = [
            TraceBookmarkType::Analysis, TraceBookmarkType::Note,
            TraceBookmarkType::Warning, TraceBookmarkType::Error,
            TraceBookmarkType::Type,
        ];
        for t in &types {
            assert!(!format!("{:?}", t).is_empty());
        }
    }

    #[test]
    fn test_bookmark_creation() {
        let bm = TraceBookmark::new(
            1, 0x400000, Lifespan::at(5),
            TraceBookmarkType::Note, "general", "Entry point",
        );
        assert_eq!(bm.address, 0x400000);
        assert_eq!(bm.comment, "Entry point");
    }
}

#[cfg(test)]
mod thread_tests {
    use ghidra_debug::model::TraceThread;

    #[test]
    fn test_thread_creation() {
        let thread = TraceThread::new(1, "/process/1/thread/1", "main", 100);
        assert_eq!(thread.key, 1);
        assert_eq!(thread.name, "main");
    }
}

#[cfg(test)]
mod register_context_tests {
    use ghidra_debug::model::{ContextAddressRange, ContextRegisterValue, RegisterId};

    #[test]
    fn test_context_address_range() {
        let range = ContextAddressRange::new(0x400000, 0x401000);
        assert_eq!(range.min, 0x400000);
        assert_eq!(range.max, 0x401000);
    }

    #[test]
    fn test_context_register_value() {
        let reg_id = RegisterId::new("TMode", 1);
        let val = ContextRegisterValue::new(reg_id.clone(), vec![1]);
        assert_eq!(val.register, reg_id);
    }

    #[test]
    fn test_register_id() {
        let id = RegisterId::new("TMode", 1);
        assert_eq!(id.name, "TMode");
    }
}
