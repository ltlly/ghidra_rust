//! Comprehensive tests for remaining Debug module port coverage.
//!
//! Tests cover Framework-TraceModeling model types, target object model,
//! path filtering, plugin framework, and integration scenarios.

#[cfg(test)]
mod tests {
    // ===== Lifespan =====

    #[test]
    fn test_lifespan_at() {
        use crate::model::lifespan::Lifespan;
        let at = Lifespan::at(5);
        assert!(!at.is_empty());
        assert!(at.contains(5));
    }

    #[test]
    fn test_lifespan_span() {
        use crate::model::lifespan::Lifespan;
        let span = Lifespan::span(0, 10);
        assert!(span.contains(0));
        assert!(span.contains(10));
        assert!(!span.contains(11));
        assert_eq!(span.lmin(), 0);
        assert_eq!(span.lmax(), 10);
    }

    #[test]
    fn test_lifespan_intersection() {
        use crate::model::lifespan::Lifespan;
        let a = Lifespan::span(0, 10);
        let b = Lifespan::span(5, 15);
        let c = a.intersect(&b);
        assert_eq!(c.lmin(), 5);
        assert_eq!(c.lmax(), 10);
    }

    #[test]
    fn test_lifespan_encloses() {
        use crate::model::lifespan::Lifespan;
        let outer = Lifespan::span(0, 100);
        let inner = Lifespan::span(10, 50);
        assert!(outer.encloses(&inner));
        assert!(!inner.encloses(&outer));
    }

    #[test]
    fn test_lifespan_scratch() {
        use crate::model::lifespan::is_scratch;
        assert!(is_scratch(-1));
        assert!(!is_scratch(0));
    }

    #[test]
    fn test_lifespan_since() {
        use crate::model::lifespan::Lifespan;
        let span = Lifespan::since(10);
        // since(10) = [0, 10]
        assert!(span.contains(0));
        assert!(span.contains(10));
        assert!(!span.contains(11));
    }

    // ===== KeyPath =====

    #[test]
    fn test_key_path_basic() {
        use crate::target::key_path::KeyPath;
        let path = KeyPath::parse("Processes[2].Threads[0]");
        // Brackets are stripped: "Processes", "2", "Threads", "0"
        assert_eq!(path.size(), 4);
        assert_eq!(path.get(0), Some("Processes"));
        assert_eq!(path.get(1), Some("2"));
        assert_eq!(path.get(2), Some("Threads"));
        assert_eq!(path.get(3), Some("0"));
    }

    #[test]
    fn test_key_path_root() {
        use crate::target::key_path::KeyPath;
        assert!(KeyPath::ROOT.is_root());
        assert_eq!(KeyPath::ROOT.size(), 0);
    }

    #[test]
    fn test_key_path_parent() {
        use crate::target::key_path::KeyPath;
        let path = KeyPath::parse("Processes[2].Threads");
        let parent = path.parent();
        assert_eq!(parent.size(), 2);
    }

    #[test]
    fn test_key_path_extend() {
        use crate::target::key_path::KeyPath;
        let base = KeyPath::parse("Processes[2]");
        let full = base.extend("Threads");
        assert_eq!(full.size(), 3);
    }

    #[test]
    fn test_key_path_extend_path() {
        use crate::target::key_path::KeyPath;
        let base = KeyPath::parse("Processes[2]");
        let sub = KeyPath::parse("Threads[0]");
        let full = base.extend_path(&sub);
        assert_eq!(full.size(), 4);
    }

    #[test]
    fn test_key_path_is_ancestor() {
        use crate::target::key_path::KeyPath;
        let a = KeyPath::parse("Processes[2]");
        let b = KeyPath::parse("Processes[2].Threads[0]");
        assert!(a.is_ancestor(&b));
        assert!(!b.is_ancestor(&a));
    }

    #[test]
    fn test_key_path_index_check() {
        use crate::target::key_path::KeyPath;
        // is_index checks if key parses as i64 (brackets already stripped in KeyPath)
        assert!(KeyPath::is_index("42"));
        assert!(!KeyPath::is_index("Processes"));
        assert!(KeyPath::is_name("Processes"));
        // is_index_str checks for bracket syntax
        assert!(KeyPath::is_index_str("[42]"));
    }

    #[test]
    fn test_key_path_wildcard() {
        use crate::target::key_path::KeyPath;
        let wild = KeyPath::parse("Processes[].Threads");
        assert!(wild.contains_wildcard());
        assert_eq!(wild.count_wildcards(), 1);

        let exact = KeyPath::parse("Processes[2].Threads");
        assert!(!exact.contains_wildcard());
    }

    // ===== Path Pattern / Matcher =====

    #[test]
    fn test_path_pattern_wildcard() {
        use crate::target::path_pattern::PathPattern;
        use crate::target::key_path::KeyPath;
        // KeyPath::of preserves brackets; parse strips them
        let pattern = PathPattern::new(KeyPath::of(&["Processes", "[]", "Threads"]));
        // Bracketed indices match the [] wildcard
        assert!(pattern.matches(&KeyPath::of(&["Processes", "[5]", "Threads"])));
        assert!(pattern.matches(&KeyPath::of(&["Processes", "[99]", "Threads"])));
        // Non-index names do not match [] wildcard
        assert!(!pattern.matches(&KeyPath::of(&["Processes", "name", "Threads"])));
        // Wrong path
        assert!(!pattern.matches(&KeyPath::of(&["Processes", "[5]", "Registers"])));
    }

    #[test]
    fn test_path_pattern_exact() {
        use crate::target::path_pattern::PathPattern;
        use crate::target::key_path::KeyPath;
        let pattern = PathPattern::new(KeyPath::of(&["Processes", "[2]", "Threads"]));
        assert!(pattern.matches(&KeyPath::of(&["Processes", "[2]", "Threads"])));
        assert!(!pattern.matches(&KeyPath::of(&["Processes", "[3]", "Threads"])));
    }

    #[test]
    fn test_path_pattern_successor() {
        use crate::target::path_pattern::PathPattern;
        use crate::target::key_path::KeyPath;
        let pattern = PathPattern::new(KeyPath::of(&["a", "b", "c"]));
        assert!(pattern.successor_could_match(&KeyPath::of(&["a"]), false));
        assert!(pattern.successor_could_match(&KeyPath::of(&["a", "b"]), false));
        assert!(!pattern.successor_could_match(&KeyPath::of(&["a", "b", "c"]), true));
    }

    // ===== Trace Object =====

    #[test]
    fn test_trace_object_basic() {
        use crate::target::trace_object::{TraceObject, TraceObjectManager};
        use crate::target::key_path::KeyPath;
        let mut mgr = TraceObjectManager::new();
        let obj = TraceObject::new(KeyPath::of(&["root"]), "ROOT");
        let path = KeyPath::of(&["root"]);
        mgr.add_object(obj);
        assert!(mgr.get_object(&path).is_some());
    }

    #[test]
    fn test_trace_object_interfaces() {
        use crate::target::trace_object::TraceObject;
        use crate::target::key_path::KeyPath;
        let mut obj = TraceObject::new(KeyPath::of(&["Sessions", "0"]), "SESSION");
        obj.add_interface("Aggregate");
        obj.add_interface("Activatable");
        assert!(obj.has_interface("Aggregate"));
        assert!(!obj.has_interface("Thread"));
    }

    #[test]
    fn test_trace_object_attributes() {
        use crate::target::trace_object::{TraceObject, ObjectValue};
        use crate::target::key_path::KeyPath;
        use crate::model::lifespan::Lifespan;
        let mut obj = TraceObject::new(KeyPath::of(&["Processes", "0"]), "PROCESS");
        obj.set_attribute("_display", ObjectValue::String("bash".to_string()), Lifespan::at(0));
        let val = obj.get_attribute("_display", 0);
        assert!(val.is_some());
    }

    // ===== Schema =====

    #[test]
    fn test_schema_name() {
        use crate::model::target_schema::SchemaName;
        let name = SchemaName::new("THREAD");
        assert_eq!(name.name, "THREAD");
        assert_eq!(SchemaName::object().name, "OBJECT");
    }

    #[test]
    fn test_attribute_schema() {
        use crate::model::target_schema::{AttributeSchema, SchemaName};
        let attr = AttributeSchema::new("name", SchemaName::new("string"))
            .hidden()
            .required();
        assert!(attr.hidden);
        assert!(attr.required);
    }

    #[test]
    fn test_schema_context_basic() {
        use crate::model::target_schema::{SchemaContext, TraceObjectSchemaDef};
        let mut ctx = SchemaContext::new();
        let schema = TraceObjectSchemaDef::new("TEST", "test_type");
        ctx.register(schema);
        assert!(ctx.get_schema("TEST").is_some());
    }

    // ===== Target Interfaces =====

    #[test]
    fn test_target_interface_keys() {
        use crate::model::target_iface::keys;
        assert_eq!(keys::DISPLAY, "_display");
        assert_eq!(keys::COMMENT, "_comment");
        assert_eq!(keys::KIND, "_kind");
    }

    #[test]
    fn test_trace_activatable() {
        use crate::model::target_iface::TraceActivatable;
        use crate::target::key_path::KeyPath;
        let mut act = TraceActivatable::new(KeyPath::parse("Processes[0].Threads[0]"));
        assert!(!act.is_active());
        act.set_active(true);
        assert!(act.is_active());
    }

    #[test]
    fn test_trace_togglable() {
        use crate::model::target_iface::TraceTogglable;
        use crate::target::key_path::KeyPath;
        let mut tog = TraceTogglable::new(KeyPath::parse("Breakpoints[0]"));
        assert!(tog.is_enabled());
        tog.toggle();
        assert!(!tog.is_enabled());
    }

    #[test]
    fn test_trace_focus_scope() {
        use crate::model::target_iface::TraceFocusScope;
        use crate::target::key_path::KeyPath;
        let mut fs = TraceFocusScope::new(KeyPath::parse("Sessions[0]"));
        assert!(fs.focused().is_none());
        fs.set_focus(Some(KeyPath::parse("Processes[0].Threads[0]")));
        assert!(fs.focused().is_some());
    }

    #[test]
    fn test_trace_aggregate() {
        use crate::model::target_iface::TraceAggregate;
        use crate::target::key_path::KeyPath;
        let _agg = TraceAggregate::new(KeyPath::parse("Sessions[0]"));
    }

    #[test]
    fn test_trace_environment() {
        use crate::model::target_iface::TraceEnvironment;
        use crate::target::key_path::KeyPath;
        let env = TraceEnvironment::new(KeyPath::parse("Envs[0]"), "linux", "x86_64");
        assert_eq!(env.os, "linux");
        assert_eq!(env.arch, "x86_64");
    }

    #[test]
    fn test_trace_method_iface() {
        use crate::model::target_iface::TraceMethod;
        use crate::target::key_path::KeyPath;
        let method = TraceMethod::new(KeyPath::parse("Methods[0]"), "main", 0x4000);
        assert_eq!(method.name, "main");
        assert_eq!(method.entry_point, 0x4000);
    }

    #[test]
    fn test_execution_state_variants() {
        use crate::model::target_iface::ExecutionState;
        assert_eq!(ExecutionState::Running as u8, 0);
        assert_eq!(ExecutionState::Stopped as u8, 1);
        assert_eq!(ExecutionState::Terminating as u8, 2);
        assert_eq!(ExecutionState::Terminated as u8, 3);
        assert_eq!(ExecutionState::Unknown as u8, 4);
    }

    #[test]
    fn test_trace_target_section() {
        use crate::model::target_iface::TraceTargetSection;
        use crate::target::key_path::KeyPath;
        let section = TraceTargetSection::new(
            KeyPath::parse("Sections[0]"),
            ".text",
            0x1000,
            0x2000,
            0x0,
        );
        assert!(section.contains(0x1500));
        assert!(!section.contains(0x3000));
    }

    #[test]
    fn test_trace_target_stack() {
        use crate::model::target_iface::{TraceTargetStack, TraceTargetStackFrame};
        use crate::target::key_path::KeyPath;
        let mut stack = TraceTargetStack::new(KeyPath::parse("Stacks[0]"), 1);
        let frame = TraceTargetStackFrame::new(KeyPath::parse("Frames[0]"), 0, 0x4000, 0x7FFF);
        stack.push_frame(frame);
        assert_eq!(stack.depth(), 1);
        assert!(stack.innermost().is_some());
    }

    // ===== Model: Module =====

    #[test]
    fn test_module_basic() {
        use crate::model::module::TraceModule;
        use crate::model::lifespan::Lifespan;
        let module = TraceModule::new(
            1,
            "/usr/lib/libc.so",
            "libc.so",
            0x7f000000,
            0x7f100000,
            Lifespan::span(0, 100),
        );
        assert_eq!(module.key, 1);
        assert_eq!(module.module_name, "libc.so");
        assert!(module.is_loaded_at(50));
        assert!(!module.is_loaded_at(200));
    }

    // ===== Model: Thread =====

    #[test]
    fn test_thread_basic() {
        use crate::model::thread::TraceThread;
        let thread = TraceThread::new(1, "Threads[0]", "main", 0);
        assert_eq!(thread.key, 1);
    }

    // ===== Model: Execution State =====

    #[test]
    fn test_trace_execution_state_variants() {
        use crate::model::execution_state::TraceExecutionState;
        let _running = TraceExecutionState::Running;
        let _stopped = TraceExecutionState::Stopped;
        let _terminated = TraceExecutionState::Terminated;
    }

    // ===== Model: Breakpoint =====

    #[test]
    fn test_breakpoint_kind_variants() {
        use crate::model::breakpoint::TraceBreakpointKind;
        let kinds = [
            TraceBreakpointKind::SwExecute,
            TraceBreakpointKind::HwExecute,
            TraceBreakpointKind::Read,
            TraceBreakpointKind::Write,
        ];
        for kind in &kinds {
            let _ = format!("{:?}", kind);
            let _ = kind.encoding_char();
        }
    }

    // ===== Model: Stack =====

    #[test]
    fn test_stack_frame_basic() {
        use crate::model::stack::TraceStackFrame;
        let frame = TraceStackFrame::new(0, 0x4000, 0x7FFF);
        assert_eq!(frame.level, 0);
        assert_eq!(frame.pc, 0x4000);
        assert!(frame.is_innermost());
    }

    // ===== Model: Guest =====

    #[test]
    fn test_guest_platform() {
        use crate::model::guest::TracePlatform;
        let platform = TracePlatform::new(1, "x86:LE:32:default", "gcc");
        assert_eq!(platform.key, 1);
        assert!(!platform.is_64_bit());
    }

    // ===== Model: Trace Location =====

    #[test]
    fn test_trace_location() {
        use crate::model::trace_location::TraceLocation;
        let _loc = TraceLocation::new(0, 0x4000);
    }

    // ===== Model: Memory =====

    #[test]
    fn test_memory_state_variants() {
        use crate::model::memory::TraceMemoryState;
        let _known = TraceMemoryState::Known;
        let _unknown = TraceMemoryState::Unknown;
        let _error = TraceMemoryState::Error;
    }

    // ===== Model: Domain Object =====

    #[test]
    fn test_domain_object_event() {
        use crate::model::domain_object_listener::DomainObjectEvent;
        let _evt = DomainObjectEvent::Restored;
        let _evt2 = DomainObjectEvent::PropertyChanged;
    }

    // ===== Model: Unique Object =====

    #[test]
    fn test_unique_object_base() {
        use crate::model::trace_unique_object::UniqueObjectBase;
        let obj = UniqueObjectBase::new(42);
        assert_eq!(obj.key, 42);
    }

    // ===== Model: Duplicate Key =====

    #[test]
    fn test_duplicate_key_exception() {
        use crate::model::duplicate_key::DuplicateKeyException;
        use crate::model::lifespan::Lifespan;
        let _err = DuplicateKeyException::new(
            "key",
            1,
            Lifespan::span(0, 10),
            Lifespan::span(5, 15),
        );
    }

    // ===== DB: Manager Trait =====

    #[test]
    fn test_db_trace_manager_trait() {
        use crate::db::trace_db_manager::DbTraceManager;
        struct TestManager {
            name: String,
        }
        impl DbTraceManager for TestManager {
            fn invalidate_cache(&self, _all: bool) {}
            fn manager_name(&self) -> &str {
                &self.name
            }
        }
        let mgr = TestManager {
            name: "test".to_string(),
        };
        assert_eq!(mgr.manager_name(), "test");
        mgr.invalidate_cache(true);
    }

    // ===== Plugin: Phase =====

    #[test]
    fn test_plugin_phase() {
        use crate::plugin::abstract_plugin::PluginPhase;
        assert_eq!(PluginPhase::Initializing as u8, 0);
        assert_eq!(PluginPhase::Active as u8, 1);
        assert_eq!(PluginPhase::Disposing as u8, 2);
        assert_eq!(PluginPhase::Disposed as u8, 3);
    }

    // ===== Target: Visitors =====

    #[test]
    fn test_visit_result() {
        use crate::target::visitors::VisitResult;
        assert!(VisitResult::result(true, true).includes());
        assert!(VisitResult::result(true, true).descends());
        assert!(!VisitResult::result(false, false).includes());
        assert!(!VisitResult::result(false, false).descends());
    }

    // ===== Integration: Lifespan + KeyPath =====

    #[test]
    fn test_lifespan_key_path_integration() {
        use crate::model::lifespan::Lifespan;
        use crate::target::key_path::KeyPath;
        let span = Lifespan::span(0, 100);
        let path = KeyPath::parse("Processes[0].Threads[0].Registers");
        assert!(span.contains(50));
        // "Processes", "0", "Threads", "0", "Registers" => 5 keys
        assert_eq!(path.size(), 5);
    }

    // ===== Integration: Object Manager + Schema =====

    #[test]
    fn test_schema_object_integration() {
        use crate::model::target_schema::{SchemaContext, TraceObjectSchemaDef};
        use crate::target::trace_object::{TraceObject, TraceObjectManager};
        use crate::target::key_path::KeyPath;

        let mut ctx = SchemaContext::new();
        let schema = TraceObjectSchemaDef::new("SESSION", "session_type");
        ctx.register(schema);
        assert!(ctx.get_schema("SESSION").is_some());

        let mut mgr = TraceObjectManager::new();
        let obj = TraceObject::new(KeyPath::of(&["Sessions", "0"]), "SESSION");
        mgr.add_object(obj);
        assert!(mgr.get_object(&KeyPath::of(&["Sessions", "0"])).is_some());
    }

    // ===== Integration: Path Filter + KeyPath =====

    #[test]
    fn test_path_filter_integration() {
        use crate::target::path_pattern::PathPattern;
        use crate::target::key_path::KeyPath;

        let pattern = PathPattern::new(KeyPath::of(&["a", "b", "c"]));
        let partial = KeyPath::of(&["a"]);
        assert!(pattern.successor_could_match(&partial, false));

        let full_match = KeyPath::of(&["a", "b", "c"]);
        assert!(pattern.matches(&full_match));
    }
}
