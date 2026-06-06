//! Final comprehensive tests for remaining Debug module ports.
//!
//! Tests the PrimitiveTraceObjectSchema, DebuggerTraceViewDiffPlugin,
//! and ensures all critical framework types work correctly.

#[cfg(test)]
mod primitive_schema_tests {
    use crate::model::{
        AttributeSchema, MinimalSchemaContext, PrimitiveTraceObjectSchema, SchemaContext,
        SchemaName, TraceObjectSchemaDef,
    };

    #[test]
    fn test_all_variants_present() {
        let variants = PrimitiveTraceObjectSchema::all_variants();
        assert_eq!(variants.len(), 22);
    }

    #[test]
    fn test_any_is_universal() {
        let any = PrimitiveTraceObjectSchema::Any;
        assert!(any.is_assignable_from("anything"));
        assert_eq!(any.default_element_schema().name, "OBJECT");
        assert_eq!(any.name().name, "ANY");
    }

    #[test]
    fn test_object_accepts_all() {
        let obj = PrimitiveTraceObjectSchema::Object;
        assert!(obj.is_assignable_from("something"));
        assert_eq!(obj.default_element_schema().name, "OBJECT");
    }

    #[test]
    fn test_void_rejects_all() {
        let void = PrimitiveTraceObjectSchema::Void;
        assert!(!void.is_assignable_from("anything"));
        assert_eq!(void.default_element_schema().name, "VOID");
    }

    #[test]
    fn test_primitive_types_match_self() {
        for variant in PrimitiveTraceObjectSchema::all_variants() {
            let name = variant.name().name.clone();
            match variant {
                PrimitiveTraceObjectSchema::Any | PrimitiveTraceObjectSchema::Object => {
                    assert!(variant.is_assignable_from(&name));
                }
                PrimitiveTraceObjectSchema::Void => {
                    assert!(!variant.is_assignable_from(&name));
                }
                _ => {
                    assert!(variant.is_assignable_from(&name));
                }
            }
        }
    }

    #[test]
    fn test_schema_for_type_comprehensive() {
        assert_eq!(
            PrimitiveTraceObjectSchema::schema_for_type("bool"),
            Some(PrimitiveTraceObjectSchema::Bool)
        );
        assert_eq!(
            PrimitiveTraceObjectSchema::schema_for_type("Boolean"),
            Some(PrimitiveTraceObjectSchema::Bool)
        );
        assert_eq!(
            PrimitiveTraceObjectSchema::schema_for_type("i8"),
            Some(PrimitiveTraceObjectSchema::Byte)
        );
        assert_eq!(
            PrimitiveTraceObjectSchema::schema_for_type("u8"),
            Some(PrimitiveTraceObjectSchema::Byte)
        );
        assert_eq!(
            PrimitiveTraceObjectSchema::schema_for_type("i16"),
            Some(PrimitiveTraceObjectSchema::Short)
        );
        assert_eq!(
            PrimitiveTraceObjectSchema::schema_for_type("i32"),
            Some(PrimitiveTraceObjectSchema::Int)
        );
        assert_eq!(
            PrimitiveTraceObjectSchema::schema_for_type("Integer"),
            Some(PrimitiveTraceObjectSchema::Int)
        );
        assert_eq!(
            PrimitiveTraceObjectSchema::schema_for_type("i64"),
            Some(PrimitiveTraceObjectSchema::Long)
        );
        assert_eq!(
            PrimitiveTraceObjectSchema::schema_for_type("u64"),
            Some(PrimitiveTraceObjectSchema::Long)
        );
        assert_eq!(
            PrimitiveTraceObjectSchema::schema_for_type("String"),
            Some(PrimitiveTraceObjectSchema::String)
        );
        assert_eq!(
            PrimitiveTraceObjectSchema::schema_for_type("Address"),
            Some(PrimitiveTraceObjectSchema::Address)
        );
        assert_eq!(
            PrimitiveTraceObjectSchema::schema_for_type("Range"),
            Some(PrimitiveTraceObjectSchema::Range)
        );
        assert_eq!(
            PrimitiveTraceObjectSchema::schema_for_type("AddressRange"),
            Some(PrimitiveTraceObjectSchema::Range)
        );
        assert_eq!(
            PrimitiveTraceObjectSchema::schema_for_type("TraceExecutionState"),
            Some(PrimitiveTraceObjectSchema::ExecutionState)
        );
        assert_eq!(
            PrimitiveTraceObjectSchema::schema_for_type("Character"),
            Some(PrimitiveTraceObjectSchema::Char)
        );
        assert_eq!(
            PrimitiveTraceObjectSchema::schema_for_type("char"),
            Some(PrimitiveTraceObjectSchema::Char)
        );
        // Arrays
        assert_eq!(
            PrimitiveTraceObjectSchema::schema_for_type("boolean[]"),
            Some(PrimitiveTraceObjectSchema::BoolArr)
        );
        assert_eq!(
            PrimitiveTraceObjectSchema::schema_for_type("bool[]"),
            Some(PrimitiveTraceObjectSchema::BoolArr)
        );
        assert_eq!(
            PrimitiveTraceObjectSchema::schema_for_type("byte[]"),
            Some(PrimitiveTraceObjectSchema::ByteArr)
        );
        assert_eq!(
            PrimitiveTraceObjectSchema::schema_for_type("u8[]"),
            Some(PrimitiveTraceObjectSchema::ByteArr)
        );
        assert_eq!(
            PrimitiveTraceObjectSchema::schema_for_type("char[]"),
            Some(PrimitiveTraceObjectSchema::CharArr)
        );
        assert_eq!(
            PrimitiveTraceObjectSchema::schema_for_type("short[]"),
            Some(PrimitiveTraceObjectSchema::ShortArr)
        );
        assert_eq!(
            PrimitiveTraceObjectSchema::schema_for_type("i16[]"),
            Some(PrimitiveTraceObjectSchema::ShortArr)
        );
        assert_eq!(
            PrimitiveTraceObjectSchema::schema_for_type("int[]"),
            Some(PrimitiveTraceObjectSchema::IntArr)
        );
        assert_eq!(
            PrimitiveTraceObjectSchema::schema_for_type("i32[]"),
            Some(PrimitiveTraceObjectSchema::IntArr)
        );
        assert_eq!(
            PrimitiveTraceObjectSchema::schema_for_type("long[]"),
            Some(PrimitiveTraceObjectSchema::LongArr)
        );
        assert_eq!(
            PrimitiveTraceObjectSchema::schema_for_type("i64[]"),
            Some(PrimitiveTraceObjectSchema::LongArr)
        );
        assert_eq!(
            PrimitiveTraceObjectSchema::schema_for_type("String[]"),
            Some(PrimitiveTraceObjectSchema::StringArr)
        );
        // Unknown
        assert_eq!(
            PrimitiveTraceObjectSchema::schema_for_type("NonExistent"),
            None
        );
    }

    #[test]
    fn test_minimal_schema_context_contents() {
        let msc = MinimalSchemaContext::new();
        let ctx = msc.context();

        // Verify all primitive schemas are registered
        for variant in PrimitiveTraceObjectSchema::all_variants() {
            let name = variant.name().name;
            assert!(ctx.has_schema(&name), "Missing schema: {}", name);
        }

        assert_eq!(ctx.schema_count(), 22);
    }

    #[test]
    fn test_minimal_schema_context_default() {
        let msc1 = MinimalSchemaContext::new();
        let msc2 = MinimalSchemaContext::default();
        assert_eq!(msc1.context().schema_count(), msc2.context().schema_count());
    }

    #[test]
    fn test_primitive_schema_not_canonical() {
        for variant in PrimitiveTraceObjectSchema::all_variants() {
            assert!(
                !variant.is_canonical_container(),
                "{:?} should not be canonical container",
                variant
            );
        }
    }

    #[test]
    fn test_primitive_schema_empty_collections() {
        for variant in PrimitiveTraceObjectSchema::all_variants() {
            assert!(variant.interfaces().is_empty());
            assert!(variant.element_schemas().is_empty());
            assert!(variant.attribute_schemas().is_empty());
        }
    }

    #[test]
    fn test_primitive_schema_display() {
        assert_eq!(format!("{}", PrimitiveTraceObjectSchema::Any), "ANY");
        assert_eq!(format!("{}", PrimitiveTraceObjectSchema::Object), "OBJECT");
        assert_eq!(format!("{}", PrimitiveTraceObjectSchema::Void), "VOID");
        assert_eq!(format!("{}", PrimitiveTraceObjectSchema::Bool), "BOOL");
        assert_eq!(format!("{}", PrimitiveTraceObjectSchema::Byte), "BYTE");
        assert_eq!(format!("{}", PrimitiveTraceObjectSchema::Short), "SHORT");
        assert_eq!(format!("{}", PrimitiveTraceObjectSchema::Int), "INT");
        assert_eq!(format!("{}", PrimitiveTraceObjectSchema::Long), "LONG");
        assert_eq!(format!("{}", PrimitiveTraceObjectSchema::String), "STRING");
        assert_eq!(format!("{}", PrimitiveTraceObjectSchema::Address), "ADDRESS");
        assert_eq!(format!("{}", PrimitiveTraceObjectSchema::Range), "RANGE");
        assert_eq!(format!("{}", PrimitiveTraceObjectSchema::Char), "CHAR");
    }

    #[test]
    fn test_primitive_schema_serde_roundtrip() {
        for variant in PrimitiveTraceObjectSchema::all_variants() {
            let json = serde_json::to_string(variant).unwrap();
            let back: PrimitiveTraceObjectSchema = serde_json::from_str(&json).unwrap();
            assert_eq!(&back, variant);
        }
    }

    #[test]
    fn test_primitive_schema_equality() {
        assert_eq!(
            PrimitiveTraceObjectSchema::Bool,
            PrimitiveTraceObjectSchema::Bool
        );
        assert_ne!(
            PrimitiveTraceObjectSchema::Bool,
            PrimitiveTraceObjectSchema::Int
        );
    }

    #[test]
    fn test_primitive_schema_clone() {
        let a = PrimitiveTraceObjectSchema::Long;
        let b = a;
        assert_eq!(a, b);
    }

    #[test]
    fn test_primitive_schema_hash() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        for variant in PrimitiveTraceObjectSchema::all_variants() {
            set.insert(*variant);
        }
        assert_eq!(set.len(), 22);
    }

    #[test]
    fn test_primitive_default_attribute_schema() {
        // Any and Object should have a permissive default
        let any_attr = PrimitiveTraceObjectSchema::Any.default_attribute_schema();
        assert_eq!(any_attr.name, "*");
        assert_eq!(any_attr.schema.name, "OBJECT");

        let obj_attr = PrimitiveTraceObjectSchema::Object.default_attribute_schema();
        assert_eq!(obj_attr.name, "*");
        assert_eq!(obj_attr.schema.name, "OBJECT");

        // Others should have VOID default
        let bool_attr = PrimitiveTraceObjectSchema::Bool.default_attribute_schema();
        assert_eq!(bool_attr.name, "*");
        assert_eq!(bool_attr.schema.name, "VOID");

        let int_attr = PrimitiveTraceObjectSchema::Int.default_attribute_schema();
        assert_eq!(int_attr.schema.name, "VOID");
    }
}

#[cfg(test)]
mod trace_diff_plugin_tests {
    use crate::plugin::trace_diff_plugin::*;

    #[test]
    fn test_diff_session_state_default() {
        assert_eq!(DiffSessionState::default(), DiffSessionState::Inactive);
    }

    #[test]
    fn test_diff_range_basics() {
        let r = DiffRange::new(100, 200);
        assert_eq!(r.len(), 101);
        assert!(r.contains(150));
        assert!(!r.contains(50));
    }

    #[test]
    fn test_diff_range_overlap_and_merge() {
        let a = DiffRange::new(10, 20);
        let b = DiffRange::new(15, 25);
        assert!(a.overlaps(&b));
        let merged = a.merge(&b);
        assert_eq!(merged.min, 10);
        assert_eq!(merged.max, 25);
    }

    #[test]
    fn test_diff_address_set_operations() {
        let mut set = DiffAddressSet::new();
        assert!(set.is_empty());

        set.add(100, 200);
        assert_eq!(set.range_count(), 1);
        assert_eq!(set.total_bytes(), 101);
        assert_eq!(set.min_address(), Some(100));
        assert_eq!(set.max_address(), Some(200));

        set.add(300, 400);
        assert_eq!(set.range_count(), 2);

        // Add overlapping range
        set.add(150, 350);
        assert_eq!(set.range_count(), 1);
        assert_eq!(set.min_address(), Some(100));
        assert_eq!(set.max_address(), Some(400));
    }

    #[test]
    fn test_diff_address_set_intersect() {
        let mut a = DiffAddressSet::new();
        a.add(0, 100);
        a.add(200, 300);

        let mut b = DiffAddressSet::new();
        b.add(50, 250);

        let c = a.intersect(&b);
        assert_eq!(c.range_count(), 2);
        assert!(c.contains(50));
        assert!(c.contains(200));
    }

    #[test]
    fn test_diff_address_set_union() {
        let mut a = DiffAddressSet::new();
        a.add(0, 100);

        let mut b = DiffAddressSet::new();
        b.add(200, 300);

        let c = a.union(&b);
        assert_eq!(c.range_count(), 2);
        assert_eq!(c.min_address(), Some(0));
        assert_eq!(c.max_address(), Some(300));
    }

    #[test]
    fn test_compare_bytes_all_same() {
        let buf = vec![42u8; 100];
        let mut set = DiffAddressSet::new();
        compare_bytes(&mut set, 0, &buf, &buf);
        assert!(set.is_empty());
    }

    #[test]
    fn test_compare_bytes_all_different() {
        let buf1 = vec![0u8; 10];
        let buf2 = vec![1u8; 10];
        let mut set = DiffAddressSet::new();
        compare_bytes(&mut set, 0x1000, &buf1, &buf2);
        assert_eq!(set.range_count(), 1);
        assert_eq!(set.min_address(), Some(0x1000));
        assert_eq!(set.max_address(), Some(0x1009));
    }

    #[test]
    fn test_compare_bytes_with_base_offset() {
        let buf1 = vec![0u8; 5];
        let mut buf2 = vec![0u8; 5];
        buf2[2] = 0xFF;
        let mut set = DiffAddressSet::new();
        compare_bytes(&mut set, 0x400000, &buf1, &buf2);
        assert!(set.contains(0x400002));
        assert!(!set.contains(0x400001));
    }

    #[test]
    fn test_block_size_utils() {
        // Note: min_of_block and max_of_block are only valid for non-zero offsets
        assert_eq!(min_of_block(4096, 1), 0);
        assert_eq!(min_of_block(4096, 4095), 0);
        assert_eq!(min_of_block(4096, 4096), 4096);

        assert_eq!(max_of_block(4096, 1), 4095);
        assert_eq!(max_of_block(4096, 4095), 4095);
        // offset 4096 is at start of second block
        assert_eq!(max_of_block(4096, 4096), 4095);
        assert_eq!(max_of_block(4096, 8192), 8191);

        assert_eq!(len_remains_block(4096, 1), 4095);
        assert_eq!(len_remains_block(4096, 4095), 1);
        assert_eq!(len_remains_block(4096, 4096), 4096);
    }

    #[test]
    fn test_snapshot_diff_result_basic() {
        let result = SnapshotDiffResult::new(0, 1);
        assert!(!result.has_differences());
        assert!(!result.is_degenerate());
        assert_eq!(result.range_count(), 0);
        assert_eq!(result.byte_count(), 0);
    }

    #[test]
    fn test_snapshot_diff_degenerate() {
        let result = SnapshotDiffResult::new(42, 42);
        assert!(result.is_degenerate());
    }

    #[test]
    fn test_snapshot_diff_with_changes() {
        let mut result = SnapshotDiffResult::new(0, 1);
        result.diff_set.add(0x400000, 0x400FFF);
        result.diff_set.add(0x500000, 0x5000FF);
        result.compute_time_ms = 150;

        assert!(result.has_differences());
        assert_eq!(result.range_count(), 2);
        assert_eq!(result.byte_count(), 4096 + 256);
    }

    #[test]
    fn test_diff_plugin_config() {
        let config = TraceDiffPluginConfig::default();
        assert_eq!(config.block_size, 4096);
        assert!(config.show_markers);
        assert_eq!(config.diff_color, (255, 200, 200));
    }

    #[test]
    fn test_diff_address_set_serialization() {
        let mut set = DiffAddressSet::new();
        set.add(100, 200);
        set.add(300, 400);

        let json = serde_json::to_string(&set).unwrap();
        let back: DiffAddressSet = serde_json::from_str(&json).unwrap();
        assert_eq!(back.range_count(), 2);
        assert_eq!(back.min_address(), Some(100));
        assert_eq!(back.max_address(), Some(400));
    }

    #[test]
    fn test_diff_range_serialization() {
        let r = DiffRange::new(0x1000, 0x2000);
        let json = serde_json::to_string(&r).unwrap();
        let back: DiffRange = serde_json::from_str(&json).unwrap();
        assert_eq!(back.min, 0x1000);
        assert_eq!(back.max, 0x2000);
    }

    #[test]
    fn test_diff_address_set_add_address() {
        let mut set = DiffAddressSet::new();
        set.add_address(100);
        set.add_address(101);
        set.add_address(102);
        // Should merge into one range
        assert_eq!(set.range_count(), 1);
        assert_eq!(set.min_address(), Some(100));
        assert_eq!(set.max_address(), Some(102));
    }

    #[test]
    fn test_complex_diff_scenario() {
        let block_size = 256;
        let buf1 = vec![0u8; block_size];
        let mut buf2 = vec![0u8; block_size];

        buf2[10] = 0xFF;
        buf2[11] = 0xFE;
        buf2[100] = 0xAA;

        let mut diff_set = DiffAddressSet::new();
        compare_bytes(&mut diff_set, 0x400000, &buf1, &buf2);

        // Should have 2 ranges (10-11 and 100)
        assert_eq!(diff_set.range_count(), 2);
        assert!(diff_set.contains(0x40000A));
        assert!(diff_set.contains(0x40000B));
        assert!(diff_set.contains(0x400064)); // 100 = 0x64
    }
}

#[cfg(test)]
mod remaining_framework_integration_tests {
    use crate::model::{
        is_scratch, AttributeSchema, Lifespan, PrimitiveTraceObjectSchema,
        SchemaName, SchemaContext, TraceExecutionState, TraceObjectSchemaDef,
    };
    use crate::model::target_schema::SchemaBuilder;
    use crate::api::{
        ActionSource, AutoMapSpec, AutoReadMemorySpec, GoToInput, LocationTracker,
        TrackingEvent,
    };
    use crate::api::modules::MapEntry;

    #[test]
    fn test_lifespan_with_primitive_schemas() {
        let _lifespan = Lifespan::span(0, 100);

        let schema = PrimitiveTraceObjectSchema::Object;
        assert!(schema.is_assignable_from("TraceObject"));
    }

    #[test]
    fn test_schema_context_with_real_schemas() {
        let mut ctx = SchemaContext::new();

        let process_schema = TraceObjectSchemaDef::new("PROCESS", "TraceObject")
            .with_interface("TraceProcess")
            .with_interface("TraceObjectInterface");
        ctx.register(process_schema);

        let thread_schema = TraceObjectSchemaDef::new("THREAD", "TraceObject")
            .with_interface("TraceThread");
        ctx.register(thread_schema);

        assert!(ctx.has_schema("PROCESS"));
        assert!(ctx.has_schema("THREAD"));
        assert_eq!(ctx.schema_count(), 2);
    }

    #[test]
    fn test_execution_state_with_schema() {
        let _state = TraceExecutionState::Running;
        let schema = PrimitiveTraceObjectSchema::ExecutionState;
        assert_eq!(schema.name().name, "EXECUTIONSTATE");
    }

    #[test]
    fn test_map_entry_with_lifespan() {
        let lifespan = Lifespan::span(0, 100);
        let entry = MapEntry::new("trace1", 0x400000, 0x400FFF, 0x100000, 0x100FFF, lifespan);

        assert_eq!(entry.length, 0x1000);
        assert!(entry.contains_from(0x400500, 50));
        assert!(!entry.contains_from(0x400500, 200)); // outside lifespan
    }

    #[test]
    fn test_goto_input_integration() {
        let input = GoToInput::from_string("ram:0x400000");
        assert_eq!(input.space.as_deref(), Some("ram"));
        assert_eq!(input.offset, "0x400000");

        let display = input.to_string();
        assert_eq!(display, "ram:0x400000");
    }

    #[test]
    fn test_action_source_integration() {
        assert!(ActionSource::Manual.is_manual());
        assert!(ActionSource::Automatic.is_automatic());
    }

    #[test]
    fn test_schema_builder_with_attributes() {
        let schema = SchemaBuilder::new("PROCESS", "TraceObject")
            .interface("TraceProcess")
            .interface("TraceObjectInterface")
            .attribute(AttributeSchema::new("pid", SchemaName::new("INT")).required())
            .build();

        assert!(schema.implements("TraceProcess"));
        assert!(schema.implements("TraceObjectInterface"));
        assert!(!schema.implements("TraceThread"));
    }

    #[test]
    fn test_tracking_event_variants() {
        let events = vec![
            TrackingEvent::ValueChanged,
            TrackingEvent::StackChanged,
            TrackingEvent::SnapChanged,
            TrackingEvent::ThreadChanged,
        ];
        assert_eq!(events.len(), 4);
        assert_ne!(events[0], events[1]);
    }

    #[test]
    fn test_auto_map_spec_roundtrip() {
        let spec = AutoMapSpec::new("module", "Map Modules", "Maps loaded modules");
        let json = serde_json::to_string(&spec).unwrap();
        let back: AutoMapSpec = serde_json::from_str(&json).unwrap();
        assert_eq!(back.config_name, "module");
        assert_eq!(back.menu_name, "Map Modules");
    }

    #[test]
    fn test_location_tracker_serialization() {
        let tracker = LocationTracker::new("PC").with_goto_expression("RIP");
        let json = serde_json::to_string(&tracker).unwrap();
        let back: LocationTracker = serde_json::from_str(&json).unwrap();
        assert_eq!(back.spec_name, "PC");
        assert_eq!(back.goto_expression, "RIP");
    }

    #[test]
    fn test_auto_read_memory_spec_registry() {
        let mut registry = crate::api::action::AutoReadMemorySpecRegistry::new();
        assert!(registry.is_empty());

        registry.register(AutoReadMemorySpec::new("regions", "Read Regions", "Read memory"));
        registry.register(AutoReadMemorySpec::new("all", "Read All", "Read all memory"));

        assert_eq!(registry.len(), 2);
        assert!(registry.get("regions").is_some());
        assert!(registry.get("nonexistent").is_none());
    }
}

#[cfg(test)]
mod db_framework_tests {
    use crate::model::{is_scratch, Lifespan};

    #[test]
    fn test_lifespan_scratch() {
        assert!(is_scratch(i64::MIN));
        assert!(!is_scratch(0));
        assert!(!is_scratch(1));
        assert!(!is_scratch(100));
    }

    #[test]
    fn test_lifespan_intersection() {
        let a = Lifespan::span(0, 100);
        let b = Lifespan::span(50, 150);
        let c = Lifespan::span(200, 300);
        assert!(a.intersects(&b));
        assert!(b.intersects(&a));
        assert!(!a.intersects(&c));
        assert!(!c.intersects(&a));
    }

    #[test]
    fn test_lifespan_containment() {
        let span = Lifespan::span(10, 20);
        assert!(span.contains(10));
        assert!(span.contains(15));
        assert!(span.contains(20));
        assert!(!span.contains(9));
        assert!(!span.contains(21));
    }

    #[test]
    fn test_lifespan_at() {
        let span = Lifespan::at(42);
        assert_eq!(span.lmin(), 42);
        assert_eq!(span.lmax(), 42);
        assert!(span.contains(42));
        assert!(!span.contains(41));
    }
}

#[cfg(test)]
mod util_framework_tests {
    use crate::util::copy_on_write::CopyOnWrite;
    use crate::util::method_protector::MethodProtector;

    #[test]
    fn test_copy_on_write_basic() {
        let mut cow = CopyOnWrite::new(vec![1, 2, 3]);
        assert_eq!(cow.get(), &vec![1, 2, 3]);

        // Modify triggers copy
        cow.get_mut().push(4);
        assert_eq!(cow.get(), &vec![1, 2, 3, 4]);
    }

    #[test]
    fn test_copy_on_write_set() {
        let mut cow = CopyOnWrite::new(42);
        assert_eq!(*cow.get(), 42);
        cow.set(100);
        assert_eq!(*cow.get(), 100);
    }

    #[test]
    fn test_method_protector() {
        let protector = MethodProtector::new();
        assert!(!protector.is_active());

        let entered = protector.enter();
        assert!(entered);
        assert!(protector.is_active());
        protector.exit();
        assert!(!protector.is_active());
    }

    #[test]
    fn test_method_protector_reentrant() {
        let protector = MethodProtector::new();
        assert!(!protector.is_active());

        let first = protector.enter();
        assert!(first);
        assert!(protector.is_active());

        // Re-entrant call returns false
        let second = protector.enter();
        assert!(!second);

        // exit() sets active to false regardless of re-entrant state
        protector.exit();
        assert!(!protector.is_active());
    }

    #[test]
    fn test_method_protector_protect() {
        let protector = MethodProtector::new();
        let result = protector.protect(|| 42);
        assert_eq!(result, Some(42));
    }
}
