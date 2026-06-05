//! Comprehensive tests for newly ported Debug modules.
//!
//! Covers: breakpoint specs, listing views, symbol views, path filter expr,
//! and cross-module integration scenarios.

#[cfg(test)]
mod new_port_tests {
    use crate::model::{
        BreakpointKindSet, CodeUnitType, Lifespan, TraceBreakpointCommon, TraceBreakpointLocation,
        TraceBreakpointKind, TraceBreakpointSpec, TraceCodeUnit, TraceCodeUnitsView, TraceDataView,
        TraceDefinedDataView, TraceDefinedUnitsView, TraceInstructionsView, TraceSymbol,
        TraceSymbolKind, TraceSymbolWithAddressView, TraceSymbolWithLocationView,
        TraceUndefinedDataView,
    };
    use crate::target::{KeyPath, PathFilterExpr};

    fn make_kp(segments: &[&str]) -> KeyPath {
        KeyPath::new(segments.iter().map(|s| s.to_string()).collect())
    }

    // ── Breakpoint Spec ─────────────────────────────────────────────

    #[test]
    fn test_breakpoint_common_name_time_travel() {
        let mut bp = TraceBreakpointCommon::new("t1", "bp[0]", Lifespan::span(0, 200));
        bp.set_name(0, "initial");
        bp.set_name(50, "renamed");
        bp.set_name(150, "final");
        assert_eq!(bp.get_name(0), "initial");
        assert_eq!(bp.get_name(49), "initial");
        assert_eq!(bp.get_name(50), "renamed");
        assert_eq!(bp.get_name(100), "renamed");
        assert_eq!(bp.get_name(150), "final");
        assert_eq!(bp.get_name(199), "final");
    }

    #[test]
    fn test_breakpoint_common_enabled_toggle() {
        let mut bp = TraceBreakpointCommon::new("t1", "bp[0]", Lifespan::span(0, 100));
        assert!(bp.is_enabled(0));
        bp.set_enabled(Lifespan::span(10, 20), false);
        bp.set_enabled(Lifespan::span(30, 40), false);
        assert!(bp.is_enabled(5));
        assert!(!bp.is_enabled(15));
        assert!(bp.is_enabled(25));
        assert!(!bp.is_enabled(35));
        assert!(bp.is_enabled(45));
    }

    #[test]
    fn test_breakpoint_spec_full_lifecycle() {
        let mut spec = TraceBreakpointSpec::new("t1", "specs[0]", Lifespan::span(0, 100));
        spec.set_expression(0, "main");
        spec.common.set_name(0, "Main breakpoint");
        spec.common.set_enabled(Lifespan::span(0, 100), true);

        let mut kinds = BreakpointKindSet::new();
        kinds.insert(TraceBreakpointKind::SwExecute);
        spec.set_kinds(0, kinds);

        assert_eq!(spec.get_expression(0), Some("main"));
        assert_eq!(spec.common.get_name(0), "Main breakpoint");
        assert!(spec.common.is_enabled(50));
        assert!(spec.get_kinds(0).is_some());
    }

    #[test]
    fn test_breakpoint_spec_serialization_roundtrip() {
        let mut spec = TraceBreakpointSpec::new("t1", "specs[0]", Lifespan::span(0, 100));
        spec.set_expression(0, "malloc");
        let json = serde_json::to_string(&spec).unwrap();
        let deser: TraceBreakpointSpec = serde_json::from_str(&json).unwrap();
        assert_eq!(deser.get_expression(0), Some("malloc"));
    }

    #[test]
    fn test_breakpoint_location_range_coverage() {
        let loc = TraceBreakpointLocation::new(
            "t1", "l[0]", Lifespan::span(0, 100), 0x400000, 16, "ram",
        );
        assert!(loc.covers_address("ram", 0x400000));
        assert!(loc.covers_address("ram", 0x40000F));
        assert!(!loc.covers_address("ram", 0x400010));
        assert!(!loc.covers_address("stack", 0x400000));
    }

    #[test]
    fn test_breakpoint_location_zero_length() {
        let loc = TraceBreakpointLocation::new(
            "t1", "l[0]", Lifespan::span(0, 100), 0x400000, 0, "ram",
        );
        assert!(loc.covers_address("ram", 0x400000));
        assert!(loc.covers_address("ram", 0xFFFFFFFF));
    }

    #[test]
    fn test_breakpoint_kind_set_roundtrip() {
        let mut kinds = BreakpointKindSet::new();
        kinds.insert(TraceBreakpointKind::Read);
        kinds.insert(TraceBreakpointKind::Write);
        kinds.insert(TraceBreakpointKind::HwExecute);
        let bits = TraceBreakpointKind::to_bits(&kinds);
        let decoded = TraceBreakpointKind::from_bits(bits);
        assert_eq!(decoded.len(), 3);
        assert!(decoded.contains(&TraceBreakpointKind::Read));
        assert!(decoded.contains(&TraceBreakpointKind::Write));
        assert!(decoded.contains(&TraceBreakpointKind::HwExecute));
    }

    // ── Listing Views ───────────────────────────────────────────────

    #[test]
    fn test_code_units_view_empty() {
        let view = TraceCodeUnitsView::new();
        assert!(view.is_empty());
        assert_eq!(view.len(), 0);
        assert_eq!(view.instructions().len(), 0);
        assert_eq!(view.data().len(), 0);
    }

    #[test]
    fn test_code_units_view_mixed_content() {
        let mut view = TraceCodeUnitsView::new();
        view.push(TraceCodeUnit::instruction(
            1, 0x1000, "ram", Lifespan::span(0, 100), 3, "NOP", vec![0x90; 3],
        ));
        view.push(TraceCodeUnit::instruction(
            2, 0x2000, "ram", Lifespan::span(0, 100), 5, "CALL", vec![0xE8; 5],
        ));
        view.push(TraceCodeUnit::data(
            3, 0x3000, "ram", Lifespan::span(0, 100), 4, "dword", vec![0x01, 0x02, 0x03, 0x04],
        ));
        view.push(TraceCodeUnit::undefined(4, 0x4000, "ram", Lifespan::span(0, 100), 1));
        view.push(TraceCodeUnit::undefined(5, 0x5000, "ram", Lifespan::span(0, 100), 1));

        assert_eq!(view.len(), 5);
        assert_eq!(view.instructions().len(), 2);
        assert_eq!(view.data().len(), 3);
        assert_eq!(view.defined_data().len(), 1);
        assert_eq!(view.undefined_data().len(), 2);
    }

    #[test]
    fn test_instructions_view_range_query() {
        let mut view = TraceInstructionsView::new();
        for i in 0..10 {
            view.units.push(TraceCodeUnit::instruction(
                i + 1,
                0x1000 + (i * 4) as u64,
                "ram",
                Lifespan::span(0, 100),
                4,
                "NOP",
                vec![0x90; 4],
            ));
        }
        assert_eq!(view.len(), 10);
        let in_range = view.in_range(0x1000, 0x100F, 50);
        assert_eq!(in_range.len(), 4);
    }

    #[test]
    fn test_data_view_operations() {
        let mut view = TraceDataView::new();
        view.units.push(TraceCodeUnit::data(
            1, 0x2000, "ram", Lifespan::span(0, 100), 4, "dword", vec![0; 4],
        ));
        view.units.push(TraceCodeUnit::data(
            2, 0x2004, "ram", Lifespan::span(0, 100), 8, "qword", vec![0; 8],
        ));

        assert_eq!(view.len(), 2);
        let at = view.get_at(0x2005, 50);
        assert!(at.is_some());
        assert_eq!(at.unwrap().mnemonic, "qword");
    }

    #[test]
    fn test_code_unit_at_address_with_length() {
        let mut view = TraceCodeUnitsView::new();
        view.push(TraceCodeUnit::instruction(
            1, 0x1000, "ram", Lifespan::span(0, 100), 5, "CALL", vec![0xE8; 5],
        ));

        let unit = view.get_at(0x1002, 50);
        assert!(unit.is_some());
        assert_eq!(unit.unwrap().address, 0x1000);

        assert!(view.get_at(0x1005, 50).is_none());
        assert!(view.get_at(0x1002, 150).is_none());
    }

    #[test]
    fn test_defined_and_undefined_views() {
        let d = TraceDefinedDataView::new();
        assert!(d.is_empty());

        let u = TraceUndefinedDataView::new();
        assert!(u.is_empty());

        let du = TraceDefinedUnitsView::new();
        assert!(du.is_empty());
    }

    #[test]
    fn test_code_unit_type_comparisons() {
        assert_eq!(CodeUnitType::Instruction, CodeUnitType::Instruction);
        assert_ne!(CodeUnitType::Instruction, CodeUnitType::Data);
        assert_ne!(CodeUnitType::Data, CodeUnitType::Undefined);
    }

    // ── Symbol Views ────────────────────────────────────────────────

    #[test]
    fn test_symbol_with_address_view_operations() {
        let mut view = TraceSymbolWithAddressView::in_range("ram", 0x400000, 0x400FFF);
        view.push(TraceSymbol::label(1, "main", 0x400000, "ram", Lifespan::span(0, 100)));
        view.push(TraceSymbol::label(2, "helper", 0x400100, "ram", Lifespan::span(0, 100)));
        assert_eq!(view.len(), 2);
        assert!(!view.is_empty());
    }

    #[test]
    fn test_symbol_with_location_view() {
        let mut view = TraceSymbolWithLocationView::new("ram");
        view.push(TraceSymbol::label(1, "start", 0x1000, "ram", Lifespan::span(0, 100)));
        view.push(TraceSymbol::label(2, "end", 0x2000, "ram", Lifespan::span(0, 100)));
        assert_eq!(view.len(), 2);
    }

    #[test]
    fn test_symbol_kind_equality() {
        assert_eq!(TraceSymbolKind::Label, TraceSymbolKind::Label);
        assert_ne!(TraceSymbolKind::Label, TraceSymbolKind::Namespace);
        assert_ne!(TraceSymbolKind::Reference, TraceSymbolKind::Equate);
    }

    // ── PathFilterExpr ──────────────────────────────────────────────

    #[test]
    fn test_path_filter_none_any() {
        assert!(!PathFilterExpr::none().matches(&make_kp(&["x"])));
        assert!(PathFilterExpr::any().matches(&make_kp(&["x", "y"])));
    }

    #[test]
    fn test_path_filter_exact_match() {
        let f = PathFilterExpr::exact(make_kp(&["Processes", "Threads", "[0]"]));
        assert!(f.matches(&make_kp(&["Processes", "Threads", "[0]"])));
        assert!(!f.matches(&make_kp(&["Processes", "Threads", "[1]"])));
    }

    #[test]
    fn test_path_filter_key_at() {
        let f = PathFilterExpr::key_at(0, "Processes");
        assert!(f.matches(&make_kp(&["Processes"])));
        assert!(f.matches(&make_kp(&["Processes", "Threads"])));
        assert!(!f.matches(&make_kp(&["Environment"])));
    }

    #[test]
    fn test_path_filter_or_combination() {
        let f = PathFilterExpr::key_at(0, "A").or(PathFilterExpr::key_at(0, "B"));
        assert!(f.matches(&make_kp(&["A"])));
        assert!(f.matches(&make_kp(&["B"])));
        assert!(!f.matches(&make_kp(&["C"])));
    }

    #[test]
    fn test_path_filter_and_combination() {
        let f = PathFilterExpr::key_at(0, "A").and(PathFilterExpr::key_at(1, "B"));
        assert!(f.matches(&make_kp(&["A", "B"])));
        assert!(!f.matches(&make_kp(&["A", "C"])));
        assert!(!f.matches(&make_kp(&["X", "B"])));
    }

    #[test]
    fn test_path_filter_negation() {
        let f = PathFilterExpr::key_at(0, "A").not();
        assert!(!f.matches(&make_kp(&["A"])));
        assert!(f.matches(&make_kp(&["B"])));
    }

    #[test]
    fn test_path_filter_prefix() {
        let f = PathFilterExpr::prefix(make_kp(&["Processes"]));
        assert!(f.matches(&make_kp(&["Processes"])));
        assert!(f.matches(&make_kp(&["Processes", "Threads", "[0]"])));
        assert!(!f.matches(&make_kp(&["Environment"])));
    }

    #[test]
    fn test_path_filter_successor_matching() {
        let f = PathFilterExpr::exact(make_kp(&["a", "b", "c"]));
        assert!(f.successor_could_match(&make_kp(&["a"]), true));
        assert!(f.successor_could_match(&make_kp(&["a", "b"]), true));
        assert!(!f.successor_could_match(&make_kp(&["a", "b", "c"]), true));
        assert!(f.successor_could_match(&make_kp(&["a", "b", "c"]), false));
    }

    #[test]
    fn test_path_filter_next_keys() {
        let f = PathFilterExpr::exact(make_kp(&["a", "b", "c"]));
        let next = f.get_next_keys(&make_kp(&["a"]));
        assert!(next.contains("b"));
    }

    #[test]
    fn test_path_filter_serialization() {
        let f = PathFilterExpr::prefix(make_kp(&["Processes"]));
        let json = serde_json::to_string(&f).unwrap();
        let d: PathFilterExpr = serde_json::from_str(&json).unwrap();
        assert!(d.matches(&make_kp(&["Processes", "Threads"])));
    }

    // ── Cross-module integration ────────────────────────────────────

    #[test]
    fn test_full_session_with_breakpoints_code_and_symbols() {
        let mut view = TraceCodeUnitsView::new();
        view.push(TraceCodeUnit::instruction(
            1, 0x401000, "ram", Lifespan::span(0, 200), 5, "PUSH RBP", vec![0x55; 5],
        ));
        view.push(TraceCodeUnit::instruction(
            2, 0x401005, "ram", Lifespan::span(0, 200), 3, "MOV", vec![0x48; 3],
        ));
        view.push(TraceCodeUnit::data(
            3, 0x402000, "ram", Lifespan::span(0, 200), 8, "qword", vec![0; 8],
        ));

        assert_eq!(view.instructions().len(), 2);
        assert_eq!(view.data().len(), 1);

        let mut spec = TraceBreakpointSpec::new("t1", "specs[0]", Lifespan::span(0, 200));
        spec.set_expression(0, "0x401000");
        spec.common.set_name(0, "entry bp");

        let loc = TraceBreakpointLocation::new(
            "t1", "locs[0]", Lifespan::span(0, 200), 0x401000, 5, "ram",
        );
        assert!(loc.covers_address("ram", 0x401000));
        assert!(loc.covers_address("ram", 0x401004));

        let mut sym_view = TraceSymbolWithAddressView::in_range("ram", 0x401000, 0x401FFF);
        sym_view.push(TraceSymbol::label(1, "entry", 0x401000, "ram", Lifespan::span(0, 200)));
        sym_view.push(TraceSymbol::label(
            2, "data_section", 0x402000, "ram", Lifespan::span(0, 200),
        ));
        assert_eq!(sym_view.len(), 2);

        let filter = PathFilterExpr::prefix(make_kp(&["Processes", "Threads"]));
        assert!(filter.matches(&make_kp(&["Processes", "Threads", "[0]"])));
        assert!(!filter.matches(&make_kp(&["Processes", "Memory"])));
    }

    #[test]
    fn test_all_types_serialize() {
        let bp = TraceBreakpointCommon::new("t1", "bp[0]", Lifespan::span(0, 100));
        let _ = serde_json::to_string(&bp).unwrap();

        let spec = TraceBreakpointSpec::new("t1", "s[0]", Lifespan::span(0, 100));
        let _ = serde_json::to_string(&spec).unwrap();

        let loc = TraceBreakpointLocation::new("t1", "l[0]", Lifespan::span(0, 100), 0, 4, "ram");
        let _ = serde_json::to_string(&loc).unwrap();

        let view = TraceCodeUnitsView::new();
        let _ = serde_json::to_string(&view).unwrap();

        let sv = TraceSymbolWithAddressView::at_address("ram", 0);
        let _ = serde_json::to_string(&sv).unwrap();

        let lv = TraceSymbolWithLocationView::new("ram");
        let _ = serde_json::to_string(&lv).unwrap();

        let f = PathFilterExpr::any();
        let _ = serde_json::to_string(&f).unwrap();
    }
}
