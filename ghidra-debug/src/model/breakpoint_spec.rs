//! TraceBreakpointSpec and TraceBreakpointCommon - breakpoint specification
//! and common properties for breakpoint objects in the trace model.
//!
//! Ported from Ghidra's `ghidra.trace.model.breakpoint` package:
//! - `TraceBreakpointCommon`: common properties shared by specs and locations.
//! - `TraceBreakpointSpec`: a breakpoint specification that may resolve to
//!   multiple locations.

use serde::{Deserialize, Serialize};

use super::Lifespan;
use super::breakpoint::BreakpointKindSet;

/// Schema name for breakpoint specifications.
pub const SCHEMA_BREAKPOINT_SPEC: &str = "BreakpointSpec";

/// Schema name for breakpoint locations.
pub const SCHEMA_BREAKPOINT_LOCATION: &str = "BreakpointLocation";

/// Key for the expression attribute on a breakpoint specification.
pub const KEY_EXPRESSION: &str = "_expression";

/// Key for the kinds attribute on a breakpoint specification.
pub const KEY_KINDS: &str = "_kinds";

/// Key for the back-reference to the spec from a location.
pub const KEY_AS_BPT: &str = "_bpt";

/// Key for the display name attribute.
pub const KEY_DISPLAY: &str = "_display";

/// Fixed keys for breakpoint specification schemas.
pub const BREAKPOINT_SPEC_FIXED_KEYS: &[&str] = &[KEY_DISPLAY, KEY_EXPRESSION, KEY_KINDS];

/// Attributes declared on breakpoint specification schemas.
pub const BREAKPOINT_SPEC_ATTRIBUTES: &[&str] = &[KEY_EXPRESSION, KEY_KINDS, KEY_AS_BPT];

/// Common properties shared by breakpoint specifications and breakpoint
/// locations. Ported from Ghidra's `TraceBreakpointCommon` interface.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceBreakpointCommon {
    /// The trace ID containing this breakpoint.
    pub trace_id: String,
    /// The full path name unique to this breakpoint.
    pub path: String,
    /// The display name for the breakpoint (snap -> name).
    pub names: Vec<(i64, String)>,
    /// Whether this breakpoint was enabled at various times (start, end, enabled).
    pub enabled_states: Vec<(i64, i64, bool)>,
    /// The object key in the target tree.
    pub object_key: Option<i64>,
    /// The lifespan (creation/deletion snaps).
    pub lifespan: Lifespan,
}

impl TraceBreakpointCommon {
    /// Create a new breakpoint common with a path and lifespan.
    pub fn new(trace_id: impl Into<String>, path: impl Into<String>, lifespan: Lifespan) -> Self {
        Self {
            trace_id: trace_id.into(),
            path: path.into(),
            names: Vec::new(),
            enabled_states: Vec::new(),
            object_key: None,
            lifespan,
        }
    }

    /// Get the trace ID.
    pub fn trace_id(&self) -> &str {
        &self.trace_id
    }

    /// Get the full path name.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Set the display name for a given snap.
    pub fn set_name(&mut self, snap: i64, name: impl Into<String>) {
        self.names.push((snap, name.into()));
        self.names.sort_by_key(|(s, _)| *s);
    }

    /// Get the display name effective at the given snap.
    pub fn get_name(&self, snap: i64) -> &str {
        let mut result = &self.path as &str;
        for (s, name) in &self.names {
            if *s <= snap {
                result = name.as_str();
            } else {
                break;
            }
        }
        result
    }

    /// Set whether this breakpoint is enabled for a given lifespan.
    pub fn set_enabled(&mut self, lifespan: Lifespan, enabled: bool) {
        self.enabled_states
            .push((lifespan.lmin(), lifespan.lmax(), enabled));
        self.enabled_states.sort_by_key(|(s, _, _)| *s);
    }

    /// Check if this breakpoint is enabled at the given snap.
    pub fn is_enabled(&self, snap: i64) -> bool {
        let mut result = true; // enabled by default
        for (start, end, enabled) in &self.enabled_states {
            if *start <= snap && snap <= *end {
                result = *enabled;
            }
        }
        result
    }
}

/// The specification of a breakpoint applied to a target object.
///
/// A single specification may resolve to zero or more
/// [`TraceBreakpointLocation`] objects. If the debugger does not distinguish
/// specifications from locations, a single object can implement both roles.
///
/// Ported from Ghidra's `TraceBreakpointSpec` interface.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceBreakpointSpec {
    /// Common breakpoint properties.
    pub common: TraceBreakpointCommon,
    /// The expression specifying the breakpoint (e.g., function name, address).
    pub expressions: Vec<(i64, String)>,
    /// The set of breakpoint kinds (snap -> kinds).
    pub kind_sets: Vec<(i64, BreakpointKindSet)>,
}

impl TraceBreakpointSpec {
    /// Create a new breakpoint specification.
    pub fn new(trace_id: impl Into<String>, path: impl Into<String>, lifespan: Lifespan) -> Self {
        Self {
            common: TraceBreakpointCommon::new(trace_id, path, lifespan),
            expressions: Vec::new(),
            kind_sets: Vec::new(),
        }
    }

    /// Set the expression for the breakpoint specification.
    pub fn set_expression(&mut self, snap: i64, expression: impl Into<String>) {
        self.expressions.push((snap, expression.into()));
        self.expressions.sort_by_key(|(s, _)| *s);
    }

    /// Get the expression effective at the given snap.
    pub fn get_expression(&self, snap: i64) -> Option<&str> {
        let mut result = None;
        for (s, expr) in &self.expressions {
            if *s <= snap {
                result = Some(expr.as_str());
            } else {
                break;
            }
        }
        result
    }

    /// Set the kinds for this breakpoint specification.
    pub fn set_kinds(&mut self, snap: i64, kinds: BreakpointKindSet) {
        self.kind_sets.push((snap, kinds));
        self.kind_sets.sort_by_key(|(s, _)| *s);
    }

    /// Get the breakpoint kinds effective at the given snap.
    pub fn get_kinds(&self, snap: i64) -> Option<&BreakpointKindSet> {
        let mut result = None;
        for (s, kinds) in &self.kind_sets {
            if *s <= snap {
                result = Some(kinds);
            } else {
                break;
            }
        }
        result
    }

    /// Get the trace ID.
    pub fn trace_id(&self) -> &str {
        self.common.trace_id()
    }

    /// Get the full path.
    pub fn path(&self) -> &str {
        self.common.path()
    }

    /// Get the lifespan.
    pub fn lifespan(&self) -> &Lifespan {
        &self.common.lifespan
    }
}

/// A resolved location of a breakpoint specification in the trace.
///
/// Ported from Ghidra's `TraceBreakpointLocation` (analogous to the database
/// implementation `DBTraceBreakpointLocation`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceBreakpointLocation {
    /// Common breakpoint properties.
    pub common: TraceBreakpointCommon,
    /// The address offset of this breakpoint location.
    pub offset: u64,
    /// The length in bytes this breakpoint covers (0 for a point breakpoint).
    pub length: u32,
    /// The address space name.
    pub space: String,
    /// The object key of the parent breakpoint specification.
    pub spec_object_key: Option<i64>,
}

impl TraceBreakpointLocation {
    /// Create a new breakpoint location.
    pub fn new(
        trace_id: impl Into<String>,
        path: impl Into<String>,
        lifespan: Lifespan,
        offset: u64,
        length: u32,
        space: impl Into<String>,
    ) -> Self {
        Self {
            common: TraceBreakpointCommon::new(trace_id, path, lifespan),
            offset,
            length,
            space: space.into(),
            spec_object_key: None,
        }
    }

    /// Get the trace ID.
    pub fn trace_id(&self) -> &str {
        self.common.trace_id()
    }

    /// Check if this location covers the given address.
    pub fn covers_address(&self, space: &str, addr: u64) -> bool {
        self.space == space
            && addr >= self.offset
            && (self.length == 0 || addr < self.offset + self.length as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_breakpoint_common_name() {
        let mut bp = TraceBreakpointCommon::new("trace1", "Breakpoints[0]", Lifespan::span(0, 100));
        assert_eq!(bp.get_name(0), "Breakpoints[0]");

        bp.set_name(10, "main breakpoint");
        assert_eq!(bp.get_name(5), "Breakpoints[0]");
        assert_eq!(bp.get_name(10), "main breakpoint");
        assert_eq!(bp.get_name(50), "main breakpoint");
    }

    #[test]
    fn test_breakpoint_common_enabled() {
        let mut bp = TraceBreakpointCommon::new("t1", "bp[0]", Lifespan::span(0, 100));
        assert!(bp.is_enabled(0));

        bp.set_enabled(Lifespan::span(10, 20), false);
        assert!(bp.is_enabled(5));
        assert!(!bp.is_enabled(15));
        assert!(bp.is_enabled(25));
    }

    #[test]
    fn test_breakpoint_spec_expression() {
        let mut spec = TraceBreakpointSpec::new("t1", "specs[0]", Lifespan::span(0, 100));
        spec.set_expression(0, "main");
        spec.set_expression(50, "malloc");
        assert_eq!(spec.get_expression(0), Some("main"));
        assert_eq!(spec.get_expression(30), Some("main"));
        assert_eq!(spec.get_expression(50), Some("malloc"));
        assert_eq!(spec.get_expression(99), Some("malloc"));
    }

    #[test]
    fn test_breakpoint_spec_kinds() {
        let mut spec = TraceBreakpointSpec::new("t1", "specs[0]", Lifespan::span(0, 100));
        let mut kinds = BreakpointKindSet::new();
        kinds.insert(super::super::breakpoint::TraceBreakpointKind::SwExecute);
        spec.set_kinds(0, kinds.clone());

        assert!(spec.get_kinds(0).is_some());
        assert!(spec.get_kinds(50).is_some());
    }

    #[test]
    fn test_breakpoint_location_covers_address() {
        let loc = TraceBreakpointLocation::new(
            "t1", "locs[0]", Lifespan::span(0, 100), 0x400000, 4, "ram",
        );
        assert!(loc.covers_address("ram", 0x400000));
        assert!(loc.covers_address("ram", 0x400003));
        assert!(!loc.covers_address("ram", 0x400004));
        assert!(!loc.covers_address("register", 0x400000));
    }

    #[test]
    fn test_breakpoint_spec_serialization() {
        let spec = TraceBreakpointSpec::new("t1", "specs[0]", Lifespan::span(0, 100));
        let json = serde_json::to_string(&spec).unwrap();
        let deserialized: TraceBreakpointSpec = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.path(), "specs[0]");
    }
}
