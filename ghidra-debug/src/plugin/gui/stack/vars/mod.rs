//! Stack variable value hover service.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.debug.gui.stack.vars` package.
//!
//! Provides the `VariableValueHoverPlugin` and its supporting types for
//! displaying live variable values in tooltips when hovering over variables
//! in the listing or decompiler views.

use serde::{Deserialize, Serialize};

/// Plugin configuration for the variable value hover service.
///
/// Ported from `VariableValueHoverPlugin.java`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VariableValueHoverPlugin {
    /// Whether the hover service is enabled.
    pub enabled: bool,
    /// Maximum number of stack frames to search when resolving variables.
    pub max_frames: usize,
    /// Maximum tooltip width in characters.
    pub max_tooltip_width: usize,
    /// Whether to show register-based variables.
    pub show_register_vars: bool,
    /// Whether to show stack-based variables.
    pub show_stack_vars: bool,
}

impl Default for VariableValueHoverPlugin {
    fn default() -> Self {
        Self {
            enabled: true,
            max_frames: 10,
            max_tooltip_width: 80,
            show_register_vars: true,
            show_stack_vars: true,
        }
    }
}

/// The result of a variable value hover lookup.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VariableValueHoverResult {
    /// The variable name.
    pub name: String,
    /// The formatted value string.
    pub value: String,
    /// The value's memory state (known, unknown, etc.).
    pub state: VariableMemoryState,
    /// The data type of the variable.
    pub data_type: String,
    /// The source (register or stack).
    pub source: VariableSource,
    /// The address or register where the variable lives.
    pub location: String,
}

/// The memory state of a variable value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum VariableMemoryState {
    /// The value is known.
    Known,
    /// The value is unknown (uninitialized memory).
    Unknown,
    /// The value is partially known.
    Partial,
}

impl VariableMemoryState {
    /// Return the CSS-like style class for this state.
    pub fn style_class(&self) -> &'static str {
        match self {
            Self::Known => "known",
            Self::Unknown => "stale",
            Self::Partial => "partial",
        }
    }

    /// Style an HTML string based on the memory state.
    pub fn style_html(&self, content: &str) -> String {
        match self {
            Self::Known => content.to_string(),
            Self::Unknown => {
                format!(
                    "<span style='color:gray'><i>{}</i></span>",
                    content
                )
            }
            Self::Partial => {
                format!(
                    "<span style='color:orange'><b>{}</b></span>",
                    content
                )
            }
        }
    }
}

/// The source location type of a variable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum VariableSource {
    /// Stored in a register.
    Register,
    /// Stored on the stack (memory).
    Stack,
    /// Stored in a global/static location.
    Global,
}

impl std::fmt::Display for VariableSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Register => f.write_str("register"),
            Self::Stack => f.write_str("stack"),
            Self::Global => f.write_str("global"),
        }
    }
}

/// The hover service implementation.
///
/// Ported from `VariableValueHoverService.java`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VariableValueHoverService {
    /// The plugin configuration.
    pub config: VariableValueHoverPlugin,
}

impl VariableValueHoverService {
    /// Create a new hover service with default configuration.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a hover service with the given configuration.
    pub fn with_config(config: VariableValueHoverPlugin) -> Self {
        Self { config }
    }

    /// Build an HTML tooltip for a set of variable values.
    pub fn build_tooltip(&self, values: &[VariableValueHoverResult]) -> Option<String> {
        if values.is_empty() {
            return None;
        }

        let mut html = String::from("<html><body style='font-family:monospace'>");
        html.push_str("<table border='0' cellpadding='2'>");

        for (i, val) in values.iter().enumerate() {
            if i > 0 {
                html.push_str("<tr><td colspan='3'><hr/></td></tr>");
            }
            let styled_value = val.state.style_html(&val.value);
            html.push_str(&format!(
                "<tr><td><b>{}</b></td><td>{}</td><td style='color:gray'>({})</td></tr>",
                val.name, styled_value, val.data_type
            ));
            html.push_str(&format!(
                "<tr><td colspan='3' style='font-size:smaller;color:gray'>{}: {}</td></tr>",
                val.source, val.location,
            ));
        }

        html.push_str("</table></body></html>");

        // Truncate if too long
        if html.len() > self.config.max_tooltip_width * 2 {
            html.truncate(self.config.max_tooltip_width * 2);
            html.push_str("...");
        }

        Some(html)
    }

    /// Filter results based on configuration.
    pub fn filter_results(
        &self,
        results: Vec<VariableValueHoverResult>,
    ) -> Vec<VariableValueHoverResult> {
        results
            .into_iter()
            .filter(|r| match r.source {
                VariableSource::Register => self.config.show_register_vars,
                VariableSource::Stack => self.config.show_stack_vars,
                VariableSource::Global => true,
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plugin_default() {
        let p = VariableValueHoverPlugin::default();
        assert!(p.enabled);
        assert_eq!(p.max_frames, 10);
    }

    #[test]
    fn test_memory_state_style_known() {
        let html = VariableMemoryState::Known.style_html("0x42");
        assert_eq!(html, "0x42");
    }

    #[test]
    fn test_memory_state_style_unknown() {
        let html = VariableMemoryState::Unknown.style_html("?");
        assert!(html.contains("gray"));
        assert!(html.contains("?"));
    }

    #[test]
    fn test_memory_state_style_partial() {
        let html = VariableMemoryState::Partial.style_html("partial");
        assert!(html.contains("orange"));
    }

    #[test]
    fn test_memory_state_class() {
        assert_eq!(VariableMemoryState::Known.style_class(), "known");
        assert_eq!(VariableMemoryState::Unknown.style_class(), "stale");
        assert_eq!(VariableMemoryState::Partial.style_class(), "partial");
    }

    #[test]
    fn test_variable_source_display() {
        assert_eq!(format!("{}", VariableSource::Register), "register");
        assert_eq!(format!("{}", VariableSource::Stack), "stack");
        assert_eq!(format!("{}", VariableSource::Global), "global");
    }

    #[test]
    fn test_hover_service_tooltip_empty() {
        let svc = VariableValueHoverService::new();
        assert!(svc.build_tooltip(&[]).is_none());
    }

    #[test]
    fn test_hover_service_tooltip_single() {
        let svc = VariableValueHoverService::new();
        let vals = vec![VariableValueHoverResult {
            name: "RAX".into(),
            value: "0x400000".into(),
            state: VariableMemoryState::Known,
            data_type: "long".into(),
            source: VariableSource::Register,
            location: "RAX".into(),
        }];
        let html = svc.build_tooltip(&vals).unwrap();
        assert!(html.contains("RAX"));
        assert!(html.contains("0x400000"));
    }

    #[test]
    fn test_hover_service_tooltip_styled() {
        let svc = VariableValueHoverService::new();
        let vals = vec![VariableValueHoverResult {
            name: "x".into(),
            value: "?".into(),
            state: VariableMemoryState::Unknown,
            data_type: "int".into(),
            source: VariableSource::Stack,
            location: "SP+8".into(),
        }];
        let html = svc.build_tooltip(&vals).unwrap();
        assert!(html.contains("gray"));
    }

    #[test]
    fn test_filter_results() {
        let mut config = VariableValueHoverPlugin::default();
        config.show_register_vars = false;
        let svc = VariableValueHoverService::with_config(config);

        let results = vec![
            VariableValueHoverResult {
                name: "RAX".into(),
                value: "1".into(),
                state: VariableMemoryState::Known,
                data_type: "long".into(),
                source: VariableSource::Register,
                location: "RAX".into(),
            },
            VariableValueHoverResult {
                name: "x".into(),
                value: "2".into(),
                state: VariableMemoryState::Known,
                data_type: "int".into(),
                source: VariableSource::Stack,
                location: "SP+8".into(),
            },
        ];

        let filtered = svc.filter_results(results);
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].name, "x");
    }

    #[test]
    fn test_filter_results_show_all() {
        let svc = VariableValueHoverService::new();
        let results = vec![
            VariableValueHoverResult {
                name: "a".into(),
                value: "1".into(),
                state: VariableMemoryState::Known,
                data_type: "int".into(),
                source: VariableSource::Register,
                location: "RAX".into(),
            },
            VariableValueHoverResult {
                name: "b".into(),
                value: "2".into(),
                state: VariableMemoryState::Known,
                data_type: "int".into(),
                source: VariableSource::Stack,
                location: "SP+4".into(),
            },
            VariableValueHoverResult {
                name: "c".into(),
                value: "3".into(),
                state: VariableMemoryState::Known,
                data_type: "int".into(),
                source: VariableSource::Global,
                location: "0x4000".into(),
            },
        ];
        assert_eq!(svc.filter_results(results).len(), 3);
    }

    #[test]
    fn test_hover_service_with_config() {
        let mut config = VariableValueHoverPlugin::default();
        config.max_tooltip_width = 20;
        let svc = VariableValueHoverService::with_config(config);
        assert_eq!(svc.config.max_tooltip_width, 20);
    }

    #[test]
    fn test_tooltip_multi() {
        let config = VariableValueHoverPlugin {
            max_tooltip_width: 800,
            ..Default::default()
        };
        let svc = VariableValueHoverService::with_config(config);
        let vals = vec![
            VariableValueHoverResult {
                name: "RAX".into(),
                value: "1".into(),
                state: VariableMemoryState::Known,
                data_type: "long".into(),
                source: VariableSource::Register,
                location: "RAX".into(),
            },
            VariableValueHoverResult {
                name: "RBX".into(),
                value: "2".into(),
                state: VariableMemoryState::Known,
                data_type: "long".into(),
                source: VariableSource::Register,
                location: "RBX".into(),
            },
        ];
        let html = svc.build_tooltip(&vals).unwrap();
        assert!(html.contains("RAX"));
        assert!(html.contains("RBX"));
        assert!(html.contains("<hr/>"));
    }
}
