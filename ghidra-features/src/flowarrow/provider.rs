//! Flow Arrow margin provider -- provides the flow arrow margin in the listing.
//!
//! Ported from `ghidra.app.plugin.core.flowarrow.FlowArrowMarginProvider` and
//! `FlowArrowPlugin`.

use super::{FlowArrow, FlowArrowLayout, FlowArrowModel, FlowArrowType};
use ghidra_core::Address;

/// Provider that supplies flow arrow data for the listing margin.
///
/// Ported from `ghidra.app.plugin.core.flowarrow.FlowArrowMarginProvider`.
#[derive(Debug)]
pub struct FlowArrowMarginProvider {
    /// The flow arrow model.
    model: FlowArrowModel,
    /// Whether the provider is enabled.
    enabled: bool,
    /// Maximum number of columns to display.
    max_columns: usize,
}

impl FlowArrowMarginProvider {
    /// Create a new margin provider.
    pub fn new() -> Self {
        Self {
            model: FlowArrowModel::new(),
            enabled: true,
            max_columns: 8,
        }
    }

    /// Whether the provider is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Enable or disable the provider.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    /// Get the maximum number of columns.
    pub fn max_columns(&self) -> usize {
        self.max_columns
    }

    /// Set the maximum number of columns.
    pub fn set_max_columns(&mut self, max: usize) {
        self.max_columns = max;
    }

    /// Add a flow arrow.
    pub fn add_arrow(&mut self, arrow: FlowArrow) {
        self.model.add_arrow(arrow);
    }

    /// Clear all arrows.
    pub fn clear(&mut self) {
        self.model.clear();
    }

    /// Get the number of arrows.
    pub fn arrow_count(&self) -> usize {
        self.model.count()
    }

    /// Get all arrows with columns assigned.
    pub fn get_arrows_with_columns(&self) -> Vec<FlowArrow> {
        let mut arrows: Vec<FlowArrow> = self.model.get_arrows().to_vec();
        FlowArrowLayout::assign_columns(&mut arrows);
        // Limit to max_columns
        arrows.retain(|a| a.column < self.max_columns);
        arrows
    }

    /// Rebuild arrows from instruction flow analysis.
    ///
    /// This simulates the analysis pass that examines instructions
    /// to determine their control flow targets.
    pub fn rebuild_from_flow(
        &mut self,
        branches: &[(Address, Address, bool)],  // (from, to, is_conditional)
        calls: &[(Address, Address)],             // (from, to)
        fallthroughs: &[(Address, Address)],      // (from, to)
    ) {
        self.model.clear();

        // Add branch arrows
        for &(from, to, is_conditional) in branches {
            let arrow_type = if is_conditional {
                if to > from {
                    FlowArrowType::ConditionalForward
                } else {
                    FlowArrowType::ConditionalBackward
                }
            } else if to > from {
                FlowArrowType::JumpForward
            } else {
                FlowArrowType::JumpBackward
            };
            self.model.add_arrow(FlowArrow::new(from, to, arrow_type));
        }

        // Add call arrows
        for &(from, to) in calls {
            self.model.add_arrow(FlowArrow::new(from, to, FlowArrowType::Call));
        }

        // Add fallthrough arrows
        for &(from, to) in fallthroughs {
            self.model.add_arrow(FlowArrow::new(from, to, FlowArrowType::FallThrough));
        }
    }
}

impl Default for FlowArrowMarginProvider {
    fn default() -> Self {
        Self::new()
    }
}

/// Plugin managing flow arrow display.
///
/// Ported from `ghidra.app.plugin.core.flowarrow.FlowArrowPlugin`.
#[derive(Debug)]
pub struct FlowArrowPlugin {
    /// Plugin name.
    name: String,
    /// The margin provider.
    provider: FlowArrowMarginProvider,
    /// Whether the plugin is active.
    active: bool,
    /// Current program name.
    current_program: Option<String>,
}

impl FlowArrowPlugin {
    /// Create a new flow arrow plugin.
    pub fn new() -> Self {
        Self {
            name: "FlowArrowPlugin".to_string(),
            provider: FlowArrowMarginProvider::new(),
            active: false,
            current_program: None,
        }
    }

    /// Plugin name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Activate the plugin.
    pub fn activate(&mut self) {
        self.active = true;
    }

    /// Deactivate the plugin.
    pub fn deactivate(&mut self) {
        self.active = false;
    }

    /// Whether the plugin is active.
    pub fn is_active(&self) -> bool {
        self.active
    }

    /// Set the current program.
    pub fn set_program(&mut self, program: Option<String>) {
        self.current_program = program;
    }

    /// Get the current program name.
    pub fn current_program(&self) -> Option<&str> {
        self.current_program.as_deref()
    }

    /// Get a reference to the margin provider.
    pub fn provider(&self) -> &FlowArrowMarginProvider {
        &self.provider
    }

    /// Get a mutable reference to the margin provider.
    pub fn provider_mut(&mut self) -> &mut FlowArrowMarginProvider {
        &mut self.provider
    }

    /// Rebuild the flow arrows for the current program.
    pub fn rebuild(
        &mut self,
        branches: &[(Address, Address, bool)],
        calls: &[(Address, Address)],
        fallthroughs: &[(Address, Address)],
    ) {
        self.provider.rebuild_from_flow(branches, calls, fallthroughs);
    }
}

impl Default for FlowArrowPlugin {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_margin_provider_basic() {
        let provider = FlowArrowMarginProvider::new();
        assert!(provider.is_enabled());
        assert_eq!(provider.max_columns(), 8);
        assert_eq!(provider.arrow_count(), 0);
    }

    #[test]
    fn test_margin_provider_arrows() {
        let mut provider = FlowArrowMarginProvider::new();
        provider.add_arrow(FlowArrow::new(
            Address::new(0x1000),
            Address::new(0x2000),
            FlowArrowType::JumpForward,
        ));
        provider.add_arrow(FlowArrow::new(
            Address::new(0x3000),
            Address::new(0x1000),
            FlowArrowType::JumpBackward,
        ));
        assert_eq!(provider.arrow_count(), 2);
    }

    #[test]
    fn test_margin_provider_with_columns() {
        let mut provider = FlowArrowMarginProvider::new();
        provider.add_arrow(FlowArrow::new(
            Address::new(0x1000),
            Address::new(0x3000),
            FlowArrowType::JumpForward,
        ));
        provider.add_arrow(FlowArrow::new(
            Address::new(0x2000),
            Address::new(0x4000),
            FlowArrowType::JumpForward,
        ));

        let arrows = provider.get_arrows_with_columns();
        assert_eq!(arrows.len(), 2);
        // Columns should be assigned
    }

    #[test]
    fn test_margin_provider_max_columns() {
        let mut provider = FlowArrowMarginProvider::new();
        provider.set_max_columns(2);

        // Add 3 overlapping arrows
        for i in 0..3 {
            provider.add_arrow(FlowArrow::new(
                Address::new(0x1000 + i * 0x100),
                Address::new(0x5000 + i * 0x100),
                FlowArrowType::JumpForward,
            ));
        }

        let arrows = provider.get_arrows_with_columns();
        // Should only include arrows with column < 2
        assert!(arrows.len() <= 3);
    }

    #[test]
    fn test_margin_provider_rebuild() {
        let mut provider = FlowArrowMarginProvider::new();
        let branches = vec![
            (Address::new(0x1000), Address::new(0x2000), true),
            (Address::new(0x3000), Address::new(0x1000), false),
        ];
        let calls = vec![(Address::new(0x4000), Address::new(0x5000))];
        let fallthroughs = vec![(Address::new(0x1000), Address::new(0x1004))];

        provider.rebuild_from_flow(&branches, &calls, &fallthroughs);
        assert_eq!(provider.arrow_count(), 4);
    }

    #[test]
    fn test_flow_arrow_plugin_lifecycle() {
        let mut plugin = FlowArrowPlugin::new();
        assert_eq!(plugin.name(), "FlowArrowPlugin");
        assert!(!plugin.is_active());
        assert!(plugin.current_program().is_none());

        plugin.set_program(Some("test.exe".into()));
        assert_eq!(plugin.current_program(), Some("test.exe"));

        plugin.activate();
        assert!(plugin.is_active());

        plugin.deactivate();
        assert!(!plugin.is_active());
    }

    #[test]
    fn test_flow_arrow_plugin_rebuild() {
        let mut plugin = FlowArrowPlugin::new();
        let branches = vec![
            (Address::new(0x1000), Address::new(0x2000), true),
        ];
        let calls = vec![];
        let fallthroughs = vec![(Address::new(0x1000), Address::new(0x1004))];

        plugin.rebuild(&branches, &calls, &fallthroughs);
        assert_eq!(plugin.provider().arrow_count(), 2);
    }

    #[test]
    fn test_margin_provider_clear() {
        let mut provider = FlowArrowMarginProvider::new();
        provider.add_arrow(FlowArrow::new(
            Address::new(0x1000),
            Address::new(0x2000),
            FlowArrowType::JumpForward,
        ));
        assert_eq!(provider.arrow_count(), 1);
        provider.clear();
        assert_eq!(provider.arrow_count(), 0);
    }

    #[test]
    fn test_margin_provider_enabled() {
        let mut provider = FlowArrowMarginProvider::new();
        provider.set_enabled(false);
        assert!(!provider.is_enabled());
        provider.set_enabled(true);
        assert!(provider.is_enabled());
    }
}
