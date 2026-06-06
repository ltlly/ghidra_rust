//! Port of Ghidra's `ghidra.graph.viewer.actions.VisualGraphSatelliteActionContext`.

/// Context for actions triggered from the satellite (mini-map) view.
#[derive(Debug, Clone)]
pub struct VisualGraphSatelliteActionContext {
    /// Position in satellite view where the action was triggered.
    pub satellite_position: (f64, f64),
    /// Corresponding position in the main graph view.
    pub graph_position: (f64, f64),
}

impl VisualGraphSatelliteActionContext {
    /// Create a new satellite action context.
    pub fn new(sat_x: f64, sat_y: f64, graph_x: f64, graph_y: f64) -> Self {
        Self {
            satellite_position: (sat_x, sat_y),
            graph_position: (graph_x, graph_y),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_satellite_context() {
        let ctx = VisualGraphSatelliteActionContext::new(10.0, 20.0, 100.0, 200.0);
        assert_eq!(ctx.satellite_position, (10.0, 20.0));
        assert_eq!(ctx.graph_position, (100.0, 200.0));
    }
}
