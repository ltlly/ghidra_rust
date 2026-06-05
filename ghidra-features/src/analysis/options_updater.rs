//! AnalysisOptionsUpdater -- re-export from base analyzer worker.
//!
//! Re-exports [`AnalysisOptionsUpdater`] from `base::analyzer::worker`.

pub use crate::base::analyzer::AnalysisOptionsUpdater;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_options_updater_reexport() {
        let _ = std::any::type_name::<AnalysisOptionsUpdater>();
    }
}
