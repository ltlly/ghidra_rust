//! TransientProgramProperties -- re-export from base analyzer worker.
//!
//! Re-exports [`TransientProgramProperties`] from `base::analyzer::worker`.

pub use crate::base::analyzer::TransientProgramProperties;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transient_properties_reexport() {
        let _ = std::any::type_name::<TransientProgramProperties>();
    }
}
