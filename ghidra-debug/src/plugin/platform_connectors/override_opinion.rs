//! Override platform opinion.
//!
//! Ported from Ghidra's `OverrideDebuggerPlatformOpinion`.
//! Allows manual override of platform mapping decisions with
//! negative confidence to indicate user-specified overrides.

use crate::services::platform_impl::{Endian, LanguageCompilerSpecId, PlatformOffer};
use super::PlatformOpinionProvider;

/// Override platform opinion implementation.
///
/// Provides manually-overridden platform offers with negative confidence
/// so they appear first in the sorted list when `include_overrides` is true.
#[derive(Debug, Clone, Default)]
pub struct OverridePlatformOpinion;

/// Negative confidence used for override offers.
pub const OVERRIDE_CONFIDENCE: f64 = -1.0;

impl OverridePlatformOpinion {
    /// Create a new override platform opinion.
    pub fn new() -> Self {
        Self
    }

    /// Create an override offer for a specific language/compiler-spec pair.
    pub fn create_override_offer(
        lang_id: &str,
        cspec_id: &str,
        reason: &str,
    ) -> PlatformOffer {
        PlatformOffer {
            lcsp: LanguageCompilerSpecId::new(lang_id, cspec_id),
            confidence: OVERRIDE_CONFIDENCE,
            reason: format!("Override: {}", reason),
            is_override: true,
        }
    }
}

impl PlatformOpinionProvider for OverridePlatformOpinion {
    fn name(&self) -> &str {
        "Override"
    }

    fn get_offers(
        &self,
        _debugger: Option<&str>,
        _arch: &str,
        _os: &str,
        _endian: Option<Endian>,
        include_overrides: bool,
    ) -> Vec<PlatformOffer> {
        if !include_overrides {
            return Vec::new();
        }
        // Override opinions are created dynamically by the user, not statically.
        // This returns empty for the base implementation.
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_override_name() {
        assert_eq!(OverridePlatformOpinion::new().name(), "Override");
    }

    #[test]
    fn test_override_excluded_by_default() {
        let opinion = OverridePlatformOpinion::new();
        let offers = opinion.get_offers(Some("gdb"), "x86_64", "Linux", Some(Endian::Little), false);
        assert!(offers.is_empty());
    }

    #[test]
    fn test_override_create_offer() {
        let offer = OverridePlatformOpinion::create_override_offer(
            "x86:LE:64:default", "gcc", "User selected",
        );
        assert!(offer.is_override);
        assert!(offer.confidence < 0.0);
        assert!(offer.reason.contains("Override"));
    }
}
