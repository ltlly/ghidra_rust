//! Extended debugger platform service implementation types.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.debug.service.platform` package.
//! Provides the platform service plugin data model.

use std::collections::BTreeMap;

/// A platform opinion from a debugger backend.
#[derive(Debug, Clone)]
pub struct PlatformOpinion {
    /// The debugger type that provides this opinion (e.g., "gdb", "lldb").
    pub debugger_type: String,
    /// The language ID.
    pub language_id: String,
    /// The compiler spec ID.
    pub compiler_spec_id: String,
    /// Confidence score (0.0 to 1.0).
    pub confidence: f64,
    /// Human-readable description.
    pub description: String,
}

impl PlatformOpinion {
    /// Create a new platform opinion.
    pub fn new(
        debugger_type: impl Into<String>,
        language_id: impl Into<String>,
        compiler_spec_id: impl Into<String>,
        confidence: f64,
    ) -> Self {
        Self {
            debugger_type: debugger_type.into(),
            language_id: language_id.into(),
            compiler_spec_id: compiler_spec_id.into(),
            confidence,
            description: String::new(),
        }
    }

    /// Set the description.
    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = desc.into();
        self
    }
}

/// A platform offer combining an opinion with additional metadata.
#[derive(Debug, Clone)]
pub struct PlatformOffer {
    /// The platform opinion.
    pub opinion: PlatformOpinion,
    /// Whether this offer is available for auto-selection.
    pub auto_select: bool,
    /// The processor name.
    pub processor_name: String,
    /// Address size in bits.
    pub address_size: u32,
}

impl PlatformOffer {
    /// Create a new platform offer.
    pub fn new(
        opinion: PlatformOpinion,
        processor_name: impl Into<String>,
        address_size: u32,
    ) -> Self {
        Self {
            opinion,
            auto_select: false,
            processor_name: processor_name.into(),
            address_size,
        }
    }
}

/// Implementation data for the platform service.
///
/// Corresponds to Java's `DebuggerPlatformServicePlugin`.
#[derive(Debug)]
pub struct PlatformServiceData {
    /// Registered platform opinions by debugger type.
    opinions: BTreeMap<String, Vec<PlatformOpinion>>,
    /// Available platform offers.
    offers: Vec<PlatformOffer>,
    /// Currently selected language ID.
    pub selected_language: Option<String>,
    /// Currently selected compiler spec ID.
    pub selected_compiler_spec: Option<String>,
}

impl PlatformServiceData {
    /// Create new platform service data.
    pub fn new() -> Self {
        Self {
            opinions: BTreeMap::new(),
            offers: Vec::new(),
            selected_language: None,
            selected_compiler_spec: None,
        }
    }

    /// Register a platform opinion.
    pub fn add_opinion(&mut self, opinion: PlatformOpinion) {
        self.opinions
            .entry(opinion.debugger_type.clone())
            .or_default()
            .push(opinion);
    }

    /// Get opinions for a debugger type.
    pub fn get_opinions(&self, debugger_type: &str) -> Option<&Vec<PlatformOpinion>> {
        self.opinions.get(debugger_type)
    }

    /// Get all opinions across all debugger types.
    pub fn all_opinions(&self) -> Vec<&PlatformOpinion> {
        self.opinions.values().flat_map(|v| v.iter()).collect()
    }

    /// Register a platform offer.
    pub fn add_offer(&mut self, offer: PlatformOffer) {
        self.offers.push(offer);
    }

    /// Get all available offers.
    pub fn all_offers(&self) -> &[PlatformOffer] {
        &self.offers
    }

    /// Get the best offer for a given debugger type.
    pub fn best_offer(&self, debugger_type: &str) -> Option<&PlatformOffer> {
        self.offers
            .iter()
            .filter(|o| o.opinion.debugger_type == debugger_type)
            .max_by(|a, b| a.opinion.confidence.partial_cmp(&b.opinion.confidence).unwrap_or(std::cmp::Ordering::Equal))
    }

    /// Select a platform by language and compiler spec.
    pub fn select_platform(&mut self, language_id: impl Into<String>, compiler_spec_id: impl Into<String>) {
        self.selected_language = Some(language_id.into());
        self.selected_compiler_spec = Some(compiler_spec_id.into());
    }

    /// Check if a platform is selected.
    pub fn has_selection(&self) -> bool {
        self.selected_language.is_some() && self.selected_compiler_spec.is_some()
    }

    /// Clear the platform selection.
    pub fn clear_selection(&mut self) {
        self.selected_language = None;
        self.selected_compiler_spec = None;
    }

    /// Get the number of registered debugger types.
    pub fn debugger_type_count(&self) -> usize {
        self.opinions.len()
    }
}

impl Default for PlatformServiceData {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_platform_opinion() {
        let opinion = PlatformOpinion::new("gdb", "x86:LE:64:default", "default", 0.9)
            .with_description("x86-64 Linux");
        assert_eq!(opinion.debugger_type, "gdb");
        assert_eq!(opinion.confidence, 0.9);
        assert_eq!(opinion.description, "x86-64 Linux");
    }

    #[test]
    fn test_platform_offer() {
        let opinion = PlatformOpinion::new("gdb", "x86:LE:64:default", "default", 0.95);
        let offer = PlatformOffer::new(opinion, "x86", 64);
        assert_eq!(offer.processor_name, "x86");
        assert_eq!(offer.address_size, 64);
        assert!(!offer.auto_select);
    }

    #[test]
    fn test_platform_service_data() {
        let mut data = PlatformServiceData::new();
        assert!(!data.has_selection());

        data.add_opinion(PlatformOpinion::new("gdb", "x86:LE:64:default", "default", 0.9));
        data.add_opinion(PlatformOpinion::new("gdb", "ARM:LE:32:v8", "default", 0.7));
        data.add_opinion(PlatformOpinion::new("lldb", "x86:LE:64:default", "default", 0.85));

        assert_eq!(data.debugger_type_count(), 2);
        assert_eq!(data.get_opinions("gdb").unwrap().len(), 2);
        assert_eq!(data.get_opinions("lldb").unwrap().len(), 1);
        assert_eq!(data.all_opinions().len(), 3);
    }

    #[test]
    fn test_platform_service_select() {
        let mut data = PlatformServiceData::new();
        data.select_platform("x86:LE:64:default", "default");
        assert!(data.has_selection());
        assert_eq!(data.selected_language.as_deref(), Some("x86:LE:64:default"));

        data.clear_selection();
        assert!(!data.has_selection());
    }

    #[test]
    fn test_platform_service_offers() {
        let mut data = PlatformServiceData::new();
        data.add_offer(PlatformOffer::new(
            PlatformOpinion::new("gdb", "x86:LE:64:default", "default", 0.95),
            "x86", 64,
        ));
        data.add_offer(PlatformOffer::new(
            PlatformOpinion::new("gdb", "ARM:LE:32:v8", "default", 0.7),
            "ARM", 32,
        ));

        let best = data.best_offer("gdb").unwrap();
        assert_eq!(best.opinion.confidence, 0.95);
    }
}
