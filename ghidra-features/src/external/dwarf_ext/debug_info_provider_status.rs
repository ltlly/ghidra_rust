//! DebugInfoProviderStatus -- status of a debug info provider.
//!
//! Ported from `ghidra.app.util.bin.format.dwarf.external.DebugInfoProviderStatus`.

/// Represents the current status of a [`DebugInfoProvider`](super::DebugInfoProvider).
///
/// Providers may be in an unknown state (not yet checked), valid (operational),
/// or invalid (configured but unable to serve requests, e.g. a missing directory).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DebugInfoProviderStatus {
    /// The provider's status has not been determined yet.
    Unknown,
    /// The provider is operational and ready to serve requests.
    Valid,
    /// The provider is configured but currently unable to serve requests.
    Invalid,
}

impl DebugInfoProviderStatus {
    /// Returns `true` if the status is [`Valid`](DebugInfoProviderStatus::Valid).
    pub fn is_valid(self) -> bool {
        self == DebugInfoProviderStatus::Valid
    }

    /// Returns `true` if the status is [`Invalid`](DebugInfoProviderStatus::Invalid).
    pub fn is_invalid(self) -> bool {
        self == DebugInfoProviderStatus::Invalid
    }

    /// Returns `true` if the status is [`Unknown`](DebugInfoProviderStatus::Unknown).
    pub fn is_unknown(self) -> bool {
        self == DebugInfoProviderStatus::Unknown
    }
}

impl std::fmt::Display for DebugInfoProviderStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DebugInfoProviderStatus::Unknown => write!(f, "UNKNOWN"),
            DebugInfoProviderStatus::Valid => write!(f, "VALID"),
            DebugInfoProviderStatus::Invalid => write!(f, "INVALID"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_status_predicates() {
        assert!(DebugInfoProviderStatus::Valid.is_valid());
        assert!(!DebugInfoProviderStatus::Valid.is_invalid());
        assert!(!DebugInfoProviderStatus::Valid.is_unknown());

        assert!(DebugInfoProviderStatus::Invalid.is_invalid());
        assert!(DebugInfoProviderStatus::Unknown.is_unknown());
    }

    #[test]
    fn test_display() {
        assert_eq!(DebugInfoProviderStatus::Unknown.to_string(), "UNKNOWN");
        assert_eq!(DebugInfoProviderStatus::Valid.to_string(), "VALID");
        assert_eq!(DebugInfoProviderStatus::Invalid.to_string(), "INVALID");
    }
}
