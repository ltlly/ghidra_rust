//! Port of `ghidra.framework.options.WrappedDate`.
//!
//! A wrapper for persisting date/time values as options. Stores a timestamp
//! in milliseconds since the Unix epoch that can be serialized to/from a
//! key/value state map.

use super::option_type::OptionType;
use super::option_value::OptionValue;
use super::wrapped_option::WrappedOption;

/// Wrapper for a date/time value that can be persisted as an option value.
///
/// Ported from Ghidra's `ghidra.framework.options.WrappedDate`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WrappedDate {
    /// The stored timestamp as milliseconds since the Unix epoch.
    timestamp_ms: i64,
}

impl WrappedDate {
    /// Create a new wrapped date from a timestamp in milliseconds.
    pub fn new(timestamp_ms: i64) -> Self {
        Self { timestamp_ms }
    }

    /// Create a wrapped date representing the current time.
    pub fn now() -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        Self {
            timestamp_ms: now.as_millis() as i64,
        }
    }

    /// Get the stored timestamp in milliseconds.
    pub fn timestamp_ms(&self) -> i64 {
        self.timestamp_ms
    }

    /// Set the stored timestamp in milliseconds.
    pub fn set_timestamp_ms(&mut self, timestamp_ms: i64) {
        self.timestamp_ms = timestamp_ms;
    }
}

impl Default for WrappedDate {
    fn default() -> Self {
        Self::now()
    }
}

impl WrappedOption for WrappedDate {
    fn get_object(&self) -> OptionValue {
        OptionValue::Long(self.timestamp_ms)
    }

    fn read_state(&mut self, state: &[(String, OptionValue)]) {
        for (key, val) in state {
            if key == "date" {
                if let OptionValue::Long(ts) = val {
                    self.timestamp_ms = *ts;
                }
            }
        }
    }

    fn write_state(&self) -> Vec<(String, OptionValue)> {
        vec![("date".to_string(), OptionValue::Long(self.timestamp_ms))]
    }

    fn option_type(&self) -> OptionType {
        OptionType::DateType
    }
}

impl std::fmt::Display for WrappedDate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "WrappedDate: {}", self.timestamp_ms)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wrapped_date_new() {
        let d = WrappedDate::new(1_700_000_000_000);
        assert_eq!(d.timestamp_ms(), 1_700_000_000_000);
    }

    #[test]
    fn test_wrapped_date_now() {
        let d = WrappedDate::now();
        assert!(d.timestamp_ms() > 0);
    }

    #[test]
    fn test_wrapped_date_default() {
        let d = WrappedDate::default();
        assert!(d.timestamp_ms() > 0);
    }

    #[test]
    fn test_wrapped_date_option_type() {
        let d = WrappedDate::new(1000);
        assert_eq!(d.option_type(), OptionType::DateType);
    }

    #[test]
    fn test_wrapped_date_get_object() {
        let d = WrappedDate::new(12345);
        match d.get_object() {
            OptionValue::Long(ts) => assert_eq!(ts, 12345),
            _ => panic!("Expected Long option value"),
        }
    }

    #[test]
    fn test_wrapped_date_roundtrip() {
        let d = WrappedDate::new(1234567890);
        let state = d.write_state();
        assert_eq!(state.len(), 1);

        let mut d2 = WrappedDate::new(0);
        d2.read_state(&state);
        assert_eq!(d2.timestamp_ms(), 1234567890);
    }

    #[test]
    fn test_wrapped_date_set_timestamp() {
        let mut d = WrappedDate::new(0);
        d.set_timestamp_ms(9999);
        assert_eq!(d.timestamp_ms(), 9999);
    }

    #[test]
    fn test_wrapped_date_display() {
        let d = WrappedDate::new(1000);
        let s = format!("{}", d);
        assert!(s.contains("1000"));
    }

    #[test]
    fn test_wrapped_date_equality() {
        let d1 = WrappedDate::new(100);
        let d2 = WrappedDate::new(100);
        let d3 = WrappedDate::new(200);
        assert_eq!(d1, d2);
        assert_ne!(d1, d3);
    }
}
