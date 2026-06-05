//! ValStr - a value paired with its string representation.
//!
//! Ported from Ghidra's `ghidra.debug.api.ValStr`.

/// A value paired with its display string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValStr<T> {
    /// The actual value.
    pub value: T,
    /// The string representation for display.
    pub display: String,
}

impl<T> ValStr<T> {
    /// Create a new ValStr.
    pub fn new(value: T, display: impl Into<String>) -> Self {
        Self {
            value,
            display: display.into(),
        }
    }

    /// Create a ValStr using Debug formatting for the display.
    pub fn from_debug(value: T) -> Self
    where
        T: std::fmt::Debug,
    {
        Self {
            display: format!("{:?}", value),
            value,
        }
    }

    /// Create a ValStr using Display formatting for the display.
    pub fn from_display(value: T) -> Self
    where
        T: std::fmt::Display,
    {
        Self {
            display: value.to_string(),
            value,
        }
    }
}

impl<T: std::fmt::Display> std::fmt::Display for ValStr<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.display)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_val_str_new() {
        let vs = ValStr::new(42, "0x2a");
        assert_eq!(vs.value, 42);
        assert_eq!(vs.display, "0x2a");
    }

    #[test]
    fn test_val_str_from_debug() {
        let vs = ValStr::from_debug(vec![1, 2, 3]);
        assert_eq!(vs.display, "[1, 2, 3]");
    }

    #[test]
    fn test_val_str_from_display() {
        let vs = ValStr::from_display(255u8);
        assert_eq!(vs.display, "255");
    }

    #[test]
    fn test_val_str_display() {
        let vs = ValStr::new(10, "ten");
        assert_eq!(format!("{}", vs), "ten");
    }

    #[test]
    fn test_val_str_equality() {
        let a = ValStr::new(1, "one");
        let b = ValStr::new(1, "one");
        let c = ValStr::new(1, "ONE");
        assert_eq!(a, b);
        assert_ne!(a, c);
    }
}
