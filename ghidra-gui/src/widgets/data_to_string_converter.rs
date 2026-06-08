//! Data-to-string conversion trait.
//!
//! Port of Ghidra's `DataToStringConverter` interface. A generic trait for
//! converting typed data objects into their display string representation.
//! Used by table renderers, list widgets, and filter components.

/// A trait for converting a data object of type `T` into a display string.
///
/// This is the Rust equivalent of Ghidra's `DataToStringConverter<T>` interface.
/// It is used wherever a widget needs to convert an opaque data object into a
/// human-readable string for display purposes.
///
/// # Examples
///
/// ```ignore
/// use ghidra_gui::widgets::data_to_string_converter::DataToStringConverter;
///
/// struct MyConverter;
/// impl DataToStringConverter<u32> for MyConverter {
///     fn get_string(&self, value: &u32) -> String {
///         format!("0x{:08X}", value)
///     }
/// }
///
/// let converter = MyConverter;
/// assert_eq!(converter.get_string(&255), "0x000000FF");
/// ```
pub trait DataToStringConverter<T> {
    /// Convert the given data value into a display string.
    fn get_string(&self, value: &T) -> String;
}

/// A pass-through converter for `String` values.
///
/// This is the Rust equivalent of Ghidra's built-in
/// `DataToStringConverter.stringDataToStringConverter` static instance.
pub struct StringDataToStringConverter;

impl DataToStringConverter<String> for StringDataToStringConverter {
    fn get_string(&self, value: &String) -> String {
        value.clone()
    }
}

/// A converter that uses `Display` for any type implementing `std::fmt::Display`.
///
/// This is a convenience converter that works for any `T: Display`.
pub struct DisplayToStringConverter;

impl<T: std::fmt::Display> DataToStringConverter<T> for DisplayToStringConverter {
    fn get_string(&self, value: &T) -> String {
        format!("{}", value)
    }
}

/// A converter that uses `Debug` formatting for any type implementing `std::fmt::Debug`.
pub struct DebugToStringConverter;

impl<T: std::fmt::Debug> DataToStringConverter<T> for DebugToStringConverter {
    fn get_string(&self, value: &T) -> String {
        format!("{:?}", value)
    }
}

/// A converter that applies a user-provided closure.
///
/// This is the Rust equivalent of passing a lambda/function to Java's
/// functional interfaces. It allows inline converter definitions without
/// creating a new struct.
pub struct FnConverter<F>(pub F);

impl<T, F> DataToStringConverter<T> for FnConverter<F>
where
    F: Fn(&T) -> String,
{
    fn get_string(&self, value: &T) -> String {
        (self.0)(value)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_string_converter() {
        let converter = StringDataToStringConverter;
        assert_eq!(converter.get_string(&"hello".to_string()), "hello");
        assert_eq!(converter.get_string(&"".to_string()), "");
    }

    #[test]
    fn test_display_converter_u32() {
        let converter = DisplayToStringConverter;
        assert_eq!(converter.get_string(&42u32), "42");
    }

    #[test]
    fn test_display_converter_f64() {
        let converter = DisplayToStringConverter;
        assert_eq!(converter.get_string(&3.14f64), "3.14");
    }

    #[test]
    fn test_debug_converter() {
        let converter = DebugToStringConverter;
        assert_eq!(converter.get_string(&vec![1, 2, 3]), "[1, 2, 3]");
    }

    #[test]
    fn test_fn_converter() {
        let converter = FnConverter(|x: &u32| format!("0x{:X}", x));
        assert_eq!(converter.get_string(&255), "0xFF");
    }

    #[test]
    fn test_fn_converter_closure() {
        let prefix = "Item".to_string();
        let converter = FnConverter(move |x: &i32| format!("{}-{}", prefix, x));
        assert_eq!(converter.get_string(&7), "Item-7");
    }

    #[test]
    fn test_trait_object() {
        let converters: Vec<Box<dyn DataToStringConverter<i32>>> = vec![
            Box::new(DisplayToStringConverter),
            Box::new(FnConverter(|x: &i32| format!("[{}]", x))),
        ];
        assert_eq!(converters[0].get_string(&5), "5");
        assert_eq!(converters[1].get_string(&5), "[5]");
    }
}
