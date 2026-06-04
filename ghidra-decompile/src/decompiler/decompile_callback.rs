//! DecompileCallback: callbacks from the decompiler to the database.
//!
//! Port of Ghidra's `ghidra.app.decompiler.DecompileCallback`.
//!
//! These are routines that the decompiler invokes to gather info during
//! decompilation of a function.  In the native Ghidra, these are
//! implemented as XML-over-pipe callbacks.  Here they are abstracted
//! as a trait.

use ghidra_core::addr::Address;

/// Maximum number of symbols returned per query.
pub const MAX_SYMBOL_COUNT: usize = 16;

/// Data returned for a query about strings.
#[derive(Debug, Clone)]
pub struct StringData {
    /// Whether the string was truncated.
    pub is_truncated: bool,
    /// The UTF-8 encoded byte data.
    pub byte_data: Vec<u8>,
}

impl StringData {
    /// Create a new StringData from a string.
    pub fn new(value: &str, max_chars: usize) -> Self {
        let bytes = value.as_bytes();
        let (data, truncated) = if bytes.len() > max_chars {
            (&bytes[..max_chars], true)
        } else {
            (bytes, false)
        };
        Self {
            is_truncated: truncated,
            byte_data: data.to_vec(),
        }
    }
}

/// Information about a symbol (variable, function, etc.).
#[derive(Debug, Clone)]
pub struct SymbolInfo {
    /// Symbol name.
    pub name: String,
    /// Symbol address.
    pub address: Address,
    /// Symbol namespace.
    pub namespace: Option<String>,
    /// Data type name.
    pub datatype_name: Option<String>,
    /// Whether the symbol is a function.
    pub is_function: bool,
}

/// Information about a memory range.
#[derive(Debug, Clone)]
pub struct MemoryRange {
    /// Start address.
    pub start: Address,
    /// End address (inclusive).
    pub end: Address,
    /// Whether the range is read-only.
    pub read_only: bool,
    /// Whether the range is volatile.
    pub volatile: bool,
}

/// Information about a function.
#[derive(Debug, Clone)]
pub struct FunctionInfo {
    /// Function entry point.
    pub entry: Address,
    /// Function name.
    pub name: String,
    /// Function signature.
    pub signature: Option<String>,
    /// Whether the function is a thunk.
    pub is_thunk: bool,
    /// Stack purge size (extra pop).
    pub extra_pop: i64,
}

/// Trait representing callbacks from the decompiler to the database.
///
/// Implement this trait to provide the decompiler with access to the
/// program database (symbols, memory, types, etc.).
pub trait DecompileCallbackHandler: std::fmt::Debug {
    /// Get memory bytes at the given address.
    fn get_memory_bytes(&self, address: Address, size: usize) -> Vec<u8>;

    /// Get a symbol at the given address.
    fn get_symbol_at(&self, address: Address) -> Option<SymbolInfo>;

    /// Get symbols in the given address range.
    fn get_symbols_in_range(&self, start: Address, end: Address) -> Vec<SymbolInfo>;

    /// Get function information at the given address.
    fn get_function_at(&self, address: Address) -> Option<FunctionInfo>;

    /// Get string data at the given address.
    fn get_string_data(&self, address: Address, max_chars: usize) -> Option<StringData>;

    /// Get the read-only status of the memory at the given address.
    fn is_read_only(&self, address: Address) -> bool;

    /// Get the volatile status of the memory at the given address.
    fn is_volatile(&self, address: Address) -> bool;

    /// Get the native message from the decompiler.
    fn get_native_message(&self) -> Option<String> {
        None
    }

    /// Get the address of the function being decompiled.
    fn get_function_entry(&self) -> Option<Address> {
        None
    }
}

/// Default no-op callback handler.
#[derive(Debug, Clone, Default)]
pub struct NullCallbackHandler;

impl DecompileCallbackHandler for NullCallbackHandler {
    fn get_memory_bytes(&self, _address: Address, size: usize) -> Vec<u8> {
        vec![0u8; size]
    }

    fn get_symbol_at(&self, _address: Address) -> Option<SymbolInfo> {
        None
    }

    fn get_symbols_in_range(&self, _start: Address, _end: Address) -> Vec<SymbolInfo> {
        Vec::new()
    }

    fn get_function_at(&self, _address: Address) -> Option<FunctionInfo> {
        None
    }

    fn get_string_data(&self, _address: Address, _max_chars: usize) -> Option<StringData> {
        None
    }

    fn is_read_only(&self, _address: Address) -> bool {
        false
    }

    fn is_volatile(&self, _address: Address) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_string_data_new() {
        let sd = StringData::new("hello", 100);
        assert!(!sd.is_truncated);
        assert_eq!(sd.byte_data, b"hello");
    }

    #[test]
    fn test_string_data_truncated() {
        let sd = StringData::new("hello world", 5);
        assert!(sd.is_truncated);
        assert_eq!(sd.byte_data, b"hello");
    }

    #[test]
    fn test_null_callback_handler() {
        let handler = NullCallbackHandler;
        let bytes = handler.get_memory_bytes(Address::new(0x1000), 4);
        assert_eq!(bytes, vec![0, 0, 0, 0]);
        assert!(handler.get_symbol_at(Address::new(0x1000)).is_none());
        assert!(!handler.is_read_only(Address::new(0x1000)));
        assert!(!handler.is_volatile(Address::new(0x1000)));
    }

    #[test]
    fn test_symbol_info_clone() {
        let info = SymbolInfo {
            name: "main".to_string(),
            address: Address::new(0x1000),
            namespace: Some("Global".to_string()),
            datatype_name: Some("int".to_string()),
            is_function: true,
        };
        let cloned = info.clone();
        assert_eq!(cloned.name, "main");
        assert!(cloned.is_function);
    }
}
