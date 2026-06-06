//! Proxy objects for listing fields -- ported from `ghidra.app.util.viewer.proxy`.
//!
//! Proxy objects provide lazy access to program data for field rendering.

/// A proxy object that provides lazy access to a program data item.
///
/// Ported from `ProxyObj.java`.
#[derive(Debug)]
pub struct ProxyObj<T> {
    /// The cached value.
    value: Option<T>,
    /// The address this proxy represents.
    address: u64,
    /// Whether the value needs to be refreshed.
    dirty: bool,
}

impl<T> ProxyObj<T> {
    /// Create a new proxy for the given address.
    pub fn new(address: u64) -> Self {
        Self {
            value: None,
            address,
            dirty: true,
        }
    }

    /// Create a new proxy with an initial value.
    pub fn with_value(address: u64, value: T) -> Self {
        Self {
            value: Some(value),
            address,
            dirty: false,
        }
    }

    /// Get the address.
    pub fn address(&self) -> u64 {
        self.address
    }

    /// Get a reference to the cached value, if any.
    pub fn get(&self) -> Option<&T> {
        self.value.as_ref()
    }

    /// Set the value.
    pub fn set(&mut self, value: T) {
        self.value = Some(value);
        self.dirty = false;
    }

    /// Returns true if the proxy has a value.
    pub fn has_value(&self) -> bool {
        self.value.is_some()
    }

    /// Returns true if the value needs refreshing.
    pub fn is_dirty(&self) -> bool {
        self.dirty
    }

    /// Mark the proxy as needing a refresh.
    pub fn mark_dirty(&mut self) {
        self.dirty = true;
    }
}

/// A proxy for an empty/null data item.
#[derive(Debug)]
pub struct EmptyProxy {
    address: u64,
}

impl EmptyProxy {
    /// Create a new empty proxy.
    pub fn new(address: u64) -> Self {
        Self { address }
    }

    /// Get the address.
    pub fn address(&self) -> u64 {
        self.address
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proxy_basic() {
        let p = ProxyObj::<String>::new(0x401000);
        assert_eq!(p.address(), 0x401000);
        assert!(!p.has_value());
        assert!(p.is_dirty());
    }

    #[test]
    fn test_proxy_with_value() {
        let mut p = ProxyObj::with_value(0x401000, "mov eax, ebx");
        assert!(p.has_value());
        assert!(!p.is_dirty());
        assert_eq!(p.get(), Some(&"mov eax, ebx"));

        p.mark_dirty();
        assert!(p.is_dirty());
    }

    #[test]
    fn test_proxy_set() {
        let mut p = ProxyObj::<String>::new(0x401000);
        p.set("push ebp".to_string());
        assert!(p.has_value());
        assert!(!p.is_dirty());
    }

    #[test]
    fn test_empty_proxy() {
        let p = EmptyProxy::new(0x401000);
        assert_eq!(p.address(), 0x401000);
    }
}
