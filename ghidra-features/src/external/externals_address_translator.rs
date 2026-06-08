//! ExternalsAddressTranslator -- translates addresses between external
//! programs during a merge operation.
//!
//! Ported from
//! `ghidra.app.merge.listing.ExternalsAddressTranslator`.
//!
//! This translator maps source-program external-space addresses to
//! destination-program external-space addresses.  It is used by the
//! merge infrastructure (`ProgramMerge`) when copying external
//! locations from one version of a program to another.
//!
//! Before using the translator with `ProgramMerge`, callers must
//! register all address pairs via [`ExternalsAddressTranslator::set_pair`].
//! Attempting to translate an unregistered address yields
//! [`AddressTranslationError`].
//!
//! # Examples
//!
//! ```rust
//! use ghidra_features::external::{
//!     ExternalsAddressTranslator, AddressTranslationError,
//! };
//! use ghidra_core::addr::Address;
//!
//! let mut translator = ExternalsAddressTranslator::new(
//!     "result_program",
//!     "my_program",
//! );
//!
//! // Register a mapping from the source external address to
//! // the destination external address.
//! let src = Address::new(0xE000_0001);
//! let dst = Address::new(0xE000_0002);
//! translator.set_pair(Some(dst), src);
//!
//! // Translate
//! let translated = translator.get_address(src).unwrap();
//! assert_eq!(translated, dst);
//!
//! // Unregistered address -> error
//! let bad = Address::new(0xE000_0099);
//! assert!(translator.get_address(bad).is_err());
//! ```

use std::collections::HashMap;
use std::fmt;

use ghidra_core::addr::{Address, AddressRange, AddressSet};

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

/// Errors raised during address translation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AddressTranslationError {
    /// The source address was not registered with the translator.
    UnmappedSource(Address),
    /// The address set contained more than one address, which is not
    /// supported by the external address translator.
    MultipleAddresses(usize),
    /// The address range had a length other than 1.
    InvalidRangeLength(u64),
}

impl fmt::Display for AddressTranslationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AddressTranslationError::UnmappedSource(addr) => {
                write!(
                    f,
                    "The specified source address {} never had an external address \
                     pair added to the translator.",
                    addr
                )
            }
            AddressTranslationError::MultipleAddresses(n) => {
                write!(
                    f,
                    "An external address translator can only handle a single address \
                     at a time; got {} addresses.",
                    n
                )
            }
            AddressTranslationError::InvalidRangeLength(len) => {
                write!(
                    f,
                    "An external address translator can only handle a single address \
                     at a time; got range length {}.",
                    len
                )
            }
        }
    }
}

impl std::error::Error for AddressTranslationError {}

// ---------------------------------------------------------------------------
// ExternalsAddressTranslator
// ---------------------------------------------------------------------------

/// Translates external-space addresses between a source and a
/// destination program during a merge.
///
/// This is the Rust port of Ghidra's `ExternalsAddressTranslator`.
/// It maintains a bidirectional-ish mapping from source addresses
/// to destination addresses.  The mapping is populated via
/// [`set_pair`](ExternalsAddressTranslator::set_pair) and queried via
/// [`get_address`](ExternalsAddressTranslator::get_address).
///
/// The translator is **one-for-one** (each source address maps to at
/// most one destination address) and only supports single-address
/// operations; address sets with more than one element will produce
/// an error.
#[derive(Debug, Clone)]
pub struct ExternalsAddressTranslator {
    /// Name of the destination (result) program.
    destination_program: String,
    /// Name of the source program.
    source_program: String,
    /// Map from source address to destination address.
    address_map: HashMap<Address, Address>,
}

impl ExternalsAddressTranslator {
    /// Create a new translator for the given program pair.
    ///
    /// * `destination_program` -- name of the destination (result) program.
    /// * `source_program` -- name of the source program.
    pub fn new(
        destination_program: impl Into<String>,
        source_program: impl Into<String>,
    ) -> Self {
        Self {
            destination_program: destination_program.into(),
            source_program: source_program.into(),
            address_map: HashMap::new(),
        }
    }

    /// Returns the destination program name.
    pub fn destination_program(&self) -> &str {
        &self.destination_program
    }

    /// Returns the source program name.
    pub fn source_program(&self) -> &str {
        &self.source_program
    }

    /// Register an address pair.
    ///
    /// If `destination_address` is `None` the mapping for
    /// `source_address` is removed.
    pub fn set_pair(
        &mut self,
        destination_address: Option<Address>,
        source_address: Address,
    ) {
        match destination_address {
            Some(dst) => {
                self.address_map.insert(source_address, dst);
            }
            None => {
                self.address_map.remove(&source_address);
            }
        }
    }

    /// Translate a single source address to its destination.
    ///
    /// Returns [`AddressTranslationError::UnmappedSource`] if the
    /// source address was never registered.
    pub fn get_address(
        &self,
        source_address: Address,
    ) -> Result<Address, AddressTranslationError> {
        self.address_map
            .get(&source_address)
            .copied()
            .ok_or(AddressTranslationError::UnmappedSource(source_address))
    }

    /// Returns `true` -- this translator is always one-for-one.
    pub fn is_one_for_one_translator(&self) -> bool {
        true
    }

    /// Translate an address set.
    ///
    /// Only address sets with zero or one element are supported.
    /// An empty set returns an empty set.  A set with one element
    /// is translated and returned as a new single-element set.
    pub fn get_address_set(
        &self,
        source_set: &AddressSet,
    ) -> Result<AddressSet, AddressTranslationError> {
        let count = source_set.num_address_ranges();
        if count > 1 {
            return Err(AddressTranslationError::MultipleAddresses(count));
        }
        if count == 0 {
            return Ok(AddressSet::new());
        }
        let source_address = source_set.get_min_address().unwrap();
        let destination_address = self.get_address(source_address)?;
        let mut result = AddressSet::new();
        result.add(destination_address);
        Ok(result)
    }

    /// Translate an address range.
    ///
    /// Only ranges with exactly one address are supported.
    pub fn get_address_range(
        &self,
        source_range: &AddressRange,
    ) -> Result<AddressRange, AddressTranslationError> {
        if source_range.len() != 1 {
            return Err(AddressTranslationError::InvalidRangeLength(
                source_range.len(),
            ));
        }
        let source_address = source_range.get_min_address();
        let destination_address = self.get_address(source_address)?;
        Ok(AddressRange::new(destination_address, destination_address))
    }

    /// Returns the number of registered address pairs.
    pub fn len(&self) -> usize {
        self.address_map.len()
    }

    /// Returns `true` if no pairs are registered.
    pub fn is_empty(&self) -> bool {
        self.address_map.is_empty()
    }

    /// Clear all registered address pairs.
    pub fn clear(&mut self) {
        self.address_map.clear();
    }
}

impl Default for ExternalsAddressTranslator {
    fn default() -> Self {
        Self::new("result", "source")
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_translator() {
        let t = ExternalsAddressTranslator::new("result", "my");
        assert_eq!(t.destination_program(), "result");
        assert_eq!(t.source_program(), "my");
        assert!(t.is_empty());
        assert_eq!(t.len(), 0);
    }

    #[test]
    fn test_default_translator() {
        let t = ExternalsAddressTranslator::default();
        assert_eq!(t.destination_program(), "result");
        assert_eq!(t.source_program(), "source");
    }

    #[test]
    fn test_set_and_get_pair() {
        let mut t = ExternalsAddressTranslator::new("r", "s");
        let src = Address::new(0xE000_0001);
        let dst = Address::new(0xE000_0002);
        t.set_pair(Some(dst), src);

        assert_eq!(t.len(), 1);
        assert!(!t.is_empty());
        assert_eq!(t.get_address(src).unwrap(), dst);
    }

    #[test]
    fn test_get_unmapped_address() {
        let t = ExternalsAddressTranslator::new("r", "s");
        let src = Address::new(0xE000_0099);
        let result = t.get_address(src);
        assert!(result.is_err());
        match result.unwrap_err() {
            AddressTranslationError::UnmappedSource(a) => assert_eq!(a, src),
            _ => panic!("Expected UnmappedSource"),
        }
    }

    #[test]
    fn test_remove_pair() {
        let mut t = ExternalsAddressTranslator::new("r", "s");
        let src = Address::new(0xE000_0001);
        let dst = Address::new(0xE000_0002);
        t.set_pair(Some(dst), src);
        assert_eq!(t.len(), 1);

        t.set_pair(None, src);
        assert!(t.is_empty());
        assert!(t.get_address(src).is_err());
    }

    #[test]
    fn test_overwrite_pair() {
        let mut t = ExternalsAddressTranslator::new("r", "s");
        let src = Address::new(0xE000_0001);
        let dst1 = Address::new(0xE000_0002);
        let dst2 = Address::new(0xE000_0003);
        t.set_pair(Some(dst1), src);
        assert_eq!(t.get_address(src).unwrap(), dst1);

        t.set_pair(Some(dst2), src);
        assert_eq!(t.get_address(src).unwrap(), dst2);
        assert_eq!(t.len(), 1);
    }

    #[test]
    fn test_is_one_for_one() {
        let t = ExternalsAddressTranslator::new("r", "s");
        assert!(t.is_one_for_one_translator());
    }

    #[test]
    fn test_get_address_set_empty() {
        let t = ExternalsAddressTranslator::new("r", "s");
        let empty = AddressSet::new();
        let result = t.get_address_set(&empty).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_get_address_set_single() {
        let mut t = ExternalsAddressTranslator::new("r", "s");
        let src = Address::new(0xE000_0001);
        let dst = Address::new(0xE000_0002);
        t.set_pair(Some(dst), src);

        let mut set = AddressSet::new();
        set.add(src);
        let result = t.get_address_set(&set).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result.min_address().unwrap(), dst);
    }

    #[test]
    fn test_get_address_set_multiple_errors() {
        let t = ExternalsAddressTranslator::new("r", "s");
        let mut set = AddressSet::new();
        set.add(Address::new(0xE000_0001));
        set.add(Address::new(0xE000_0004)); // non-adjacent to avoid range merging
        let result = t.get_address_set(&set);
        assert!(result.is_err());
        match result.unwrap_err() {
            AddressTranslationError::MultipleAddresses(n) => assert_eq!(n, 2),
            _ => panic!("Expected MultipleAddresses"),
        }
    }

    #[test]
    fn test_get_address_range_single() {
        let mut t = ExternalsAddressTranslator::new("r", "s");
        let src = Address::new(0xE000_0001);
        let dst = Address::new(0xE000_0002);
        t.set_pair(Some(dst), src);

        let range = AddressRange::single(src);
        let result = t.get_address_range(&range).unwrap();
        assert_eq!(result.min(), dst);
        assert_eq!(result.get_max_address(), dst);
        assert_eq!(result.length(), 1);
    }

    #[test]
    fn test_get_address_range_too_long_errors() {
        let t = ExternalsAddressTranslator::new("r", "s");
        let range = AddressRange::new(Address::new(0xE000_0001), Address::new(0xE000_0003));
        let result = t.get_address_range(&range);
        assert!(result.is_err());
        match result.unwrap_err() {
            AddressTranslationError::InvalidRangeLength(n) => assert_eq!(n, 3),
            _ => panic!("Expected InvalidRangeLength"),
        }
    }

    #[test]
    fn test_clear() {
        let mut t = ExternalsAddressTranslator::new("r", "s");
        t.set_pair(Some(Address::new(0x2)), Address::new(0x1));
        t.set_pair(Some(Address::new(0x4)), Address::new(0x3));
        assert_eq!(t.len(), 2);

        t.clear();
        assert!(t.is_empty());
        assert_eq!(t.len(), 0);
    }

    #[test]
    fn test_multiple_pairs() {
        let mut t = ExternalsAddressTranslator::new("r", "s");
        let pairs = vec![
            (Address::new(0xE000_0001), Address::new(0xE000_0101)),
            (Address::new(0xE000_0002), Address::new(0xE000_0102)),
            (Address::new(0xE000_0003), Address::new(0xE000_0103)),
        ];
        for (src, dst) in &pairs {
            t.set_pair(Some(*dst), *src);
        }
        assert_eq!(t.len(), 3);

        for (src, dst) in &pairs {
            assert_eq!(t.get_address(*src).unwrap(), *dst);
        }
    }

    #[test]
    fn test_error_display() {
        let err = AddressTranslationError::UnmappedSource(Address::new(0xDEAD));
        assert!(err.to_string().contains("dead"));

        let err = AddressTranslationError::MultipleAddresses(5);
        assert!(err.to_string().contains("5"));

        let err = AddressTranslationError::InvalidRangeLength(10);
        assert!(err.to_string().contains("10"));
    }
}
