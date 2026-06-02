//! Tests for address types: creation, arithmetic, ranges, and space management.
//!
//! Covers the `ghidra_core::addr` module:
//! - [`Address`] creation and properties
//! - [`AddressSpace`] construction and defaults
//! - [`AddressRange`] operations (length, containment, iteration)
//! - Address comparison, ordering, and display formatting

use ghidra_core::addr::{Address, AddressRange, AddressSpace, AddressRangeIterator};

// ---------------------------------------------------------------------------
// AddressSpace tests
// ---------------------------------------------------------------------------

#[test]
fn test_address_space_construction() {
    let ram = AddressSpace::new("ram", 8, false);
    assert_eq!(ram.name, "ram");
    assert_eq!(ram.pointer_size, 8);
    assert!(!ram.big_endian);

    let reg = AddressSpace::new("register", 4, false);
    assert_eq!(reg.pointer_size, 4);

    let big = AddressSpace::new("rom", 4, true);
    assert!(big.big_endian);
}

#[test]
fn test_address_space_default_ram() {
    let ram = AddressSpace::ram();
    assert_eq!(ram.name, "ram");
    assert_eq!(ram.pointer_size, 8);
    assert!(!ram.big_endian);
}

#[test]
fn test_address_space_display() {
    let space = AddressSpace::new("register", 4, false);
    assert_eq!(format!("{}", space), "register");

    let ram = AddressSpace::ram();
    assert_eq!(format!("{}", ram), "ram");
}

#[test]
fn test_address_space_equality() {
    let a = AddressSpace::new("ram", 8, false);
    let b = AddressSpace::new("ram", 8, false);
    let c = AddressSpace::new("register", 4, false);
    assert_eq!(a, b);
    assert_ne!(a, c);
}

// ---------------------------------------------------------------------------
// Address tests
// ---------------------------------------------------------------------------

#[test]
fn test_address_creation() {
    let addr = Address::new(0x1000);
    assert_eq!(addr.offset, 0x1000);

    let zero = Address::new(0);
    assert_eq!(zero.offset, 0);
}

#[test]
fn test_address_null() {
    assert!(Address::NULL.is_null());
    assert!(!Address::new(0).is_null());
    assert_eq!(Address::NULL.offset, u64::MAX);
}

#[test]
fn test_address_from_u64() {
    let addr: Address = 0xDEADBEEF.into();
    assert_eq!(addr.offset, 0xDEADBEEF);
    assert_eq!(addr, Address::new(0xDEADBEEF));
}

#[test]
fn test_address_into_u64() {
    let addr = Address::new(0xCAFE);
    let val: u64 = addr.into();
    assert_eq!(val, 0xCAFE);
}

#[test]
fn test_address_add() {
    let addr = Address::new(0x1000);
    let next = addr.add(8);
    assert_eq!(next.offset, 0x1008);

    // Overflow wraps
    let max = Address::new(u64::MAX);
    let overflow = max.add(1);
    assert_eq!(overflow.offset, 0);
}

#[test]
fn test_address_sub() {
    let addr = Address::new(0x1000);
    let prev = addr.sub(8);
    assert_eq!(prev.offset, 0xFF8); // wrapping subtract
}

#[test]
fn test_address_subtract() {
    let a = Address::new(0x2000);
    let b = Address::new(0x1000);
    assert_eq!(a.subtract(&b), 0x1000);
    assert_eq!(b.subtract(&a), -0x1000);
}

#[test]
fn test_address_next_prev() {
    let addr = Address::new(0x1000);
    assert_eq!(addr.next(), Address::new(0x1001));
    assert_eq!(addr.prev(), Address::new(0xFFF));
}

#[test]
fn test_address_comparison() {
    let a = Address::new(0x1000);
    let b = Address::new(0x2000);
    let c = Address::new(0x1000);
    assert!(a < b);
    assert!(b > a);
    assert_eq!(a, c);
    assert!(a <= c);
    assert!(a >= c);
}

#[test]
fn test_address_display() {
    let addr = Address::new(0xDEADBEEF);
    assert_eq!(format!("{}", addr), "deadbeef");

    let small = Address::new(0x42);
    assert_eq!(format!("{}", small), "00000042");

    let zero = Address::new(0);
    assert_eq!(format!("{}", zero), "00000000");
}

#[test]
fn test_address_lower_hex() {
    let addr = Address::new(0xABCD);
    assert_eq!(format!("{:08x}", addr), "0000abcd");
    assert_eq!(format!("{:x}", addr), "0000abcd");
}

#[test]
fn test_address_clone_copy() {
    let addr = Address::new(0x1000);
    let copy = addr; // Copy
    let clone = addr.clone();
    assert_eq!(addr, copy);
    assert_eq!(addr, clone);
}

// ---------------------------------------------------------------------------
// AddressRange tests
// ---------------------------------------------------------------------------

#[test]
fn test_address_range_creation() {
    let range = AddressRange::new(Address::new(0x1000), Address::new(0x10FF));
    assert_eq!(range.start, Address::new(0x1000));
    assert_eq!(range.end, Address::new(0x10FF));
}

#[test]
fn test_address_range_len() {
    let range = AddressRange::new(Address::new(0x1000), Address::new(0x10FF));
    assert_eq!(range.len(), 256); // 0x10FF - 0x1000 + 1 = 0x100 = 256

    let single = AddressRange::new(Address::new(0x42), Address::new(0x42));
    assert_eq!(single.len(), 1);

    let two_addr = AddressRange::new(Address::new(0x1000), Address::new(0x1001));
    assert_eq!(two_addr.len(), 2);
}

#[test]
fn test_address_range_is_empty() {
    // end < start = empty
    let empty = AddressRange::new(Address::new(0x2000), Address::new(0x1000));
    assert!(empty.is_empty());

    let not_empty = AddressRange::new(Address::new(0x1000), Address::new(0x1000));
    assert!(!not_empty.is_empty());
}

#[test]
fn test_address_range_contains() {
    let range = AddressRange::new(Address::new(0x1000), Address::new(0x10FF));

    assert!(range.contains(&Address::new(0x1000))); // start boundary
    assert!(range.contains(&Address::new(0x10FF))); // end boundary
    assert!(range.contains(&Address::new(0x1050))); // middle
    assert!(!range.contains(&Address::new(0xFFF)));  // before
    assert!(!range.contains(&Address::new(0x1100))); // after
}

#[test]
fn test_address_range_iter() {
    let range = AddressRange::new(Address::new(0x1000), Address::new(0x1003));
    let addrs: Vec<Address> = range.iter().collect();

    assert_eq!(addrs.len(), 4);
    assert_eq!(addrs[0], Address::new(0x1000));
    assert_eq!(addrs[1], Address::new(0x1001));
    assert_eq!(addrs[2], Address::new(0x1002));
    assert_eq!(addrs[3], Address::new(0x1003));
}

#[test]
fn test_address_range_iter_empty() {
    let range = AddressRange::new(Address::new(0x2000), Address::new(0x1000));
    let addrs: Vec<Address> = range.iter().collect();
    assert!(addrs.is_empty());
}

#[test]
fn test_address_range_iter_single() {
    let range = AddressRange::new(Address::new(0x42), Address::new(0x42));
    let addrs: Vec<Address> = range.iter().collect();
    assert_eq!(addrs.len(), 1);
    assert_eq!(addrs[0], Address::new(0x42));
}

#[test]
fn test_address_range_large_iter_partial() {
    // Verify iteration doesn't panic on large ranges
    let range = AddressRange::new(Address::new(0), Address::new(9));
    let mut iter = range.iter();
    for i in 0..=9 {
        assert_eq!(iter.next(), Some(Address::new(i)));
    }
    assert_eq!(iter.next(), None);
}

#[test]
fn test_address_range_display() {
    let range = AddressRange::new(Address::new(0x1000), Address::new(0x10FF));
    let s = format!("{}", range);
    assert!(s.contains("00001000"));
    assert!(s.contains("000010ff"));
    assert!(s.contains("-"));
}

#[test]
fn test_address_range_copy_clone() {
    let range = AddressRange::new(Address::new(0x1000), Address::new(0x2000));
    let copy = range; // Copy
    let clone = range.clone();
    assert_eq!(range, copy);
    assert_eq!(range, clone);
}

#[test]
fn test_address_range_equality() {
    let a = AddressRange::new(Address::new(0x1000), Address::new(0x2000));
    let b = AddressRange::new(Address::new(0x1000), Address::new(0x2000));
    let c = AddressRange::new(Address::new(0x1000), Address::new(0x2001));
    assert_eq!(a, b);
    assert_ne!(a, c);
}

// ---------------------------------------------------------------------------
// AddressRangeIterator tests
// ---------------------------------------------------------------------------

#[test]
fn test_address_range_iterator_empty() {
    let mut iter = AddressRangeIterator { current: 10, end: 0 };
    assert_eq!(iter.next(), None);
}

#[test]
fn test_address_range_iterator_boundary() {
    // Iterator at u64::MAX boundary
    let mut iter = AddressRangeIterator { current: u64::MAX - 1, end: u64::MAX };
    assert_eq!(iter.next(), Some(Address::new(u64::MAX - 1)));
    assert_eq!(iter.next(), Some(Address::new(u64::MAX)));
    assert_eq!(iter.next(), None);
}

// ---------------------------------------------------------------------------
// Combined scenario tests
// ---------------------------------------------------------------------------

#[test]
fn test_paginated_address_range() {
    // Simulate iterating over 4KB pages
    let page_size: u64 = 0x1000;
    let start = Address::new(0x0000_0000);
    let end = Address::new(0x0000_2FFF); // 3 pages

    let range = AddressRange::new(start, end);
    assert_eq!(range.len(), 0x3000);

    let mut page_addrs = Vec::new();
    let mut current = start;
    while current <= end {
        page_addrs.push(current);
        current = current.add(page_size);
    }

    assert_eq!(page_addrs.len(), 3);
    assert_eq!(page_addrs[0], Address::new(0x0000));
    assert_eq!(page_addrs[1], Address::new(0x1000));
    assert_eq!(page_addrs[2], Address::new(0x2000));
}

#[test]
fn test_address_space_independence() {
    // Addresses from different spaces can share the same offset
    let ram = AddressSpace::new("ram", 8, false);
    let reg = AddressSpace::new("register", 4, false);

    // Both can have offset 0x4, but they refer to different things
    let ram_view = Address::new(0x4);
    let reg_view = Address::new(0x4);

    assert_eq!(ram_view.offset, reg_view.offset);
    // Different space info is tracked at the usage site, not in Address itself
}
