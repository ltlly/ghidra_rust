//! Core types for the Ghidra Rust analysis subsystem.

use std::collections::HashMap;
use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::atomic::AtomicU64;

// ============================================================================
// Address primitives
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Address {
    pub space_id: u16,
    pub offset: u64,
}

impl Address {
    pub const fn new(offset: u64) -> Self { Self { space_id: 0, offset } }
    pub const fn in_space(space_id: u16, offset: u64) -> Self { Self { space_id, offset } }
    pub const ZERO: Self = Self::new(0);
    pub const EXTERNAL_SPACE: u16 = u16::MAX;
    pub fn add(&self, delta: u64) -> Self { Self { space_id: self.space_id, offset: self.offset.wrapping_add(delta) } }
    pub fn sub(&self, delta: u64) -> Self { Self { space_id: self.space_id, offset: self.offset.wrapping_sub(delta) } }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.space_id == 0 { write!(f, "{:#010x}", self.offset) }
        else { write!(f, "{}:{:#010x}", self.space_id, self.offset) }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AddressRange { pub start: Address, pub end: Address }

impl AddressRange {
    pub fn new(start: Address, end: Address) -> Self {
        assert_eq!(start.space_id, end.space_id, "AddressRange must be within a single address space");
        assert!(start.offset <= end.offset);
        Self { start, end }
    }
    pub fn single(addr: Address) -> Self { Self { start: addr, end: addr } }
    pub fn len(&self) -> u64 { self.end.offset - self.start.offset + 1 }
    pub fn is_empty(&self) -> bool { self.start.offset > self.end.offset }
    pub fn contains(&self, addr: &Address) -> bool {
        addr.space_id == self.start.space_id && addr.offset >= self.start.offset && addr.offset <= self.end.offset
    }
}

#[derive(Debug, Clone, Default)]
pub struct AddressSet { ranges: Vec<AddressRange> }

impl AddressSet {
    pub fn new() -> Self { Self { ranges: Vec::new() } }
    pub fn from_address(addr: Address) -> Self { let mut s = Self::new(); s.add(addr); s }
    pub fn from_range(range: AddressRange) -> Self { let mut s = Self::new(); s.add_range(range); s }
    pub fn add(&mut self, addr: Address) { self.add_range(AddressRange::single(addr)); }
    pub fn add_range(&mut self, range: AddressRange) {
        if range.is_empty() { return; }
        let mut i = 0;
        while i < self.ranges.len() {
            let e = &self.ranges[i];
            if e.start.space_id != range.start.space_id {
                if e.start.space_id < range.start.space_id { i += 1; } else { self.ranges.insert(i, range); return; }
            } else if e.end.offset < range.start.offset {
                // Existing range ends before new range starts -> continue
                i += 1;
            } else if range.end.offset < e.start.offset {
                // New range ends before existing range starts -> insert here
                break;
            } else {
                // Overlapping or adjacent -> insert here, merge will fix it
                break;
            }
        }
        self.ranges.insert(i, range);
        self.merge_overlapping();
    }
    pub fn add_all(&mut self, other: &AddressSet) { for r in &other.ranges { self.add_range(*r); } }
    pub fn delete(&mut self, other: &AddressSet) {
        let mut result = Vec::new();
        for range in &self.ranges {
            let mut remaining = vec![*range];
            for or in &other.ranges {
                let mut next = Vec::new();
                for r in &remaining {
                    if or.start.space_id != r.start.space_id || or.end.offset < r.start.offset || or.start.offset > r.end.offset { next.push(*r); }
                    else {
                        if or.start.offset > r.start.offset { next.push(AddressRange::new(r.start, Address::new(or.start.offset - 1))); }
                        if or.end.offset < r.end.offset { next.push(AddressRange::new(Address::new(or.end.offset + 1), r.end)); }
                    }
                }
                remaining = next;
            }
            result.extend(remaining);
        }
        self.ranges = result;
    }
    pub fn intersect(&self, other: &AddressSet) -> AddressSet {
        let mut result = AddressSet::new();
        for r1 in &self.ranges { for r2 in &other.ranges {
            if r1.start.space_id != r2.start.space_id { continue; }
            let lo = r1.start.offset.max(r2.start.offset); let hi = r1.end.offset.min(r2.end.offset);
            if lo <= hi { result.add_range(AddressRange::new(Address::in_space(r1.start.space_id, lo), Address::in_space(r1.start.space_id, hi))); }
        }}
        result
    }
    pub fn union(&self, other: &AddressSet) -> AddressSet { let mut r = self.clone(); r.add_all(other); r }
    pub fn contains(&self, addr: &Address) -> bool { self.ranges.iter().any(|r| r.contains(addr)) }
    pub fn contains_set(&self, other: &AddressSet) -> bool {
        if other.is_empty() { return true; }
        if self.is_empty() { return false; }
        for range in &other.ranges {
            let mut addr = range.start;
            while addr.offset <= range.end.offset {
                if !self.contains(&addr) { return false; }
                addr = addr.add(1);
            }
        }
        true
    }
    pub fn is_empty(&self) -> bool { self.ranges.is_empty() }
    pub fn num_addresses(&self) -> u64 { self.ranges.iter().map(|r| r.len()).sum() }
    pub fn iter(&self) -> impl Iterator<Item = &AddressRange> { self.ranges.iter() }
    pub fn get_addresses(&self, _forward: bool) -> AddressIterator<'_> { AddressIterator { ranges: &self.ranges, range_idx: 0, current_offset: None } }
    pub fn min_address(&self) -> Address { self.ranges.first().map(|r| r.start).unwrap_or(Address::ZERO) }
    pub fn max_address(&self) -> Address { self.ranges.last().map(|r| r.end).unwrap_or(Address::ZERO) }
    pub fn clear(&mut self) { self.ranges.clear(); }
    fn merge_overlapping(&mut self) {
        if self.ranges.len() < 2 { return; }
        // Sort by (space_id, start) to ensure correct merge order
        self.ranges.sort_by_key(|r| (r.start.space_id, r.start.offset));
        let mut merged = Vec::new(); let mut current = self.ranges[0];
        for &range in &self.ranges[1..] {
            if range.start.space_id != current.start.space_id { merged.push(current); current = range; }
            else if current.end.offset.checked_add(1).map_or(false, |next| range.start.offset <= next) {
                // Overlapping or adjacent -> merge
                if range.end.offset > current.end.offset { current.end = range.end; }
                // Also handle case where range starts before current (shouldn't happen after sort, but be safe)
                if range.start.offset < current.start.offset { current.start = range.start; }
            }
            else { merged.push(current); current = range; }
        }
        merged.push(current); self.ranges = merged;
    }
}

impl<'a> From<&'a Address> for AddressSet { fn from(addr: &'a Address) -> Self { Self::from_address(*addr) } }
impl From<AddressRange> for AddressSet { fn from(range: AddressRange) -> Self { Self::from_range(range) } }

pub struct AddressIterator<'a> { ranges: &'a [AddressRange], range_idx: usize, current_offset: Option<u64> }
impl<'a> Iterator for AddressIterator<'a> {
    type Item = Address;
    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if self.range_idx >= self.ranges.len() { return None; }
            let range = &self.ranges[self.range_idx];
            let offset = self.current_offset.unwrap_or(range.start.offset);
            if offset > range.end.offset { self.range_idx += 1; self.current_offset = None; continue; }
            self.current_offset = Some(offset + 1);
            return Some(Address::in_space(range.start.space_id, offset));
        }
    }
}

pub trait AddressSetView: std::ops::Deref<Target = AddressSet> {}
impl<T: std::ops::Deref<Target = AddressSet>> AddressSetView for T {}

// ============================================================================
// TaskMonitor
// ============================================================================

pub trait TaskMonitor: Send + Sync {
    fn is_cancelled(&self) -> bool;
    fn set_message(&self, message: &str);
    fn get_message(&self) -> String;
    fn set_progress(&self, value: u64);
    fn initialize(&self, max: u64);
    fn set_maximum(&self, max: u64);
    fn get_maximum(&self) -> u64;
    fn increment_progress(&self, amount: u64);
    fn get_progress(&self) -> u64;
    fn set_show_progress_value(&self, show: bool);
    fn set_indeterminate(&self, indeterminate: bool);
    fn is_indeterminate(&self) -> bool;
    fn cancel(&self);
    fn is_cancel_enabled(&self) -> bool;
    fn set_cancel_enabled(&self, enabled: bool);
    fn clear_cancelled(&self);
    fn check_cancelled(&self) -> Result<(), CancelledError> { if self.is_cancelled() { Err(CancelledError) } else { Ok(()) } }
}

#[derive(Debug, Default)]
pub struct BasicTaskMonitor { cancelled: AtomicBool, message: std::sync::Mutex<String>, progress: AtomicU64, maximum: AtomicU64, indeterminate: AtomicBool, cancel_enabled: AtomicBool, show_progress: AtomicBool }
impl BasicTaskMonitor {
    pub fn new() -> Self { Self { cancelled: AtomicBool::new(false), message: std::sync::Mutex::new(String::new()), progress: AtomicU64::new(0), maximum: AtomicU64::new(0), indeterminate: AtomicBool::new(false), cancel_enabled: AtomicBool::new(true), show_progress: AtomicBool::new(true) } }
}
impl TaskMonitor for BasicTaskMonitor {
    fn is_cancelled(&self) -> bool { self.cancelled.load(Ordering::Relaxed) }
    fn set_message(&self, msg: &str) { if let Ok(mut m) = self.message.lock() { *m = msg.to_string(); } }
    fn get_message(&self) -> String { self.message.lock().map(|m| m.clone()).unwrap_or_default() }
    fn set_progress(&self, v: u64) { self.progress.store(v, Ordering::Relaxed); }
    fn initialize(&self, max: u64) { self.progress.store(0, Ordering::Relaxed); self.maximum.store(max, Ordering::Relaxed); }
    fn set_maximum(&self, max: u64) { self.maximum.store(max, Ordering::Relaxed); }
    fn get_maximum(&self) -> u64 { self.maximum.load(Ordering::Relaxed) }
    fn increment_progress(&self, amt: u64) { self.progress.fetch_add(amt, Ordering::Relaxed); }
    fn get_progress(&self) -> u64 { self.progress.load(Ordering::Relaxed) }
    fn set_show_progress_value(&self, show: bool) { self.show_progress.store(show, Ordering::Relaxed); }
    fn set_indeterminate(&self, ind: bool) { self.indeterminate.store(ind, Ordering::Relaxed); }
    fn is_indeterminate(&self) -> bool { self.indeterminate.load(Ordering::Relaxed) }
    fn cancel(&self) { self.cancelled.store(true, Ordering::Relaxed); }
    fn is_cancel_enabled(&self) -> bool { self.cancel_enabled.load(Ordering::Relaxed) }
    fn set_cancel_enabled(&self, enabled: bool) { self.cancel_enabled.store(enabled, Ordering::Relaxed); }
    fn clear_cancelled(&self) { self.cancelled.store(false, Ordering::Relaxed); }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CancelledError;
impl fmt::Display for CancelledError { fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "analysis cancelled by user") } }
impl std::error::Error for CancelledError {}

// ============================================================================
// Program stubs
// ============================================================================

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Language { pub processor: String, pub variant: String, pub size: u32 }
impl Language {
    pub fn has_property(&self, _name: &str) -> bool { false }
    pub fn get_property_as_bool(&self, _name: &str, default: bool) -> bool { default }
    pub fn default_pointer_size(&self) -> u32 { self.size / 8 }
    pub fn instruction_alignment(&self) -> u32 { 1 }
    pub fn is_segmented(&self) -> bool { self.processor.to_lowercase().contains("x86") && self.variant.to_lowercase().contains("seg") }
}

#[derive(Debug, Clone)]
pub struct MemoryBlock { pub name: String, pub start: Address, pub size: u64, pub is_read: bool, pub is_write: bool, pub is_execute: bool, pub is_initialized: bool }

#[derive(Debug, Clone)]
pub struct Function { pub entry_point: Address, pub body: AddressSet, pub name: Option<String>, pub is_external: bool, pub is_thunk: bool, pub is_inline: bool, pub has_noreturn: bool, pub call_fixup: Option<String> }

#[derive(Debug, Clone)]
pub struct Instruction { pub address: Address, pub length: u32, pub mnemonic: String, pub flow_type: FlowType, pub fall_through: Option<Address>, pub flows: Vec<Address>, pub num_operands: u32 }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowType { Fallthrough, Jump, ConditionalJump, Call, ConditionalCall, Return, Terminator, Unknown }
impl FlowType {
    pub fn is_call(&self) -> bool { matches!(self, FlowType::Call | FlowType::ConditionalCall) }
    pub fn is_jump(&self) -> bool { matches!(self, FlowType::Jump | FlowType::ConditionalJump) }
    pub fn has_fallthrough(&self) -> bool { matches!(self, FlowType::Fallthrough | FlowType::Call | FlowType::ConditionalCall | FlowType::ConditionalJump) }
    pub fn is_terminal(&self) -> bool { matches!(self, FlowType::Return | FlowType::Terminator) }
    pub fn is_computed(&self) -> bool { false }
}

#[derive(Debug, Clone)]
pub struct Data { pub address: Address, pub length: u32, pub data_type_name: String }
impl Data { pub fn is_pointer(&self) -> bool { self.data_type_name.contains("pointer") || self.data_type_name == "addr" } }

#[derive(Debug, Clone)]
pub struct Reference { pub from_address: Address, pub to_address: Address, pub ref_type: RefType }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefType { Read, Write, Flow, Call, Data }
impl RefType { pub fn is_call(&self) -> bool { *self == RefType::Call } pub fn is_flow(&self) -> bool { *self == RefType::Flow } pub fn is_read(&self) -> bool { *self == RefType::Read } pub fn is_write(&self) -> bool { *self == RefType::Write } }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BookmarkType { Analysis, Warning, Error, Info }

#[derive(Debug, Clone, Default)]
pub struct Listing { pub instructions: HashMap<Address, Instruction>, pub data_items: HashMap<Address, Data> }
impl Listing {
    pub fn get_instruction_at(&self, addr: &Address) -> Option<&Instruction> { self.instructions.get(addr) }
    pub fn get_instruction_containing(&self, addr: &Address) -> Option<&Instruction> {
        for instr in self.instructions.values() { let end = instr.address.add(instr.length as u64);
            if addr.space_id == instr.address.space_id && addr.offset >= instr.address.offset && addr.offset < end.offset { return Some(instr); }
        }
        None
    }
    pub fn get_defined_data_at(&self, addr: &Address) -> Option<&Data> { self.data_items.get(addr) }
    pub fn get_instructions<'a>(&'a self, set: &'a AddressSet, _forward: bool) -> InstructionIterator<'a> { InstructionIterator { listing: self, ranges: set.iter().collect(), range_idx: 0, current_addr: None } }
    pub fn num_instructions(&self) -> usize { self.instructions.len() }
    pub fn num_defined_data(&self) -> usize { self.data_items.len() }
}

pub struct InstructionIterator<'a> { listing: &'a Listing, ranges: Vec<&'a AddressRange>, range_idx: usize, current_addr: Option<Address> }
impl<'a> Iterator for InstructionIterator<'a> {
    type Item = &'a Instruction;
    fn next(&mut self) -> Option<Self::Item> { loop {
        if self.range_idx >= self.ranges.len() { return None; }
        let range = self.ranges[self.range_idx]; let addr = self.current_addr.unwrap_or(range.start);
        if addr.offset > range.end.offset { self.range_idx += 1; self.current_addr = None; continue; }
        self.current_addr = Some(addr.add(1));
        if let Some(instr) = self.listing.instructions.get(&addr) { return Some(instr); }
    }}
}

#[derive(Debug, Clone, Default)]
pub struct FunctionManager { pub functions: HashMap<Address, Function> }
impl FunctionManager {
    pub fn get_function_at(&self, entry: &Address) -> Option<&Function> { self.functions.get(entry) }
    pub fn get_function_containing(&self, addr: &Address) -> Option<&Function> { for func in self.functions.values() { if func.body.contains(addr) { return Some(func); } } None }
    pub fn get_functions(&self, _include_external: bool) -> FunctionIterator<'_> { FunctionIterator { inner: self.functions.values() } }
}
pub struct FunctionIterator<'a> { inner: std::collections::hash_map::Values<'a, Address, Function> }
impl<'a> Iterator for FunctionIterator<'a> {
    type Item = &'a Function;
    fn next(&mut self) -> Option<Self::Item> { self.inner.next() }
    fn size_hint(&self) -> (usize, Option<usize>) { self.inner.size_hint() }
}

#[derive(Debug, Clone)]
pub struct Program { pub name: String, pub language: Language, pub memory_blocks: Vec<MemoryBlock>, pub listing: Listing, pub function_manager: FunctionManager, pub image_base: u64, pub memory: AddressSet, pub is_temporary: bool, pub is_changed: bool, pub executable_format: Option<String>, pub external_references: HashMap<Address, String>, pub symbols: HashMap<Address, String>, pub bookmarks: Vec<(Address, BookmarkType, String, String)> }
impl Default for Program { fn default() -> Self { Program::new("", Language { processor: String::new(), variant: String::new(), size: 0 }) } }
impl Program {
    pub fn new(name: &str, language: Language) -> Self { Self { name: name.to_string(), language, memory_blocks: Vec::new(), listing: Listing::default(), function_manager: FunctionManager::default(), image_base: 0, memory: AddressSet::new(), is_temporary: true, is_changed: false, executable_format: None, external_references: HashMap::new(), symbols: HashMap::new(), bookmarks: Vec::new() } }
    pub fn get_listing(&self) -> &Listing { &self.listing }
    pub fn get_language(&self) -> &Language { &self.language }
    pub fn get_function_manager(&self) -> &FunctionManager { &self.function_manager }
    pub fn get_memory(&self) -> &AddressSet { &self.memory }
    pub fn get_executable_format(&self) -> Option<&str> { self.executable_format.as_deref() }
    pub fn get_min_address(&self) -> Option<Address> { if self.memory.is_empty() { None } else { Some(self.memory.min_address()) } }
    pub fn set_bookmark(&mut self, addr: Address, bt: BookmarkType, cat: impl Into<String>, msg: impl Into<String>) { self.bookmarks.push((addr, bt, cat.into(), msg.into())); }
}

#[derive(Debug, Clone, Default)]
pub struct MessageLog { messages: Vec<String> }
impl MessageLog {
    pub fn new() -> Self { Self { messages: Vec::new() } }
    pub fn append_msg(&mut self, message: impl Into<String>) { self.messages.push(message.into()); }
    pub fn clear(&mut self) { self.messages.clear(); }
    pub fn iter(&self) -> impl Iterator<Item = &str> { self.messages.iter().map(|s| s.as_str()) }
    pub fn len(&self) -> usize { self.messages.len() }
    pub fn is_empty(&self) -> bool { self.messages.is_empty() }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Address tests
    #[test]
    fn test_address_new() {
        let a = Address::new(0x1000);
        assert_eq!(a.offset, 0x1000);
        assert_eq!(a.space_id, 0);
    }

    #[test]
    fn test_address_in_space() {
        let a = Address::in_space(1, 0x2000);
        assert_eq!(a.space_id, 1);
        assert_eq!(a.offset, 0x2000);
    }

    #[test]
    fn test_address_add_sub() {
        let a = Address::new(0x1000);
        assert_eq!(a.add(0x10).offset, 0x1010);
        assert_eq!(a.sub(0x10).offset, 0x0FF0);
    }

    #[test]
    fn test_address_display() {
        assert_eq!(format!("{}", Address::new(0x1000)), "0x00001000");
        assert_eq!(format!("{}", Address::in_space(1, 0x2000)), "1:0x00002000");
    }

    #[test]
    fn test_address_ordering() {
        let a = Address::new(0x1000);
        let b = Address::new(0x2000);
        assert!(a < b);
    }

    // AddressRange tests
    #[test]
    fn test_address_range_new() {
        let r = AddressRange::new(Address::new(0x1000), Address::new(0x1FFF));
        assert_eq!(r.len(), 0x1000);
        assert!(!r.is_empty());
    }

    #[test]
    fn test_address_range_single() {
        let r = AddressRange::single(Address::new(0x1000));
        assert_eq!(r.len(), 1);
        assert!(r.contains(&Address::new(0x1000)));
    }

    #[test]
    fn test_address_range_contains() {
        let r = AddressRange::new(Address::new(0x1000), Address::new(0x2000));
        assert!(r.contains(&Address::new(0x1500)));
        assert!(!r.contains(&Address::new(0x3000)));
    }

    #[test]
    fn test_address_range_is_empty() {
        // A properly constructed range is never empty since start <= end is enforced
        let r = AddressRange::new(Address::new(0x1000), Address::new(0x1000));
        assert!(!r.is_empty());
        assert_eq!(r.len(), 1);
    }

    // AddressSet tests
    #[test]
    fn test_address_set_add_and_contains() {
        let mut s = AddressSet::new();
        s.add(Address::new(0x1000));
        assert!(s.contains(&Address::new(0x1000)));
        assert!(!s.contains(&Address::new(0x1001)));
    }

    #[test]
    fn test_address_set_add_range() {
        let mut s = AddressSet::new();
        s.add_range(AddressRange::new(Address::new(0x1000), Address::new(0x10FF)));
        assert!(s.contains(&Address::new(0x1000)));
        assert!(s.contains(&Address::new(0x1080)));
        assert!(s.contains(&Address::new(0x10FF)));
        assert!(!s.contains(&Address::new(0x1100)));
        assert_eq!(s.num_addresses(), 0x100);
    }

    #[test]
    fn test_address_set_merge_adjacent() {
        let mut s = AddressSet::new();
        s.add_range(AddressRange::new(Address::new(0x1000), Address::new(0x100F)));
        s.add_range(AddressRange::new(Address::new(0x1010), Address::new(0x101F)));
        // Adjacent ranges should be merged
        let ranges: Vec<_> = s.iter().collect();
        assert_eq!(ranges.len(), 1);
        assert_eq!(s.num_addresses(), 0x20);
    }

    #[test]
    fn test_address_set_intersect() {
        let mut s1 = AddressSet::new();
        s1.add_range(AddressRange::new(Address::new(0x1000), Address::new(0x2000)));
        let mut s2 = AddressSet::new();
        s2.add_range(AddressRange::new(Address::new(0x1800), Address::new(0x2800)));
        let inter = s1.intersect(&s2);
        assert!(inter.contains(&Address::new(0x1800)));
        assert!(inter.contains(&Address::new(0x2000)));
        assert!(!inter.contains(&Address::new(0x1000)));
        assert!(!inter.contains(&Address::new(0x2800)));
    }

    #[test]
    fn test_address_set_delete() {
        let mut s = AddressSet::new();
        s.add_range(AddressRange::new(Address::new(0x1000), Address::new(0x2000)));
        let mut del = AddressSet::new();
        del.add_range(AddressRange::new(Address::new(0x1500), Address::new(0x1800)));
        s.delete(&del);
        assert!(s.contains(&Address::new(0x1000)));
        assert!(!s.contains(&Address::new(0x1500)));
        assert!(!s.contains(&Address::new(0x1800)));
        assert!(s.contains(&Address::new(0x1900)));
    }

    #[test]
    fn test_address_set_union() {
        let mut s1 = AddressSet::new();
        s1.add(Address::new(0x1000));
        let mut s2 = AddressSet::new();
        s2.add(Address::new(0x2000));
        let u = s1.union(&s2);
        assert!(u.contains(&Address::new(0x1000)));
        assert!(u.contains(&Address::new(0x2000)));
        assert_eq!(u.num_addresses(), 2);
    }

    #[test]
    fn test_address_set_min_max() {
        let mut s = AddressSet::new();
        s.add(Address::new(0x3000));
        s.add(Address::new(0x1000));
        s.add(Address::new(0x2000));
        assert_eq!(s.min_address(), Address::new(0x1000));
        assert_eq!(s.max_address(), Address::new(0x3000));
    }

    #[test]
    fn test_address_set_iterator() {
        let mut s = AddressSet::new();
        s.add_range(AddressRange::new(Address::new(0x1000), Address::new(0x1002)));
        let addrs: Vec<Address> = s.get_addresses(true).collect();
        assert_eq!(addrs.len(), 3);
        assert_eq!(addrs[0], Address::new(0x1000));
        assert_eq!(addrs[1], Address::new(0x1001));
        assert_eq!(addrs[2], Address::new(0x1002));
    }

    #[test]
    fn test_address_set_clear() {
        let mut s = AddressSet::from_address(Address::new(0x1000));
        assert!(!s.is_empty());
        s.clear();
        assert!(s.is_empty());
    }

    #[test]
    fn test_address_set_from_conversions() {
        let s = AddressSet::from_address(Address::new(0x1000));
        assert_eq!(s.num_addresses(), 1);

        let s = AddressSet::from_range(AddressRange::new(Address::new(0x1000), Address::new(0x100F)));
        assert_eq!(s.num_addresses(), 16);
    }

    // BasicTaskMonitor tests
    #[test]
    fn test_task_monitor_basic() {
        let m = BasicTaskMonitor::new();
        assert!(!m.is_cancelled());
        m.set_message("test");
        assert_eq!(m.get_message(), "test");
    }

    #[test]
    fn test_task_monitor_progress() {
        let m = BasicTaskMonitor::new();
        m.initialize(100);
        assert_eq!(m.get_maximum(), 100);
        assert_eq!(m.get_progress(), 0);
        m.set_progress(50);
        assert_eq!(m.get_progress(), 50);
        m.increment_progress(25);
        assert_eq!(m.get_progress(), 75);
    }

    #[test]
    fn test_task_monitor_cancel() {
        let m = BasicTaskMonitor::new();
        m.cancel();
        assert!(m.is_cancelled());
        assert!(m.check_cancelled().is_err());
        m.clear_cancelled();
        assert!(!m.is_cancelled());
        assert!(m.check_cancelled().is_ok());
    }

    #[test]
    fn test_task_monitor_indeterminate() {
        let m = BasicTaskMonitor::new();
        assert!(!m.is_indeterminate());
        m.set_indeterminate(true);
        assert!(m.is_indeterminate());
    }

    // FlowType tests
    #[test]
    fn test_flow_type_properties() {
        assert!(FlowType::Call.is_call());
        assert!(FlowType::ConditionalCall.is_call());
        assert!(!FlowType::Jump.is_call());

        assert!(FlowType::Jump.is_jump());
        assert!(FlowType::ConditionalJump.is_jump());
        assert!(!FlowType::Call.is_jump());

        assert!(FlowType::Return.is_terminal());
        assert!(FlowType::Terminator.is_terminal());
        assert!(!FlowType::Fallthrough.is_terminal());

        assert!(FlowType::Call.has_fallthrough());
        assert!(FlowType::ConditionalJump.has_fallthrough());
        assert!(!FlowType::Return.has_fallthrough());
    }

    // Language tests
    #[test]
    fn test_language_properties() {
        let lang = Language { processor: "x86".into(), variant: "seg".into(), size: 16 };
        assert!(lang.is_segmented());
        assert_eq!(lang.default_pointer_size(), 2);
        assert_eq!(lang.instruction_alignment(), 1);

        let lang2 = Language { processor: "ARM".into(), variant: "LE".into(), size: 32 };
        assert!(!lang2.is_segmented());
        assert_eq!(lang2.default_pointer_size(), 4);
    }

    // Program tests
    #[test]
    fn test_program_new() {
        let lang = Language { processor: "x86".into(), variant: "LE".into(), size: 64 };
        let p = Program::new("test", lang);
        assert_eq!(p.name, "test");
        assert!(p.is_temporary);
        assert!(!p.is_changed);
        assert!(p.executable_format.is_none());
    }

    #[test]
    fn test_program_bookmarks() {
        let lang = Language { processor: "x86".into(), variant: "LE".into(), size: 64 };
        let mut p = Program::new("test", lang);
        p.set_bookmark(Address::new(0x1000), BookmarkType::Analysis, "cat", "msg");
        assert_eq!(p.bookmarks.len(), 1);
        assert_eq!(p.bookmarks[0].2, "cat");
    }

    #[test]
    fn test_program_get_min_address() {
        let lang = Language { processor: "x86".into(), variant: "LE".into(), size: 64 };
        let mut p = Program::new("test", lang);
        assert!(p.get_min_address().is_none());
        p.memory.add(Address::new(0x1000));
        assert_eq!(p.get_min_address(), Some(Address::new(0x1000)));
    }

    // MessageLog tests
    #[test]
    fn test_message_log() {
        let mut log = MessageLog::new();
        assert!(log.is_empty());
        log.append_msg("test message");
        assert_eq!(log.len(), 1);
        assert!(!log.is_empty());
        let msgs: Vec<&str> = log.iter().collect();
        assert_eq!(msgs, vec!["test message"]);
        log.clear();
        assert!(log.is_empty());
    }

    // Data tests
    #[test]
    fn test_data_is_pointer() {
        let d = Data { address: Address::new(0x1000), length: 4, data_type_name: "pointer".into() };
        assert!(d.is_pointer());
        let d2 = Data { address: Address::new(0x1000), length: 4, data_type_name: "int".into() };
        assert!(!d2.is_pointer());
    }

    // RefType tests
    #[test]
    fn test_ref_type_properties() {
        assert!(RefType::Call.is_call());
        assert!(!RefType::Read.is_call());
        assert!(RefType::Flow.is_flow());
        assert!(RefType::Read.is_read());
        assert!(RefType::Write.is_write());
    }

    // CancelledError tests
    #[test]
    fn test_cancelled_error_display() {
        let e = CancelledError;
        assert!(e.to_string().contains("cancelled"));
    }

    // Listing tests
    #[test]
    fn test_listing_get_instruction() {
        let mut listing = Listing::default();
        let instr = Instruction {
            address: Address::new(0x1000),
            length: 4,
            mnemonic: "mov".into(),
            flow_type: FlowType::Fallthrough,
            fall_through: Some(Address::new(0x1004)),
            flows: vec![],
            num_operands: 2,
        };
        listing.instructions.insert(Address::new(0x1000), instr);
        assert!(listing.get_instruction_at(&Address::new(0x1000)).is_some());
        assert!(listing.get_instruction_at(&Address::new(0x1004)).is_none());
        assert_eq!(listing.num_instructions(), 1);
    }

    #[test]
    fn test_listing_instruction_containing() {
        let mut listing = Listing::default();
        let instr = Instruction {
            address: Address::new(0x1000),
            length: 4,
            mnemonic: "mov".into(),
            flow_type: FlowType::Fallthrough,
            fall_through: Some(Address::new(0x1004)),
            flows: vec![],
            num_operands: 2,
        };
        listing.instructions.insert(Address::new(0x1000), instr);
        assert!(listing.get_instruction_containing(&Address::new(0x1002)).is_some());
        assert!(listing.get_instruction_containing(&Address::new(0x1004)).is_none());
    }

    // FunctionManager tests
    #[test]
    fn test_function_manager() {
        let mut fm = FunctionManager::default();
        let func = Function {
            entry_point: Address::new(0x1000),
            body: AddressSet::from_range(AddressRange::new(Address::new(0x1000), Address::new(0x10FF))),
            name: Some("main".into()),
            is_external: false,
            is_thunk: false,
            is_inline: false,
            has_noreturn: false,
            call_fixup: None,
        };
        fm.functions.insert(Address::new(0x1000), func);
        assert!(fm.get_function_at(&Address::new(0x1000)).is_some());
        assert!(fm.get_function_containing(&Address::new(0x1050)).is_some());
        assert!(fm.get_function_containing(&Address::new(0x2000)).is_none());
        assert_eq!(fm.get_functions(true).count(), 1);
    }
}
