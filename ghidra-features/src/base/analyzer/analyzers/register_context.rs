//! Register context builder.
use std::collections::HashMap;
use crate::base::analyzer::core::Address;

#[derive(Debug, Clone)]
pub struct RegisterContextBuilder { pub register_name: String, pub is_bit_register: bool, pub mask: Option<u64>, value: Option<u64>, set_addr: Option<Address>, value_history: Vec<(Address, Option<u64>)> }
impl RegisterContextBuilder {
    pub fn new_bit(name: &str) -> Self { Self { register_name: name.to_string(), is_bit_register: true, mask: Some(1), value: None, set_addr: None, value_history: Vec::new() } }
    pub fn new(name: &str, mask: u64) -> Self { Self { register_name: name.to_string(), is_bit_register: false, mask: if mask != 0 { Some(mask) } else { None }, value: None, set_addr: None, value_history: Vec::new() } }
    pub fn set_value_unknown(&mut self, addr: Address) { self.value = None; self.set_addr = Some(addr); self.value_history.push((addr, None)); }
    pub fn set_value(&mut self, addr: Address, v: u64) { let masked = if let Some(m) = self.mask { v & m } else { v }; self.value = Some(masked); self.set_addr = Some(addr); self.value_history.push((addr, Some(masked))); }
    pub fn get_value(&self) -> Option<u64> { self.value }
    pub fn is_value_known(&self) -> bool { self.value.is_some() }
    pub fn value_equals(&self, expected: u64) -> bool { match self.value { Some(v) => if let Some(m) = self.mask { (v & m) == (expected & m) } else { v == expected }, None => false } }
    pub fn value_history(&self) -> &[(Address, Option<u64>)] { &self.value_history }
}

#[derive(Debug, Clone, Default)]
pub struct RegisterContextTracker { builders: HashMap<String, RegisterContextBuilder> }
impl RegisterContextTracker {
    pub fn new() -> Self { Self { builders: HashMap::new() } }
    pub fn track_bit_register(&mut self, name: &str) { self.builders.insert(name.to_string(), RegisterContextBuilder::new_bit(name)); }
    pub fn track_register(&mut self, name: &str, mask: u64) { self.builders.insert(name.to_string(), RegisterContextBuilder::new(name, mask)); }
    pub fn set_value(&mut self, name: &str, addr: Address, v: u64) { if let Some(b) = self.builders.get_mut(name) { b.set_value(addr, v); } }
    pub fn set_unknown(&mut self, name: &str, addr: Address) { if let Some(b) = self.builders.get_mut(name) { b.set_value_unknown(addr); } }
    pub fn get_value(&self, name: &str) -> Option<u64> { self.builders.get(name).and_then(|b| b.get_value()) }
    pub fn is_known(&self, name: &str) -> bool { self.builders.get(name).map_or(false, |b| b.is_value_known()) }
    pub fn register_names(&self) -> Vec<&str> { self.builders.keys().map(|s| s.as_str()).collect() }
}
