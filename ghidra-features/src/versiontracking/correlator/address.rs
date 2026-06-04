//! Address correlators.

use ghidra_core::addr::Address;
use crate::versiontracking::options::VtOptions;

#[derive(Debug, Clone)]
pub struct AddressCorrelation { pub source_entry: Address, pub destination_entry: Address, pub mappings: Vec<AddressMapping>, pub confidence: f64 }

#[derive(Debug, Clone, Copy)]
pub struct AddressMapping { pub source: Address, pub destination: Address }

pub trait AddressCorrelator: Send + Sync {
    fn name(&self) -> &str;
    fn correlate_functions(&self, source_entry: Address, source_bytes: &[u8], source_mnemonics: &[String],
        destination_entry: Address, destination_bytes: &[u8], destination_mnemonics: &[String]) -> Option<AddressCorrelation>;
    fn correlate_data(&self, source_entry: Address, source_bytes: &[u8], destination_entry: Address, destination_bytes: &[u8]) -> Option<AddressCorrelation>;
    fn options(&self) -> &VtOptions;
    fn set_options(&mut self, options: VtOptions);
    fn priority(&self) -> i32 { 100 }
}

pub struct ExactMatchAddressCorrelator { options: VtOptions }
impl ExactMatchAddressCorrelator { pub fn new() -> Self { Self { options: VtOptions::new("ExactMatchAddressCorrelator") } } }
impl Default for ExactMatchAddressCorrelator { fn default() -> Self { Self::new() } }

impl AddressCorrelator for ExactMatchAddressCorrelator {
    fn name(&self) -> &str { "ExactMatchAddressCorrelator" }
    fn correlate_functions(&self, source_entry: Address, source_bytes: &[u8], _: &[String],
        destination_entry: Address, destination_bytes: &[u8], _: &[String]) -> Option<AddressCorrelation> {
        if source_bytes == destination_bytes && !source_bytes.is_empty() {
            let mappings: Vec<AddressMapping> = (0..source_bytes.len()).map(|i| AddressMapping {
                source: source_entry.add(i as u64), destination: destination_entry.add(i as u64) }).collect();
            Some(AddressCorrelation { source_entry, destination_entry, mappings, confidence: 1.0 })
        } else { None }
    }
    fn correlate_data(&self, se: Address, sb: &[u8], de: Address, db: &[u8]) -> Option<AddressCorrelation> {
        if sb == db && !sb.is_empty() { Some(AddressCorrelation { source_entry: se, destination_entry: de, mappings: vec![AddressMapping { source: se, destination: de }], confidence: 1.0 }) } else { None }
    }
    fn options(&self) -> &VtOptions { &self.options }
    fn set_options(&mut self, options: VtOptions) { self.options = options; }
    fn priority(&self) -> i32 { 10 }
}

pub struct LinearAddressCorrelator { options: VtOptions }
impl LinearAddressCorrelator { pub fn new() -> Self { Self { options: VtOptions::new("LinearAddressCorrelator") } } }
impl Default for LinearAddressCorrelator { fn default() -> Self { Self::new() } }

impl AddressCorrelator for LinearAddressCorrelator {
    fn name(&self) -> &str { "LinearAddressCorrelator" }
    fn correlate_functions(&self, source_entry: Address, source_bytes: &[u8], _: &[String],
        destination_entry: Address, destination_bytes: &[u8], _: &[String]) -> Option<AddressCorrelation> {
        if source_bytes.is_empty() || destination_bytes.is_empty() { return None; }
        let src_len = source_bytes.len() as u64; let dst_len = destination_bytes.len() as u64;
        let mappings: Vec<AddressMapping> = (0..src_len as usize).map(|i| {
            let dst_offset = (i as u64 * dst_len) / src_len;
            AddressMapping { source: source_entry.add(i as u64), destination: destination_entry.add(dst_offset) }
        }).collect();
        let ratio = if src_len > dst_len { dst_len as f64 / src_len as f64 } else { src_len as f64 / dst_len as f64 };
        Some(AddressCorrelation { source_entry, destination_entry, mappings, confidence: ratio })
    }
    fn correlate_data(&self, se: Address, _: &[u8], de: Address, _: &[u8]) -> Option<AddressCorrelation> {
        Some(AddressCorrelation { source_entry: se, destination_entry: de, mappings: vec![AddressMapping { source: se, destination: de }], confidence: 0.5 })
    }
    fn options(&self) -> &VtOptions { &self.options }
    fn set_options(&mut self, options: VtOptions) { self.options = options; }
    fn priority(&self) -> i32 { 200 }
}

pub struct StraightLineCorrelation { options: VtOptions }
impl StraightLineCorrelation { pub fn new() -> Self { Self { options: VtOptions::new("StraightLineCorrelation") } } }
impl Default for StraightLineCorrelation { fn default() -> Self { Self::new() } }

impl AddressCorrelator for StraightLineCorrelation {
    fn name(&self) -> &str { "StraightLineCorrelation" }
    fn correlate_functions(&self, source_entry: Address, _: &[u8], source_mnemonics: &[String],
        destination_entry: Address, _: &[u8], destination_mnemonics: &[String]) -> Option<AddressCorrelation> {
        if source_mnemonics.is_empty() || destination_mnemonics.is_empty() { return None; }
        let mut dst_map: std::collections::HashMap<&str, Vec<usize>> = std::collections::HashMap::new();
        for (i, mnem) in destination_mnemonics.iter().enumerate() { dst_map.entry(mnem.as_str()).or_default().push(i); }
        let mut mappings = Vec::new(); let mut dst_idx = 0usize; let mut matched = 0usize;
        for (src_i, src_mnem) in source_mnemonics.iter().enumerate() {
            if dst_idx < destination_mnemonics.len() && destination_mnemonics[dst_idx] == *src_mnem {
                mappings.push(AddressMapping { source: source_entry.add(src_i as u64), destination: destination_entry.add(dst_idx as u64) });
                dst_idx += 1; matched += 1;
            } else if let Some(indices) = dst_map.get(src_mnem.as_str()) {
                if let Some(&next_dst) = indices.iter().find(|&&idx| idx >= dst_idx) {
                    mappings.push(AddressMapping { source: source_entry.add(src_i as u64), destination: destination_entry.add(next_dst as u64) });
                    dst_idx = next_dst + 1; matched += 1;
                }
            }
        }
        if mappings.is_empty() { return None; }
        let confidence = matched as f64 / source_mnemonics.len().max(destination_mnemonics.len()) as f64;
        Some(AddressCorrelation { source_entry, destination_entry, mappings, confidence })
    }
    fn correlate_data(&self, se: Address, _: &[u8], de: Address, _: &[u8]) -> Option<AddressCorrelation> {
        Some(AddressCorrelation { source_entry: se, destination_entry: de, mappings: vec![AddressMapping { source: se, destination: de }], confidence: 0.5 })
    }
    fn options(&self) -> &VtOptions { &self.options }
    fn set_options(&mut self, options: VtOptions) { self.options = options; }
    fn priority(&self) -> i32 { 150 }
}

pub struct VtHashedFunctionAddressCorrelator { options: VtOptions, processor: String }
impl VtHashedFunctionAddressCorrelator { pub fn new(processor: impl Into<String>) -> Self { Self { options: VtOptions::new("VTHashedFunctionAddressCorrelator"), processor: processor.into() } } }

impl AddressCorrelator for VtHashedFunctionAddressCorrelator {
    fn name(&self) -> &str { "VTHashedFunctionAddressCorrelator" }
    fn correlate_functions(&self, source_entry: Address, _: &[u8], source_mnemonics: &[String],
        destination_entry: Address, _: &[u8], destination_mnemonics: &[String]) -> Option<AddressCorrelation> {
        if source_mnemonics.is_empty() || destination_mnemonics.is_empty() { return None; }
        let mut mappings = Vec::new(); let mut used_dst = std::collections::HashSet::new();
        for (src_i, src_mnem) in source_mnemonics.iter().enumerate() {
            let mut best_dst = None; let mut best_dist = usize::MAX;
            for (dst_j, dst_mnem) in destination_mnemonics.iter().enumerate() {
                if dst_mnem == src_mnem && !used_dst.contains(&dst_j) {
                    let dist = if src_i > dst_j { src_i - dst_j } else { dst_j - src_i };
                    if dist < best_dist { best_dist = dist; best_dst = Some(dst_j); }
                }
            }
            if let Some(dst_j) = best_dst { used_dst.insert(dst_j);
                mappings.push(AddressMapping { source: source_entry.add(src_i as u64), destination: destination_entry.add(dst_j as u64) }); }
        }
        if mappings.is_empty() { return None; }
        let confidence = mappings.len() as f64 / source_mnemonics.len().max(destination_mnemonics.len()) as f64;
        Some(AddressCorrelation { source_entry, destination_entry, mappings, confidence })
    }
    fn correlate_data(&self, _: Address, _: &[u8], _: Address, _: &[u8]) -> Option<AddressCorrelation> { None }
    fn options(&self) -> &VtOptions { &self.options }
    fn set_options(&mut self, options: VtOptions) { self.options = options; }
    fn priority(&self) -> i32 { 85 }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(v: u64) -> Address { Address::new(v) }

    #[test]
    fn test_exact_match_identical() {
        let corr = ExactMatchAddressCorrelator::new();
        let bytes = &[0x55u8, 0x48, 0x89, 0xe5, 0xc3];
        let result = corr.correlate_functions(addr(0x1000), bytes, &[], addr(0x2000), bytes, &[]);
        assert!(result.is_some());
        assert_eq!(result.unwrap().mappings.len(), 5);
    }

    #[test]
    fn test_linear_correlator() {
        let corr = LinearAddressCorrelator::new();
        let result = corr.correlate_functions(addr(0x1000), &[0x55, 0x48, 0x89, 0xe5, 0xc3], &[], addr(0x2000), &[0x55, 0x48, 0x89, 0xe5, 0x31, 0xc0, 0xc3], &[]);
        assert!(result.is_some());
        assert_eq!(result.unwrap().mappings.len(), 5);
    }

    #[test]
    fn test_correlator_priority_ordering() {
        let exact = ExactMatchAddressCorrelator::new();
        let linear = LinearAddressCorrelator::new();
        assert!(exact.priority() < linear.priority());
    }
}
