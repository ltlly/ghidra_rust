//! PDB Address Calculator -- calculates addresses for PDB items.
//!
//! Ports Ghidra's `ghidra.app.util.pdb.pdbapplicator.PdbAddressCalculator`.

use std::collections::BTreeMap;
use std::fmt;

/// Special address constants.
pub mod addresses {
    /// A bad/invalid address.
    pub const BAD_ADDRESS: u64 = u64::MAX;
    /// An external address (not in the program's memory).
    pub const EXTERNAL_ADDRESS: u64 = u64::MAX - 1;
    /// The zero address.
    pub const ZERO_ADDRESS: u64 = 0;
}

/// Information about a memory segment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SegmentInfo {
    /// The start RVA (Relative Virtual Address) of the segment.
    start: u64,
    /// The length of the segment in bytes.
    length: u64,
}

impl SegmentInfo {
    /// Create a new SegmentInfo.
    pub fn new(start: u64, length: u64) -> Self {
        Self { start, length }
    }

    /// Get the start RVA.
    pub fn start(&self) -> u64 {
        self.start
    }

    /// Get the length.
    pub fn length(&self) -> u64 {
        self.length
    }
}

impl fmt::Display for SegmentInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "start: {:08x} length: {:08x}", self.start, self.length)
    }
}

/// The type of address calculation to use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressCalculatorType {
    /// Use image section headers.
    ImageHeader,
    /// Use image section headers with OMAP translation.
    ImageHeaderWithOmap,
    /// Use segment map descriptions.
    SegmentMap,
    /// Use PE/COFF section symbols.
    PeCoffSection,
    /// Use program memory blocks.
    MemoryMap,
}

/// Calculates addresses for PDB items based on segment information.
///
/// Different calculation strategies are used depending on what information
/// is available in the PDB (image headers, segment maps, OMAP data, etc.).
#[derive(Debug)]
pub struct PdbAddressCalculator {
    /// The image base address.
    image_base: u64,
    /// Segment information for address calculation.
    segment_info: Vec<SegmentInfo>,
    /// Maximum segment number (for bounds checking).
    max_segment: u32,
    /// OMAP from source translation table (if available).
    omap_from_source: Option<BTreeMap<u64, u64>>,
    /// The type of calculator.
    calculator_type: AddressCalculatorType,
}

impl PdbAddressCalculator {
    /// Create a new address calculator with image section headers.
    pub fn from_image_headers(image_base: u64, headers: &[ImageSectionHeader]) -> Self {
        let segment_info: Vec<SegmentInfo> = headers
            .iter()
            .map(|h| SegmentInfo::new(h.virtual_address as u64, h.raw_data_size as u64))
            .collect();
        let max_segment = segment_info.len() as u32 + 1;

        Self {
            image_base,
            segment_info,
            max_segment,
            omap_from_source: None,
            calculator_type: AddressCalculatorType::ImageHeader,
        }
    }

    /// Create a new address calculator with image headers and OMAP.
    pub fn from_image_headers_with_omap(
        image_base: u64,
        headers: &[ImageSectionHeader],
        omap: BTreeMap<u64, u64>,
    ) -> Self {
        let mut calc = Self::from_image_headers(image_base, headers);
        calc.omap_from_source = Some(omap);
        calc.calculator_type = AddressCalculatorType::ImageHeaderWithOmap;
        calc
    }

    /// Create a new address calculator from segment map descriptions.
    pub fn from_segment_map(image_base: u64, segments: &[SegmentInfo]) -> Self {
        let synthesized = Self::synthesize_segment_info(segments, 0x1000, 0x1000);
        let max_segment = synthesized.len() as u32 + 1;

        Self {
            image_base,
            segment_info: synthesized,
            max_segment,
            omap_from_source: None,
            calculator_type: AddressCalculatorType::SegmentMap,
        }
    }

    /// Create a new address calculator from PE/COFF section symbols.
    pub fn from_pe_coff_sections(
        image_base: u64,
        correction: u64,
        sections: &[PeCoffSection],
    ) -> Self {
        let mut adjusted_correction = correction;

        // Check if correction should be applied
        for section in sections {
            if section.rva != 0 && (section.rva as u64) < correction {
                adjusted_correction = 0;
                break;
            }
        }

        let segment_info: Vec<SegmentInfo> = sections
            .iter()
            .map(|s| {
                let offset = if s.rva != 0 {
                    (s.rva as u64) - adjusted_correction
                } else {
                    0
                };
                SegmentInfo::new(offset, s.length as u64)
            })
            .collect();
        let max_segment = segment_info.len() as u32 + 1;

        Self {
            image_base,
            segment_info,
            max_segment,
            omap_from_source: None,
            calculator_type: AddressCalculatorType::PeCoffSection,
        }
    }

    /// Create a new address calculator from program memory blocks.
    pub fn from_memory_blocks(image_base: u64, blocks: &[MemoryBlockInfo]) -> Self {
        let segment_info: Vec<SegmentInfo> = blocks
            .iter()
            .map(|b| {
                let offset = b.start_address.wrapping_sub(image_base);
                SegmentInfo::new(offset, b.size)
            })
            .collect();
        let max_segment = segment_info.len() as u32 + 1;

        Self {
            image_base,
            segment_info,
            max_segment,
            omap_from_source: None,
            calculator_type: AddressCalculatorType::MemoryMap,
        }
    }

    /// Get the type of calculator.
    pub fn calculator_type(&self) -> AddressCalculatorType {
        self.calculator_type
    }

    /// Get the image base address.
    pub fn image_base(&self) -> u64 {
        self.image_base
    }

    /// Get the segment info.
    pub fn segment_info(&self) -> &[SegmentInfo] {
        &self.segment_info
    }

    /// Calculate the address for a given segment and offset.
    ///
    /// Returns `BAD_ADDRESS` if the segment is invalid, `EXTERNAL_ADDRESS`
    /// if the segment is 0 or max, or the calculated address otherwise.
    pub fn get_address(&self, segment: u32, offset: u64) -> u64 {
        if segment > self.max_segment {
            return addresses::BAD_ADDRESS;
        }
        if segment == 0 || segment == self.max_segment {
            return addresses::EXTERNAL_ADDRESS;
        }

        let rva = self.get_rva(segment, offset);
        match rva {
            None => addresses::BAD_ADDRESS,
            Some(0) => addresses::ZERO_ADDRESS,
            Some(rva) => self.image_base.wrapping_add(rva),
        }
    }

    /// Get the RVA for a given segment and offset.
    fn get_rva(&self, segment: u32, offset: u64) -> Option<u64> {
        let index = (segment - 1) as usize;
        if index >= self.segment_info.len() {
            return None;
        }
        let base_rva = self.segment_info[index].start + offset;

        // Apply OMAP translation if available
        if let Some(ref omap) = self.omap_from_source {
            Self::apply_omap(omap, base_rva)
        } else {
            Some(base_rva)
        }
    }

    /// Apply OMAP translation to an RVA.
    fn apply_omap(omap: &BTreeMap<u64, u64>, rva: u64) -> Option<u64> {
        // Find the largest key <= rva
        let from = omap.range(..=rva).next_back()?;
        let (from_addr, to_addr) = from;
        if *to_addr == 0 {
            Some(0)
        } else {
            Some(to_addr + (rva - from_addr))
        }
    }

    /// Synthesize missing segment offset data.
    ///
    /// Corrects incomplete segment information by synthesizing missing offsets
    /// based on section alignment.
    fn synthesize_segment_info(
        segments: &[SegmentInfo],
        first_section_offset: u64,
        image_align: u64,
    ) -> Vec<SegmentInfo> {
        let mask = !(image_align - 1);
        let addend = image_align - 1;

        let mut determined_offset = first_section_offset;
        let mut section_length = 0u64;

        let mut result = Vec::with_capacity(segments.len());
        for seg in segments {
            if seg.start != 0 {
                determined_offset = seg.start;
            } else {
                // Ceiling function with image_align
                determined_offset += (section_length + addend) & mask;
            }
            section_length = seg.length;
            result.push(SegmentInfo::new(determined_offset, section_length));
        }
        result
    }
}

/// Image section header information.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageSectionHeader {
    /// Virtual address of the section.
    pub virtual_address: u32,
    /// Size of raw data.
    pub raw_data_size: u32,
}

/// PE/COFF section information.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeCoffSection {
    /// Relative Virtual Address.
    pub rva: u32,
    /// Section length.
    pub length: u32,
}

/// Memory block information.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryBlockInfo {
    /// Start address of the block.
    pub start_address: u64,
    /// Size of the block in bytes.
    pub size: u64,
}

impl fmt::Display for PdbAddressCalculator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PdbAddressCalculator [base={:016X}, segments={}, type={:?}]",
            self.image_base,
            self.segment_info.len(),
            self.calculator_type
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_address_calculation() {
        let headers = vec![
            ImageSectionHeader {
                virtual_address: 0x1000,
                raw_data_size: 0x2000,
            },
            ImageSectionHeader {
                virtual_address: 0x4000,
                raw_data_size: 0x1000,
            },
        ];
        let calc = PdbAddressCalculator::from_image_headers(0x400000, &headers);

        // Segment 1, offset 0 -> 0x400000 + 0x1000 = 0x401000
        assert_eq!(calc.get_address(1, 0), 0x401000);

        // Segment 1, offset 0x100 -> 0x400000 + 0x1100 = 0x401100
        assert_eq!(calc.get_address(1, 0x100), 0x401100);

        // Segment 2, offset 0 -> 0x400000 + 0x4000 = 0x404000
        assert_eq!(calc.get_address(2, 0), 0x404000);
    }

    #[test]
    fn test_external_address() {
        let headers = vec![ImageSectionHeader {
            virtual_address: 0x1000,
            raw_data_size: 0x1000,
        }];
        let calc = PdbAddressCalculator::from_image_headers(0x400000, &headers);

        // Segment 0 is external
        assert_eq!(calc.get_address(0, 0), addresses::EXTERNAL_ADDRESS);

        // Segment 2 (max+1) is external
        assert_eq!(calc.get_address(2, 0), addresses::EXTERNAL_ADDRESS);
    }

    #[test]
    fn test_bad_address() {
        let headers = vec![ImageSectionHeader {
            virtual_address: 0x1000,
            raw_data_size: 0x1000,
        }];
        let calc = PdbAddressCalculator::from_image_headers(0x400000, &headers);

        // Segment 100 is out of range
        assert_eq!(calc.get_address(100, 0), addresses::BAD_ADDRESS);
    }

    #[test]
    fn test_omap_translation() {
        let headers = vec![ImageSectionHeader {
            virtual_address: 0x1000,
            raw_data_size: 0x2000,
        }];
        let mut omap = BTreeMap::new();
        omap.insert(0x1000, 0x2000);
        omap.insert(0x1500, 0x2800);

        let calc = PdbAddressCalculator::from_image_headers_with_omap(0x400000, &headers, omap);

        // RVA 0x1000 -> OMAP 0x2000 -> 0x402000
        assert_eq!(calc.get_address(1, 0), 0x402000);

        // RVA 0x1100 -> OMAP 0x2000 + 0x100 = 0x2100 -> 0x402100
        assert_eq!(calc.get_address(1, 0x100), 0x402100);
    }

    #[test]
    fn test_segment_map() {
        let segments = vec![
            SegmentInfo::new(0x1000, 0x2000),
            SegmentInfo::new(0, 0x1000), // will be synthesized
        ];
        let calc = PdbAddressCalculator::from_segment_map(0x400000, &segments);

        assert_eq!(calc.get_address(1, 0), 0x401000);
    }

    #[test]
    fn test_pe_coff_sections() {
        let sections = vec![
            PeCoffSection {
                rva: 0x1000,
                length: 0x2000,
            },
            PeCoffSection {
                rva: 0x4000,
                length: 0x1000,
            },
        ];
        let calc = PdbAddressCalculator::from_pe_coff_sections(0x400000, 0, &sections);

        assert_eq!(calc.get_address(1, 0), 0x401000);
        assert_eq!(calc.get_address(2, 0), 0x404000);
    }

    #[test]
    fn test_segment_info_display() {
        let seg = SegmentInfo::new(0x1000, 0x2000);
        let s = format!("{}", seg);
        assert!(s.contains("00001000"));
        assert!(s.contains("00002000"));
    }

    #[test]
    fn test_calculator_display() {
        let headers = vec![ImageSectionHeader {
            virtual_address: 0x1000,
            raw_data_size: 0x1000,
        }];
        let calc = PdbAddressCalculator::from_image_headers(0x400000, &headers);
        let s = format!("{}", calc);
        assert!(s.contains("PdbAddressCalculator"));
        assert!(s.contains("00400000"));
    }
}
