//! XCOFF symbol table entry ported from Ghidra's
//! `ghidra.app.util.bin.format.xcoff.XCoffSymbol`.

use std::fmt;

use crate::bin_format::binary_reader::BinaryReader;

use super::xcoff_exception::XCoffException;
use super::xcoff_optional_header::XCoffOptionalHeader;
use super::xcoff_section_header_names;
use super::xcoff_symbol_storage_class;
use super::xcoff_symbol_storage_class_csect;

/// Size of a single symbol table entry in bytes.
pub const SYMSZ: usize = 18;

/// Maximum length of an inline symbol name.
pub const SYMNMLEN: usize = 8;

/// Section number indicating a debug symbol.
pub const N_DEBUG: i16 = -2;

/// Section number indicating an absolute symbol.
pub const N_ABS: i16 = -1;

/// Section number indicating an undefined symbol.
pub const N_UNDEF: i16 = 0;

/// XCOFF Symbol Table Entry.
///
/// Ported from `ghidra.app.util.bin.format.xcoff.XCoffSymbol`.
#[derive(Debug, Clone)]
pub struct XCoffSymbol {
    /// Symbol name, or pointer into string table if name > SYMNMLEN.
    n_name: [u8; SYMNMLEN],
    /// Symbol's value: dependent on section number, storage class and type.
    n_value: i32,
    /// Section number.
    n_scnum: i16,
    /// Symbolic type. Obsolete in XCOFF.
    n_type: i16,
    /// Storage class.
    n_sclass: u8,
    /// Number of auxiliary entries.
    n_numaux: u8,
    /// Auxiliary entry data.
    aux: Vec<u8>,
    /// Storage mapping class in csect auxiliary entry.
    x_smclas: u8,
    /// Cached optional header for function/variable classification.
    sn_text: u16,
    sn_bss: u16,
    sn_data: u16,
}

impl XCoffSymbol {
    /// Parse an XCOFF symbol from a reader.
    pub fn from_reader(
        reader: &mut BinaryReader,
        optional_header: &XCoffOptionalHeader,
    ) -> Result<Self, XCoffException> {
        let mut n_name = [0u8; SYMNMLEN];
        for i in 0..SYMNMLEN {
            n_name[i] = reader.read_next_byte().map_err(XCoffException::from)? as u8;
        }

        let n_value = reader.read_next_int().map_err(XCoffException::from)? as i32;
        let n_scnum = reader.read_next_short().map_err(XCoffException::from)? as i16;
        let n_type = reader.read_next_short().map_err(XCoffException::from)? as i16;
        let n_sclass = reader.read_next_byte().map_err(XCoffException::from)? as u8;
        let n_numaux = reader.read_next_byte().map_err(XCoffException::from)? as u8;

        let aux_len = (n_numaux as usize) * SYMSZ;
        let mut aux = vec![0u8; aux_len];
        // Note: in the Java source, the aux bytes are allocated but not read here.
        // The x_smclas is read from position [aux.length - 7] which is the 11th byte
        // in the last auxiliary entry (csect).
        let x_smclas = if n_numaux > 0 && aux_len >= 7 {
            aux[aux_len - 7]
        } else {
            0
        };

        Ok(Self {
            n_name,
            n_value,
            n_scnum,
            n_type,
            n_sclass,
            n_numaux,
            aux,
            x_smclas,
            sn_text: optional_header.section_number_for_text(),
            sn_bss: optional_header.section_number_for_bss(),
            sn_data: optional_header.section_number_for_data(),
        })
    }

    /// Returns `true` if this symbol uses a long name (first 4 bytes are zero).
    pub fn is_long_name(&self) -> bool {
        self.n_name[0] == 0
            && self.n_name[1] == 0
            && self.n_name[2] == 0
            && self.n_name[3] == 0
    }

    /// Returns the symbol name as a string.
    pub fn name(&self) -> &str {
        let len = self.n_name.iter().position(|&b| b == 0).unwrap_or(SYMNMLEN);
        core::str::from_utf8(&self.n_name[..len]).unwrap_or("")
    }

    /// Returns `true` if this symbol represents a function.
    pub fn is_function(&self) -> bool {
        (self.n_sclass == xcoff_symbol_storage_class::C_EXT
            || self.n_sclass == xcoff_symbol_storage_class::C_HIDEXT
            || self.n_sclass == xcoff_symbol_storage_class::C_WEAKEXT)
            && self.n_scnum == self.sn_text as i16
            && self.name() != xcoff_section_header_names::TEXT
    }

    /// Returns `true` if this symbol represents a variable.
    pub fn is_variable(&self) -> bool {
        (self.n_sclass == xcoff_symbol_storage_class::C_EXT
            || self.n_sclass == xcoff_symbol_storage_class::C_HIDEXT
            || self.n_sclass == xcoff_symbol_storage_class::C_WEAKEXT)
            && (self.n_scnum == self.sn_bss as i16 || self.n_scnum == self.sn_data as i16)
            && self.x_smclas != xcoff_symbol_storage_class_csect::XMC_TC0
            && self.x_smclas != xcoff_symbol_storage_class_csect::XMC_TC
            && self.x_smclas != xcoff_symbol_storage_class_csect::XMC_DS
            && self.name() != xcoff_section_header_names::BSS
            && self.name() != xcoff_section_header_names::DATA
    }

    /// Returns the symbol value.
    pub fn value(&self) -> i32 {
        self.n_value
    }

    /// Returns the section number.
    pub fn section_number(&self) -> i16 {
        self.n_scnum
    }

    /// Returns the symbol type.
    pub fn sym_type(&self) -> i16 {
        self.n_type
    }

    /// Returns the storage class.
    pub fn storage_class(&self) -> u8 {
        self.n_sclass
    }

    /// Returns the number of auxiliary entries.
    pub fn num_aux(&self) -> u8 {
        self.n_numaux
    }

    /// Returns the storage mapping class.
    pub fn storage_mapping_class(&self) -> u8 {
        self.x_smclas
    }
}

impl fmt::Display for XCoffSymbol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "SYMBOL TABLE ENTRY")?;
        writeln!(f, "n_value = {}", self.n_value)?;
        writeln!(f, "n_scnum = {}", self.n_scnum)?;
        writeln!(f, "n_type = {}", self.n_type)?;
        writeln!(f, "n_sclass = {}", self.n_sclass)?;
        writeln!(f, "n_numaux = {}", self.n_numaux)
    }
}
