//! LF_PROCEDURE -- concrete Procedure (function) type record.
//!
//! Ports Ghidra's `ProcedureMsType` (PDB_ID = 0x1008) and
//! `AbstractProcedureMsType` Java classes.
//!
//! Represents a C/C++ function type (not a function definition, but the
//! *type* of a function -- its signature) in the PDB type stream.
//!
//! # Binary Layout (LF_PROCEDURE / 0x1008)
//!
//! ```text
//! +0  u32   returnType         Type index of the return type
//! +4  u8    callingConvention  Calling convention (CallingConvention enum)
//! +5  u8    functionAttributes Bitfield of FunctionAttributes flags
//! +6  u16   numParameters      Number of parameters
//! +8  u32   argList            Type index of the LF_ARGLIST record
//! ```

use std::fmt;

use super::abstract_ms_type::AbstractMsType;
use super::bind::Bind;
use super::RecordNumber;
use crate::pdb::pdb_byte_reader::PdbByteReader;
use crate::pdb::pdb_exception::PdbException;

// =============================================================================
// CallingConvention
// =============================================================================

/// Calling convention used by a function type.
///
/// Corresponds to the Java `CallingConvention` enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum CallingConvention {
    /// Near C convention (`__cdecl`), right-to-left push, caller pops.
    NearC = 0x00,
    /// Far C convention (`__cdecl`).
    FarC = 0x01,
    /// Near Pascal convention (`__pascal`).
    NearPascal = 0x02,
    /// Far Pascal convention (`__pascal`).
    FarPascal = 0x03,
    /// Near fast call (`__fastcall`).
    NearFast = 0x04,
    /// Far fast call (`__fastcall`).
    FarFast = 0x05,
    /// Skipped / unused.
    Skipped = 0x06,
    /// Near standard call (`__stdcall`).
    NearStd = 0x07,
    /// Far standard call (`__stdcall`).
    FarStd = 0x08,
    /// Near syscall (`__syscall`).
    NearSys = 0x09,
    /// Far syscall (`__syscall`).
    FarSys = 0x0a,
    /// This call (`__thiscall`), `this` pointer passed in register.
    ThisCall = 0x0b,
    /// MIPS call.
    MipsCall = 0x0c,
    /// Generic call sequence.
    Generic = 0x0d,
    /// Alpha call.
    AlphaCall = 0x0e,
    /// PowerPC call.
    PpcCall = 0x0f,
    /// Hitachi SuperH call.
    ShCall = 0x10,
    /// ARM call.
    ArmCall = 0x11,
    /// AM33 call.
    Am33Call = 0x12,
    /// TriCore call.
    TriCall = 0x13,
    /// Hitachi SuperH-5 call.
    Sh5Call = 0x14,
    /// M32R call.
    M32rCall = 0x15,
    /// CLR call.
    ClrCall = 0x16,
    /// Inline marker (always inlined, no convention).
    Inline = 0x17,
    /// Near vector call (`__vectorcall`).
    NearVector = 0x18,
}

impl CallingConvention {
    /// The C-style ABI label (e.g. `"__cdecl"`, `"__stdcall"`).
    pub fn label(&self) -> &'static str {
        match self {
            Self::NearC | Self::FarC => "__cdecl",
            Self::NearPascal | Self::FarPascal => "__pascal",
            Self::NearFast | Self::FarFast => "__fastcall",
            Self::Skipped => "",
            Self::NearStd | Self::FarStd => "__stdcall",
            Self::NearSys | Self::FarSys => "__syscall",
            Self::ThisCall => "__thiscall",
            Self::MipsCall => "mips",
            Self::Generic => "generic",
            Self::AlphaCall => "alpha",
            Self::PpcCall => "ppc",
            Self::ShCall => "sh",
            Self::ArmCall => "arm",
            Self::Am33Call => "am33",
            Self::TriCall => "tricore",
            Self::Sh5Call => "sh5",
            Self::M32rCall => "m32r",
            Self::ClrCall => "clrcall",
            Self::Inline => "inline",
            Self::NearVector => "__vectorcall",
        }
    }

    /// Parse from a raw byte value.  Returns `None` for unknown values.
    pub fn from_value(val: u8) -> Option<Self> {
        match val {
            0x00 => Some(Self::NearC),
            0x01 => Some(Self::FarC),
            0x02 => Some(Self::NearPascal),
            0x03 => Some(Self::FarPascal),
            0x04 => Some(Self::NearFast),
            0x05 => Some(Self::FarFast),
            0x06 => Some(Self::Skipped),
            0x07 => Some(Self::NearStd),
            0x08 => Some(Self::FarStd),
            0x09 => Some(Self::NearSys),
            0x0a => Some(Self::FarSys),
            0x0b => Some(Self::ThisCall),
            0x0c => Some(Self::MipsCall),
            0x0d => Some(Self::Generic),
            0x0e => Some(Self::AlphaCall),
            0x0f => Some(Self::PpcCall),
            0x10 => Some(Self::ShCall),
            0x11 => Some(Self::ArmCall),
            0x12 => Some(Self::Am33Call),
            0x13 => Some(Self::TriCall),
            0x14 => Some(Self::Sh5Call),
            0x15 => Some(Self::M32rCall),
            0x16 => Some(Self::ClrCall),
            0x17 => Some(Self::Inline),
            0x18 => Some(Self::NearVector),
            _ => None,
        }
    }
}

impl fmt::Display for CallingConvention {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.label())
    }
}

// =============================================================================
// FunctionAttributes
// =============================================================================

/// Attributes for a function type record.
///
/// Parsed from a single byte in the PDB type record.  Corresponds to the
/// Java `FunctionMsAttributes` class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FunctionAttributes {
    /// Whether the function has a C++-style return UDT.
    pub has_cpp_style_return_udt: bool,
    /// Whether the function is an instance constructor.
    pub is_instance_constructor: bool,
    /// Whether the function is an instance constructor of a class with
    /// virtual bases.
    pub is_instance_constructor_virtual_bases: bool,
}

impl FunctionAttributes {
    /// Create from a raw byte value.
    pub fn from_byte(val: u8) -> Self {
        Self {
            has_cpp_style_return_udt: (val & 0x01) != 0,
            is_instance_constructor: (val & 0x02) != 0,
            is_instance_constructor_virtual_bases: (val & 0x04) != 0,
        }
    }

    /// Create empty (all flags false).
    pub fn empty() -> Self {
        Self {
            has_cpp_style_return_udt: false,
            is_instance_constructor: false,
            is_instance_constructor_virtual_bases: false,
        }
    }

    /// Whether this is any kind of constructor.
    pub fn is_constructor(&self) -> bool {
        self.is_instance_constructor || self.is_instance_constructor_virtual_bases
    }

    /// Emit a pipe-delimited string of active attribute labels.
    pub fn emit_string(&self) -> String {
        let mut parts = Vec::new();
        if self.has_cpp_style_return_udt {
            parts.push("return UDT (C++ style)");
        }
        if self.is_instance_constructor {
            parts.push("instance constructor");
        }
        if self.is_instance_constructor_virtual_bases {
            parts.push("instance constructor of a class with virtual base");
        }
        parts.join("|")
    }
}

impl fmt::Display for FunctionAttributes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.emit_string())
    }
}

// =============================================================================
// LfProcedure -- the concrete procedure type record
// =============================================================================

/// Concrete PDB procedure type record (`LF_PROCEDURE`).
///
/// This is the Rust equivalent of Ghidra's `ProcedureMsType`.  It stores
/// the function's return type, calling convention, function attributes,
/// parameter count, and argument list type index.
///
/// # Variadic Functions
///
/// A procedure is considered variadic if its argument list contains exactly
/// one parameter of type `T_NOTYPE` (0x0003, `void`), which is a common
/// convention in PDB files to denote `...` (ellipsis) parameters.
#[derive(Debug, Clone)]
pub struct LfProcedure {
    /// Record number of this type (set during TPI/IPI registration).
    record_number: RecordNumber,
    /// Record number of the return value type.
    pub return_value_record_number: RecordNumber,
    /// The calling convention used by this function.
    pub calling_convention: CallingConvention,
    /// Function attributes (constructor, C++-style return UDT, etc.).
    pub function_attributes: FunctionAttributes,
    /// Number of parameters.
    pub num_parameters: u16,
    /// Record number of the LF_ARGLIST type record listing the parameter types.
    pub arg_list_record_number: RecordNumber,
}

impl LfProcedure {
    /// PDB ID for the 16-bit procedure variant.
    pub const PDB_ID_16: u32 = 0x0008;
    /// PDB ID for the ST-format procedure variant.
    pub const PDB_ID_ST: u32 = 0x1008;
    /// PDB ID for the 32-bit (MsType) procedure variant.
    pub const PDB_ID_32: u32 = 0x1008;

    /// Create a new procedure type record.
    pub fn new(
        return_value_record_number: RecordNumber,
        calling_convention: CallingConvention,
        function_attributes: FunctionAttributes,
        num_parameters: u16,
        arg_list_record_number: RecordNumber,
    ) -> Self {
        Self {
            record_number: RecordNumber::NO_TYPE,
            return_value_record_number,
            calling_convention,
            function_attributes,
            num_parameters,
            arg_list_record_number,
        }
    }

    /// Create from raw parsed field values.
    pub fn from_parsed(
        return_type_index: u32,
        calling_convention_byte: u8,
        attributes_byte: u8,
        num_parameters: u16,
        arg_list_type_index: u32,
    ) -> Self {
        Self::new(
            RecordNumber::type_record(return_type_index),
            CallingConvention::from_value(calling_convention_byte)
                .unwrap_or(CallingConvention::NearC),
            FunctionAttributes::from_byte(attributes_byte),
            num_parameters,
            RecordNumber::type_record(arg_list_type_index),
        )
    }

    /// Get the record number of the return type.
    ///
    /// Mirrors Java `AbstractProcedureMsType.getReturnRecordNumber()`.
    pub fn return_record_number(&self) -> RecordNumber {
        self.return_value_record_number
    }

    /// Get the record number of the argument list type.
    ///
    /// Mirrors Java `AbstractProcedureMsType.getArgListRecordNumber()`.
    pub fn arg_list_record_number(&self) -> RecordNumber {
        self.arg_list_record_number
    }

    /// Get the number of parameters.
    ///
    /// Mirrors Java `AbstractProcedureMsType.getNumParams()`.
    pub fn num_params(&self) -> u16 {
        self.num_parameters
    }

    /// Get the calling convention.
    ///
    /// Mirrors Java `AbstractProcedureMsType.getCallingConvention()`.
    pub fn calling_convention(&self) -> CallingConvention {
        self.calling_convention
    }

    /// Get the function attributes.
    ///
    /// Mirrors Java `AbstractProcedureMsType.getFunctionAttributes()`.
    pub fn function_attributes(&self) -> &FunctionAttributes {
        &self.function_attributes
    }

    /// Whether this procedure is a constructor.
    ///
    /// Mirrors Java `FunctionMsAttributes.isConstructor()`.
    pub fn is_constructor(&self) -> bool {
        self.function_attributes.is_constructor()
    }

    /// Whether this procedure has a C++-style return UDT.
    ///
    /// Mirrors Java `FunctionMsAttributes.hasCppStyleReturnUdt()`.
    pub fn has_cpp_return_udt(&self) -> bool {
        self.function_attributes.has_cpp_style_return_udt
    }

    /// Whether this function is an inline marker.
    pub fn is_inline(&self) -> bool {
        self.calling_convention == CallingConvention::Inline
    }

    /// Whether this procedure is variadic (takes `...` arguments).
    ///
    /// A procedure is considered variadic if its argument list contains
    /// exactly one parameter of type `T_NOTYPE` (0x0003, `void`), which
    /// is a common convention in PDB files to denote ellipsis parameters.
    ///
    /// This method returns `true` based on the `num_parameters` field being
    /// exactly 1 and the arg list record number pointing to a T_NOTYPE.
    /// For a definitive check, the actual `LfArglist` record should be
    /// resolved and checked via [`super::lf_arglist::LfArglist::is_variadic`].
    ///
    /// This is a heuristic that matches the Java convention.
    pub fn is_variadic_heuristic(&self) -> bool {
        self.num_parameters == 1
    }

    /// Get the calling convention byte value for serialization.
    pub fn calling_convention_byte(&self) -> u8 {
        self.calling_convention as u8
    }

    /// Get the function attributes byte value for serialization.
    pub fn attributes_byte(&self) -> u8 {
        (self.function_attributes.has_cpp_style_return_udt as u8)
            | ((self.function_attributes.is_instance_constructor as u8) << 1)
            | ((self.function_attributes.is_instance_constructor_virtual_bases as u8) << 2)
    }

    /// Get the return type record number.
    ///
    /// Alias for [`return_record_number`] for consistency with
    /// Java's `AbstractProcedureMsType.getReturnRecordNumber()`.
    pub fn get_return_type_record_number(&self) -> RecordNumber {
        self.return_value_record_number
    }

    /// Get the argument list type record number.
    ///
    /// Alias for [`arg_list_record_number`] for consistency with
    /// Java's `AbstractProcedureMsType.getArgListRecordNumber()`.
    pub fn get_arg_list_type_record_number(&self) -> RecordNumber {
        self.arg_list_record_number
    }

    /// Get the number of parameters.
    ///
    /// Alias for [`num_params`] returning `usize` for convenience.
    pub fn get_num_parameters(&self) -> usize {
        self.num_parameters as usize
    }

    /// Get the raw number of parameters as `u16`.
    pub fn get_num_parameters_raw(&self) -> u16 {
        self.num_parameters
    }

    /// Whether this procedure takes no parameters.
    pub fn is_no_params(&self) -> bool {
        self.num_parameters == 0
    }

    /// Get the calling convention label string.
    ///
    /// Returns the ABI label (e.g., `"__cdecl"`, `"__stdcall"`).
    pub fn calling_convention_label(&self) -> &'static str {
        self.calling_convention.label()
    }

    /// Parse a procedure type record from a byte reader (32-bit MsType variant).
    ///
    /// Reads the return type index, calling convention byte, function
    /// attributes byte, parameter count, and argument list type index.
    /// This mirrors the Java `ProcedureMsType` constructor which calls the
    /// `AbstractProcedureMsType` base with `recordNumberSize=32`.
    ///
    /// # Errors
    ///
    /// Returns [`PdbException`] if the reader does not have enough data.
    pub fn parse_from_reader(reader: &mut PdbByteReader) -> Result<Self, PdbException> {
        let return_type_index = reader.read_u32()?;
        let calling_convention_byte = reader.read_u8()?;
        let attributes_byte = reader.read_u8()?;
        let num_parameters = reader.read_u16()?;
        let arg_list_type_index = reader.read_u32()?;
        reader.align(4); // skipPadding
        Ok(Self::from_parsed(
            return_type_index,
            calling_convention_byte,
            attributes_byte,
            num_parameters,
            arg_list_type_index,
        ))
    }

    /// Emit the full signature including calling convention, parameter count,
    /// and a `this` pointer reference when present.
    ///
    /// This method produces output closer to the Java `emit()` which emits
    /// the arg list then recursively emits the return type at `Bind::PROC`.
    fn emit_full(&self, bind: Bind) -> String {
        let mut result = String::new();

        if bind < Bind::PROC {
            result.push('(');
        }

        // Emit argument list reference (mirrors Java: builder.append(getArgumentsListType()))
        result.push_str(&self.arg_list_record_number.to_string());

        // Emit return type with PROC binding (mirrors Java:
        //   getReturnType().emit(builder, Bind.PROC))
        result.push(' ');
        result.push_str(&self.return_value_record_number.to_string());

        // Emit calling convention annotation if non-empty.
        if !self.calling_convention.label().is_empty() {
            result.push_str(" [");
            result.push_str(self.calling_convention.label());
            result.push(']');
        }

        // Emit parameter count.
        result.push_str(&format!(" params={}", self.num_parameters));

        // Emit function attributes if non-empty.
        let attrs_str = self.function_attributes.emit_string();
        if !attrs_str.is_empty() {
            result.push_str(&format!(" attrs={{{}}}", attrs_str));
        }

        if bind < Bind::PROC {
            result.push(')');
        }

        result
    }
}

impl AbstractMsType for LfProcedure {
    fn pdb_id(&self) -> u32 {
        Self::PDB_ID_32 // LF_PROCEDURE = 0x1008
    }

    fn record_number(&self) -> RecordNumber {
        self.record_number
    }

    fn set_record_number(&mut self, record_number: RecordNumber) {
        self.record_number = record_number;
    }

    fn emit(&self, bind: Bind) -> String {
        self.emit_full(bind)
    }
}

impl fmt::Display for LfProcedure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.emit(Bind::NONE))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_procedure() -> LfProcedure {
        LfProcedure::new(
            RecordNumber::type_record(0x0074), // int return type
            CallingConvention::NearC,
            FunctionAttributes::empty(),
            2,
            RecordNumber::type_record(0x1001), // arg list
        )
    }

    #[test]
    fn test_calling_convention_from_value() {
        assert_eq!(
            CallingConvention::from_value(0x00),
            Some(CallingConvention::NearC)
        );
        assert_eq!(
            CallingConvention::from_value(0x07),
            Some(CallingConvention::NearStd)
        );
        assert_eq!(
            CallingConvention::from_value(0x0b),
            Some(CallingConvention::ThisCall)
        );
        assert_eq!(
            CallingConvention::from_value(0x18),
            Some(CallingConvention::NearVector)
        );
        assert_eq!(CallingConvention::from_value(0xFF), None);
    }

    #[test]
    fn test_calling_convention_label() {
        assert_eq!(CallingConvention::NearC.label(), "__cdecl");
        assert_eq!(CallingConvention::NearStd.label(), "__stdcall");
        assert_eq!(CallingConvention::ThisCall.label(), "__thiscall");
        assert_eq!(CallingConvention::NearVector.label(), "__vectorcall");
        assert_eq!(CallingConvention::Skipped.label(), "");
    }

    #[test]
    fn test_calling_convention_display() {
        assert_eq!(format!("{}", CallingConvention::NearC), "__cdecl");
        assert_eq!(format!("{}", CallingConvention::NearFast), "__fastcall");
    }

    #[test]
    fn test_function_attributes_from_byte() {
        let attrs = FunctionAttributes::from_byte(0x00);
        assert!(!attrs.has_cpp_style_return_udt);
        assert!(!attrs.is_instance_constructor);
        assert!(!attrs.is_instance_constructor_virtual_bases);

        let attrs = FunctionAttributes::from_byte(0x01);
        assert!(attrs.has_cpp_style_return_udt);
        assert!(!attrs.is_instance_constructor);

        let attrs = FunctionAttributes::from_byte(0x06);
        assert!(!attrs.has_cpp_style_return_udt);
        assert!(attrs.is_instance_constructor);
        assert!(attrs.is_instance_constructor_virtual_bases);
    }

    #[test]
    fn test_function_attributes_is_constructor() {
        let attrs = FunctionAttributes::empty();
        assert!(!attrs.is_constructor());

        let attrs = FunctionAttributes::from_byte(0x02);
        assert!(attrs.is_constructor());

        let attrs = FunctionAttributes::from_byte(0x04);
        assert!(attrs.is_constructor());
    }

    #[test]
    fn test_function_attributes_emit() {
        let attrs = FunctionAttributes::empty();
        assert_eq!(attrs.emit_string(), "");

        let attrs = FunctionAttributes::from_byte(0x01);
        assert_eq!(attrs.emit_string(), "return UDT (C++ style)");

        let attrs = FunctionAttributes::from_byte(0x03);
        assert!(attrs.emit_string().contains("return UDT"));
        assert!(attrs.emit_string().contains("instance constructor"));
    }

    #[test]
    fn test_procedure_basic() {
        let p = make_test_procedure();
        assert_eq!(p.pdb_id(), 0x1008);
        assert_eq!(
            p.return_value_record_number,
            RecordNumber::type_record(0x0074)
        );
        assert_eq!(p.calling_convention, CallingConvention::NearC);
        assert_eq!(p.num_parameters, 2);
        assert_eq!(
            p.arg_list_record_number,
            RecordNumber::type_record(0x1001)
        );
    }

    #[test]
    fn test_procedure_from_parsed() {
        let p = LfProcedure::from_parsed(0x0074, 0x07, 0x00, 3, 0x1002);
        assert_eq!(p.calling_convention, CallingConvention::NearStd);
        assert_eq!(p.num_parameters, 3);
        assert_eq!(
            p.arg_list_record_number,
            RecordNumber::type_record(0x1002)
        );
    }

    #[test]
    fn test_procedure_from_parsed_unknown_cc() {
        let p = LfProcedure::from_parsed(0x0074, 0xFF, 0x00, 0, 0x1001);
        // Unknown calling convention falls back to NearC.
        assert_eq!(p.calling_convention, CallingConvention::NearC);
    }

    #[test]
    fn test_procedure_emit() {
        let p = make_test_procedure();
        let emitted = p.emit(Bind::NONE);
        assert!(emitted.contains("0x0074")); // return type
        assert!(emitted.contains("__cdecl")); // calling convention
        assert!(emitted.contains("0x1001")); // arg list
        assert!(emitted.contains("params=2")); // param count
    }

    #[test]
    fn test_procedure_emit_below_proc() {
        let p = make_test_procedure();
        let emitted = p.emit(Bind::ARRAY);
        assert!(emitted.starts_with('('));
        assert!(emitted.ends_with(')'));
    }

    #[test]
    fn test_procedure_emit_at_proc() {
        let p = make_test_procedure();
        let emitted = p.emit(Bind::PROC);
        assert!(!emitted.starts_with('('));
    }

    #[test]
    fn test_procedure_accessors() {
        let p = make_test_procedure();
        assert_eq!(p.return_record_number(), RecordNumber::type_record(0x0074));
        assert_eq!(p.arg_list_record_number(), RecordNumber::type_record(0x1001));
        assert_eq!(p.num_params(), 2);
        assert_eq!(p.calling_convention(), CallingConvention::NearC);
        assert!(!p.is_constructor());
    }

    #[test]
    fn test_procedure_is_constructor() {
        let p = LfProcedure::new(
            RecordNumber::NO_TYPE,
            CallingConvention::ThisCall,
            FunctionAttributes::from_byte(0x02), // instance constructor
            0,
            RecordNumber::type_record(0x1002),
        );
        assert!(p.is_constructor());
    }

    #[test]
    fn test_procedure_emit_constructor_attrs() {
        let p = LfProcedure::new(
            RecordNumber::NO_TYPE,
            CallingConvention::ThisCall,
            FunctionAttributes::from_byte(0x02),
            0,
            RecordNumber::type_record(0x1002),
        );
        let emitted = p.emit(Bind::NONE);
        assert!(emitted.contains("attrs={"));
        assert!(emitted.contains("instance constructor"));
    }

    #[test]
    fn test_procedure_record_number() {
        let mut p = make_test_procedure();
        assert!(p.record_number().is_no_type());
        p.set_record_number(RecordNumber::type_record(0x2000));
        assert_eq!(p.record_number().index(), 0x2000);
    }

    #[test]
    fn test_procedure_display() {
        let p = make_test_procedure();
        let display = format!("{}", p);
        assert!(!display.is_empty());
    }

    #[test]
    fn test_procedure_stdcall() {
        let p = LfProcedure::new(
            RecordNumber::type_record(0x0074),
            CallingConvention::NearStd,
            FunctionAttributes::empty(),
            1,
            RecordNumber::type_record(0x1001),
        );
        let emitted = p.emit(Bind::NONE);
        assert!(emitted.contains("__stdcall"));
        assert!(emitted.contains("[__stdcall]"));
    }

    #[test]
    fn test_procedure_has_cpp_return_udt() {
        let p = LfProcedure::new(
            RecordNumber::type_record(0x0074),
            CallingConvention::NearC,
            FunctionAttributes::from_byte(0x01),
            1,
            RecordNumber::type_record(0x1001),
        );
        assert!(p.has_cpp_return_udt());

        let p = make_test_procedure();
        assert!(!p.has_cpp_return_udt());
    }

    #[test]
    fn test_procedure_is_inline() {
        let p = LfProcedure::new(
            RecordNumber::type_record(0x0074),
            CallingConvention::Inline,
            FunctionAttributes::empty(),
            0,
            RecordNumber::type_record(0x1001),
        );
        assert!(p.is_inline());
        assert_eq!(p.calling_convention.label(), "inline");

        let p = make_test_procedure();
        assert!(!p.is_inline());
    }

    #[test]
    fn test_procedure_pdb_id_constants() {
        assert_eq!(LfProcedure::PDB_ID_16, 0x0008);
        assert_eq!(LfProcedure::PDB_ID_32, 0x1008);
    }

    #[test]
    fn test_procedure_is_variadic_heuristic_true() {
        let p = LfProcedure::new(
            RecordNumber::type_record(0x0074),
            CallingConvention::NearC,
            FunctionAttributes::empty(),
            1, // single param -- heuristic says variadic
            RecordNumber::type_record(0x1001),
        );
        assert!(p.is_variadic_heuristic());
    }

    #[test]
    fn test_procedure_is_variadic_heuristic_false() {
        let p = make_test_procedure(); // 2 params
        assert!(!p.is_variadic_heuristic());
    }

    #[test]
    fn test_procedure_is_variadic_heuristic_false_zero_params() {
        let p = LfProcedure::new(
            RecordNumber::NO_TYPE,
            CallingConvention::NearC,
            FunctionAttributes::empty(),
            0,
            RecordNumber::type_record(0x1001),
        );
        assert!(!p.is_variadic_heuristic());
    }

    #[test]
    fn test_procedure_calling_convention_byte() {
        let p = LfProcedure::new(
            RecordNumber::type_record(0x0074),
            CallingConvention::ThisCall,
            FunctionAttributes::empty(),
            1,
            RecordNumber::type_record(0x1001),
        );
        assert_eq!(p.calling_convention_byte(), 0x0b);
    }

    #[test]
    fn test_procedure_calling_convention_byte_cdecl() {
        let p = make_test_procedure();
        assert_eq!(p.calling_convention_byte(), 0x00);
    }

    #[test]
    fn test_procedure_attributes_byte_empty() {
        let p = make_test_procedure();
        assert_eq!(p.attributes_byte(), 0x00);
    }

    #[test]
    fn test_procedure_attributes_byte_constructor() {
        let p = LfProcedure::new(
            RecordNumber::NO_TYPE,
            CallingConvention::ThisCall,
            FunctionAttributes::from_byte(0x02),
            0,
            RecordNumber::type_record(0x1002),
        );
        assert_eq!(p.attributes_byte(), 0x02);
    }

    #[test]
    fn test_procedure_attributes_byte_cpp_return_udt() {
        let p = LfProcedure::new(
            RecordNumber::type_record(0x0074),
            CallingConvention::NearC,
            FunctionAttributes::from_byte(0x01),
            1,
            RecordNumber::type_record(0x1001),
        );
        assert_eq!(p.attributes_byte(), 0x01);
    }

    #[test]
    fn test_procedure_attributes_byte_all() {
        let p = LfProcedure::new(
            RecordNumber::type_record(0x0074),
            CallingConvention::NearC,
            FunctionAttributes::from_byte(0x07), // all bits
            1,
            RecordNumber::type_record(0x1001),
        );
        assert_eq!(p.attributes_byte(), 0x07);
    }

    // =========================================================================
    // Additional accessor tests
    // =========================================================================

    #[test]
    fn test_procedure_get_return_type_record_number() {
        let p = make_test_procedure();
        assert_eq!(
            p.get_return_type_record_number(),
            RecordNumber::type_record(0x0074)
        );
    }

    #[test]
    fn test_procedure_get_arg_list_type_record_number() {
        let p = make_test_procedure();
        assert_eq!(
            p.get_arg_list_type_record_number(),
            RecordNumber::type_record(0x1001)
        );
    }

    #[test]
    fn test_procedure_get_num_parameters() {
        let p = make_test_procedure();
        assert_eq!(p.get_num_parameters(), 2);
    }

    #[test]
    fn test_procedure_get_num_parameters_raw() {
        let p = make_test_procedure();
        assert_eq!(p.get_num_parameters_raw(), 2);
    }

    #[test]
    fn test_procedure_is_no_params_true() {
        let p = LfProcedure::new(
            RecordNumber::type_record(0x0074),
            CallingConvention::NearC,
            FunctionAttributes::empty(),
            0,
            RecordNumber::type_record(0x1001),
        );
        assert!(p.is_no_params());
    }

    #[test]
    fn test_procedure_is_no_params_false() {
        let p = make_test_procedure(); // 2 params
        assert!(!p.is_no_params());
    }

    #[test]
    fn test_procedure_calling_convention_label() {
        let p = make_test_procedure();
        assert_eq!(p.calling_convention_label(), "__cdecl");

        let p2 = LfProcedure::new(
            RecordNumber::type_record(0x0074),
            CallingConvention::NearStd,
            FunctionAttributes::empty(),
            1,
            RecordNumber::type_record(0x1001),
        );
        assert_eq!(p2.calling_convention_label(), "__stdcall");
    }

    // =========================================================================
    // Binary parsing tests
    // =========================================================================

    use crate::pdb::pdb_byte_reader::PdbByteReader;

    #[test]
    fn test_procedure_parse_from_reader() {
        // returnType=0x0074(u32), cc=0x07(NearStd)(u8), attrs=0x00(u8),
        // numParams=3(u16), argList=0x1002(u32)
        let mut data = Vec::new();
        data.extend_from_slice(&0x0074u32.to_le_bytes());
        data.push(0x07u8);  // NearStd
        data.push(0x00u8);  // no attributes
        data.extend_from_slice(&3u16.to_le_bytes());
        data.extend_from_slice(&0x1002u32.to_le_bytes());
        let mut reader = PdbByteReader::new(&data);
        let p = LfProcedure::parse_from_reader(&mut reader).unwrap();
        assert_eq!(p.calling_convention, CallingConvention::NearStd);
        assert_eq!(p.num_parameters, 3);
        assert_eq!(
            p.arg_list_record_number,
            RecordNumber::type_record(0x1002)
        );
        assert_eq!(
            p.return_value_record_number,
            RecordNumber::type_record(0x0074)
        );
        assert!(!p.is_constructor());
    }

    #[test]
    fn test_procedure_parse_from_reader_constructor() {
        let mut data = Vec::new();
        data.extend_from_slice(&0x0074u32.to_le_bytes());
        data.push(0x0bu8);  // ThisCall
        data.push(0x02u8);  // instance constructor
        data.extend_from_slice(&0u16.to_le_bytes());
        data.extend_from_slice(&0x1002u32.to_le_bytes());
        let mut reader = PdbByteReader::new(&data);
        let p = LfProcedure::parse_from_reader(&mut reader).unwrap();
        assert_eq!(p.calling_convention, CallingConvention::ThisCall);
        assert!(p.is_constructor());
        assert_eq!(p.num_parameters, 0);
    }

    #[test]
    fn test_procedure_parse_from_reader_unknown_cc() {
        let mut data = Vec::new();
        data.extend_from_slice(&0x0074u32.to_le_bytes());
        data.push(0xFFu8);  // unknown calling convention
        data.push(0x00u8);
        data.extend_from_slice(&0u16.to_le_bytes());
        data.extend_from_slice(&0x1001u32.to_le_bytes());
        let mut reader = PdbByteReader::new(&data);
        let p = LfProcedure::parse_from_reader(&mut reader).unwrap();
        // Falls back to NearC for unknown values.
        assert_eq!(p.calling_convention, CallingConvention::NearC);
    }

    #[test]
    fn test_procedure_parse_from_reader_truncated() {
        let data = [0x74u8, 0x00, 0x00, 0x00]; // only 4 bytes
        let mut reader = PdbByteReader::new(&data);
        let result = LfProcedure::parse_from_reader(&mut reader);
        assert!(result.is_err());
    }

    #[test]
    fn test_procedure_parse_from_reader_cpp_return_udt() {
        let mut data = Vec::new();
        data.extend_from_slice(&0x0074u32.to_le_bytes());
        data.push(0x00u8);  // NearC
        data.push(0x01u8);  // has_cpp_style_return_udt
        data.extend_from_slice(&1u16.to_le_bytes());
        data.extend_from_slice(&0x1001u32.to_le_bytes());
        let mut reader = PdbByteReader::new(&data);
        let p = LfProcedure::parse_from_reader(&mut reader).unwrap();
        assert!(p.has_cpp_return_udt());
    }
}
