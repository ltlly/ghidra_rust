//! LF_MFUNCTION -- concrete Member Function type record.
//!
//! Ports Ghidra's `MemberFunctionMsType` (PDB_ID = 0x1009) Java class.
//!
//! Represents a C++ member function type (method signature) in the PDB
//! type stream. Similar to [`super::lf_procedure::LfProcedure`] but adds
//! the class type, the `this` pointer type, and a calling convention
//! specific to member functions.
//!
//! # Binary Layout (LF_MFUNCTION / 0x1009)
//!
//! ```text
//! +0  u32   returnType         Type index of the return type
//! +4  u32   classType          Type index of the containing class
//! +8  u32   thisType           Type index of the this-pointer type
//! +12 u8    callingConvention  Calling convention
//! +13 u8    functionAttributes Bitfield of FunctionAttributes flags
//! +14 u16   numParameters      Number of parameters
//! +16 u32   argList            Type index of the LF_ARGLIST record
//! +20 u32   thisAdjustment     Adjustment to the this-pointer
//! ```

use std::fmt;

use super::abstract_ms_type::AbstractMsType;
use super::bind::Bind;
use super::lf_procedure::{CallingConvention, FunctionAttributes};
use super::RecordNumber;
use crate::pdb::pdb_byte_reader::PdbByteReader;
use crate::pdb::pdb_exception::PdbException;

/// Concrete PDB member function type record (`LF_MFUNCTION`).
///
/// This is the Rust equivalent of Ghidra's `MemberFunctionMsType`. It extends
/// the procedure type concept with class/this type information and a
/// this-pointer adjustment.
#[derive(Debug, Clone)]
pub struct LfMfunction {
    /// Record number of this type (set during TPI/IPI registration).
    record_number: RecordNumber,
    /// Record number of the return value type.
    pub return_value_record_number: RecordNumber,
    /// Record number of the containing class type.
    pub class_record_number: RecordNumber,
    /// Record number of the this-pointer type (typically a pointer type).
    pub this_record_number: RecordNumber,
    /// The calling convention used by this member function.
    pub calling_convention: CallingConvention,
    /// Function attributes (constructor, C++-style return UDT, etc.).
    pub function_attributes: FunctionAttributes,
    /// Number of parameters (excluding the implicit `this` pointer).
    pub num_parameters: u16,
    /// Record number of the LF_ARGLIST type record listing the parameter types.
    pub arg_list_record_number: RecordNumber,
    /// Adjustment to the `this` pointer (used for multiple/virtual inheritance).
    pub this_adjustment: u32,
}

impl LfMfunction {
    /// PDB ID for the 16-bit member function variant.
    pub const PDB_ID_16: u32 = 0x0009;
    /// PDB ID for the ST-format member function variant.
    pub const PDB_ID_ST: u32 = 0x1009;
    /// PDB ID for the 32-bit (MsType) member function variant.
    pub const PDB_ID_32: u32 = 0x1009;

    /// Create a new member function type record.
    pub fn new(
        return_value_record_number: RecordNumber,
        class_record_number: RecordNumber,
        this_record_number: RecordNumber,
        calling_convention: CallingConvention,
        function_attributes: FunctionAttributes,
        num_parameters: u16,
        arg_list_record_number: RecordNumber,
        this_adjustment: u32,
    ) -> Self {
        Self {
            record_number: RecordNumber::NO_TYPE,
            return_value_record_number,
            class_record_number,
            this_record_number,
            calling_convention,
            function_attributes,
            num_parameters,
            arg_list_record_number,
            this_adjustment,
        }
    }

    /// Create from raw parsed field values.
    pub fn from_parsed(
        return_type_index: u32,
        class_type_index: u32,
        this_type_index: u32,
        calling_convention_byte: u8,
        attributes_byte: u8,
        num_parameters: u16,
        arg_list_type_index: u32,
        this_adjustment: u32,
    ) -> Self {
        Self::new(
            RecordNumber::type_record(return_type_index),
            RecordNumber::type_record(class_type_index),
            RecordNumber::type_record(this_type_index),
            CallingConvention::from_value(calling_convention_byte)
                .unwrap_or(CallingConvention::NearC),
            FunctionAttributes::from_byte(attributes_byte),
            num_parameters,
            RecordNumber::type_record(arg_list_type_index),
            this_adjustment,
        )
    }

    /// Get the record number of the return type.
    ///
    /// Mirrors Java `AbstractMemberFunctionMsType.getReturnRecordNumber()`.
    pub fn return_record_number(&self) -> RecordNumber {
        self.return_value_record_number
    }

    /// Get the record number of the containing class type.
    ///
    /// Mirrors Java `AbstractMemberFunctionMsType.getContainingClassRecordNumber()`.
    pub fn containing_class_record_number(&self) -> RecordNumber {
        self.class_record_number
    }

    /// Get the record number of the this-pointer type.
    ///
    /// Mirrors Java `AbstractMemberFunctionMsType.getThisPointerRecordNumber()`.
    pub fn this_pointer_record_number(&self) -> RecordNumber {
        self.this_record_number
    }

    /// Get the record number of the argument list type.
    ///
    /// Mirrors Java `AbstractMemberFunctionMsType.getArgListRecordNumber()`.
    pub fn arg_list_record_number(&self) -> RecordNumber {
        self.arg_list_record_number
    }

    /// Get the number of parameters.
    ///
    /// Mirrors Java `AbstractMemberFunctionMsType.getNumParams()`.
    pub fn num_params(&self) -> u16 {
        self.num_parameters
    }

    /// Get the calling convention.
    ///
    /// Mirrors Java `AbstractMemberFunctionMsType.getCallingConvention()`.
    pub fn calling_convention(&self) -> CallingConvention {
        self.calling_convention
    }

    /// Get the function attributes.
    ///
    /// Mirrors Java `AbstractMemberFunctionMsType.getFunctionAttributes()`.
    pub fn function_attributes(&self) -> &FunctionAttributes {
        &self.function_attributes
    }

    /// Whether this member function is a constructor.
    ///
    /// Mirrors Java `AbstractMemberFunctionMsType.isConstructor()`.
    pub fn is_constructor(&self) -> bool {
        self.function_attributes.is_constructor()
    }

    /// Whether this member function has a C++-style return UDT.
    pub fn has_cpp_return_udt(&self) -> bool {
        self.function_attributes.has_cpp_style_return_udt
    }

    /// Whether this function is an inline marker.
    pub fn is_inline(&self) -> bool {
        self.calling_convention == CallingConvention::Inline
    }

    /// Get the this-pointer adjustment value.
    ///
    /// Mirrors Java `AbstractMemberFunctionMsType.getThisAdjuster()`.
    pub fn this_adjuster(&self) -> i32 {
        self.this_adjustment as i32
    }

    /// Whether this member function has a non-zero this-pointer adjustment.
    ///
    /// A non-zero adjustment occurs with multiple or virtual inheritance,
    /// where the `this` pointer must be adjusted before accessing the
    /// correct vtable or member offsets.
    pub fn has_this_adjustment(&self) -> bool {
        self.this_adjustment != 0
    }

    /// Whether this member function has a virtual base this-pointer
    /// adjustment (adjustment for virtual inheritance).
    ///
    /// In practice, a non-zero `this_adjustment` combined with the
    /// constructor attribute for virtual bases indicates this case.
    pub fn has_virtual_base_this_adjustment(&self) -> bool {
        self.this_adjustment != 0
            && self.function_attributes.is_instance_constructor_virtual_bases
    }

    /// Whether this member function is a destructor.
    ///
    /// Note: PDB does not explicitly mark destructors in the function
    /// attributes. This method returns `true` if the return type is void
    /// (NO_TYPE) and the function is not a constructor, which is a common
    /// heuristic. For definitive identification, the symbol name should
    /// be checked instead.
    pub fn is_destructor_heuristic(&self) -> bool {
        self.return_value_record_number == RecordNumber::NO_TYPE
            && !self.function_attributes.is_constructor()
            && self.num_parameters == 0
    }

    /// Get the return type record number.
    ///
    /// Alias for [`return_record_number`] for consistency with
    /// Java's `AbstractMemberFunctionMsType.getReturnRecordNumber()`.
    pub fn get_return_type_record_number(&self) -> RecordNumber {
        self.return_value_record_number
    }

    /// Get the containing class type record number.
    ///
    /// Alias for [`containing_class_record_number`] for consistency with
    /// Java's `AbstractMemberFunctionMsType.getContainingClassRecordNumber()`.
    pub fn get_containing_class_record_number(&self) -> RecordNumber {
        self.class_record_number
    }

    /// Get the this-pointer type record number.
    ///
    /// Alias for [`this_pointer_record_number`] for consistency with
    /// Java's `AbstractMemberFunctionMsType.getThisPointerRecordNumber()`.
    pub fn get_this_pointer_record_number(&self) -> RecordNumber {
        self.this_record_number
    }

    /// Get the argument list type record number.
    ///
    /// Alias for [`arg_list_record_number`] for consistency with
    /// Java's `AbstractMemberFunctionMsType.getArgListRecordNumber()`.
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

    /// Get the raw this-pointer adjustment value as `u32`.
    pub fn get_this_adjustment_raw(&self) -> u32 {
        self.this_adjustment
    }

    /// Whether this member function takes no parameters (excluding `this`).
    pub fn is_no_params(&self) -> bool {
        self.num_parameters == 0
    }

    /// Get the calling convention label string.
    ///
    /// Returns the ABI label (e.g., `"__thiscall"`, `"__cdecl"`).
    pub fn calling_convention_label(&self) -> &'static str {
        self.calling_convention.label()
    }

    /// Parse a member function type record from a byte reader (32-bit MsType).
    ///
    /// Reads the return type index, class type index, this-pointer type
    /// index, calling convention byte, function attributes byte, parameter
    /// count, argument list type index, and this-pointer adjustment.
    /// This mirrors the Java `MemberFunctionMsType` constructor which calls
    /// the `AbstractMemberFunctionMsType` base with `recordNumberSize=32`.
    ///
    /// # Errors
    ///
    /// Returns [`PdbException`] if the reader does not have enough data.
    pub fn parse_from_reader(reader: &mut PdbByteReader) -> Result<Self, PdbException> {
        let return_type_index = reader.read_u32()?;
        let class_type_index = reader.read_u32()?;
        let this_type_index = reader.read_u32()?;
        let calling_convention_byte = reader.read_u8()?;
        let attributes_byte = reader.read_u8()?;
        let num_parameters = reader.read_u16()?;
        let arg_list_type_index = reader.read_u32()?;
        let this_adjustment = reader.read_i32()? as u32;
        reader.align(4); // skipPadding
        Ok(Self::from_parsed(
            return_type_index,
            class_type_index,
            this_type_index,
            calling_convention_byte,
            attributes_byte,
            num_parameters,
            arg_list_type_index,
            this_adjustment,
        ))
    }

    /// Parse a 16-bit member function type record from a byte reader.
    ///
    /// Reads u16 record numbers for the return type, class type, this-pointer
    /// type, and argument list type. This mirrors the Java
    /// `MemberFunction16MsType` constructor which calls the
    /// `AbstractMemberFunctionMsType` base with `recordNumberSize=16`.
    ///
    /// # Errors
    ///
    /// Returns [`PdbException`] if the reader does not have enough data.
    pub fn parse_from_reader_16(reader: &mut PdbByteReader) -> Result<Self, PdbException> {
        let return_type_index = reader.read_u16()? as u32;
        let class_type_index = reader.read_u16()? as u32;
        let this_type_index = reader.read_u16()? as u32;
        let calling_convention_byte = reader.read_u8()?;
        let attributes_byte = reader.read_u8()?;
        let num_parameters = reader.read_u16()?;
        let arg_list_type_index = reader.read_u16()? as u32;
        let this_adjustment = reader.read_i32()? as u32;
        reader.align(4); // skipPadding
        Ok(Self::from_parsed(
            return_type_index,
            class_type_index,
            this_type_index,
            calling_convention_byte,
            attributes_byte,
            num_parameters,
            arg_list_type_index,
            this_adjustment,
        ))
    }

    /// Emit the full signature including class qualification, this-pointer
    /// info, and structured metadata matching the Java `emit()` output.
    fn emit_full(&self, bind: Bind) -> String {
        let mut result = String::new();

        if bind < Bind::PROC {
            result.push('(');
        }

        // Emit containing class reference with "::"
        // Mirrors Java: myBuilder.append(getContainingClassType()); myBuilder.append("::");
        result.push_str(&self.class_record_number.to_string());
        result.push_str("::");

        // Emit argument list reference.
        // Mirrors Java: builder.append(getArgumentsListType());
        result.push_str(&self.arg_list_record_number.to_string());

        // Emit structured metadata in angle brackets.
        // Mirrors Java: builder.append("<this<thisPtrType>,adjuster,numParams,attrs>")
        result.push('<');
        result.push_str("this");
        result.push_str(&self.this_record_number.to_string());
        result.push(',');
        result.push_str(&self.this_adjustment.to_string());
        result.push(',');
        result.push_str(&self.num_parameters.to_string());
        let attrs_str = self.function_attributes.emit_string();
        if attrs_str.is_empty() {
            result.push(',');
        } else {
            result.push(',');
            result.push_str(&attrs_str);
        }
        result.push('>');

        // Emit return type with PROC binding.
        // Mirrors Java: getReturnType().emit(builder, Bind.PROC);
        result.push(' ');
        result.push_str(&self.return_value_record_number.to_string());

        // Emit calling convention annotation.
        if !self.calling_convention.label().is_empty() {
            result.push_str(" [");
            result.push_str(self.calling_convention.label());
            result.push(']');
        }

        if bind < Bind::PROC {
            result.push(')');
        }

        result
    }
}

impl AbstractMsType for LfMfunction {
    fn pdb_id(&self) -> u32 {
        Self::PDB_ID_32 // LF_MFUNCTION = 0x1009
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

impl fmt::Display for LfMfunction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.emit(Bind::NONE))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_mfunction() -> LfMfunction {
        LfMfunction::new(
            RecordNumber::type_record(0x0074), // int return type
            RecordNumber::type_record(0x1000), // class type
            RecordNumber::type_record(0x1001), // this-pointer type
            CallingConvention::ThisCall,
            FunctionAttributes::empty(),
            2,
            RecordNumber::type_record(0x1002), // arg list
            0,
        )
    }

    #[test]
    fn test_mfunction_basic() {
        let mf = make_test_mfunction();
        assert_eq!(mf.pdb_id(), 0x1009);
        assert_eq!(
            mf.return_value_record_number,
            RecordNumber::type_record(0x0074)
        );
        assert_eq!(mf.class_record_number, RecordNumber::type_record(0x1000));
        assert_eq!(mf.this_record_number, RecordNumber::type_record(0x1001));
        assert_eq!(mf.calling_convention, CallingConvention::ThisCall);
        assert_eq!(mf.num_parameters, 2);
        assert_eq!(
            mf.arg_list_record_number,
            RecordNumber::type_record(0x1002)
        );
        assert_eq!(mf.this_adjustment, 0);
    }

    #[test]
    fn test_mfunction_from_parsed() {
        let mf = LfMfunction::from_parsed(
            0x0074, // return type
            0x1000, // class type
            0x1001, // this type
            0x0b,   // ThisCall
            0x00,   // no attributes
            3,      // 3 params
            0x1002, // arg list
            0,      // no this adjustment
        );
        assert_eq!(mf.calling_convention, CallingConvention::ThisCall);
        assert_eq!(mf.num_parameters, 3);
    }

    #[test]
    fn test_mfunction_from_parsed_with_adjustment() {
        let mf = LfMfunction::from_parsed(
            0x0074,
            0x1000,
            0x1001,
            0x0b,
            0x00,
            1,
            0x1002,
            8, // this adjustment
        );
        assert_eq!(mf.this_adjustment, 8);
    }

    #[test]
    fn test_mfunction_from_parsed_unknown_cc() {
        let mf = LfMfunction::from_parsed(
            0x0074, 0x1000, 0x1001, 0xFF, 0x00, 0, 0x1002, 0,
        );
        // Unknown calling convention falls back to NearC.
        assert_eq!(mf.calling_convention, CallingConvention::NearC);
    }

    #[test]
    fn test_mfunction_emit() {
        let mf = make_test_mfunction();
        let emitted = mf.emit(Bind::NONE);
        assert!(emitted.contains("0x0074")); // return type
        assert!(emitted.contains("0x1000")); // class type
        assert!(emitted.contains("__thiscall"));
        assert!(emitted.contains("0x1002")); // arg list
        assert!(emitted.contains("this"));   // this-pointer marker
    }

    #[test]
    fn test_mfunction_emit_with_adjustment() {
        let mf = LfMfunction::new(
            RecordNumber::type_record(0x0074),
            RecordNumber::type_record(0x1000),
            RecordNumber::type_record(0x1001),
            CallingConvention::ThisCall,
            FunctionAttributes::empty(),
            1,
            RecordNumber::type_record(0x1002),
            8,
        );
        let emitted = mf.emit(Bind::NONE);
        // Adjustment appears in the angle-bracket metadata.
        assert!(emitted.contains(",8,"));
    }

    #[test]
    fn test_mfunction_emit_no_adjustment() {
        let mf = make_test_mfunction();
        let emitted = mf.emit(Bind::NONE);
        // Zero adjustment still appears in metadata.
        assert!(emitted.contains(",0,"));
    }

    #[test]
    fn test_mfunction_emit_below_proc() {
        let mf = make_test_mfunction();
        let emitted = mf.emit(Bind::ARRAY);
        assert!(emitted.starts_with('('));
        assert!(emitted.ends_with(')'));
    }

    #[test]
    fn test_mfunction_emit_at_proc() {
        let mf = make_test_mfunction();
        let emitted = mf.emit(Bind::PROC);
        assert!(!emitted.starts_with('('));
    }

    #[test]
    fn test_mfunction_record_number() {
        let mut mf = make_test_mfunction();
        assert!(mf.record_number().is_no_type());
        mf.set_record_number(RecordNumber::type_record(0x2000));
        assert_eq!(mf.record_number().index(), 0x2000);
    }

    #[test]
    fn test_mfunction_display() {
        let mf = make_test_mfunction();
        let display = format!("{}", mf);
        assert!(!display.is_empty());
        assert!(display.contains("0x1000"));
    }

    #[test]
    fn test_mfunction_constructor() {
        let mf = LfMfunction::new(
            RecordNumber::NO_TYPE, // void return
            RecordNumber::type_record(0x1000),
            RecordNumber::type_record(0x1001),
            CallingConvention::ThisCall,
            FunctionAttributes::from_byte(0x02), // instance constructor
            0,
            RecordNumber::type_record(0x1002),
            0,
        );
        assert!(mf.function_attributes.is_constructor());
    }

    #[test]
    fn test_mfunction_cdecl() {
        let mf = LfMfunction::new(
            RecordNumber::type_record(0x0074),
            RecordNumber::type_record(0x1000),
            RecordNumber::type_record(0x1001),
            CallingConvention::NearC,
            FunctionAttributes::empty(),
            1,
            RecordNumber::type_record(0x1002),
            0,
        );
        let emitted = mf.emit(Bind::NONE);
        assert!(emitted.contains("[__cdecl]"));
    }

    #[test]
    fn test_mfunction_accessors() {
        let mf = make_test_mfunction();
        assert_eq!(mf.return_record_number(), RecordNumber::type_record(0x0074));
        assert_eq!(mf.containing_class_record_number(), RecordNumber::type_record(0x1000));
        assert_eq!(mf.this_pointer_record_number(), RecordNumber::type_record(0x1001));
        assert_eq!(mf.arg_list_record_number(), RecordNumber::type_record(0x1002));
        assert_eq!(mf.num_params(), 2);
        assert_eq!(mf.calling_convention(), CallingConvention::ThisCall);
        assert!(!mf.is_constructor());
        assert_eq!(mf.this_adjuster(), 0);
    }

    #[test]
    fn test_mfunction_is_constructor() {
        let mf = LfMfunction::new(
            RecordNumber::NO_TYPE,
            RecordNumber::type_record(0x1000),
            RecordNumber::type_record(0x1001),
            CallingConvention::ThisCall,
            FunctionAttributes::from_byte(0x04), // virtual base constructor
            0,
            RecordNumber::type_record(0x1002),
            0,
        );
        assert!(mf.is_constructor());
    }

    #[test]
    fn test_mfunction_emit_angle_bracket_metadata() {
        let mf = make_test_mfunction();
        let emitted = mf.emit(Bind::NONE);
        // The angle-bracket metadata contains this-pointer, adjustment, param count.
        assert!(emitted.contains('<'));
        assert!(emitted.contains('>'));
        assert!(emitted.contains("this0x1001"));
    }

    #[test]
    fn test_mfunction_has_cpp_return_udt() {
        let mf = LfMfunction::new(
            RecordNumber::type_record(0x0074),
            RecordNumber::type_record(0x1000),
            RecordNumber::type_record(0x1001),
            CallingConvention::ThisCall,
            FunctionAttributes::from_byte(0x01),
            1,
            RecordNumber::type_record(0x1002),
            0,
        );
        assert!(mf.has_cpp_return_udt());

        let mf = make_test_mfunction();
        assert!(!mf.has_cpp_return_udt());
    }

    #[test]
    fn test_mfunction_is_inline() {
        let mf = LfMfunction::new(
            RecordNumber::type_record(0x0074),
            RecordNumber::type_record(0x1000),
            RecordNumber::type_record(0x1001),
            CallingConvention::Inline,
            FunctionAttributes::empty(),
            0,
            RecordNumber::type_record(0x1002),
            0,
        );
        assert!(mf.is_inline());

        let mf = make_test_mfunction();
        assert!(!mf.is_inline());
    }

    #[test]
    fn test_mfunction_pdb_id_constants() {
        assert_eq!(LfMfunction::PDB_ID_16, 0x0009);
        assert_eq!(LfMfunction::PDB_ID_32, 0x1009);
    }

    #[test]
    fn test_mfunction_has_this_adjustment_false() {
        let mf = make_test_mfunction();
        assert!(!mf.has_this_adjustment());
    }

    #[test]
    fn test_mfunction_has_this_adjustment_true() {
        let mf = LfMfunction::new(
            RecordNumber::type_record(0x0074),
            RecordNumber::type_record(0x1000),
            RecordNumber::type_record(0x1001),
            CallingConvention::ThisCall,
            FunctionAttributes::empty(),
            1,
            RecordNumber::type_record(0x1002),
            4, // non-zero adjustment
        );
        assert!(mf.has_this_adjustment());
    }

    #[test]
    fn test_mfunction_has_virtual_base_this_adjustment_true() {
        let mf = LfMfunction::new(
            RecordNumber::type_record(0x0074),
            RecordNumber::type_record(0x1000),
            RecordNumber::type_record(0x1001),
            CallingConvention::ThisCall,
            FunctionAttributes::from_byte(0x04), // virtual base constructor
            0,
            RecordNumber::type_record(0x1002),
            8, // non-zero adjustment
        );
        assert!(mf.has_virtual_base_this_adjustment());
    }

    #[test]
    fn test_mfunction_has_virtual_base_this_adjustment_false_zero_adj() {
        let mf = LfMfunction::new(
            RecordNumber::type_record(0x0074),
            RecordNumber::type_record(0x1000),
            RecordNumber::type_record(0x1001),
            CallingConvention::ThisCall,
            FunctionAttributes::from_byte(0x04), // virtual base constructor
            0,
            RecordNumber::type_record(0x1002),
            0, // zero adjustment
        );
        assert!(!mf.has_virtual_base_this_adjustment());
    }

    #[test]
    fn test_mfunction_has_virtual_base_this_adjustment_false_not_vbase() {
        let mf = LfMfunction::new(
            RecordNumber::type_record(0x0074),
            RecordNumber::type_record(0x1000),
            RecordNumber::type_record(0x1001),
            CallingConvention::ThisCall,
            FunctionAttributes::empty(), // no virtual base flag
            0,
            RecordNumber::type_record(0x1002),
            8, // non-zero adjustment
        );
        assert!(!mf.has_virtual_base_this_adjustment());
    }

    #[test]
    fn test_mfunction_is_destructor_heuristic_true() {
        let mf = LfMfunction::new(
            RecordNumber::NO_TYPE, // void return
            RecordNumber::type_record(0x1000),
            RecordNumber::type_record(0x1001),
            CallingConvention::ThisCall,
            FunctionAttributes::empty(), // not a constructor
            0,                           // no params
            RecordNumber::type_record(0x1002),
            0,
        );
        assert!(mf.is_destructor_heuristic());
    }

    #[test]
    fn test_mfunction_is_destructor_heuristic_false_constructor() {
        let mf = LfMfunction::new(
            RecordNumber::NO_TYPE,
            RecordNumber::type_record(0x1000),
            RecordNumber::type_record(0x1001),
            CallingConvention::ThisCall,
            FunctionAttributes::from_byte(0x02), // constructor
            0,
            RecordNumber::type_record(0x1002),
            0,
        );
        assert!(!mf.is_destructor_heuristic());
    }

    #[test]
    fn test_mfunction_is_destructor_heuristic_false_has_return() {
        let mf = make_test_mfunction(); // has int return type
        assert!(!mf.is_destructor_heuristic());
    }

    #[test]
    fn test_mfunction_emit_contains_angle_bracket_metadata() {
        let mf = make_test_mfunction();
        let emitted = mf.emit(Bind::NONE);
        // Angle brackets should contain this-pointer, adjustment, param count, attrs
        assert!(emitted.contains('<'));
        assert!(emitted.contains('>'));
        // Should contain "::" for class qualification
        assert!(emitted.contains("::"));
    }

    #[test]
    fn test_mfunction_emit_with_virtual_base_constructor() {
        let mf = LfMfunction::new(
            RecordNumber::type_record(0x0074),
            RecordNumber::type_record(0x1000),
            RecordNumber::type_record(0x1001),
            CallingConvention::ThisCall,
            FunctionAttributes::from_byte(0x04), // virtual base constructor
            0,
            RecordNumber::type_record(0x1002),
            12,
        );
        let emitted = mf.emit(Bind::NONE);
        assert!(emitted.contains("virtual base"));
        assert!(emitted.contains(",12,"));
    }

    // =========================================================================
    // Additional accessor tests
    // =========================================================================

    #[test]
    fn test_mfunction_get_return_type_record_number() {
        let mf = make_test_mfunction();
        assert_eq!(
            mf.get_return_type_record_number(),
            RecordNumber::type_record(0x0074)
        );
    }

    #[test]
    fn test_mfunction_get_containing_class_record_number() {
        let mf = make_test_mfunction();
        assert_eq!(
            mf.get_containing_class_record_number(),
            RecordNumber::type_record(0x1000)
        );
    }

    #[test]
    fn test_mfunction_get_this_pointer_record_number() {
        let mf = make_test_mfunction();
        assert_eq!(
            mf.get_this_pointer_record_number(),
            RecordNumber::type_record(0x1001)
        );
    }

    #[test]
    fn test_mfunction_get_arg_list_type_record_number() {
        let mf = make_test_mfunction();
        assert_eq!(
            mf.get_arg_list_type_record_number(),
            RecordNumber::type_record(0x1002)
        );
    }

    #[test]
    fn test_mfunction_get_num_parameters() {
        let mf = make_test_mfunction();
        assert_eq!(mf.get_num_parameters(), 2);
    }

    #[test]
    fn test_mfunction_get_num_parameters_raw() {
        let mf = make_test_mfunction();
        assert_eq!(mf.get_num_parameters_raw(), 2);
    }

    #[test]
    fn test_mfunction_get_this_adjustment_raw() {
        let mf = make_test_mfunction();
        assert_eq!(mf.get_this_adjustment_raw(), 0);

        let mf2 = LfMfunction::new(
            RecordNumber::type_record(0x0074),
            RecordNumber::type_record(0x1000),
            RecordNumber::type_record(0x1001),
            CallingConvention::ThisCall,
            FunctionAttributes::empty(),
            1,
            RecordNumber::type_record(0x1002),
            8,
        );
        assert_eq!(mf2.get_this_adjustment_raw(), 8);
    }

    #[test]
    fn test_mfunction_is_no_params_true() {
        let mf = LfMfunction::new(
            RecordNumber::type_record(0x0074),
            RecordNumber::type_record(0x1000),
            RecordNumber::type_record(0x1001),
            CallingConvention::ThisCall,
            FunctionAttributes::empty(),
            0,
            RecordNumber::type_record(0x1002),
            0,
        );
        assert!(mf.is_no_params());
    }

    #[test]
    fn test_mfunction_is_no_params_false() {
        let mf = make_test_mfunction(); // 2 params
        assert!(!mf.is_no_params());
    }

    #[test]
    fn test_mfunction_calling_convention_label() {
        let mf = make_test_mfunction();
        assert_eq!(mf.calling_convention_label(), "__thiscall");

        let mf2 = LfMfunction::new(
            RecordNumber::type_record(0x0074),
            RecordNumber::type_record(0x1000),
            RecordNumber::type_record(0x1001),
            CallingConvention::NearC,
            FunctionAttributes::empty(),
            1,
            RecordNumber::type_record(0x1002),
            0,
        );
        assert_eq!(mf2.calling_convention_label(), "__cdecl");
    }

    // =========================================================================
    // Binary parsing tests
    // =========================================================================

    use crate::pdb::pdb_byte_reader::PdbByteReader;

    #[test]
    fn test_mfunction_parse_from_reader() {
        // returnType=0x0074(u32), classType=0x1000(u32), thisType=0x1001(u32),
        // cc=0x0b(ThisCall)(u8), attrs=0x00(u8), numParams=2(u16),
        // argList=0x1002(u32), thisAdjustment=0(i32)
        let mut data = Vec::new();
        data.extend_from_slice(&0x0074u32.to_le_bytes());
        data.extend_from_slice(&0x1000u32.to_le_bytes());
        data.extend_from_slice(&0x1001u32.to_le_bytes());
        data.push(0x0bu8); // ThisCall
        data.push(0x00u8); // no attributes
        data.extend_from_slice(&2u16.to_le_bytes());
        data.extend_from_slice(&0x1002u32.to_le_bytes());
        data.extend_from_slice(&0i32.to_le_bytes()); // this_adjustment
        let mut reader = PdbByteReader::new(&data);
        let mf = LfMfunction::parse_from_reader(&mut reader).unwrap();
        assert_eq!(mf.calling_convention, CallingConvention::ThisCall);
        assert_eq!(mf.num_parameters, 2);
        assert_eq!(mf.this_adjustment, 0);
        assert_eq!(mf.class_record_number, RecordNumber::type_record(0x1000));
        assert_eq!(mf.this_record_number, RecordNumber::type_record(0x1001));
    }

    #[test]
    fn test_mfunction_parse_from_reader_with_adjustment() {
        let mut data = Vec::new();
        data.extend_from_slice(&0x0074u32.to_le_bytes());
        data.extend_from_slice(&0x1000u32.to_le_bytes());
        data.extend_from_slice(&0x1001u32.to_le_bytes());
        data.push(0x0bu8);
        data.push(0x04u8); // virtual base constructor
        data.extend_from_slice(&0u16.to_le_bytes());
        data.extend_from_slice(&0x1002u32.to_le_bytes());
        data.extend_from_slice(&8i32.to_le_bytes()); // this_adjustment = 8
        let mut reader = PdbByteReader::new(&data);
        let mf = LfMfunction::parse_from_reader(&mut reader).unwrap();
        assert_eq!(mf.this_adjustment, 8);
        assert!(mf.has_this_adjustment());
        assert!(mf.has_virtual_base_this_adjustment());
    }

    #[test]
    fn test_mfunction_parse_from_reader_truncated() {
        let data = [0x74u8, 0x00, 0x00, 0x00]; // only 4 bytes
        let mut reader = PdbByteReader::new(&data);
        let result = LfMfunction::parse_from_reader(&mut reader);
        assert!(result.is_err());
    }

    #[test]
    fn test_mfunction_parse_from_reader_cdecl() {
        let mut data = Vec::new();
        data.extend_from_slice(&0x0074u32.to_le_bytes());
        data.extend_from_slice(&0x1000u32.to_le_bytes());
        data.extend_from_slice(&0x1001u32.to_le_bytes());
        data.push(0x00u8); // NearC
        data.push(0x00u8);
        data.extend_from_slice(&1u16.to_le_bytes());
        data.extend_from_slice(&0x1002u32.to_le_bytes());
        data.extend_from_slice(&0i32.to_le_bytes());
        let mut reader = PdbByteReader::new(&data);
        let mf = LfMfunction::parse_from_reader(&mut reader).unwrap();
        assert_eq!(mf.calling_convention, CallingConvention::NearC);
        let emitted = mf.emit(Bind::NONE);
        assert!(emitted.contains("[__cdecl]"));
    }

    // =========================================================================
    // 16-bit variant parsing tests
    // =========================================================================

    #[test]
    fn test_mfunction_parse_from_reader_16() {
        // returnType=0x0074(u16), classType=0x1000(u16), thisType=0x1001(u16),
        // cc=0x0b(ThisCall)(u8), attrs=0x00(u8), numParams=2(u16),
        // argList=0x1002(u16), thisAdjustment=0(i32)
        let mut data = Vec::new();
        data.extend_from_slice(&0x0074u16.to_le_bytes());
        data.extend_from_slice(&0x1000u16.to_le_bytes());
        data.extend_from_slice(&0x1001u16.to_le_bytes());
        data.push(0x0bu8); // ThisCall
        data.push(0x00u8); // no attributes
        data.extend_from_slice(&2u16.to_le_bytes());
        data.extend_from_slice(&0x1002u16.to_le_bytes());
        data.extend_from_slice(&0i32.to_le_bytes()); // this_adjustment
        let mut reader = PdbByteReader::new(&data);
        let mf = LfMfunction::parse_from_reader_16(&mut reader).unwrap();
        assert_eq!(mf.calling_convention, CallingConvention::ThisCall);
        assert_eq!(mf.num_parameters, 2);
        assert_eq!(mf.this_adjustment, 0);
        assert_eq!(mf.class_record_number, RecordNumber::type_record(0x1000));
        assert_eq!(mf.this_record_number, RecordNumber::type_record(0x1001));
    }

    #[test]
    fn test_mfunction_parse_from_reader_16_truncated() {
        let data = [0x74u8, 0x00, 0x00, 0x00]; // only 4 bytes
        let mut reader = PdbByteReader::new(&data);
        let result = LfMfunction::parse_from_reader_16(&mut reader);
        assert!(result.is_err());
    }

    #[test]
    fn test_mfunction_parse_from_reader_16_with_adjustment() {
        let mut data = Vec::new();
        data.extend_from_slice(&0x0074u16.to_le_bytes());
        data.extend_from_slice(&0x1000u16.to_le_bytes());
        data.extend_from_slice(&0x1001u16.to_le_bytes());
        data.push(0x0bu8); // ThisCall
        data.push(0x04u8); // virtual base constructor
        data.extend_from_slice(&0u16.to_le_bytes());
        data.extend_from_slice(&0x1002u16.to_le_bytes());
        data.extend_from_slice(&8i32.to_le_bytes()); // this_adjustment = 8
        let mut reader = PdbByteReader::new(&data);
        let mf = LfMfunction::parse_from_reader_16(&mut reader).unwrap();
        assert_eq!(mf.this_adjustment, 8);
        assert!(mf.has_this_adjustment());
        assert!(mf.has_virtual_base_this_adjustment());
    }
}
