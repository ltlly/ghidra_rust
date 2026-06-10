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
}

impl AbstractMsType for LfMfunction {
    fn pdb_id(&self) -> u32 {
        0x1009 // LF_MFUNCTION
    }

    fn record_number(&self) -> RecordNumber {
        self.record_number
    }

    fn set_record_number(&mut self, record_number: RecordNumber) {
        self.record_number = record_number;
    }

    fn emit(&self, bind: Bind) -> String {
        let mut result = String::new();

        if bind < Bind::PROC {
            result.push('(');
        }

        // Emit the return type reference.
        result.push_str(&self.return_value_record_number.to_string());
        result.push(' ');

        // Emit the class type reference.
        result.push_str(&self.class_record_number.to_string());
        result.push_str("::(");

        // Emit calling convention.
        if !self.calling_convention.label().is_empty() {
            result.push_str(self.calling_convention.label());
            result.push(' ');
        }

        // Emit argument list reference.
        result.push_str(&self.arg_list_record_number.to_string());
        result.push(')');

        // Emit this-pointer adjustment if non-zero.
        if self.this_adjustment != 0 {
            result.push_str(&format!(" this+{}", self.this_adjustment));
        }

        if bind < Bind::PROC {
            result.push(')');
        }

        result
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
        assert!(emitted.contains("this+8"));
    }

    #[test]
    fn test_mfunction_emit_no_adjustment() {
        let mf = make_test_mfunction();
        let emitted = mf.emit(Bind::NONE);
        assert!(!emitted.contains("this+"));
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
        assert!(emitted.contains("__cdecl"));
    }
}
