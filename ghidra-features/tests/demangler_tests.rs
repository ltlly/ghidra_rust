//! Integration tests for the demangler module.

use ghidra_features::demangler::microsoft::datatype::parser::parse_data_type;
use ghidra_features::demangler::microsoft::datatype::{DataType, Sign};
use ghidra_features::demangler::microsoft::function::CallingConvention;
use ghidra_features::demangler::microsoft::iterator::CharacterIterator;
use ghidra_features::demangler::microsoft::modifier::CVMod;
use ghidra_features::demangler::microsoft::naming::{
    BasicName, FragmentName, Qualification, SpecialName,
};
use ghidra_features::demangler::microsoft::typeinfo::TypeInfo;
use ghidra_features::demangler::microsoft::{DemangleError, MicrosoftDemangler};

// ============================================================================
// Microsoft Demangler Integration Tests
// ============================================================================

#[test]
fn test_ms_demangler_simple_function() {
    let d = MicrosoftDemangler::new();
    // ?foo@@YAXXZ = void __cdecl foo(void)
    let result = d.demangle("?foo@@YAXXZ").unwrap();
    assert!(result.is_function);
    assert_eq!(result.base_name, "foo");
    assert!(result.demangled_name.contains("void"));
    assert!(result.demangled_name.contains("foo"));
}

#[test]
fn test_ms_demangler_int_return() {
    let d = MicrosoftDemangler::new();
    // ?bar@@YAHXZ = int __cdecl bar(void)
    let result = d.demangle("?bar@@YAHXZ").unwrap();
    assert!(result.is_function);
    assert_eq!(result.base_name, "bar");
    let ret = result.return_type.as_ref().unwrap();
    assert_eq!(ret.emit(), "int");
}

#[test]
fn test_ms_demangler_float_return() {
    let d = MicrosoftDemangler::new();
    // ?baz@@YAMXZ = float __cdecl baz(void)
    let result = d.demangle("?baz@@YAMXZ").unwrap();
    let ret = result.return_type.as_ref().unwrap();
    assert_eq!(ret.emit(), "float");
}

#[test]
fn test_ms_demangler_with_int_args() {
    let d = MicrosoftDemangler::new();
    // ?add@@YAHHH@Z = int __cdecl add(int, int)
    let result = d.demangle("?add@@YAHHH@Z").unwrap();
    assert!(result.is_function);
    assert_eq!(result.argument_types.len(), 2);
}

#[test]
fn test_ms_demangler_stdcall() {
    let d = MicrosoftDemangler::new();
    // ?func@@YGXXZ = void __stdcall func(void)
    let result = d.demangle("?func@@YGXXZ").unwrap();
    assert!(result.demangled_name.contains("__stdcall"));
}

#[test]
fn test_ms_demangler_fastcall() {
    let d = MicrosoftDemangler::new();
    // ?func@@YIXXZ = void __fastcall func(void)
    let result = d.demangle("?func@@YIXXZ").unwrap();
    assert!(result.demangled_name.contains("__fastcall"));
}

#[test]
fn test_ms_demangler_namespaced_function() {
    let d = MicrosoftDemangler::new();
    // ?func@ns@@YAXXZ = void __cdecl ns::func(void)
    let result = d.demangle("?func@ns@@YAXXZ").unwrap();
    assert!(result.namespace.contains(&"ns".to_string()));
    assert!(result.demangled_name.contains("ns"));
}

#[test]
fn test_ms_demangler_data_symbol() {
    let d = MicrosoftDemangler::new();
    // ?myVar@@3HA = int myVar
    let result = d.demangle("?myVar@@3HA").unwrap();
    assert_eq!(result.base_name, "myVar");
    assert!(result.is_data || !result.is_function);
}

#[test]
fn test_ms_demangler_pointer_to_int() {
    let d = MicrosoftDemangler::new();
    // ?ptr@@3PEAHE = int * ptr
    let result = d.demangle("?ptr@@3PEAHE").unwrap();
    assert!(result.demangled_name.contains("*"));
}

#[test]
fn test_ms_demangler_varargs() {
    let d = MicrosoftDemangler::new();
    // ?printf@@YAHPEBDZZ = int __cdecl printf(char const *, ...)
    let result = d.demangle("?printf@@YAHPEBDZZ").unwrap();
    assert!(result.demangled_name.contains("..."));
}

#[test]
fn test_ms_demangler_constructor() {
    let d = MicrosoftDemangler::new();
    // ??0MyClass@@QEAA@XZ
    let result = d.demangle("??0MyClass@@QEAA@XZ").unwrap();
    assert!(result.demangled_name.contains("MyClass"));
}

#[test]
fn test_ms_demangler_destructor() {
    let d = MicrosoftDemangler::new();
    // ??1MyClass@@QEAA@XZ
    let result = d.demangle("??1MyClass@@QEAA@XZ").unwrap();
    assert!(result.demangled_name.contains("MyClass"));
}

#[test]
fn test_ms_demangler_operator_plus() {
    let d = MicrosoftDemangler::new();
    // ??H@YAPEAVC@@PEAV0@0@Z = operator+ type
    let result = d.demangle("??H@YAPEAVC@@PEAV0@0@Z");
    assert!(result.is_ok());
}

#[test]
fn test_ms_demangler_empty_symbol() {
    let d = MicrosoftDemangler::new();
    let result = d.demangle("");
    assert!(matches!(result, Err(DemangleError::EmptySymbol)));
}

#[test]
fn test_ms_demangler_not_ms_symbol() {
    let d = MicrosoftDemangler::new();
    let result = d.demangle("_Z3foov");
    assert!(result.is_err());
}

#[test]
fn test_ms_demangler_can_demangle() {
    assert!(MicrosoftDemangler::can_demangle("?foo@@YAXXZ"));
    assert!(!MicrosoftDemangler::can_demangle("_Z3foov"));
    assert!(!MicrosoftDemangler::can_demangle(""));
    assert!(!MicrosoftDemangler::can_demangle("plain"));
}

#[test]
fn test_ms_demangler_64bit_architecture() {
    let d = MicrosoftDemangler::with_architecture(64);
    let result = d.demangle("?foo@@YAXXZ").unwrap();
    assert!(result.is_function);
}

#[test]
fn test_ms_demangler_error_on_remaining() {
    let mut d = MicrosoftDemangler::new();
    d.set_error_on_remaining(true);
    let result = d.demangle("?foo@@YAXXZEXTRA");
    assert!(matches!(result, Err(DemangleError::RemainingChars(_))));
}

#[test]
fn test_ms_demangler_multiple_args() {
    let d = MicrosoftDemangler::new();
    // ?foo@@YAXHHM@Z = void __cdecl foo(int, int, float)
    let result = d.demangle("?foo@@YAXHHM@Z").unwrap();
    assert!(result.argument_types.len() >= 2);
}

#[test]
fn test_ms_demangler_reference_type() {
    let d = MicrosoftDemangler::new();
    // ?myRef@@3QAH@Z = int & myRef
    let result = d.demangle("?myRef@@3QAH@Z").unwrap();
    assert!(result.demangled_name.contains("&"));
}

#[test]
fn test_ms_demangler_struct_type() {
    let d = MicrosoftDemangler::new();
    let result = d.demangle("?myStruct@@3US@@@Z");
    assert!(result.is_ok());
}

// ============================================================================
// Character Iterator Tests
// ============================================================================

#[test]
fn test_iterator_basic() {
    let mut iter = CharacterIterator::new("?foo@@");
    assert_eq!(iter.peek(), '?');
    assert_eq!(iter.next(), '?');
    assert_eq!(iter.next(), 'f');
    assert_eq!(iter.next(), 'o');
    assert_eq!(iter.next(), 'o');
    assert_eq!(iter.next(), '@');
    assert_eq!(iter.next(), '@');
    assert!(iter.done());
}

#[test]
fn test_iterator_peek_at() {
    let iter = CharacterIterator::new("ABCD");
    assert_eq!(iter.peek_at(0), 'A');
    assert_eq!(iter.peek_at(3), 'D');
    assert_eq!(iter.peek_at(4), '\0'); // DONE
}

#[test]
fn test_iterator_starts_with() {
    let iter = CharacterIterator::new("HelloWorld");
    assert!(iter.starts_with("Hello"));
    assert!(iter.starts_with("Hell"));
    assert!(!iter.starts_with("World"));
    assert!(!iter.starts_with("Helloo"));
}

#[test]
fn test_iterator_empty() {
    let iter = CharacterIterator::new("");
    assert!(iter.done());
    assert_eq!(iter.peek(), '\0');
}

// ============================================================================
// Data Type Parser Tests
// ============================================================================

fn chars(s: &str) -> Vec<char> {
    s.chars().collect()
}

#[test]
fn test_parse_type_void() {
    let c = chars("X");
    let dt = parse_data_type(&c, &mut 0).unwrap();
    assert!(matches!(dt, DataType::Void));
}

#[test]
fn test_parse_type_int() {
    let c = chars("H");
    let dt = parse_data_type(&c, &mut 0).unwrap();
    assert!(matches!(dt, DataType::Int { sign: Sign::Signed }));
}

#[test]
fn test_parse_type_unsigned_int() {
    let c = chars("I");
    let dt = parse_data_type(&c, &mut 0).unwrap();
    assert!(matches!(dt, DataType::Int { sign: Sign::Unsigned }));
}

#[test]
fn test_parse_type_char() {
    let c = chars("C");
    let dt = parse_data_type(&c, &mut 0).unwrap();
    assert!(matches!(dt, DataType::Char { sign: Sign::SpecifiedSigned }));
}

#[test]
fn test_parse_type_float() {
    let c = chars("M");
    let dt = parse_data_type(&c, &mut 0).unwrap();
    assert!(matches!(dt, DataType::Float));
}

#[test]
fn test_parse_type_double() {
    let c = chars("N");
    let dt = parse_data_type(&c, &mut 0).unwrap();
    assert!(matches!(dt, DataType::Double));
}

#[test]
fn test_parse_type_pointer() {
    let c = chars("PH");
    let dt = parse_data_type(&c, &mut 0).unwrap();
    assert!(matches!(dt, DataType::Pointer { .. }));
    if let DataType::Pointer { pointed_to, .. } = dt {
        assert!(matches!(*pointed_to, DataType::Int { sign: Sign::Signed }));
    }
}

#[test]
fn test_parse_type_reference() {
    let c = chars("QH");
    let dt = parse_data_type(&c, &mut 0).unwrap();
    assert!(matches!(dt, DataType::Reference { .. }));
}

#[test]
fn test_parse_type_rvalue_ref() {
    let c = chars("RH");
    let dt = parse_data_type(&c, &mut 0).unwrap();
    assert!(matches!(dt, DataType::RightReference { .. }));
}

#[test]
fn test_parse_type_int64() {
    let c = chars("_J");
    let dt = parse_data_type(&c, &mut 0).unwrap();
    assert!(matches!(dt, DataType::Int64 { sign: Sign::Signed }));
}

#[test]
fn test_parse_type_unsigned_int64() {
    let c = chars("_K");
    let dt = parse_data_type(&c, &mut 0).unwrap();
    assert!(matches!(dt, DataType::Int64 { sign: Sign::Unsigned }));
}

#[test]
fn test_parse_type_wchar_t() {
    let c = chars("_W");
    let dt = parse_data_type(&c, &mut 0).unwrap();
    assert!(matches!(dt, DataType::WChar));
}

#[test]
fn test_parse_type_bool() {
    let c = chars("_Z");
    let dt = parse_data_type(&c, &mut 0).unwrap();
    assert!(matches!(dt, DataType::Bool));
}

#[test]
fn test_parse_type_varargs() {
    let c = chars("Z");
    let dt = parse_data_type(&c, &mut 0).unwrap();
    assert!(matches!(dt, DataType::VarArgs));
}

#[test]
fn test_parse_type_pointer_to_pointer() {
    let c = chars("PPH");
    let dt = parse_data_type(&c, &mut 0).unwrap();
    if let DataType::Pointer { pointed_to, .. } = dt {
        assert!(matches!(*pointed_to, DataType::Pointer { .. }));
    } else {
        panic!("Expected pointer");
    }
}

#[test]
fn test_type_display() {
    assert_eq!(DataType::Void.to_string(), "void");
    assert_eq!(DataType::Bool.to_string(), "bool");
    assert_eq!(
        DataType::Int {
            sign: Sign::Unsigned
        }
        .to_string(),
        "unsigned int"
    );
    assert_eq!(
        DataType::Char {
            sign: Sign::Signed
        }
        .to_string(),
        "char"
    );
    assert_eq!(
        DataType::Int64 {
            sign: Sign::Signed
        }
        .to_string(),
        "__int64"
    );
}

#[test]
fn test_pointer_display() {
    let ptr = DataType::Pointer {
        pointed_to: Box::new(DataType::Float),
        cv_mod: None,
    };
    assert_eq!(ptr.to_string(), "float *");
}

#[test]
fn test_reference_display() {
    let r = DataType::Reference {
        pointed_to: Box::new(DataType::Int {
            sign: Sign::Signed,
        }),
        cv_mod: None,
    };
    assert_eq!(r.to_string(), "int &");
}

// ============================================================================
// Special Name Tests
// ============================================================================

#[test]
fn test_special_name_new_operator() {
    let sn = SpecialName::from_code('2').unwrap();
    assert_eq!(sn.name, "new");
}

#[test]
fn test_special_name_delete_operator() {
    let sn = SpecialName::from_code('3').unwrap();
    assert_eq!(sn.name, "delete");
}

#[test]
fn test_special_name_assignment_operator() {
    let sn = SpecialName::from_code('4').unwrap();
    assert_eq!(sn.name, "operator=");
}

#[test]
fn test_special_name_function_call_operator() {
    let sn = SpecialName::from_code('R').unwrap();
    assert_eq!(sn.name, "operator()");
}

#[test]
fn test_special_name_constructor() {
    let sn = SpecialName::from_code('0').unwrap();
    assert!(sn.is_constructor);
    assert!(!sn.is_destructor);
}

#[test]
fn test_special_name_destructor() {
    let sn = SpecialName::from_code('1').unwrap();
    assert!(sn.is_destructor);
    assert!(!sn.is_constructor);
}

#[test]
fn test_special_name_type_cast() {
    let sn = SpecialName::from_code('B').unwrap();
    assert!(sn.is_type_cast);
}

#[test]
fn test_special_name_underscore_vcall() {
    let sn = SpecialName::from_underscore_code('E').unwrap();
    assert_eq!(sn.name, "`vcall'");
}

#[test]
fn test_special_name_underscore_local_static_guard() {
    let sn = SpecialName::from_underscore_code('G').unwrap();
    assert_eq!(sn.name, "`local static guard'");
}

#[test]
fn test_special_name_rtti_type_descriptor() {
    let sn = SpecialName::from_rtti_code('0').unwrap();
    assert_eq!(sn.rtti_number, 0);
    assert_eq!(sn.name, "`RTTI Type Descriptor'");
}

#[test]
fn test_special_name_rtti_complete_object_locator() {
    let sn = SpecialName::from_rtti_code('4').unwrap();
    assert_eq!(sn.rtti_number, 4);
}

// ============================================================================
// Fragment Name Tests
// ============================================================================

#[test]
fn test_fragment_name_simple() {
    let c = chars("hello@");
    let frag = FragmentName::parse(&c, &mut 0);
    assert_eq!(frag.name, "hello");
}

#[test]
fn test_fragment_name_with_template() {
    let c = chars("vector<int>@");
    let frag = FragmentName::parse(&c, &mut 0);
    assert_eq!(frag.name, "vector<int>");
}

#[test]
fn test_fragment_name_with_dots() {
    let c = chars("std.string_view@");
    let frag = FragmentName::parse(&c, &mut 0);
    assert_eq!(frag.name, "std.string_view");
}

#[test]
fn test_fragment_name_empty() {
    let c = chars("@");
    let frag = FragmentName::parse(&c, &mut 0);
    assert_eq!(frag.name, "");
}

// ============================================================================
// Qualification Tests
// ============================================================================

#[test]
fn test_qualification_single() {
    let c = chars("ns@@");
    let qual = Qualification::parse(&c, &mut 0);
    assert_eq!(qual.qualifiers.len(), 1);
    assert_eq!(qual.emit(), "ns");
}

#[test]
fn test_qualification_multiple() {
    let c = chars("inner@outer@@");
    let qual = Qualification::parse(&c, &mut 0);
    assert_eq!(qual.qualifiers.len(), 2);
    assert_eq!(qual.qualifiers[0].name, "inner");
    assert_eq!(qual.qualifiers[1].name, "outer");
    assert_eq!(qual.emit(), "inner::outer");
}

#[test]
fn test_qualification_empty() {
    let c = chars("@");
    let qual = Qualification::parse(&c, &mut 0);
    assert!(qual.qualifiers.is_empty());
    assert!(!qual.has_content());
}

#[test]
fn test_qualification_reversed() {
    let c = chars("inner@outer@@");
    let qual = Qualification::parse(&c, &mut 0);
    assert_eq!(qual.emit_reversed(), "outer::inner");
}

#[test]
fn test_qualification_head() {
    let c = chars("inner@outer@@");
    let qual = Qualification::parse(&c, &mut 0);
    assert_eq!(qual.head().unwrap().name, "outer");
}

// ============================================================================
// Calling Convention Tests
// ============================================================================

#[test]
fn test_calling_convention_cdecl() {
    assert_eq!(
        CallingConvention::from_char('A'),
        Some(CallingConvention::Cdecl)
    );
    assert_eq!(
        CallingConvention::from_char('B'),
        Some(CallingConvention::Cdecl)
    );
}

#[test]
fn test_calling_convention_pascal() {
    assert_eq!(
        CallingConvention::from_char('C'),
        Some(CallingConvention::Pascal)
    );
}

#[test]
fn test_calling_convention_thiscall() {
    assert_eq!(
        CallingConvention::from_char('E'),
        Some(CallingConvention::Thiscall)
    );
    assert_eq!(
        CallingConvention::from_char('F'),
        Some(CallingConvention::Thiscall)
    );
}

#[test]
fn test_calling_convention_stdcall() {
    assert_eq!(
        CallingConvention::from_char('G'),
        Some(CallingConvention::Stdcall)
    );
}

#[test]
fn test_calling_convention_fastcall() {
    assert_eq!(
        CallingConvention::from_char('I'),
        Some(CallingConvention::Fastcall)
    );
}

#[test]
fn test_calling_convention_vectorcall() {
    assert_eq!(
        CallingConvention::from_char('O'),
        Some(CallingConvention::Vectorcall)
    );
}

#[test]
fn test_calling_convention_exported() {
    assert!(!CallingConvention::is_exported('A'));
    assert!(CallingConvention::is_exported('B'));
    assert!(!CallingConvention::is_exported('C'));
    assert!(CallingConvention::is_exported('D'));
}

#[test]
fn test_calling_convention_display() {
    assert_eq!(CallingConvention::Cdecl.to_string(), "__cdecl");
    assert_eq!(CallingConvention::Stdcall.to_string(), "__stdcall");
    assert_eq!(CallingConvention::Fastcall.to_string(), "__fastcall");
}

#[test]
fn test_calling_convention_unknown() {
    assert_eq!(CallingConvention::from_char('Z'), None);
}

// ============================================================================
// CVMod Tests
// ============================================================================

#[test]
fn test_cvmod_const() {
    let cv = CVMod::new_const();
    assert!(cv.has_const());
    assert!(!cv.has_volatile());
    assert!(cv.has_qualifier());
}

#[test]
fn test_cvmod_volatile() {
    let cv = CVMod::new_volatile();
    assert!(!cv.has_const());
    assert!(cv.has_volatile());
}

#[test]
fn test_cvmod_const_volatile() {
    let cv = CVMod::new_const_volatile();
    assert!(cv.has_const());
    assert!(cv.has_volatile());
}

#[test]
fn test_cvmod_display() {
    assert_eq!(CVMod::new_const().to_string(), "const");
    assert_eq!(CVMod::new_volatile().to_string(), "volatile");
}

// ============================================================================
// TypeInfo Tests
// ============================================================================

#[test]
fn test_typeinfo_parse_private_function() {
    let c = chars("A");
    let info = TypeInfo::parse(&c, &mut 0).unwrap();
    assert!(info.is_function);
    assert_eq!(
        info.access_level,
        ghidra_features::demangler::microsoft::typeinfo::AccessLevel::PrivateNonStatic
    );
}

#[test]
fn test_typeinfo_parse_public_static_function() {
    let c = chars("F");
    let info = TypeInfo::parse(&c, &mut 0).unwrap();
    assert!(info.is_function);
    assert!(info.is_static);
}

#[test]
fn test_typeinfo_parse_global_function() {
    let c = chars("Y");
    let info = TypeInfo::parse(&c, &mut 0).unwrap();
    assert!(info.is_function);
    assert!(info.is_static);
}

#[test]
fn test_typeinfo_emit_prefix() {
    let mut info = TypeInfo::new();
    info.access_level = ghidra_features::demangler::microsoft::typeinfo::AccessLevel::PublicNonStatic;
    info.is_virtual = true;
    let prefix = info.emit_prefix();
    assert!(prefix.contains("virtual"));
    assert!(prefix.contains("public"));
}

// ============================================================================
// GNU Demangler Tests
// ============================================================================

use ghidra_features::demangler::gnu::GnuDemangler;

#[test]
fn test_gnu_can_demangle_gcc_v3() {
    let d = GnuDemangler::new();
    assert!(d.can_demangle("_Z3foov"));
    assert!(d.can_demangle("_ZN3Foo3barEv"));
}

#[test]
fn test_gnu_can_demangle_dwarf_ref() {
    let d = GnuDemangler::new();
    assert!(d.can_demangle("DW.ref.__gxx_personality_v0"));
}

#[test]
fn test_gnu_can_demangle_global() {
    let d = GnuDemangler::new();
    assert!(d.can_demangle("_GLOBAL__I_main"));
}

#[test]
fn test_gnu_cannot_demangle_plain() {
    let d = GnuDemangler::new();
    assert!(!d.can_demangle("plain_symbol"));
    assert!(!d.can_demangle(""));
}

#[test]
fn test_gnu_should_skip_versioned() {
    let d = GnuDemangler::new();
    assert!(d.should_skip("foo@@GLIBC_2.5"));
    assert!(d.should_skip("___something"));
    assert!(!d.should_skip("_Z3foov"));
}

#[test]
fn test_gnu_detect_format() {
    use ghidra_features::demangler::gnu::GnuDemanglerFormat;
    assert_eq!(
        GnuDemangler::detect_format("_Z3foov"),
        GnuDemanglerFormat::GnuV3
    );
    assert_eq!(
        GnuDemangler::detect_format("__R12func"),
        GnuDemanglerFormat::Rust
    );
    assert_eq!(
        GnuDemangler::detect_format("12funcv"),
        GnuDemanglerFormat::GnuV2
    );
    assert_eq!(
        GnuDemangler::detect_format("plain"),
        GnuDemanglerFormat::Unknown
    );
}

#[test]
fn test_gnu_parse_demangled_simple() {
    let d = GnuDemangler::new();
    let sym = d.parse_demangled("_Z3foov", "foo()");
    assert_eq!(sym.base_name, "foo()");
    assert_eq!(sym.mangled, "_Z3foov");
}

#[test]
fn test_gnu_parse_demangled_destructor() {
    let d = GnuDemangler::new();
    let sym = d.parse_demangled("_ZN3FooD1Ev", "Foo::~Foo()");
    assert!(sym.is_destructor);
}

#[test]
fn test_gnu_parse_demangled_constructor() {
    let d = GnuDemangler::new();
    let sym = d.parse_demangled("_ZN3FooC1Ev", "Foo::Foo()");
    assert!(sym.is_constructor);
}

// ============================================================================
// DemangleError Tests
// ============================================================================

#[test]
fn test_demangle_error_display() {
    let err = DemangleError::EmptySymbol;
    assert!(err.to_string().contains("empty"));

    let err = DemangleError::ParseError {
        position: 42,
        message: "bad code".to_string(),
    };
    assert!(err.to_string().contains("42"));
    assert!(err.to_string().contains("bad code"));

    let err = DemangleError::RemainingChars(5);
    assert!(err.to_string().contains("5"));
}

// ============================================================================
// DataType Display Tests
// ============================================================================

#[test]
fn test_data_type_display_void() {
    assert_eq!(DataType::Void.to_string(), "void");
}

#[test]
fn test_data_type_display_signed_char() {
    assert_eq!(
        DataType::Char {
            sign: Sign::SpecifiedSigned
        }
        .to_string(),
        "signed char"
    );
}

#[test]
fn test_data_type_display_unsigned_char() {
    assert_eq!(
        DataType::Char {
            sign: Sign::Unsigned
        }
        .to_string(),
        "unsigned char"
    );
}

#[test]
fn test_data_type_display_int64() {
    assert_eq!(
        DataType::Int64 {
            sign: Sign::Signed
        }
        .to_string(),
        "__int64"
    );
}

#[test]
fn test_data_type_display_unsigned_long() {
    assert_eq!(
        DataType::Long {
            sign: Sign::Unsigned
        }
        .to_string(),
        "unsigned long"
    );
}

#[test]
fn test_data_type_display_array() {
    let arr = DataType::Array {
        element_type: Box::new(DataType::Int {
            sign: Sign::Signed,
        }),
        dimensions: vec![10],
    };
    assert_eq!(arr.to_string(), "int[10]");
}

#[test]
fn test_data_type_display_nullptr() {
    assert_eq!(DataType::NullPtr.to_string(), "std::nullptr_t");
}
