//! Const/Volatile and other type modifiers for Microsoft demangling.
//!
//! Ported from `mdemangler.datatype.modifier.MDCVMod` and related Java classes.

use std::fmt;

// ---------------------------------------------------------------------------
// CVMod
// ---------------------------------------------------------------------------

/// Const/Volatile modifier state for a type.
///
/// Corresponds to Java's `MDCVMod`.
#[derive(Debug, Clone, Default)]
pub struct CVMod {
    /// The type is `const`.
    pub is_const: bool,
    /// The type is `volatile`.
    pub is_volatile: bool,
    /// The pointer is `__ptr64`.
    pub is_pointer64: bool,
    /// The pointer is `__unaligned`.
    pub is_unaligned: bool,
    /// The pointer is `__restrict`.
    pub is_restricted: bool,
    /// The type is a left reference (`&`).
    pub is_lref: bool,
    /// The type is a right reference (`&&`).
    pub is_rref: bool,
    /// The type is a pointer.
    pub is_pointer: bool,
    /// The type is a reference.
    pub is_reference: bool,
    /// The type is a function pointer.
    pub is_function: bool,
    /// The type is a member of a class.
    pub is_member: bool,
    /// The type is a based pointer.
    pub is_based: bool,
    /// Managed properties (CLI/.NET).
    pub managed_properties: Option<ManagedProperties>,
}

/// Managed (CLI/.NET) properties attached to a type.
#[derive(Debug, Clone)]
pub struct ManagedProperties {
    /// GC tracking handle (`^`).
    pub is_gc: bool,
    /// Pin pointer (`%`).
    pub is_pin_pointer: bool,
    /// CLI array (`cli::array<>`).
    pub is_cli_array: bool,
    /// CLI property.
    pub is_cli_property: bool,
    /// Array rank (for CLI arrays).
    pub array_rank: usize,
}

impl CVMod {
    /// Create a new `const` modifier.
    pub fn new_const() -> Self {
        Self {
            is_const: true,
            ..Default::default()
        }
    }

    /// Create a new `volatile` modifier.
    pub fn new_volatile() -> Self {
        Self {
            is_volatile: true,
            ..Default::default()
        }
    }

    /// Create a new `const volatile` modifier.
    pub fn new_const_volatile() -> Self {
        Self {
            is_const: true,
            is_volatile: true,
            ..Default::default()
        }
    }

    /// Parse a CV modifier code from a single character.
    ///
    /// The codes follow the MSVC convention where:
    /// - `A` = near function, no CV
    /// - `B` = near function, const
    /// - `C` = near function, volatile
    /// - `D` = near function, const volatile
    /// - `E` = far function (or `__ptr64` prefix)
    /// - `F` = far function, const (or `__unaligned` prefix)
    /// - `G` = far function, volatile
    /// - `H` = far function, const volatile
    /// - `I` = near member, no CV (or `__restricted` prefix)
    /// - `J` = near member, const
    /// - `K` = near member, volatile
    /// - `L` = near member, const volatile
    /// - `M` = near data, no CV
    /// - `N` = near data, const
    /// - `O` = near data, volatile
    /// - `P` = near data, const volatile
    /// - `Q` = far member, no CV
    /// - `R` = far member, const
    /// - `S` = far member, volatile
    /// - `T` = far member, const volatile
    /// - `U` = far data, no CV
    /// - `V` = far data, const
    /// - `W` = far data, volatile
    /// - `X` = far data, const volatile
    pub fn from_cv_code(code: char) -> Option<Self> {
        match code {
            'A' | 'C' | 'E' | 'G' | 'I' | 'K' | 'M' | 'O' | 'Q' | 'S' | 'U' | 'W' => {
                // These are "no const, no volatile" patterns (some near/some far)
                Some(Self::default())
            }
            'B' | 'J' | 'N' | 'R' | 'V' => Some(Self::new_const()),
            'D' | 'L' | 'P' | 'T' | 'X' => Some(Self::new_volatile()),
            'F' | 'H' => Some(Self::new_const_volatile()),
            _ => None,
        }
    }

    /// Parse a member-function CV modifier (the `this` pointer qualifier).
    pub fn from_this_pointer_code(code: char) -> Option<Self> {
        match code {
            'A' => Some(Self::default()),
            'B' => Some(Self::new_const()),
            'C' => Some(Self::new_volatile()),
            'D' => Some(Self::new_const_volatile()),
            _ => None,
        }
    }

    /// Append const/volatile qualifiers to a type string.
    pub fn emit_qualified(&self, s: &mut String) {
        if self.is_const {
            s.push_str(" const");
        }
        if self.is_volatile {
            s.push_str(" volatile");
        }
        if self.is_pointer64 {
            s.push_str(" __ptr64");
        }
        if self.is_unaligned {
            s.push_str(" __unaligned");
        }
        if self.is_restricted {
            s.push_str(" __restrict");
        }
    }

    /// Returns true if any qualifier is set.
    pub fn has_qualifier(&self) -> bool {
        self.is_const || self.is_volatile || self.is_pointer64 || self.is_unaligned || self.is_restricted
    }

    /// Returns true if the type has const qualification.
    pub fn has_const(&self) -> bool {
        self.is_const
    }

    /// Returns true if the type has volatile qualification.
    pub fn has_volatile(&self) -> bool {
        self.is_volatile
    }

    /// Returns true if this is a reference (lvalue or rvalue).
    pub fn has_reference(&self) -> bool {
        self.is_lref || self.is_rref
    }
}

impl fmt::Display for CVMod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut parts = Vec::new();
        if self.is_const {
            parts.push("const");
        }
        if self.is_volatile {
            parts.push("volatile");
        }
        if self.is_pointer64 {
            parts.push("__ptr64");
        }
        if self.is_unaligned {
            parts.push("__unaligned");
        }
        if self.is_restricted {
            parts.push("__restrict");
        }
        if self.is_lref {
            parts.push("&");
        }
        if self.is_rref {
            parts.push("&&");
        }
        write!(f, "{}", parts.join(" "))
    }
}

// ---------------------------------------------------------------------------
// EFI prefixes (Pointer64, Unaligned, Restricted)
// ---------------------------------------------------------------------------

/// An EFI prefix modifier (ptr64, unaligned, restricted).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CvPrefix {
    /// `__ptr64`
    Ptr64,
    /// `__unaligned`
    Unaligned,
    /// `__restrict`
    Restrict,
}

impl CvPrefix {
    /// Parse an EFI prefix code character.
    pub fn from_char(ch: char) -> Option<Self> {
        match ch {
            'E' => Some(CvPrefix::Ptr64),
            'F' => Some(CvPrefix::Unaligned),
            'I' => Some(CvPrefix::Restrict),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Pointer format for modified types
// ---------------------------------------------------------------------------

/// The format of a pointer/reference in the type modifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PointerFormat {
    /// Plain pointer (`*`)
    Pointer,
    /// Reference (`&`)
    Reference,
    /// Right reference (`&&`)
    RightReference,
    /// Caret / GC handle (`^`)
    Caret,
    /// Percent / pin pointer (`%`)
    Percent,
    /// Array
    Array,
}

// ---------------------------------------------------------------------------
// CV modifier codes for the type modifier system
// ---------------------------------------------------------------------------

/// Codes A-P from the modified type parser.
///
/// These map the single-character codes that determine the combined
/// near/far, pointer/reference, member/data, and CV modifiers.
pub fn parse_cv_modifier_type(code: char) -> Result<(PointerFormat, bool, bool, bool), String> {
    // Returns (format, is_near, is_function, is_member)
    match code {
        'A' => Ok((PointerFormat::Pointer, true, true, false)), // near function pointer
        'B' => Ok((PointerFormat::Pointer, true, true, true)),  // near member function pointer
        'C' => Ok((PointerFormat::Pointer, true, false, false)), // near data pointer
        'D' => Ok((PointerFormat::Pointer, true, false, true)),  // near member data pointer
        'E' => Ok((PointerFormat::Reference, true, true, false)),
        'F' => Ok((PointerFormat::Reference, true, true, true)),
        'G' => Ok((PointerFormat::Reference, true, false, false)),
        'H' => Ok((PointerFormat::Reference, true, false, true)),
        'I' => Ok((PointerFormat::RightReference, true, true, false)),
        'J' => Ok((PointerFormat::RightReference, true, true, true)),
        'K' => Ok((PointerFormat::RightReference, true, false, false)),
        'L' => Ok((PointerFormat::RightReference, true, false, true)),
        'M' => Ok((PointerFormat::Pointer, false, true, false)), // far function pointer
        'N' => Ok((PointerFormat::Pointer, false, true, true)),  // far member function pointer
        'O' => Ok((PointerFormat::Pointer, false, false, false)), // far data pointer
        'P' => Ok((PointerFormat::Pointer, false, false, true)), // far member data pointer
        _ => Err(format!("Unknown CV modifier type code: {}", code)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cvmod_const() {
        let cv = CVMod::new_const();
        assert!(cv.is_const);
        assert!(!cv.is_volatile);
        assert_eq!(cv.to_string(), "const");
    }

    #[test]
    fn test_cvmod_emit() {
        let mut s = String::from("int *");
        let cv = CVMod::new_const();
        cv.emit_qualified(&mut s);
        assert_eq!(s, "int * const");
    }

    #[test]
    fn test_cvmod_has_qualifier() {
        let cv = CVMod::default();
        assert!(!cv.has_qualifier());

        let cv = CVMod::new_const();
        assert!(cv.has_qualifier());
    }

    #[test]
    fn test_parse_cv_modifier_type() {
        let (fmt, near, func, member) = parse_cv_modifier_type('A').unwrap();
        assert_eq!(fmt, PointerFormat::Pointer);
        assert!(near);
        assert!(func);
        assert!(!member);

        let (fmt, near, _, member) = parse_cv_modifier_type('P').unwrap();
        assert_eq!(fmt, PointerFormat::Pointer);
        assert!(!near);
        assert!(member);
    }

    #[test]
    fn test_cv_prefix() {
        assert_eq!(CvPrefix::from_char('E'), Some(CvPrefix::Ptr64));
        assert_eq!(CvPrefix::from_char('F'), Some(CvPrefix::Unaligned));
        assert_eq!(CvPrefix::from_char('I'), Some(CvPrefix::Restrict));
        assert_eq!(CvPrefix::from_char('X'), None);
    }
}
