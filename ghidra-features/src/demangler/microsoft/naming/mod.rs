//! Naming components for Microsoft demangling.
//!
//! Ported from `mdemangler.naming.*` Java classes.
//!
//! The naming hierarchy:
//! - `SpecialName` -- C++ operator names, constructors, destructors, RTTI, etc.
//! - `FragmentName` -- A single name fragment (letters/digits/underscores)
//! - `ReusableName` -- A name that can be referenced via back-references
//! - `Qualifier` -- A single namespace qualifier
//! - `Qualification` -- A list of qualifiers forming a namespace path
//! - `BasicName` -- The "basic" part of a name (special name or regular name)
//! - `QualifiedBasicName` -- A basic name with qualification
//! - `QualifiedName` -- A fully qualified name (for standalone types)
//! - `NestedName` -- A nested/embedded name (delimited by backticks)
//! - `NameModifier` -- A name modifier suffix (e.g., `$1` for adjustor thunks)


// ---------------------------------------------------------------------------
// SpecialName
// ---------------------------------------------------------------------------

/// Special names encode C++ operators, constructors, destructors, RTTI, etc.
///
/// Ported from `MDSpecialName.java`. The first character after `?` determines
/// the special name type.
#[derive(Debug, Clone)]
pub struct SpecialName {
    /// The display name of the special name.
    pub name: String,
    /// Whether this is a constructor.
    pub is_constructor: bool,
    /// Whether this is a destructor.
    pub is_destructor: bool,
    /// Whether this is a type-cast operator.
    pub is_type_cast: bool,
    /// Whether this is a qualified name.
    pub is_qualified: bool,
    /// RTTI number (0-4, or -1 if not RTTI).
    pub rtti_number: i32,
    /// The cast-to type string (for type-cast operators).
    pub cast_type_string: Option<String>,
    /// The qualifier for constructors/destructors.
    pub xtor_qual: Option<Qualifier>,
    /// An embedded string (for `?C` special names).
    pub embedded_string: Option<String>,
}

impl SpecialName {
    /// Create a new special name.
    pub fn new() -> Self {
        Self {
            name: String::new(),
            is_constructor: false,
            is_destructor: false,
            is_type_cast: false,
            is_qualified: false,
            rtti_number: -1,
            cast_type_string: None,
            xtor_qual: None,
            embedded_string: None,
        }
    }

    /// Parse a special name from the character following `?`.
    ///
    /// Returns a `SpecialName` with the appropriate fields set based on the
    /// character code.
    pub fn from_code(ch: char) -> Option<Self> {
        let mut sn = Self::new();
        match ch {
            '0' => {
                sn.name = "??0".to_string(); // constructor
                sn.is_constructor = true;
            }
            '1' => {
                sn.name = "??1".to_string(); // destructor
                sn.is_destructor = true;
            }
            '2' => {
                sn.name = "new".to_string();
            }
            '3' => {
                sn.name = "delete".to_string();
            }
            '4' => {
                sn.name = "operator=".to_string();
            }
            '5' => {
                sn.name = "operator>>".to_string();
            }
            '6' => {
                sn.name = "operator<<".to_string();
            }
            '7' => {
                sn.name = "operator!".to_string();
            }
            '8' => {
                sn.name = "operator==".to_string();
            }
            '9' => {
                sn.name = "operator!=".to_string();
            }
            'A' => {
                sn.name = "operator[]".to_string();
            }
            'B' => {
                sn.name = "operator".to_string(); // type-cast
                sn.is_type_cast = true;
            }
            'C' => {
                sn.name = "operator->".to_string();
            }
            'D' => {
                sn.name = "operator*".to_string();
            }
            'E' => {
                sn.name = "operator++".to_string();
            }
            'F' => {
                sn.name = "operator--".to_string();
            }
            'G' => {
                sn.name = "operator-".to_string();
            }
            'H' => {
                sn.name = "operator+".to_string();
            }
            'I' => {
                sn.name = "operator&".to_string();
            }
            'J' => {
                sn.name = "operator->*".to_string();
            }
            'K' => {
                sn.name = "operator/".to_string();
            }
            'L' => {
                sn.name = "operator%".to_string();
            }
            'M' => {
                sn.name = "operator<".to_string();
            }
            'N' => {
                sn.name = "operator<=".to_string();
            }
            'O' => {
                sn.name = "operator>".to_string();
            }
            'P' => {
                sn.name = "operator>=".to_string();
            }
            'Q' => {
                sn.name = "operator,".to_string();
            }
            'R' => {
                sn.name = "operator()".to_string();
            }
            'S' => {
                sn.name = "operator~".to_string();
            }
            'T' => {
                sn.name = "operator^".to_string();
            }
            'U' => {
                sn.name = "operator|".to_string();
            }
            'V' => {
                sn.name = "operator&&".to_string();
            }
            'W' => {
                sn.name = "operator||".to_string();
            }
            'X' => {
                sn.name = "operator*=".to_string();
            }
            'Y' => {
                sn.name = "operator+=".to_string();
            }
            'Z' => {
                sn.name = "operator-=".to_string();
            }
            _ => return None,
        }
        Some(sn)
    }

    /// Parse the `_` prefixed special names (constructors/destructors,
    /// vcall, RTTI, etc.).
    ///
    /// This corresponds to the second character after `?_` in the mangled name.
    pub fn from_underscore_code(ch: char) -> Option<Self> {
        let mut sn = Self::new();
        match ch {
            '0' => {
                sn.is_constructor = true;
                sn.name = String::new(); // constructor; name comes from context
            }
            '1' => {
                sn.is_destructor = true;
                sn.name = String::new(); // destructor; name comes from context
            }
            '2' => {
                sn.name = "new".to_string();
            }
            '3' => {
                sn.name = "delete".to_string();
            }
            '4' => {
                sn.name = "operator=".to_string();
            }
            '5' => {
                sn.name = "operator>>".to_string();
            }
            '6' => {
                sn.name = "operator<<".to_string();
            }
            '7' => {
                sn.name = "operator!".to_string();
            }
            '8' => {
                sn.name = "operator==".to_string();
            }
            '9' => {
                sn.name = "operator!=".to_string();
            }
            'A' => {
                sn.name = "operator[]".to_string();
            }
            'B' => {
                sn.name = "operator".to_string();
                sn.is_type_cast = true;
            }
            'C' => {
                sn.name = "operator->".to_string();
            }
            'D' => {
                sn.name = "operator*".to_string();
            }
            'E' => {
                sn.name = "`vcall'".to_string();
            }
            'F' => {
                sn.name = "`typeof'".to_string();
            }
            'G' => {
                sn.name = "`local static guard'".to_string();
            }
            'H' => {
                // string literal
                sn.name = String::new();
            }
            'I' => {
                sn.name = "`vbase destructor'".to_string();
            }
            'J' => {
                sn.name = "`vector deleting destructor'".to_string();
            }
            'K' => {
                sn.name = "`default constructor closure'".to_string();
            }
            'L' => {
                sn.name = "`scalar deleting destructor'".to_string();
            }
            'M' => {
                sn.name = "`vector constructor iterator'".to_string();
            }
            'N' => {
                sn.name = "`vector destructor iterator'".to_string();
            }
            'O' => {
                sn.name = "`vector vbase constructor iterator'".to_string();
            }
            'P' => {
                sn.name = "`virtual displacement map'".to_string();
            }
            'Q' => {
                sn.name = "`eh vector constructor iterator'".to_string();
            }
            'R' => {
                sn.name = "`eh vector destructor iterator'".to_string();
            }
            'S' => {
                sn.name = "`eh vector vbase constructor iterator'".to_string();
            }
            'T' => {
                sn.name = "`copy constructor closure'".to_string();
            }
            'U' => {
                sn.name = "`udt returning'".to_string();
            }
            'V' => {
                sn.name = "`EH'".to_string();
            }
            // R0-R4 are RTTI names
            _ => return None,
        }
        Some(sn)
    }

    /// Parse RTTI special names (`_R0` through `_R4`).
    pub fn from_rtti_code(ch: char) -> Option<Self> {
        let mut sn = Self::new();
        sn.is_qualified = false;
        match ch {
            '0' => {
                sn.rtti_number = 0;
                sn.name = "`RTTI Type Descriptor'".to_string();
            }
            '1' => {
                sn.rtti_number = 1;
                sn.name = "`RTTI Base Class Descriptor'".to_string();
            }
            '2' => {
                sn.rtti_number = 2;
                sn.name = "`RTTI Base Class Array'".to_string();
            }
            '3' => {
                sn.rtti_number = 3;
                sn.name = "`RTTI Class Hierarchy Descriptor'".to_string();
            }
            '4' => {
                sn.rtti_number = 4;
                sn.name = "`RTTI Complete Object Locator'".to_string();
            }
            _ => return None,
        }
        Some(sn)
    }

    /// Emit the special name, taking into account constructors/destructors
    /// and cast types.
    pub fn emit(&self) -> String {
        if self.is_constructor || self.is_destructor {
            // Name is set from the qualifier context
            let prefix = if self.is_destructor { "~" } else { "" };
            let name = if self.name.is_empty() {
                // Use xtor_qual's name if available
                self.xtor_qual
                    .as_ref()
                    .map(|q| q.name.clone())
                    .unwrap_or_default()
            } else {
                self.name.clone()
            };
            format!("{}{}", prefix, name)
        } else if self.is_type_cast {
            if let Some(ref cast_type) = self.cast_type_string {
                format!("operator {}", cast_type)
            } else {
                "operator".to_string()
            }
        } else {
            self.name.clone()
        }
    }
}

impl Default for SpecialName {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// FragmentName
// ---------------------------------------------------------------------------

/// A name fragment (letters, digits, underscores, `$`, `<`, `>`, `-`, `.`).
///
/// Ported from `MDFragmentName.java`.
#[derive(Debug, Clone)]
pub struct FragmentName {
    /// The fragment text.
    pub name: String,
}

impl FragmentName {
    pub fn new() -> Self {
        Self {
            name: String::new(),
        }
    }

    /// Parse a fragment name from the iterator.
    ///
    /// A fragment consists of alphanumeric characters, underscores, dollar signs,
    /// angle brackets, dashes, and dots. Parsing stops at `@`, `?`, or DONE.
    pub fn parse(chars: &[char], index: &mut usize) -> Self {
        let mut name = String::new();
        while *index < chars.len() {
            let ch = chars[*index];
            if ch.is_alphanumeric()
                || ch == '_'
                || ch == '$'
                || ch == '<'
                || ch == '>'
                || ch == '-'
                || ch == '.'
            {
                name.push(ch);
                *index += 1;
            } else {
                break;
            }
        }
        // Skip trailing '@' terminator
        if *index < chars.len() && chars[*index] == '@' {
            *index += 1;
        }
        Self { name }
    }
}

impl Default for FragmentName {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// ReusableName
// ---------------------------------------------------------------------------

/// A reusable name that can be back-referenced in the mangled symbol.
///
/// Ported from `MDReusableName.java`.
#[derive(Debug, Clone)]
pub struct ReusableName {
    /// The name text.
    pub name: String,
}

impl ReusableName {
    pub fn new(name: String) -> Self {
        Self { name }
    }

    /// Parse a reusable name from the iterator.
    ///
    /// A reusable name is either a numeric back-reference (`0`-`9`) or a
    /// fragment name.
    pub fn parse(chars: &[char], index: &mut usize) -> Self {
        if *index < chars.len() && chars[*index].is_ascii_digit() {
            // Back-reference: digit encodes the index
            let digit = (chars[*index] as u8).wrapping_sub(b'0');
            *index += 1;
            Self {
                name: format!("$B{}", digit),
            }
        } else {
            let fragment = FragmentName::parse(chars, index);
            Self { name: fragment.name }
        }
    }
}

// ---------------------------------------------------------------------------
// Qualifier
// ---------------------------------------------------------------------------

/// A single namespace qualifier component.
///
/// Ported from `MDQualifier.java`.
#[derive(Debug, Clone)]
pub struct Qualifier {
    /// The qualifier name.
    pub name: String,
    /// Whether this qualifier represents an anonymous namespace.
    pub is_anonymous: bool,
    /// Whether this is a numbered namespace (e.g., `?0`, `?1`).
    pub is_numbered: bool,
    /// The number for numbered namespaces.
    pub number: u32,
}

impl Qualifier {
    pub fn new(name: String) -> Self {
        Self {
            name,
            is_anonymous: false,
            is_numbered: false,
            number: 0,
        }
    }

    /// Create an anonymous namespace qualifier.
    pub fn anonymous() -> Self {
        Self {
            name: "`anonymous namespace'".to_string(),
            is_anonymous: true,
            is_numbered: false,
            number: 0,
        }
    }

    /// Create a numbered namespace qualifier.
    pub fn numbered(n: u32) -> Self {
        Self {
            name: format!("`{}'", n),
            is_anonymous: false,
            is_numbered: true,
            number: n,
        }
    }
}

// ---------------------------------------------------------------------------
// Qualification
// ---------------------------------------------------------------------------

/// A namespace qualification (list of qualifiers terminated by `@`).
///
/// Ported from `MDQualification.java`.
#[derive(Debug, Clone)]
pub struct Qualification {
    /// The qualifier components, innermost to outermost.
    pub qualifiers: Vec<Qualifier>,
}

impl Qualification {
    pub fn new() -> Self {
        Self {
            qualifiers: Vec::new(),
        }
    }

    /// Returns true if the qualification has content.
    pub fn has_content(&self) -> bool {
        !self.qualifiers.is_empty()
    }

    /// Parse a qualification from the character stream.
    ///
    /// Qualifiers are `@`-terminated fragments. The final `@` terminates
    /// the entire qualification.
    pub fn parse(chars: &[char], index: &mut usize) -> Self {
        let mut quals = Vec::new();
        while *index < chars.len() {
            let ch = chars[*index];
            if ch == '@' {
                *index += 1;
                break;
            }
            if ch == '?' && (*index + 1) < chars.len() {
                let next = chars[*index + 1];
                match next {
                    'A'..='D' => {
                        // Anonymous namespace markers
                        *index += 2;
                        quals.push(Qualifier::anonymous());
                        continue;
                    }
                    '0'..='9' => {
                        // Numbered namespace
                        let n = (next as u8 - b'0') as u32;
                        *index += 2;
                        quals.push(Qualifier::numbered(n));
                        continue;
                    }
                    _ => {}
                }
            }
            // Regular name fragment
            let fragment = FragmentName::parse(chars, index);
            if !fragment.name.is_empty() {
                quals.push(Qualifier::new(fragment.name));
            }
        }
        Self { qualifiers: quals }
    }

    /// Emit the qualification as `::`-separated names.
    pub fn emit(&self) -> String {
        self.qualifiers
            .iter()
            .map(|q| q.name.as_str())
            .collect::<Vec<_>>()
            .join("::")
    }

    /// Emit in reversed order (outermost first).
    pub fn emit_reversed(&self) -> String {
        self.qualifiers
            .iter()
            .rev()
            .map(|q| q.name.as_str())
            .collect::<Vec<_>>()
            .join("::")
    }

    /// Get the head (outermost / last) qualifier.
    pub fn head(&self) -> Option<&Qualifier> {
        self.qualifiers.last()
    }
}

impl Default for Qualification {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// BasicName
// ---------------------------------------------------------------------------

/// The "basic" part of a qualified name.
///
/// Ported from `MDBasicName.java`. Can be a special name, a template name,
/// a reusable name, or an embedded object.
#[derive(Debug, Clone)]
pub enum BasicNameKind {
    /// A regular (reusable/fragment) name.
    Regular(FragmentName),
    /// A special name (operator, constructor, destructor, etc.).
    Special(SpecialName),
    /// A template name with arguments.
    Template {
        /// The template name.
        name: String,
        /// The template arguments (as strings).
        args: Vec<String>,
    },
    /// An embedded object (for nested names).
    Embedded {
        /// The mangled string of the embedded object.
        mangled: String,
        /// The demangled name.
        demangled: String,
    },
}

/// A basic name component.
#[derive(Debug, Clone)]
pub struct BasicName {
    /// The kind of basic name.
    pub kind: BasicNameKind,
    /// An optional name modifier suffix (e.g., `$1` for adjustor thunks).
    pub name_modifier: Option<NameModifier>,
    /// Cast type string (for type-cast operators).
    pub cast_type_string: Option<String>,
}

impl BasicName {
    /// Create a basic name from a regular fragment.
    pub fn regular(fragment: FragmentName) -> Self {
        Self {
            kind: BasicNameKind::Regular(fragment),
            name_modifier: None,
            cast_type_string: None,
        }
    }

    /// Create a basic name from a special name.
    pub fn special(special: SpecialName) -> Self {
        Self {
            kind: BasicNameKind::Special(special),
            name_modifier: None,
            cast_type_string: None,
        }
    }

    /// Returns true if this is a constructor.
    pub fn is_constructor(&self) -> bool {
        matches!(&self.kind, BasicNameKind::Special(s) if s.is_constructor)
    }

    /// Returns true if this is a destructor.
    pub fn is_destructor(&self) -> bool {
        matches!(&self.kind, BasicNameKind::Special(s) if s.is_destructor)
    }

    /// Returns true if this is a type-cast operator.
    pub fn is_type_cast(&self) -> bool {
        matches!(&self.kind, BasicNameKind::Special(s) if s.is_type_cast)
    }

    /// Get the RTTI number, or -1 if not an RTTI name.
    pub fn rtti_number(&self) -> i32 {
        match &self.kind {
            BasicNameKind::Special(s) => s.rtti_number,
            _ => -1,
        }
    }

    /// Get the name as a string.
    pub fn get_name(&self) -> String {
        match &self.kind {
            BasicNameKind::Regular(f) => f.name.clone(),
            BasicNameKind::Special(s) => s.emit(),
            BasicNameKind::Template { name, .. } => name.clone(),
            BasicNameKind::Embedded { demangled, .. } => demangled.clone(),
        }
    }

    /// Emit the name.
    pub fn emit(&self) -> String {
        let mut result = match &self.kind {
            BasicNameKind::Regular(f) => f.name.clone(),
            BasicNameKind::Special(s) => s.emit(),
            BasicNameKind::Template { name, args } => {
                format!("{}<{}>", name, args.join(", "))
            }
            BasicNameKind::Embedded {
                mangled: _,
                demangled,
            } => demangled.clone(),
        };
        if let Some(ref modifier) = self.name_modifier {
            result.push_str(&modifier.modifier);
        }
        result
    }
}

// ---------------------------------------------------------------------------
// QualifiedBasicName
// ---------------------------------------------------------------------------

/// A basic name with namespace qualification.
///
/// Ported from `MDQualifiedBasicName.java`.
#[derive(Debug, Clone)]
pub struct QualifiedBasicName {
    /// The basic name.
    pub basic_name: BasicName,
    /// The namespace qualification.
    pub qualification: Qualification,
}

impl QualifiedBasicName {
    pub fn new(basic_name: BasicName, qualification: Qualification) -> Self {
        Self {
            basic_name,
            qualification,
        }
    }

    /// Returns true if this is a type-cast operator.
    pub fn is_type_cast(&self) -> bool {
        self.basic_name.is_type_cast()
    }

    /// Returns true if this is a constructor.
    pub fn is_constructor(&self) -> bool {
        self.basic_name.is_constructor()
    }

    /// Returns true if this is a destructor.
    pub fn is_destructor(&self) -> bool {
        self.basic_name.is_destructor()
    }

    /// Get the RTTI number.
    pub fn rtti_number(&self) -> i32 {
        self.basic_name.rtti_number()
    }

    /// Emit the fully qualified basic name.
    pub fn emit(&self) -> String {
        let mut result = self.basic_name.emit();
        if self.qualification.has_content() {
            result = format!("{}::{}", self.qualification.emit(), result);
        }
        result
    }
}

// ---------------------------------------------------------------------------
// QualifiedName
// ---------------------------------------------------------------------------

/// A fully qualified name (for standalone type names).
///
/// Ported from `MDQualifiedName.java`.
#[derive(Debug, Clone)]
pub struct QualifiedName {
    /// The qualification (namespace path).
    pub qualification: Qualification,
    /// The base name.
    pub base_name: String,
}

impl QualifiedName {
    pub fn new(base_name: String, qualification: Qualification) -> Self {
        Self {
            qualification,
            base_name,
        }
    }

    /// Emit the fully qualified name.
    pub fn emit(&self) -> String {
        if self.qualification.has_content() {
            format!("{}::{}", self.qualification.emit(), self.base_name)
        } else {
            self.base_name.clone()
        }
    }
}

// ---------------------------------------------------------------------------
// NestedName
// ---------------------------------------------------------------------------

/// A nested name (an embedded mangled object enclosed in backticks).
///
/// Ported from `MDNestedName.java`.
#[derive(Debug, Clone)]
pub struct NestedName {
    /// The nested mangled string.
    pub mangled: String,
    /// The demangled nested name.
    pub demangled: String,
}

impl NestedName {
    pub fn new(mangled: String, demangled: String) -> Self {
        Self { mangled, demangled }
    }

    /// Emit the nested name in backtick-delimited format.
    pub fn emit(&self) -> String {
        format!("`{}'", self.demangled)
    }
}

// ---------------------------------------------------------------------------
// NameModifier
// ---------------------------------------------------------------------------

/// A name modifier suffix (e.g., `$1` for adjustor thunks, `$H` for vtordisp).
///
/// Ported from `MDNameModifier.java`.
#[derive(Debug, Clone)]
pub struct NameModifier {
    /// The modifier string.
    pub modifier: String,
}

impl NameModifier {
    pub fn new(modifier: String) -> Self {
        Self { modifier }
    }

    /// Parse a name modifier from `$`-prefixed codes.
    pub fn parse(chars: &[char], index: &mut usize) -> Option<Self> {
        if *index >= chars.len() || chars[*index] != '$' {
            return None;
        }
        *index += 1;
        if *index >= chars.len() {
            return None;
        }
        let ch = chars[*index];
        *index += 1;
        match ch {
            '0'..='9' => Some(Self::new(format!("`adjustor{{{}' }}", ch as u8 - b'0'))),
            'A'..='F' => {
                let n = (ch as u8 - b'A' + 10) as u32;
                Some(Self::new(format!("`adjustor{{{}' }}", n)))
            }
            'H' => Some(Self::new("`vtordisp'".to_string())),
            'I' => Some(Self::new("`vtordispex'".to_string())),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_special_name_operators() {
        let sn = SpecialName::from_code('2').unwrap();
        assert_eq!(sn.name, "new");

        let sn = SpecialName::from_code('H').unwrap();
        assert_eq!(sn.name, "operator+");

        let sn = SpecialName::from_code('R').unwrap();
        assert_eq!(sn.name, "operator()");
    }

    #[test]
    fn test_special_name_constructor() {
        let sn = SpecialName::from_code('0').unwrap();
        assert!(sn.is_constructor);
    }

    #[test]
    fn test_special_name_destructor() {
        let sn = SpecialName::from_code('1').unwrap();
        assert!(sn.is_destructor);
    }

    #[test]
    fn test_special_name_type_cast() {
        let sn = SpecialName::from_code('B').unwrap();
        assert!(sn.is_type_cast);
    }

    #[test]
    fn test_special_name_underscore() {
        let sn = SpecialName::from_underscore_code('E').unwrap();
        assert_eq!(sn.name, "`vcall'");

        let sn = SpecialName::from_underscore_code('G').unwrap();
        assert_eq!(sn.name, "`local static guard'");
    }

    #[test]
    fn test_special_name_rtti() {
        let sn = SpecialName::from_rtti_code('0').unwrap();
        assert_eq!(sn.rtti_number, 0);
        assert_eq!(sn.name, "`RTTI Type Descriptor'");

        let sn = SpecialName::from_rtti_code('4').unwrap();
        assert_eq!(sn.rtti_number, 4);
    }

    #[test]
    fn test_fragment_name_parse() {
        let chars: Vec<char> = "helloWorld@".chars().collect();
        let mut index = 0;
        let frag = FragmentName::parse(&chars, &mut index);
        assert_eq!(frag.name, "helloWorld");
        assert_eq!(index, 11); // past the '@'
    }

    #[test]
    fn test_fragment_name_with_special_chars() {
        let chars: Vec<char> = "vector<int>@".chars().collect();
        let mut index = 0;
        let frag = FragmentName::parse(&chars, &mut index);
        assert_eq!(frag.name, "vector<int>");
    }

    #[test]
    fn test_qualification_parse() {
        let chars: Vec<char> = "foo@bar@@".chars().collect();
        let mut index = 0;
        let qual = Qualification::parse(&chars, &mut index);
        assert_eq!(qual.qualifiers.len(), 2);
        assert_eq!(qual.qualifiers[0].name, "foo");
        assert_eq!(qual.qualifiers[1].name, "bar");
        assert_eq!(qual.emit(), "foo::bar");
    }

    #[test]
    fn test_qualification_empty() {
        let chars: Vec<char> = "@".chars().collect();
        let mut index = 0;
        let qual = Qualification::parse(&chars, &mut index);
        assert!(qual.qualifiers.is_empty());
        assert!(!qual.has_content());
    }

    #[test]
    fn test_qualification_anonymous() {
        let chars: Vec<char> = "?A@@".chars().collect();
        let mut index = 0;
        let qual = Qualification::parse(&chars, &mut index);
        assert_eq!(qual.qualifiers.len(), 1);
        assert!(qual.qualifiers[0].is_anonymous);
    }

    #[test]
    fn test_name_modifier() {
        let chars: Vec<char> = "$1".chars().collect();
        let mut index = 0;
        let nm = NameModifier::parse(&chars, &mut index);
        assert!(nm.is_some());
        assert_eq!(index, 2);
    }

    #[test]
    fn test_basic_name_emit() {
        let frag = FragmentName {
            name: "myFunc".to_string(),
        };
        let bn = BasicName::regular(frag);
        assert_eq!(bn.emit(), "myFunc");
        assert!(!bn.is_constructor());
        assert!(!bn.is_destructor());
    }
}
