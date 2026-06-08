//! Java property wrappers for PyGhidra.
//!
//! Ported from `ghidra.pyghidra.property`.  Provides property wrappers
//! that bridge between Rust/Java getters and setters and Python's
//! property protocol.
//!
//! The original Java implementation uses `MethodHandle` for reflective
//! access; the Rust port uses function pointers / closures.

// ---------------------------------------------------------------------------
// JavaPropertyKind
// ---------------------------------------------------------------------------

/// The kind of a Java property (determines the type of the getter/setter).
///
/// Matches Java's sealed `JavaProperty` hierarchy:
/// `BooleanJavaProperty`, `ByteJavaProperty`, `CharacterJavaProperty`,
/// `DoubleJavaProperty`, `FloatJavaProperty`, `IntegerJavaProperty`,
/// `LongJavaProperty`, `ShortJavaProperty`, `ObjectJavaProperty`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JavaPropertyKind {
    /// Boolean property.
    Boolean,
    /// Byte (i8) property.
    Byte,
    /// Character (u16) property.
    Character,
    /// Double (f64) property.
    Double,
    /// Float (f32) property.
    Float,
    /// Integer (i32) property.
    Integer,
    /// Long (i64) property.
    Long,
    /// Short (i16) property.
    Short,
    /// Object (any) property.
    Object,
}

// ---------------------------------------------------------------------------
// JavaProperty trait
// ---------------------------------------------------------------------------

/// A property interface for creating Python-compatible getters and setters.
///
/// Each implementation has a defined `fget` method that returns the
/// corresponding primitive type.  This allows Python duck typing and
/// automatic boxing/unboxing.
///
/// Matches Java's sealed `JavaProperty<T>` interface.
pub trait JavaProperty {
    /// The type of value this property holds.
    type Value;

    /// Get the property value.
    ///
    /// Returns `None` if no getter is available.
    fn fget(&self) -> Option<&Self::Value>;

    /// Set the property value.
    fn fset(&mut self, value: Self::Value);

    /// Whether this property has a getter.
    fn has_getter(&self) -> bool;

    /// Whether this property has a setter.
    fn has_setter(&self) -> bool;

    /// The name of the field this property wraps.
    fn field_name(&self) -> &str;

    /// The kind of this property.
    fn kind(&self) -> JavaPropertyKind;
}

// ---------------------------------------------------------------------------
// Concrete property types
// ---------------------------------------------------------------------------

/// A boolean property.
pub struct BooleanJavaProperty {
    field: String,
    value: Option<bool>,
    has_getter: bool,
    has_setter: bool,
}

impl BooleanJavaProperty {
    pub fn new(field: impl Into<String>) -> Self {
        Self {
            field: field.into(),
            value: None,
            has_getter: true,
            has_setter: true,
        }
    }
}

impl JavaProperty for BooleanJavaProperty {
    type Value = bool;

    fn fget(&self) -> Option<&bool> {
        self.value.as_ref()
    }

    fn fset(&mut self, value: bool) {
        self.value = Some(value);
    }

    fn has_getter(&self) -> bool {
        self.has_getter
    }

    fn has_setter(&self) -> bool {
        self.has_setter
    }

    fn field_name(&self) -> &str {
        &self.field
    }

    fn kind(&self) -> JavaPropertyKind {
        JavaPropertyKind::Boolean
    }
}

/// An integer (i32) property.
pub struct IntegerJavaProperty {
    field: String,
    value: Option<i32>,
    has_getter: bool,
    has_setter: bool,
}

impl IntegerJavaProperty {
    pub fn new(field: impl Into<String>) -> Self {
        Self {
            field: field.into(),
            value: None,
            has_getter: true,
            has_setter: true,
        }
    }
}

impl JavaProperty for IntegerJavaProperty {
    type Value = i32;

    fn fget(&self) -> Option<&i32> {
        self.value.as_ref()
    }

    fn fset(&mut self, value: i32) {
        self.value = Some(value);
    }

    fn has_getter(&self) -> bool {
        self.has_getter
    }

    fn has_setter(&self) -> bool {
        self.has_setter
    }

    fn field_name(&self) -> &str {
        &self.field
    }

    fn kind(&self) -> JavaPropertyKind {
        JavaPropertyKind::Integer
    }
}

/// A long (i64) property.
pub struct LongJavaProperty {
    field: String,
    value: Option<i64>,
    has_getter: bool,
    has_setter: bool,
}

impl LongJavaProperty {
    pub fn new(field: impl Into<String>) -> Self {
        Self {
            field: field.into(),
            value: None,
            has_getter: true,
            has_setter: true,
        }
    }
}

impl JavaProperty for LongJavaProperty {
    type Value = i64;

    fn fget(&self) -> Option<&i64> {
        self.value.as_ref()
    }

    fn fset(&mut self, value: i64) {
        self.value = Some(value);
    }

    fn has_getter(&self) -> bool {
        self.has_getter
    }

    fn has_setter(&self) -> bool {
        self.has_setter
    }

    fn field_name(&self) -> &str {
        &self.field
    }

    fn kind(&self) -> JavaPropertyKind {
        JavaPropertyKind::Long
    }
}

/// A double (f64) property.
pub struct DoubleJavaProperty {
    field: String,
    value: Option<f64>,
    has_getter: bool,
    has_setter: bool,
}

impl DoubleJavaProperty {
    pub fn new(field: impl Into<String>) -> Self {
        Self {
            field: field.into(),
            value: None,
            has_getter: true,
            has_setter: true,
        }
    }
}

impl JavaProperty for DoubleJavaProperty {
    type Value = f64;

    fn fget(&self) -> Option<&f64> {
        self.value.as_ref()
    }

    fn fset(&mut self, value: f64) {
        self.value = Some(value);
    }

    fn has_getter(&self) -> bool {
        self.has_getter
    }

    fn has_setter(&self) -> bool {
        self.has_setter
    }

    fn field_name(&self) -> &str {
        &self.field
    }

    fn kind(&self) -> JavaPropertyKind {
        JavaPropertyKind::Double
    }
}

/// A string/object property.
pub struct ObjectJavaProperty {
    field: String,
    value: Option<String>,
    has_getter: bool,
    has_setter: bool,
}

impl ObjectJavaProperty {
    pub fn new(field: impl Into<String>) -> Self {
        Self {
            field: field.into(),
            value: None,
            has_getter: true,
            has_setter: true,
        }
    }
}

impl JavaProperty for ObjectJavaProperty {
    type Value = String;

    fn fget(&self) -> Option<&String> {
        self.value.as_ref()
    }

    fn fset(&mut self, value: String) {
        self.value = Some(value);
    }

    fn has_getter(&self) -> bool {
        self.has_getter
    }

    fn has_setter(&self) -> bool {
        self.has_setter
    }

    fn field_name(&self) -> &str {
        &self.field
    }

    fn kind(&self) -> JavaPropertyKind {
        JavaPropertyKind::Object
    }
}

// ---------------------------------------------------------------------------
// PropertyUtils
// ---------------------------------------------------------------------------

/// Utility functions for working with Java properties.
///
/// Matches Java's `ghidra.pyghidra.property.PropertyUtils`.
pub struct PropertyUtils;

impl PropertyUtils {
    /// Box a primitive type to its wrapper type.
    ///
    /// In Java this converts e.g. `int.class` to `Integer.class`.
    /// In Rust we just return the kind.
    pub fn box_primitive(kind: JavaPropertyKind) -> JavaPropertyKind {
        // In Rust there's no distinction between primitive and boxed types,
        // but we keep this for API compatibility.
        kind
    }

    /// Create a property from a kind and field name.
    pub fn create_property(kind: JavaPropertyKind, field: &str) -> Box<dyn AnyProperty> {
        match kind {
            JavaPropertyKind::Boolean => Box::new(BooleanJavaProperty::new(field)),
            JavaPropertyKind::Integer => Box::new(IntegerJavaProperty::new(field)),
            JavaPropertyKind::Long => Box::new(LongJavaProperty::new(field)),
            JavaPropertyKind::Double => Box::new(DoubleJavaProperty::new(field)),
            JavaPropertyKind::Float => Box::new(FloatJavaProperty::new(field)),
            JavaPropertyKind::Byte => Box::new(ByteJavaProperty::new(field)),
            JavaPropertyKind::Short => Box::new(ShortJavaProperty::new(field)),
            JavaPropertyKind::Character => Box::new(CharacterJavaProperty::new(field)),
            JavaPropertyKind::Object => Box::new(ObjectJavaProperty::new(field)),
        }
    }
}

/// Type-erased property trait for use with `PropertyUtils::create_property`.
pub trait AnyProperty {
    fn field_name(&self) -> &str;
    fn kind(&self) -> JavaPropertyKind;
    fn has_getter(&self) -> bool;
    fn has_setter(&self) -> bool;
}

/// A float (f32) property.
pub struct FloatJavaProperty {
    field: String,
    value: Option<f32>,
    has_getter: bool,
    has_setter: bool,
}

impl FloatJavaProperty {
    pub fn new(field: impl Into<String>) -> Self {
        Self {
            field: field.into(),
            value: None,
            has_getter: true,
            has_setter: true,
        }
    }
}

impl JavaProperty for FloatJavaProperty {
    type Value = f32;
    fn fget(&self) -> Option<&f32> { self.value.as_ref() }
    fn fset(&mut self, value: f32) { self.value = Some(value); }
    fn has_getter(&self) -> bool { self.has_getter }
    fn has_setter(&self) -> bool { self.has_setter }
    fn field_name(&self) -> &str { &self.field }
    fn kind(&self) -> JavaPropertyKind { JavaPropertyKind::Float }
}

/// A byte (i8) property.
pub struct ByteJavaProperty {
    field: String,
    value: Option<i8>,
    has_getter: bool,
    has_setter: bool,
}

impl ByteJavaProperty {
    pub fn new(field: impl Into<String>) -> Self {
        Self {
            field: field.into(),
            value: None,
            has_getter: true,
            has_setter: true,
        }
    }
}

impl JavaProperty for ByteJavaProperty {
    type Value = i8;
    fn fget(&self) -> Option<&i8> { self.value.as_ref() }
    fn fset(&mut self, value: i8) { self.value = Some(value); }
    fn has_getter(&self) -> bool { self.has_getter }
    fn has_setter(&self) -> bool { self.has_setter }
    fn field_name(&self) -> &str { &self.field }
    fn kind(&self) -> JavaPropertyKind { JavaPropertyKind::Byte }
}

/// A short (i16) property.
pub struct ShortJavaProperty {
    field: String,
    value: Option<i16>,
    has_getter: bool,
    has_setter: bool,
}

impl ShortJavaProperty {
    pub fn new(field: impl Into<String>) -> Self {
        Self {
            field: field.into(),
            value: None,
            has_getter: true,
            has_setter: true,
        }
    }
}

impl JavaProperty for ShortJavaProperty {
    type Value = i16;
    fn fget(&self) -> Option<&i16> { self.value.as_ref() }
    fn fset(&mut self, value: i16) { self.value = Some(value); }
    fn has_getter(&self) -> bool { self.has_getter }
    fn has_setter(&self) -> bool { self.has_setter }
    fn field_name(&self) -> &str { &self.field }
    fn kind(&self) -> JavaPropertyKind { JavaPropertyKind::Short }
}

/// A character (u16) property.
pub struct CharacterJavaProperty {
    field: String,
    value: Option<char>,
    has_getter: bool,
    has_setter: bool,
}

impl CharacterJavaProperty {
    pub fn new(field: impl Into<String>) -> Self {
        Self {
            field: field.into(),
            value: None,
            has_getter: true,
            has_setter: true,
        }
    }
}

impl JavaProperty for CharacterJavaProperty {
    type Value = char;
    fn fget(&self) -> Option<&char> { self.value.as_ref() }
    fn fset(&mut self, value: char) { self.value = Some(value); }
    fn has_getter(&self) -> bool { self.has_getter }
    fn has_setter(&self) -> bool { self.has_setter }
    fn field_name(&self) -> &str { &self.field }
    fn kind(&self) -> JavaPropertyKind { JavaPropertyKind::Character }
}

// Implement AnyProperty for all concrete types
macro_rules! impl_any_property {
    ($ty:ty) => {
        impl AnyProperty for $ty {
            fn field_name(&self) -> &str { &self.field }
            fn kind(&self) -> JavaPropertyKind { JavaProperty::kind(self) }
            fn has_getter(&self) -> bool { self.has_getter }
            fn has_setter(&self) -> bool { self.has_setter }
        }
    };
}

impl_any_property!(BooleanJavaProperty);
impl_any_property!(IntegerJavaProperty);
impl_any_property!(LongJavaProperty);
impl_any_property!(DoubleJavaProperty);
impl_any_property!(FloatJavaProperty);
impl_any_property!(ByteJavaProperty);
impl_any_property!(ShortJavaProperty);
impl_any_property!(CharacterJavaProperty);
impl_any_property!(ObjectJavaProperty);

// ---------------------------------------------------------------------------
// JavaPropertyFactory
// ---------------------------------------------------------------------------

/// Factory for creating [`AnyProperty`] instances.
///
/// Matches Java's `ghidra.pyghidra.property.JavaPropertyFactory`.  The
/// original Java implementation inspects `MethodHandle` return / parameter
/// types at runtime; the Rust port takes an explicit [`JavaPropertyKind`]
/// and field name.
pub struct JavaPropertyFactory;

impl JavaPropertyFactory {
    /// Create a property of the appropriate concrete type for the given
    /// kind and field name.
    ///
    /// This is equivalent to Java's `JavaPropertyFactory.getProperty(field,
    /// getter, setter)` when the caller has already resolved the type.
    pub fn get_property(kind: JavaPropertyKind, field: &str) -> Box<dyn AnyProperty> {
        PropertyUtils::create_property(kind, field)
    }

    /// Create a property by inferring the kind from a type name string.
    ///
    /// Accepts Java-style type names (`"boolean"`, `"int"`, `"long"`,
    /// etc.) as well as Rust-style names (`"bool"`, `"i32"`, `"i64"`,
    /// etc.).  Returns `Object` for any unrecognised type.
    pub fn from_type_name(field: &str, type_name: &str) -> Box<dyn AnyProperty> {
        let kind = match type_name {
            "boolean" | "bool" => JavaPropertyKind::Boolean,
            "byte" | "i8" => JavaPropertyKind::Byte,
            "char" | "character" | "u16" => JavaPropertyKind::Character,
            "double" | "f64" => JavaPropertyKind::Double,
            "float" | "f32" => JavaPropertyKind::Float,
            "int" | "integer" | "i32" => JavaPropertyKind::Integer,
            "long" | "i64" => JavaPropertyKind::Long,
            "short" | "i16" => JavaPropertyKind::Short,
            _ => JavaPropertyKind::Object,
        };
        Self::get_property(kind, field)
    }

    /// Whether the given type name represents a primitive type.
    ///
    /// Matches Java's `cls.isPrimitive()` check in the original factory.
    pub fn is_primitive_type(type_name: &str) -> bool {
        matches!(
            type_name,
            "boolean"
                | "bool"
                | "byte"
                | "i8"
                | "char"
                | "character"
                | "u16"
                | "double"
                | "f64"
                | "float"
                | "f32"
                | "int"
                | "integer"
                | "i32"
                | "long"
                | "i64"
                | "short"
                | "i16"
        )
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_boolean_property() {
        let mut prop = BooleanJavaProperty::new("active");
        assert_eq!(JavaProperty::field_name(&prop), "active");
        assert_eq!(JavaProperty::kind(&prop), JavaPropertyKind::Boolean);
        assert!(prop.fget().is_none());

        prop.fset(true);
        assert_eq!(prop.fget(), Some(&true));
    }

    #[test]
    fn test_integer_property() {
        let mut prop = IntegerJavaProperty::new("count");
        prop.fset(42);
        assert_eq!(prop.fget(), Some(&42));
    }

    #[test]
    fn test_long_property() {
        let mut prop = LongJavaProperty::new("timestamp");
        prop.fset(i64::MAX);
        assert_eq!(prop.fget(), Some(&i64::MAX));
    }

    #[test]
    fn test_double_property() {
        let mut prop = DoubleJavaProperty::new("ratio");
        prop.fset(3.14);
        assert!((prop.fget().unwrap() - 3.14).abs() < f64::EPSILON);
    }

    #[test]
    fn test_object_property() {
        let mut prop = ObjectJavaProperty::new("name");
        prop.fset("hello".to_string());
        assert_eq!(prop.fget(), Some(&"hello".to_string()));
    }

    #[test]
    fn test_box_primitive() {
        assert_eq!(
            PropertyUtils::box_primitive(JavaPropertyKind::Integer),
            JavaPropertyKind::Integer
        );
    }

    #[test]
    fn test_create_property() {
        let prop = PropertyUtils::create_property(JavaPropertyKind::Boolean, "flag");
        assert_eq!(prop.kind(), JavaPropertyKind::Boolean);
        assert_eq!(prop.field_name(), "flag");
    }
}
