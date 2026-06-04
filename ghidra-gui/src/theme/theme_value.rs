//! Generic theme value base with indirection support.
//!
//! Ports `generic.theme.ThemeValue<T>`.

use std::collections::HashSet;
use std::fmt;

/// A generic theme value that either holds a concrete value of type `T` or
/// a reference to another value by its id.
///
/// Ported from Ghidra's `generic.theme.ThemeValue<T>`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ThemeValue<T: Clone> {
    /// The unique identifier for this value (e.g. "color.bg.foo").
    id: String,
    /// Direct value (mutually exclusive with `reference_id`).
    value: Option<T>,
    /// Reference to another value's id (mutually exclusive with `value`).
    reference_id: Option<String>,
}

impl<T: Clone> ThemeValue<T> {
    /// Create a theme value with a direct value.
    pub fn with_value(id: impl Into<String>, value: T) -> Self {
        let id = id.into();
        Self { id, value: Some(value), reference_id: None }
    }

    /// Create a theme value that references another value by id.
    pub fn with_reference(id: impl Into<String>, reference_id: impl Into<String>) -> Self {
        let id = id.into();
        let ref_id = reference_id.into();
        assert_ne!(id, ref_id, "A theme value cannot reference itself");
        Self { id, value: None, reference_id: Some(ref_id) }
    }

    /// Get the id.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Get the direct value, if any (does not follow references).
    pub fn raw_value(&self) -> Option<&T> {
        self.value.as_ref()
    }

    /// Get the reference id, if any.
    pub fn reference_id(&self) -> Option<&str> {
        self.reference_id.as_deref()
    }

    /// Whether this value is indirect (references another value).
    pub fn is_indirect(&self) -> bool {
        self.reference_id.is_some()
    }

    /// Whether this value has a direct (non-reference) value.
    pub fn has_direct_value(&self) -> bool {
        self.value.is_some()
    }

    /// Resolve the value, following references. Returns `None` if
    /// resolution fails (circular reference or missing key).
    pub fn resolve<F>(&self, get_by_id: &F) -> Option<T>
    where
        F: Fn(&str) -> Option<ThemeValue<T>>,
    {
        if let Some(ref v) = self.value {
            return Some(v.clone());
        }

        let ref_id = self.reference_id.as_ref()?;
        let mut visited = HashSet::new();
        visited.insert(self.id.clone());
        visited.insert(ref_id.clone());

        let mut current = get_by_id(ref_id)?;
        loop {
            if let Some(ref v) = current.value {
                return Some(v.clone());
            }
            let next_ref = current.reference_id.as_ref()?;
            if visited.contains(next_ref) {
                return None; // circular reference
            }
            visited.insert(next_ref.clone());
            current = get_by_id(next_ref)?;
        }
    }

    /// Whether the value can be resolved (no circular references, key exists).
    pub fn is_resolvable<F>(&self, get_by_id: &F) -> bool
    where
        F: Fn(&str) -> Option<ThemeValue<T>>,
    {
        self.resolve(get_by_id).is_some()
    }

    /// Whether this value inherits from the given ancestor id.
    pub fn inherits_from<F>(&self, ancestor_id: &str, get_by_id: &F) -> bool
    where
        F: Fn(&str) -> Option<ThemeValue<T>>,
    {
        match &self.reference_id {
            Some(ref_id) if ref_id == ancestor_id => true,
            Some(ref_id) => {
                let mut visited = HashSet::new();
                visited.insert(self.id.clone());
                let mut current_ref = ref_id.clone();

                loop {
                    if current_ref == ancestor_id {
                        return true;
                    }
                    let tv = match get_by_id(&current_ref) {
                        Some(tv) => tv,
                        None => return false,
                    };
                    match &tv.reference_id {
                        Some(next_ref) => {
                            if visited.contains(next_ref) {
                                return false;
                            }
                            visited.insert(next_ref.clone());
                            current_ref = next_ref.clone();
                        }
                        None => return false,
                    }
                }
            }
            None => false,
        }
    }
}

impl<T: Clone + fmt::Debug> fmt::Display for ThemeValue<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match (&self.value, &self.reference_id) {
            (Some(v), _) => write!(f, "{} = {:?}", self.id, v),
            (_, Some(ref_id)) => write!(f, "{} -> {}", self.id, ref_id),
            _ => write!(f, "{} = <empty>", self.id),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn make_getter(map: &HashMap<String, ThemeValue<i32>>) -> impl Fn(&str) -> Option<ThemeValue<i32>> + '_ {
        move |id: &str| map.get(id).cloned()
    }

    #[test]
    fn test_theme_value_direct() {
        let tv = ThemeValue::with_value("color.bg", 0xFF0000i32);
        assert_eq!(tv.id(), "color.bg");
        assert!(tv.has_direct_value());
        assert!(!tv.is_indirect());
    }

    #[test]
    fn test_theme_value_reference() {
        let tv = ThemeValue::<i32>::with_reference("color.fg", "color.bg");
        assert!(tv.is_indirect());
        assert_eq!(tv.reference_id(), Some("color.bg"));
    }

    #[test]
    fn test_resolve_direct() {
        let tv = ThemeValue::with_value("key", 42);
        let getter = |_: &str| None;
        assert_eq!(tv.resolve(&getter), Some(42));
    }

    #[test]
    fn test_resolve_indirect() {
        let mut map = HashMap::new();
        map.insert("a".to_string(), ThemeValue::with_reference("a", "b"));
        map.insert("b".to_string(), ThemeValue::with_value("b", 100));

        let getter = make_getter(&map);
        assert_eq!(map["a"].resolve(&getter), Some(100));
    }

    #[test]
    fn test_resolve_circular() {
        let mut map = HashMap::new();
        map.insert("a".to_string(), ThemeValue::with_reference("a", "b"));
        map.insert("b".to_string(), ThemeValue::with_reference("b", "a"));

        let getter = make_getter(&map);
        assert_eq!(map["a"].resolve(&getter), None);
    }

    #[test]
    fn test_inherits_from() {
        let mut map = HashMap::new();
        map.insert("a".to_string(), ThemeValue::with_reference("a", "b"));
        map.insert("b".to_string(), ThemeValue::with_reference("b", "c"));
        map.insert("c".to_string(), ThemeValue::with_value("c", 1));

        let getter = make_getter(&map);
        assert!(map["a"].inherits_from("b", &getter));
        assert!(map["a"].inherits_from("c", &getter));
        assert!(!map["a"].inherits_from("d", &getter));
    }

    #[test]
    fn test_is_resolvable() {
        let mut map = HashMap::new();
        map.insert("a".to_string(), ThemeValue::with_reference("a", "b"));
        map.insert("b".to_string(), ThemeValue::with_value("b", 1));

        let getter = make_getter(&map);
        assert!(map["a"].is_resolvable(&getter));
    }

    #[test]
    #[should_panic(expected = "A theme value cannot reference itself")]
    fn test_self_reference_panics() {
        ThemeValue::<i32>::with_reference("a", "a");
    }

    #[test]
    fn test_display() {
        let tv = ThemeValue::with_value("color.red", 42);
        assert!(tv.to_string().contains("color.red"));
    }
}
