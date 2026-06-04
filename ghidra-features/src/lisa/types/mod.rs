//! P-code type system.
//!
//! Ported from the `ghidra.lisa.pcode.types` package in the Lisa
//! extension.
//!
//! Provides a simple type system for p-code values, including
//! inferred types and static type information.

/// A p-code value type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PcodeType {
    /// Unknown type.
    Unknown,
    /// Boolean (1-byte).
    Boolean,
    /// Integer of a given size in bytes.
    Integer(u32),
    /// Floating-point of a given size in bytes.
    Float(u32),
    /// Pointer (size depends on architecture).
    Pointer(u32),
    /// Array of a given element type size and count.
    Array {
        /// Element size in bytes.
        element_size: u32,
        /// Number of elements.
        count: u32,
    },
}

impl PcodeType {
    /// Get the size in bytes.
    pub fn size(&self) -> u32 {
        match self {
            Self::Unknown => 0,
            Self::Boolean => 1,
            Self::Integer(s) | Self::Float(s) | Self::Pointer(s) => *s,
            Self::Array {
                element_size,
                count,
            } => element_size * count,
        }
    }

    /// Whether this type is a numeric type (integer or float).
    pub fn is_numeric(&self) -> bool {
        matches!(self, Self::Integer(_) | Self::Float(_))
    }

    /// Whether this is a pointer type.
    pub fn is_pointer(&self) -> bool {
        matches!(self, Self::Pointer(_))
    }
}

/// The p-code type system.
///
/// Manages type assignments for p-code variables and expressions.
#[derive(Debug, Clone, Default)]
pub struct PcodeTypeSystem {
    /// Known types by variable index.
    types: Vec<PcodeType>,
}

impl PcodeTypeSystem {
    /// Create a new type system.
    pub fn new() -> Self {
        Self { types: Vec::new() }
    }

    /// Register a type for a variable index.
    pub fn set_type(&mut self, index: usize, ty: PcodeType) {
        if index >= self.types.len() {
            self.types.resize(index + 1, PcodeType::Unknown);
        }
        self.types[index] = ty;
    }

    /// Get the type for a variable index.
    pub fn get_type(&self, index: usize) -> PcodeType {
        self.types.get(index).copied().unwrap_or(PcodeType::Unknown)
    }

    /// Infer a type from a size in bytes.
    ///
    /// This is a simplified heuristic matching Ghidra's default
    /// behavior when no explicit type is available.
    pub fn infer_from_size(size: u32) -> PcodeType {
        match size {
            0 => PcodeType::Unknown,
            1 => PcodeType::Boolean,
            2 | 4 | 8 => PcodeType::Integer(size),
            _ => PcodeType::Integer(size),
        }
    }
}

/// Static type information for a p-code variable.
#[derive(Debug, Clone)]
pub struct PcodeStaticTypes {
    /// The type assignments.
    assignments: Vec<(usize, PcodeType)>,
}

impl PcodeStaticTypes {
    /// Create new static types.
    pub fn new() -> Self {
        Self {
            assignments: Vec::new(),
        }
    }

    /// Add a type assignment.
    pub fn add(&mut self, index: usize, ty: PcodeType) {
        self.assignments.push((index, ty));
    }

    /// Get all assignments.
    pub fn assignments(&self) -> &[(usize, PcodeType)] {
        &self.assignments
    }
}

/// Inferred types from dataflow analysis.
#[derive(Debug, Clone, Default)]
pub struct PcodeInferredTypes {
    /// Inferred types by variable index.
    inferred: Vec<Option<PcodeType>>,
}

impl PcodeInferredTypes {
    /// Create new inferred types.
    pub fn new() -> Self {
        Self {
            inferred: Vec::new(),
        }
    }

    /// Set an inferred type.
    pub fn set(&mut self, index: usize, ty: PcodeType) {
        if index >= self.inferred.len() {
            self.inferred.resize(index + 1, None);
        }
        self.inferred[index] = Some(ty);
    }

    /// Get the inferred type for an index.
    pub fn get(&self, index: usize) -> Option<PcodeType> {
        self.inferred.get(index).and_then(|t| *t)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pcode_type_size() {
        assert_eq!(PcodeType::Boolean.size(), 1);
        assert_eq!(PcodeType::Integer(4).size(), 4);
        assert_eq!(PcodeType::Float(8).size(), 8);
        assert_eq!(
            PcodeType::Array {
                element_size: 4,
                count: 10
            }
            .size(),
            40
        );
    }

    #[test]
    fn test_pcode_type_properties() {
        assert!(PcodeType::Integer(4).is_numeric());
        assert!(PcodeType::Float(8).is_numeric());
        assert!(!PcodeType::Boolean.is_numeric());
        assert!(PcodeType::Pointer(8).is_pointer());
    }

    #[test]
    fn test_type_system() {
        let mut ts = PcodeTypeSystem::new();
        ts.set_type(0, PcodeType::Integer(8));
        ts.set_type(1, PcodeType::Float(4));
        assert_eq!(ts.get_type(0), PcodeType::Integer(8));
        assert_eq!(ts.get_type(1), PcodeType::Float(4));
        assert_eq!(ts.get_type(99), PcodeType::Unknown);
    }

    #[test]
    fn test_infer_from_size() {
        assert_eq!(PcodeTypeSystem::infer_from_size(1), PcodeType::Boolean);
        assert_eq!(PcodeTypeSystem::infer_from_size(4), PcodeType::Integer(4));
        assert_eq!(PcodeTypeSystem::infer_from_size(0), PcodeType::Unknown);
    }

    #[test]
    fn test_inferred_types() {
        let mut it = PcodeInferredTypes::new();
        it.set(0, PcodeType::Integer(4));
        assert_eq!(it.get(0), Some(PcodeType::Integer(4)));
        assert_eq!(it.get(1), None);
    }

    #[test]
    fn test_static_types() {
        let mut st = PcodeStaticTypes::new();
        st.add(0, PcodeType::Boolean);
        st.add(1, PcodeType::Integer(8));
        assert_eq!(st.assignments().len(), 2);
    }
}
