//! Type Applier Factory -- dispatches PDB type records to type-specific appliers.
//!
//! Ports Ghidra's `ghidra.app.util.pdb.pdbapplicator.TypeApplierFactory`.
//!
//! The factory examines each incoming [`TypeRecord`] and routes it to the
//! appropriate applier implementation based on the type kind. Each applier
//! knows how to interpret its specific type variant and produce the
//! corresponding data type representation.

use std::collections::HashMap;
use std::fmt;

use super::super::abstract_pdb::{AbstractPdb, PdbReaderContext};
use super::super::{
    TypeRecord, ProcedureType, PointerType, ArrayType, ClassType,
    StructureType, UnionType, EnumType, FunctionType, MemberFunctionType,
    VtblType, ModifierType, ArgListType, FieldRecord, TypeProperty,
    SimpleType, resolve_simple_type,
};

// =============================================================================
// Errors
// =============================================================================

/// Errors that can occur when applying a type record.
#[derive(Debug, Clone)]
pub enum TypeApplyError {
    /// The type kind is not supported by any registered applier.
    Unsupported,
    /// The type references an invalid or out-of-range type index.
    InvalidTypeIndex(u32),
    /// The type data is malformed or truncated.
    Malformed(String),
    /// A circular type reference was detected.
    CircularReference(u32),
    /// Application was cancelled.
    Cancelled,
    /// An internal error occurred.
    InternalError(String),
}

impl fmt::Display for TypeApplyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsupported => write!(f, "Unsupported type kind"),
            Self::InvalidTypeIndex(idx) => write!(f, "Invalid type index: 0x{:04X}", idx),
            Self::Malformed(msg) => write!(f, "Malformed type: {}", msg),
            Self::CircularReference(idx) => write!(f, "Circular type reference at 0x{:04X}", idx),
            Self::Cancelled => write!(f, "Type application cancelled"),
            Self::InternalError(msg) => write!(f, "Internal error: {}", msg),
        }
    }
}

impl std::error::Error for TypeApplyError {}

// =============================================================================
// Applied Type Result
// =============================================================================

/// The result of successfully applying a type record.
#[derive(Debug, Clone)]
pub enum AppliedType {
    /// A composite type (class, struct, union).
    Composite {
        /// The type name.
        name: String,
        /// The kind of composite.
        kind: CompositeKind,
        /// The size in bytes.
        size: u64,
        /// Number of members.
        member_count: usize,
        /// The type index.
        type_index: u32,
    },
    /// An enumeration type.
    Enum {
        /// The type name.
        name: String,
        /// Number of enumerators.
        enumerator_count: usize,
        /// The underlying type index.
        underlying_type: u32,
        /// The type index.
        type_index: u32,
    },
    /// A pointer type.
    Pointer {
        /// The target type index.
        target_type: u32,
        /// The pointer size in bytes.
        size: u32,
        /// Whether this is a reference type.
        is_reference: bool,
        /// The type index.
        type_index: u32,
    },
    /// An array type.
    Array {
        /// The element type index.
        element_type: u32,
        /// The total size in bytes.
        size: u64,
        /// The type index.
        type_index: u32,
    },
    /// A procedure/function type.
    Procedure {
        /// The return type index.
        return_type: u32,
        /// The number of parameters.
        param_count: usize,
        /// The calling convention.
        calling_convention: String,
        /// The type index.
        type_index: u32,
    },
    /// A member function type.
    MemberFunction {
        /// The return type index.
        return_type: u32,
        /// The class type index.
        class_type: u32,
        /// The number of parameters.
        param_count: usize,
        /// The type index.
        type_index: u32,
    },
    /// A modifier (const/volatile).
    Modifier {
        /// The modified type index.
        modified_type: u32,
        /// Whether const.
        is_const: bool,
        /// Whether volatile.
        is_volatile: bool,
        /// The type index.
        type_index: u32,
    },
    /// A field list.
    FieldList {
        /// Number of fields.
        field_count: usize,
        /// The type index.
        type_index: u32,
    },
    /// An argument list.
    ArgumentList {
        /// Number of arguments.
        arg_count: usize,
        /// The type index.
        type_index: u32,
    },
    /// A simple/primitive type.
    Simple {
        /// The type name.
        name: String,
        /// The size in bytes.
        size: usize,
        /// The type index.
        type_index: u32,
    },
}

/// The kind of composite type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompositeKind {
    /// A C++ class.
    Class,
    /// A C struct.
    Struct,
    /// A C union.
    Union,
}

impl fmt::Display for CompositeKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Class => write!(f, "class"),
            Self::Struct => write!(f, "struct"),
            Self::Union => write!(f, "union"),
        }
    }
}

// =============================================================================
// Type Applier Trait
// =============================================================================

/// Trait for individual type applier implementations.
///
/// Each applier handles a specific kind of PDB type record.
pub trait TypeApplier {
    /// Apply a type record and return the result.
    ///
    /// `context` provides access to the full PDB reader context for
    /// resolving cross-references (e.g., looking up field list members).
    fn apply(
        &self,
        record: &TypeRecord,
        type_index: u32,
        context: &PdbReaderContext,
    ) -> Result<AppliedType, TypeApplyError>;

    /// Get a human-readable name for this applier.
    fn name(&self) -> &'static str;
}

// =============================================================================
// Composite Type Applier (class/struct/union)
// =============================================================================

/// Applies class, struct, and union type records.
struct CompositeTypeApplier;

impl TypeApplier for CompositeTypeApplier {
    fn apply(
        &self,
        record: &TypeRecord,
        type_index: u32,
        _context: &PdbReaderContext,
    ) -> Result<AppliedType, TypeApplyError> {
        match record {
            TypeRecord::Class(ct) => Ok(AppliedType::Composite {
                name: ct.name.clone(),
                kind: CompositeKind::Class,
                size: ct.size,
                member_count: ct.count as usize,
                type_index,
            }),
            TypeRecord::Structure(st) => Ok(AppliedType::Composite {
                name: st.name.clone(),
                kind: CompositeKind::Struct,
                size: st.size,
                member_count: st.count as usize,
                type_index,
            }),
            TypeRecord::Union(ut) => Ok(AppliedType::Composite {
                name: ut.name.clone(),
                kind: CompositeKind::Union,
                size: ut.size,
                member_count: ut.count as usize,
                type_index,
            }),
            _ => Err(TypeApplyError::Malformed("Expected composite type".into())),
        }
    }

    fn name(&self) -> &'static str {
        "CompositeTypeApplier"
    }
}

// =============================================================================
// Enum Type Applier
// =============================================================================

/// Applies enumeration type records.
struct EnumTypeApplier;

impl TypeApplier for EnumTypeApplier {
    fn apply(
        &self,
        record: &TypeRecord,
        type_index: u32,
        _context: &PdbReaderContext,
    ) -> Result<AppliedType, TypeApplyError> {
        match record {
            TypeRecord::Enum(et) => Ok(AppliedType::Enum {
                name: et.name.clone(),
                enumerator_count: et.count as usize,
                underlying_type: et.underlying_type_index,
                type_index,
            }),
            _ => Err(TypeApplyError::Malformed("Expected enum type".into())),
        }
    }

    fn name(&self) -> &'static str {
        "EnumTypeApplier"
    }
}

// =============================================================================
// Pointer Type Applier
// =============================================================================

/// Applies pointer type records.
struct PointerTypeApplier;

impl TypeApplier for PointerTypeApplier {
    fn apply(
        &self,
        record: &TypeRecord,
        type_index: u32,
        _context: &PdbReaderContext,
    ) -> Result<AppliedType, TypeApplyError> {
        match record {
            TypeRecord::Pointer(pt) => {
                let is_reference = matches!(
                    pt.pointer_mode,
                    super::super::PointerMode::LeftReference
                        | super::super::PointerMode::RightReference
                );
                Ok(AppliedType::Pointer {
                    target_type: pt.underlying_type_index,
                    size: pt.size,
                    is_reference,
                    type_index,
                })
            }
            _ => Err(TypeApplyError::Malformed("Expected pointer type".into())),
        }
    }

    fn name(&self) -> &'static str {
        "PointerTypeApplier"
    }
}

// =============================================================================
// Array Type Applier
// =============================================================================

/// Applies array type records.
struct ArrayTypeApplier;

impl TypeApplier for ArrayTypeApplier {
    fn apply(
        &self,
        record: &TypeRecord,
        type_index: u32,
        _context: &PdbReaderContext,
    ) -> Result<AppliedType, TypeApplyError> {
        match record {
            TypeRecord::Array(at) => Ok(AppliedType::Array {
                element_type: at.element_type_index,
                size: at.size,
                type_index,
            }),
            _ => Err(TypeApplyError::Malformed("Expected array type".into())),
        }
    }

    fn name(&self) -> &'static str {
        "ArrayTypeApplier"
    }
}

// =============================================================================
// Procedure Type Applier
// =============================================================================

/// Applies procedure/function type records.
struct ProcedureTypeApplier;

impl TypeApplier for ProcedureTypeApplier {
    fn apply(
        &self,
        record: &TypeRecord,
        type_index: u32,
        context: &PdbReaderContext,
    ) -> Result<AppliedType, TypeApplyError> {
        match record {
            TypeRecord::Procedure(pt) => {
                // Try to resolve the argument list to get param count
                let param_count = Self::resolve_arg_count(pt.arg_list_type_index, context);

                Ok(AppliedType::Procedure {
                    return_type: pt.return_type_index,
                    param_count,
                    calling_convention: format!("{:?}", pt.calling_convention),
                    type_index,
                })
            }
            TypeRecord::Function(ft) => {
                let param_count = Self::resolve_arg_count(ft.arg_list_type_index, context);

                Ok(AppliedType::Procedure {
                    return_type: ft.return_type_index,
                    param_count,
                    calling_convention: format!("{:?}", ft.calling_convention),
                    type_index,
                })
            }
            _ => Err(TypeApplyError::Malformed("Expected procedure type".into())),
        }
    }

    fn name(&self) -> &'static str {
        "ProcedureTypeApplier"
    }
}

impl ProcedureTypeApplier {
    /// Resolve the argument count from an argument list type index.
    fn resolve_arg_count(arg_list_index: u32, context: &PdbReaderContext) -> usize {
        if let Some(TypeRecord::ArgumentList(al)) = context.get_type(arg_list_index) {
            al.arg_type_indices.len()
        } else {
            0
        }
    }
}

// =============================================================================
// Member Function Type Applier
// =============================================================================

/// Applies member function type records.
struct MemberFunctionTypeApplier;

impl TypeApplier for MemberFunctionTypeApplier {
    fn apply(
        &self,
        record: &TypeRecord,
        type_index: u32,
        context: &PdbReaderContext,
    ) -> Result<AppliedType, TypeApplyError> {
        match record {
            TypeRecord::MemberFunction(mft) => {
                let param_count = if let Some(TypeRecord::ArgumentList(al)) =
                    context.get_type(mft.arg_list_type_index)
                {
                    al.arg_type_indices.len()
                } else {
                    0
                };

                Ok(AppliedType::MemberFunction {
                    return_type: mft.return_type_index,
                    class_type: mft.class_type_index,
                    param_count,
                    type_index,
                })
            }
            _ => Err(TypeApplyError::Malformed("Expected member function type".into())),
        }
    }

    fn name(&self) -> &'static str {
        "MemberFunctionTypeApplier"
    }
}

// =============================================================================
// Modifier Type Applier
// =============================================================================

/// Applies modifier type records (const, volatile).
struct ModifierTypeApplier;

impl TypeApplier for ModifierTypeApplier {
    fn apply(
        &self,
        record: &TypeRecord,
        type_index: u32,
        _context: &PdbReaderContext,
    ) -> Result<AppliedType, TypeApplyError> {
        match record {
            TypeRecord::Modifier(mt) => Ok(AppliedType::Modifier {
                modified_type: mt.modified_type_index,
                is_const: (mt.modifiers & 0x01) != 0,
                is_volatile: (mt.modifiers & 0x02) != 0,
                type_index,
            }),
            _ => Err(TypeApplyError::Malformed("Expected modifier type".into())),
        }
    }

    fn name(&self) -> &'static str {
        "ModifierTypeApplier"
    }
}

// =============================================================================
// Field List Type Applier
// =============================================================================

/// Applies field list type records.
struct FieldListTypeApplier;

impl TypeApplier for FieldListTypeApplier {
    fn apply(
        &self,
        record: &TypeRecord,
        type_index: u32,
        _context: &PdbReaderContext,
    ) -> Result<AppliedType, TypeApplyError> {
        match record {
            TypeRecord::FieldList { fields } => Ok(AppliedType::FieldList {
                field_count: fields.len(),
                type_index,
            }),
            _ => Err(TypeApplyError::Malformed("Expected field list type".into())),
        }
    }

    fn name(&self) -> &'static str {
        "FieldListTypeApplier"
    }
}

// =============================================================================
// Argument List Type Applier
// =============================================================================

/// Applies argument list type records.
struct ArgumentListTypeApplier;

impl TypeApplier for ArgumentListTypeApplier {
    fn apply(
        &self,
        record: &TypeRecord,
        type_index: u32,
        _context: &PdbReaderContext,
    ) -> Result<AppliedType, TypeApplyError> {
        match record {
            TypeRecord::ArgumentList(al) => Ok(AppliedType::ArgumentList {
                arg_count: al.arg_type_indices.len(),
                type_index,
            }),
            _ => Err(TypeApplyError::Malformed("Expected argument list type".into())),
        }
    }

    fn name(&self) -> &'static str {
        "ArgumentListTypeApplier"
    }
}

// =============================================================================
// Simple Type Applier
// =============================================================================

/// Applies simple/primitive type records.
struct SimpleTypeApplier;

impl TypeApplier for SimpleTypeApplier {
    fn apply(
        &self,
        record: &TypeRecord,
        type_index: u32,
        _context: &PdbReaderContext,
    ) -> Result<AppliedType, TypeApplyError> {
        match record {
            TypeRecord::Simple { leaf_id } => {
                let simple = resolve_simple_type(*leaf_id as u32);
                Ok(AppliedType::Simple {
                    name: simple.type_name(),
                    size: simple.byte_size(),
                    type_index,
                })
            }
            _ => Err(TypeApplyError::Malformed("Expected simple type".into())),
        }
    }

    fn name(&self) -> &'static str {
        "SimpleTypeApplier"
    }
}

// =============================================================================
// Type Applier Factory
// =============================================================================

/// Factory that dispatches PDB type records to the appropriate applier.
///
/// Maintains a set of [`TypeApplier`] implementations and routes each
/// incoming type record to the correct one based on the record variant.
///
/// Ports Ghidra's `TypeApplierFactory` which serves as the central
/// dispatch for all type processing in the PDB applicator.
pub struct TypeApplierFactory {
    /// Whether this factory has been initialized.
    initialized: bool,
    /// Count of types processed by this factory.
    processed_count: u64,
    /// Count of types that were successfully applied.
    applied_count: u64,
    /// Count of types that were skipped (unsupported).
    skipped_count: u64,
    /// Cache of type indices that have already been applied.
    applied_cache: HashMap<u32, AppliedType>,
}

impl TypeApplierFactory {
    /// Create a new type applier factory.
    pub fn new() -> Self {
        Self {
            initialized: true,
            processed_count: 0,
            applied_count: 0,
            skipped_count: 0,
            applied_cache: HashMap::new(),
        }
    }

    /// Apply a type record using the appropriate applier.
    ///
    /// Returns the applied type result on success.
    pub fn apply_type(
        &mut self,
        record: &TypeRecord,
        type_index: u32,
        context: &PdbReaderContext,
    ) -> Result<&AppliedType, TypeApplyError> {
        self.processed_count += 1;

        // Check cache
        if self.applied_cache.contains_key(&type_index) {
            return Ok(self.applied_cache.get(&type_index).unwrap());
        }

        let result = self.dispatch_type(record, type_index, context)?;

        match &result {
            AppliedType::Simple { .. } => {
                // Simple types are always applied
            }
            _ => {
                self.applied_count += 1;
            }
        }

        self.applied_cache.insert(type_index, result);
        Ok(self.applied_cache.get(&type_index).unwrap())
    }

    /// Dispatch a type record to the correct applier based on its variant.
    fn dispatch_type(
        &self,
        record: &TypeRecord,
        type_index: u32,
        context: &PdbReaderContext,
    ) -> Result<AppliedType, TypeApplyError> {
        match record {
            // Composite types
            TypeRecord::Class(_)
            | TypeRecord::Structure(_)
            | TypeRecord::Union(_) => {
                CompositeTypeApplier.apply(record, type_index, context)
            }

            // Enum types
            TypeRecord::Enum(_) => {
                EnumTypeApplier.apply(record, type_index, context)
            }

            // Pointer types
            TypeRecord::Pointer(_) => {
                PointerTypeApplier.apply(record, type_index, context)
            }

            // Array types
            TypeRecord::Array(_) => {
                ArrayTypeApplier.apply(record, type_index, context)
            }

            // Procedure / function types
            TypeRecord::Procedure(_) | TypeRecord::Function(_) => {
                ProcedureTypeApplier.apply(record, type_index, context)
            }

            // Member function types
            TypeRecord::MemberFunction(_) => {
                MemberFunctionTypeApplier.apply(record, type_index, context)
            }

            // Modifier types
            TypeRecord::Modifier(_) => {
                ModifierTypeApplier.apply(record, type_index, context)
            }

            // Field lists
            TypeRecord::FieldList { .. } => {
                FieldListTypeApplier.apply(record, type_index, context)
            }

            // Argument lists
            TypeRecord::ArgumentList(_) => {
                ArgumentListTypeApplier.apply(record, type_index, context)
            }

            // Simple types
            TypeRecord::Simple { .. } => {
                SimpleTypeApplier.apply(record, type_index, context)
            }

            // Unsupported types
            _ => Err(TypeApplyError::Unsupported),
        }
    }

    /// Look up an already-applied type by index.
    pub fn get_applied_type(&self, type_index: u32) -> Option<&AppliedType> {
        self.applied_cache.get(&type_index)
    }

    /// Get the total number of types processed.
    pub fn processed_count(&self) -> u64 {
        self.processed_count
    }

    /// Get the number of types successfully applied.
    pub fn applied_count(&self) -> u64 {
        self.applied_count
    }

    /// Get the number of types skipped.
    pub fn skipped_count(&self) -> u64 {
        self.skipped_count
    }

    /// Get the number of types in the cache.
    pub fn cache_size(&self) -> usize {
        self.applied_cache.len()
    }

    /// Clear the applied type cache and reset counters.
    pub fn reset(&mut self) {
        self.processed_count = 0;
        self.applied_count = 0;
        self.skipped_count = 0;
        self.applied_cache.clear();
    }

    /// Clear only the cache, preserving counters.
    pub fn clear_cache(&mut self) {
        self.applied_cache.clear();
    }
}

impl Default for TypeApplierFactory {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for TypeApplierFactory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TypeApplierFactory")
            .field("initialized", &self.initialized)
            .field("processed", &self.processed_count)
            .field("applied", &self.applied_count)
            .field("skipped", &self.skipped_count)
            .field("cached", &self.applied_cache.len())
            .finish()
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // Helper to create a minimal PdbReaderContext for testing.
    // Since type_names is pub(crate), we can construct it directly.
    fn empty_context() -> PdbReaderContext {
        PdbReaderContext {
            msf: super::super::super::MsfFile {
                blocks: Vec::new(),
                block_size: 4096,
                directory: super::super::super::MsfDirectory {
                    streams: Vec::new(),
                },
            },
            info: None,
            tpi: None,
            dbi: None,
            ipi: None,
            type_names: HashMap::new(),
        }
    }

    #[test]
    fn test_factory_default() {
        let factory = TypeApplierFactory::new();
        assert_eq!(factory.processed_count(), 0);
        assert_eq!(factory.applied_count(), 0);
        assert_eq!(factory.skipped_count(), 0);
        assert_eq!(factory.cache_size(), 0);
    }

    #[test]
    fn test_apply_class_type() {
        let mut factory = TypeApplierFactory::new();
        let ctx = empty_context();
        let record = TypeRecord::Class(ClassType {
            count: 3,
            property: TypeProperty::empty(),
            field_list_type_index: 0x1001,
            derived_type_index: 0,
            vshape_type_index: 0,
            size: 16,
            name: "MyClass".to_string(),
            mangled_name: None,
        });
        let result = factory.apply_type(&record, 0x1000, &ctx);
        assert!(result.is_ok());
        match result.unwrap() {
            AppliedType::Composite { name, kind, size, .. } => {
                assert_eq!(name, "MyClass");
                assert_eq!(*kind, CompositeKind::Class);
                assert_eq!(*size, 16);
            }
            _ => panic!("Expected Composite"),
        }
    }

    #[test]
    fn test_apply_structure_type() {
        let mut factory = TypeApplierFactory::new();
        let ctx = empty_context();
        let record = TypeRecord::Structure(StructureType {
            count: 2,
            property: TypeProperty::empty(),
            field_list_type_index: 0x1001,
            derived_type_index: 0,
            vshape_type_index: 0,
            size: 8,
            name: "Point".to_string(),
            mangled_name: None,
        });
        let result = factory.apply_type(&record, 0x1000, &ctx);
        assert!(result.is_ok());
        match result.unwrap() {
            AppliedType::Composite { kind, .. } => {
                assert_eq!(*kind, CompositeKind::Struct);
            }
            _ => panic!("Expected Composite"),
        }
    }

    #[test]
    fn test_apply_union_type() {
        let mut factory = TypeApplierFactory::new();
        let ctx = empty_context();
        let record = TypeRecord::Union(UnionType {
            count: 2,
            property: TypeProperty::empty(),
            field_list_type_index: 0x1001,
            size: 4,
            name: "Data".to_string(),
            mangled_name: None,
        });
        let result = factory.apply_type(&record, 0x1000, &ctx);
        assert!(result.is_ok());
        match result.unwrap() {
            AppliedType::Composite { kind, .. } => {
                assert_eq!(*kind, CompositeKind::Union);
            }
            _ => panic!("Expected Composite"),
        }
    }

    #[test]
    fn test_apply_enum_type() {
        let mut factory = TypeApplierFactory::new();
        let ctx = empty_context();
        let record = TypeRecord::Enum(EnumType {
            count: 4,
            property: TypeProperty::empty(),
            underlying_type_index: 0x0074, // int
            field_list_type_index: 0x1001,
            name: "Color".to_string(),
            mangled_name: None,
        });
        let result = factory.apply_type(&record, 0x1000, &ctx);
        assert!(result.is_ok());
        match result.unwrap() {
            AppliedType::Enum { name, underlying_type, .. } => {
                assert_eq!(name, "Color");
                assert_eq!(*underlying_type, 0x0074);
            }
            _ => panic!("Expected Enum"),
        }
    }

    #[test]
    fn test_apply_pointer_type() {
        let mut factory = TypeApplierFactory::new();
        let ctx = empty_context();
        let record = TypeRecord::Pointer(PointerType {
            underlying_type_index: 0x1000,
            attributes: 0,
            pointer_mode: super::super::super::PointerMode::Pointer,
            size: 4,
            is_const: false,
            is_volatile: false,
            is_unaligned: false,
            is_flat: false,
            pointer_kind: super::super::super::PointerKind::Flat32,
        });
        let result = factory.apply_type(&record, 0x1001, &ctx);
        assert!(result.is_ok());
        match result.unwrap() {
            AppliedType::Pointer { target_type, size, is_reference, .. } => {
                assert_eq!(*target_type, 0x1000);
                assert_eq!(*size, 4);
                assert!(!*is_reference);
            }
            _ => panic!("Expected Pointer"),
        }
    }

    #[test]
    fn test_apply_array_type() {
        let mut factory = TypeApplierFactory::new();
        let ctx = empty_context();
        let record = TypeRecord::Array(ArrayType {
            element_type_index: 0x0074, // int
            index_type_index: 0x0003,
            size: 40,
            name: "int[10]".to_string(),
        });
        let result = factory.apply_type(&record, 0x1000, &ctx);
        assert!(result.is_ok());
        match result.unwrap() {
            AppliedType::Array { element_type, size, .. } => {
                assert_eq!(*element_type, 0x0074);
                assert_eq!(*size, 40);
            }
            _ => panic!("Expected Array"),
        }
    }

    #[test]
    fn test_apply_procedure_type() {
        let mut factory = TypeApplierFactory::new();
        let ctx = empty_context();
        let record = TypeRecord::Procedure(ProcedureType {
            return_type_index: 0x0074, // int
            calling_convention: super::super::super::CallingConvention::NearC,
            arg_list_type_index: 0,
        });
        let result = factory.apply_type(&record, 0x1000, &ctx);
        assert!(result.is_ok());
        match result.unwrap() {
            AppliedType::Procedure { return_type, param_count, .. } => {
                assert_eq!(*return_type, 0x0074);
                assert_eq!(*param_count, 0); // no arg list resolved
            }
            _ => panic!("Expected Procedure"),
        }
    }

    #[test]
    fn test_apply_modifier_type() {
        let mut factory = TypeApplierFactory::new();
        let ctx = empty_context();
        let record = TypeRecord::Modifier(ModifierType {
            modified_type_index: 0x1000,
            modifiers: 0x03, // const | volatile
        });
        let result = factory.apply_type(&record, 0x1001, &ctx);
        assert!(result.is_ok());
        match result.unwrap() {
            AppliedType::Modifier { modified_type, is_const, is_volatile, .. } => {
                assert_eq!(*modified_type, 0x1000);
                assert!(*is_const);
                assert!(*is_volatile);
            }
            _ => panic!("Expected Modifier"),
        }
    }

    #[test]
    fn test_apply_field_list_type() {
        let mut factory = TypeApplierFactory::new();
        let ctx = empty_context();
        let record = TypeRecord::FieldList {
            fields: vec![
                FieldRecord::Member {
                    access: super::super::super::MemberAccessProtection::None,
                    offset: 0,
                    type_index: 0x0074,
                    name: "x".to_string(),
                },
                FieldRecord::Member {
                    access: super::super::super::MemberAccessProtection::None,
                    offset: 4,
                    type_index: 0x0074,
                    name: "y".to_string(),
                },
            ],
        };
        let result = factory.apply_type(&record, 0x1001, &ctx);
        assert!(result.is_ok());
        match result.unwrap() {
            AppliedType::FieldList { field_count, .. } => {
                assert_eq!(*field_count, 2);
            }
            _ => panic!("Expected FieldList"),
        }
    }

    #[test]
    fn test_apply_argument_list_type() {
        let mut factory = TypeApplierFactory::new();
        let ctx = empty_context();
        let record = TypeRecord::ArgumentList(ArgListType {
            count: 2,
            arg_type_indices: vec![0x0074, 0x0075],
        });
        let result = factory.apply_type(&record, 0x1001, &ctx);
        assert!(result.is_ok());
        match result.unwrap() {
            AppliedType::ArgumentList { arg_count, .. } => {
                assert_eq!(*arg_count, 2);
            }
            _ => panic!("Expected ArgumentList"),
        }
    }

    #[test]
    fn test_apply_simple_type() {
        let mut factory = TypeApplierFactory::new();
        let ctx = empty_context();
        let record = TypeRecord::Simple { leaf_id: 0x0010 }; // Real32 (float)
        let result = factory.apply_type(&record, 0x0010, &ctx);
        assert!(result.is_ok());
        match result.unwrap() {
            AppliedType::Simple { name, size, .. } => {
                assert!(!name.is_empty());
                assert_eq!(*size, 4);
            }
            _ => panic!("Expected Simple"),
        }
    }

    #[test]
    fn test_type_caching() {
        let mut factory = TypeApplierFactory::new();
        let ctx = empty_context();
        let record = TypeRecord::Pointer(PointerType {
            underlying_type_index: 0x1000,
            attributes: 0,
            pointer_mode: super::super::super::PointerMode::Pointer,
            size: 4,
            is_const: false,
            is_volatile: false,
            is_unaligned: false,
            is_flat: false,
            pointer_kind: super::super::super::PointerKind::Flat32,
        });

        // First apply
        let result1 = factory.apply_type(&record, 0x1001, &ctx);
        assert!(result1.is_ok());

        // Second apply (should hit cache)
        let result2 = factory.apply_type(&record, 0x1001, &ctx);
        assert!(result2.is_ok());
        assert_eq!(factory.cache_size(), 1);
    }

    #[test]
    fn test_get_applied_type() {
        let mut factory = TypeApplierFactory::new();
        let ctx = empty_context();
        let record = TypeRecord::Enum(EnumType {
            count: 2,
            property: TypeProperty::empty(),
            underlying_type_index: 0x0074,
            field_list_type_index: 0x1001,
            name: "Bool".to_string(),
            mangled_name: None,
        });
        factory.apply_type(&record, 0x1000, &ctx).unwrap();

        let applied = factory.get_applied_type(0x1000);
        assert!(applied.is_some());

        let missing = factory.get_applied_type(0x9999);
        assert!(missing.is_none());
    }

    #[test]
    fn test_reset() {
        let mut factory = TypeApplierFactory::new();
        let ctx = empty_context();
        let record = TypeRecord::Simple { leaf_id: 0x0074 };
        factory.apply_type(&record, 0x0074, &ctx).unwrap();

        factory.reset();
        assert_eq!(factory.processed_count(), 0);
        assert_eq!(factory.applied_count(), 0);
        assert_eq!(factory.cache_size(), 0);
    }

    #[test]
    fn test_clear_cache() {
        let mut factory = TypeApplierFactory::new();
        let ctx = empty_context();
        let record = TypeRecord::Simple { leaf_id: 0x0074 };
        factory.apply_type(&record, 0x0074, &ctx).unwrap();

        factory.clear_cache();
        assert_eq!(factory.cache_size(), 0);
        // Counters preserved
        assert!(factory.processed_count() > 0);
    }

    #[test]
    fn test_unsupported_type() {
        let mut factory = TypeApplierFactory::new();
        let ctx = empty_context();
        let record = TypeRecord::Unknown { leaf_id: 0xFFFF, raw_data: vec![0, 1, 2] };
        let result = factory.apply_type(&record, 0x1000, &ctx);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), TypeApplyError::Unsupported));
    }

    #[test]
    fn test_composite_kind_display() {
        assert_eq!(format!("{}", CompositeKind::Class), "class");
        assert_eq!(format!("{}", CompositeKind::Struct), "struct");
        assert_eq!(format!("{}", CompositeKind::Union), "union");
    }

    #[test]
    fn test_error_display() {
        let err = TypeApplyError::Unsupported;
        assert!(format!("{}", err).contains("Unsupported"));

        let err = TypeApplyError::InvalidTypeIndex(0x1000);
        assert!(format!("{}", err).contains("0x1000"));

        let err = TypeApplyError::CircularReference(0x2000);
        assert!(format!("{}", err).contains("0x2000"));

        let err = TypeApplyError::Malformed("bad data".into());
        assert!(format!("{}", err).contains("bad data"));
    }

    #[test]
    fn test_debug_format() {
        let factory = TypeApplierFactory::new();
        let dbg = format!("{:?}", factory);
        assert!(dbg.contains("TypeApplierFactory"));
    }

    #[test]
    fn test_pointer_reference() {
        let mut factory = TypeApplierFactory::new();
        let ctx = empty_context();
        let record = TypeRecord::Pointer(PointerType {
            underlying_type_index: 0x1000,
            attributes: 0,
            pointer_mode: super::super::super::PointerMode::LeftReference,
            size: 4,
            is_const: false,
            is_volatile: false,
            is_unaligned: false,
            is_flat: false,
            pointer_kind: super::super::super::PointerKind::Flat32,
        });
        let result = factory.apply_type(&record, 0x1001, &ctx).unwrap();
        match result {
            AppliedType::Pointer { is_reference, .. } => {
                assert!(*is_reference);
            }
            _ => panic!("Expected Pointer"),
        }
    }
}
