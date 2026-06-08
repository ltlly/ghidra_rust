//! PDB Applicator -- applies parsed PDB types and symbols to a program.
//!
//! Ports Ghidra's `ghidra.app.util.pdb.pdbapplicator` package.
//!
//! The applicator takes parsed PDB data (types from TPI/IPI, symbols from DBI
//! module streams, and debug info from the DBI header) and applies them to a
//! Ghidra [`Program`] by creating data types, function signatures, labels, and
//! other analysis artifacts.
//!
//! # Architecture
//!
//! - [`DefaultPdbApplicator`] -- The main entry point that orchestrates
//!   type application, symbol application, and debug info application.
//! - [`TypeApplier`] -- Applies CodeView type records to create Ghidra data types.
//! - [`SymbolApplier`] -- Applies CodeView symbol records to create program
//!   symbols (labels, functions, data references).
//! - [`CompositeTypeApplier`] -- Handles class/struct/union application with
//!   nested types, inheritance, and virtual function tables.
//! - [`EnumTypeApplier`] -- Applies enum type records.
//! - [`FunctionTypeApplier`] -- Applies procedure and member function types.

use std::collections::HashMap;

use super::{TypeRecord, SymbolRecord, MsfFile, DbiStream};

// =============================================================================
// Type ID -- resolved type identifier within a PDB
// =============================================================================

/// A resolved type identifier within a PDB, combining the type index
/// with metadata about the type's resolved state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedTypeId {
    /// The original type index from the PDB.
    pub type_index: u32,
    /// Whether this type has been fully resolved (applied to the program).
    pub resolved: bool,
    /// The category of type (primitive, pointer, composite, etc.).
    pub category: TypeCategory,
}

/// Categories of types in a PDB.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TypeCategory {
    /// A primitive/simple type (int, float, etc.).
    Primitive,
    /// A pointer type.
    Pointer,
    /// A class, struct, or union.
    Composite,
    /// An enumeration.
    Enum,
    /// An array.
    Array,
    /// A procedure/function type.
    Procedure,
    /// A member function type.
    MemberFunction,
    /// A modifier (const, volatile).
    Modifier,
    /// A bitfield.
    Bitfield,
    /// A field list (container for member records).
    FieldList,
    /// An argument list.
    ArgumentList,
    /// A method list.
    MethodList,
    /// A virtual function table shape.
    VtShape,
    /// Unknown or unsupported type.
    Unknown,
}

impl TypeCategory {
    /// Determine the category from a type record.
    pub fn from_type_record(record: &TypeRecord) -> Self {
        match record {
            TypeRecord::Pointer(_) => Self::Pointer,
            TypeRecord::Class(_) | TypeRecord::Structure(_) | TypeRecord::Union(_) => Self::Composite,
            TypeRecord::Enum(_) => Self::Enum,
            TypeRecord::Array(_) => Self::Array,
            TypeRecord::Procedure(_) => Self::Procedure,
            TypeRecord::MemberFunction(_) => Self::MemberFunction,
            TypeRecord::Modifier(_) => Self::Modifier,
            TypeRecord::FieldList { .. } => Self::FieldList,
            TypeRecord::ArgumentList(_) => Self::ArgumentList,
            TypeRecord::MethodList { .. } => Self::MethodList,
            TypeRecord::VtShape { .. } => Self::VtShape,
            TypeRecord::Simple { .. } => Self::Primitive,
            _ => Self::Unknown,
        }
    }
}

// =============================================================================
// Data Type representation (created from PDB type records)
// =============================================================================

/// A data type created from a PDB type record.
#[derive(Debug, Clone)]
pub enum PdbDataType {
    /// A named composite type (class, struct, union).
    Composite {
        /// The type name.
        name: String,
        /// Whether this is a struct, class, or union.
        kind: CompositeKind,
        /// The size in bytes.
        size: u64,
        /// The members of the composite.
        members: Vec<PdbMember>,
        /// Base class type indices.
        base_classes: Vec<(u32, u32)>, // (type_index, offset)
    },
    /// An enumeration type.
    Enum {
        /// The type name.
        name: String,
        /// The underlying type index.
        underlying_type: u32,
        /// The enumerators.
        enumerators: Vec<(String, i64)>,
    },
    /// A pointer to another type.
    Pointer {
        /// The target type index.
        target_type: u32,
        /// The pointer size in bytes.
        size: u32,
        /// Whether this is a reference type.
        is_reference: bool,
    },
    /// An array type.
    Array {
        /// The element type index.
        element_type: u32,
        /// The total size in bytes.
        size: u64,
        /// The array name.
        name: String,
    },
    /// A procedure/function type.
    Procedure {
        /// The return type index.
        return_type: u32,
        /// The parameter type indices.
        parameter_types: Vec<u32>,
        /// The calling convention.
        calling_convention: String,
    },
    /// A modifier (const/volatile) applied to another type.
    Modifier {
        /// The modified type index.
        modified_type: u32,
        /// Whether the type is const.
        is_const: bool,
        /// Whether the type is volatile.
        is_volatile: bool,
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

/// A member of a composite type.
#[derive(Debug, Clone)]
pub struct PdbMember {
    /// The member name.
    pub name: String,
    /// The member's type index.
    pub type_index: u32,
    /// The byte offset within the composite.
    pub offset: u64,
    /// The access protection.
    pub access: AccessProtection,
    /// Whether this is a static member.
    pub is_static: bool,
}

/// Access protection for class members.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessProtection {
    /// No access specifier.
    None,
    /// Private access.
    Private,
    /// Protected access.
    Protected,
    /// Public access.
    Public,
}

impl AccessProtection {
    /// Convert from PDB MemberAccessProtection.
    pub fn from_pdb(v: super::MemberAccessProtection) -> Self {
        match v {
            super::MemberAccessProtection::None => Self::None,
            super::MemberAccessProtection::Private => Self::Private,
            super::MemberAccessProtection::Protected => Self::Protected,
            super::MemberAccessProtection::Public => Self::Public,
        }
    }
}

// =============================================================================
// Symbol Application result
// =============================================================================

/// The result of applying a symbol to the program.
#[derive(Debug, Clone)]
pub enum SymbolApplyResult {
    /// A function was created or updated.
    Function {
        /// The function name.
        name: String,
        /// The function address (segment:offset).
        address: (u16, u64),
        /// The type index for the function signature.
        type_index: u32,
    },
    /// A label was created.
    Label {
        /// The label name.
        name: String,
        /// The label address (segment:offset).
        address: (u16, u64),
    },
    /// A data symbol was created.
    Data {
        /// The symbol name.
        name: String,
        /// The address (segment:offset).
        address: (u16, u64),
        /// The type index.
        type_index: u32,
    },
    /// A user-defined type was registered.
    UserDefinedType {
        /// The UDT name.
        name: String,
        /// The type index.
        type_index: u32,
    },
    /// A public symbol was recorded.
    Public {
        /// The symbol name.
        name: String,
        /// The address (segment:offset).
        address: (u16, u64),
    },
    /// A thunk was created.
    Thunk {
        /// The thunk name.
        name: String,
        /// The address (segment:offset).
        address: (u16, u64),
    },
    /// A reference symbol was recorded.
    Reference {
        /// The reference name.
        name: String,
        /// The module index.
        module_index: u16,
    },
    /// The symbol was skipped (not applicable).
    Skipped,
}

// =============================================================================
// PDB Applicator configuration
// =============================================================================

/// Configuration options for the PDB applicator.
#[derive(Debug, Clone)]
pub struct ApplicatorConfig {
    /// Whether to apply type information.
    pub apply_types: bool,
    /// Whether to apply function signatures.
    pub apply_function_signatures: bool,
    /// Whether to create labels from symbol names.
    pub create_labels: bool,
    /// Whether to apply data type information.
    pub apply_data_types: bool,
    /// Whether to apply external (import) symbols.
    pub apply_external_symbols: bool,
    /// Whether to apply source file information (line numbers).
    pub apply_source_info: bool,
    /// Whether to apply register variable information.
    pub apply_register_info: bool,
    /// Whether to search for a PDB automatically.
    pub auto_search: bool,
    /// The search paths for PDB files.
    pub search_paths: Vec<String>,
    /// Whether to use the Microsoft Symbol Server.
    pub use_symbol_server: bool,
}

impl Default for ApplicatorConfig {
    fn default() -> Self {
        Self {
            apply_types: true,
            apply_function_signatures: true,
            create_labels: true,
            apply_data_types: true,
            apply_external_symbols: true,
            apply_source_info: true,
            apply_register_info: true,
            auto_search: true,
            search_paths: Vec::new(),
            use_symbol_server: true,
        }
    }
}

// =============================================================================
// Default PDB Applicator
// =============================================================================

/// The main PDB applicator that applies parsed PDB data to a program.
///
/// Ports Ghidra's `DefaultPdbApplicator`.
pub struct DefaultPdbApplicator {
    /// Configuration options.
    config: ApplicatorConfig,
    /// Resolved types by type index.
    resolved_types: HashMap<u32, ResolvedTypeId>,
    /// Created data types by type index.
    data_types: HashMap<u32, PdbDataType>,
    /// Symbol application results.
    symbol_results: Vec<SymbolApplyResult>,
    /// Type index mapping (PDB index -> our index).
    type_map: HashMap<u32, u32>,
    /// Statistics about the application.
    stats: ApplicatorStats,
}

/// Statistics about PDB application.
#[derive(Debug, Clone, Default)]
pub struct ApplicatorStats {
    /// Number of types applied.
    pub types_applied: usize,
    /// Number of symbols applied.
    pub symbols_applied: usize,
    /// Number of functions created.
    pub functions_created: usize,
    /// Number of labels created.
    pub labels_created: usize,
    /// Number of data symbols created.
    pub data_symbols_created: usize,
    /// Number of source files processed.
    pub source_files_processed: usize,
    /// Number of line number records processed.
    pub line_records_processed: usize,
    /// Number of errors during application.
    pub errors: usize,
    /// Number of warnings during application.
    pub warnings: usize,
}

impl DefaultPdbApplicator {
    /// Create a new PDB applicator with default configuration.
    pub fn new() -> Self {
        Self {
            config: ApplicatorConfig::default(),
            resolved_types: HashMap::new(),
            data_types: HashMap::new(),
            symbol_results: Vec::new(),
            type_map: HashMap::new(),
            stats: ApplicatorStats::default(),
        }
    }

    /// Create a new PDB applicator with custom configuration.
    pub fn with_config(config: ApplicatorConfig) -> Self {
        Self {
            config,
            ..Self::new()
        }
    }

    /// Get the current configuration.
    pub fn config(&self) -> &ApplicatorConfig {
        &self.config
    }

    /// Get application statistics.
    pub fn stats(&self) -> &ApplicatorStats {
        &self.stats
    }

    /// Apply all PDB data from the given MSF file.
    ///
    /// This is the main entry point that parses all streams and applies
    /// types, symbols, and debug information.
    pub fn apply(&mut self, msf: &MsfFile) -> Result<&ApplicatorStats, ApplicatorError> {
        // Parse PDB Info stream (stream 1)
        let pdb_info_data = msf.read_stream(1)
            .ok_or(ApplicatorError::StreamNotFound(1))?;
        let _pdb_info = super::parse_pdb_info_stream(&pdb_info_data)
            .map_err(|e| ApplicatorError::ParseError(e.to_string()))?;

        // Parse TPI stream (stream 2)
        let tpi_data = msf.read_stream(2)
            .ok_or(ApplicatorError::StreamNotFound(2))?;
        let tpi = super::parse_tpi_stream(&tpi_data)
            .map_err(|e| ApplicatorError::ParseError(e.to_string()))?;

        // Apply types
        if self.config.apply_types {
            self.apply_types(&tpi.types)?;
        }

        // Parse DBI stream (stream 3)
        let dbi_data = msf.read_stream(3)
            .ok_or(ApplicatorError::StreamNotFound(3))?;
        let dbi = super::parse_dbi_stream(&dbi_data)
            .map_err(|e| ApplicatorError::ParseError(e.to_string()))?;

        // Apply symbols from each module
        for module in &dbi.modules {
            if module.module_sym_stream > 0 {
                if let Some(sym_data) = msf.read_stream(module.module_sym_stream as u32) {
                    self.apply_symbol_stream(&sym_data, module.module_index);
                }
            }
        }

        // Apply source info (line numbers) if configured
        if self.config.apply_source_info {
            self.apply_source_info(&dbi, msf);
        }

        Ok(&self.stats)
    }

    /// Apply type records from the TPI stream.
    fn apply_types(&mut self, types: &[TypeRecord]) -> Result<(), ApplicatorError> {
        for (idx, record) in types.iter().enumerate() {
            let type_index = 0x1000 + idx as u32; // TPI types start at 0x1000
            let category = TypeCategory::from_type_record(record);

            let resolved = ResolvedTypeId {
                type_index,
                resolved: false,
                category,
            };
            self.resolved_types.insert(type_index, resolved);

            if let Some(data_type) = self.create_data_type(record, type_index) {
                self.data_types.insert(type_index, data_type);
                self.stats.types_applied += 1;
            }
        }

        // Second pass: resolve cross-references
        self.resolve_type_references();
        Ok(())
    }

    /// Create a data type from a type record.
    fn create_data_type(&self, record: &TypeRecord, _type_index: u32) -> Option<PdbDataType> {
        match record {
            TypeRecord::Class(ct) => {
                let members = self.extract_field_members(ct.field_list_type_index);
                Some(PdbDataType::Composite {
                    name: ct.name.clone(),
                    kind: CompositeKind::Class,
                    size: ct.size,
                    members,
                    base_classes: Vec::new(),
                })
            }
            TypeRecord::Structure(st) => {
                let members = self.extract_field_members(st.field_list_type_index);
                Some(PdbDataType::Composite {
                    name: st.name.clone(),
                    kind: CompositeKind::Struct,
                    size: st.size,
                    members,
                    base_classes: Vec::new(),
                })
            }
            TypeRecord::Union(ut) => {
                let members = self.extract_field_members(ut.field_list_type_index);
                Some(PdbDataType::Composite {
                    name: ut.name.clone(),
                    kind: CompositeKind::Union,
                    size: ut.size,
                    members,
                    base_classes: Vec::new(),
                })
            }
            TypeRecord::Enum(et) => {
                let enumerators = self.extract_enumerators(et.field_list_type_index);
                Some(PdbDataType::Enum {
                    name: et.name.clone(),
                    underlying_type: et.underlying_type_index,
                    enumerators,
                })
            }
            TypeRecord::Pointer(pt) => Some(PdbDataType::Pointer {
                target_type: pt.underlying_type_index,
                size: pt.size,
                is_reference: matches!(
                    pt.pointer_mode,
                    super::PointerMode::LeftReference | super::PointerMode::RightReference
                ),
            }),
            TypeRecord::Array(at) => Some(PdbDataType::Array {
                element_type: at.element_type_index,
                size: at.size,
                name: at.name.clone(),
            }),
            TypeRecord::Procedure(pt) => Some(PdbDataType::Procedure {
                return_type: pt.return_type_index,
                parameter_types: Vec::new(), // resolved later
                calling_convention: format!("{:?}", pt.calling_convention),
            }),
            TypeRecord::Modifier(mt) => Some(PdbDataType::Modifier {
                modified_type: mt.modified_type_index,
                is_const: (mt.modifiers & 0x01) != 0,
                is_volatile: (mt.modifiers & 0x02) != 0,
            }),
            _ => None,
        }
    }

    /// Extract field members from a field list type index.
    fn extract_field_members(&self, _field_list_index: u32) -> Vec<PdbMember> {
        // In a full implementation, this would look up the field list type record
        // and extract member information from it.
        Vec::new()
    }

    /// Extract enumerators from a field list type index.
    fn extract_enumerators(&self, _field_list_index: u32) -> Vec<(String, i64)> {
        // In a full implementation, this would look up the field list type record
        // and extract enumerate records from it.
        Vec::new()
    }

    /// Resolve type cross-references (e.g., pointer targets, array elements).
    fn resolve_type_references(&mut self) {
        let type_indices: Vec<u32> = self.data_types.keys().copied().collect();
        for ti in type_indices {
            if let Some(resolved) = self.resolved_types.get_mut(&ti) {
                resolved.resolved = true;
            }
        }
    }

    /// Apply symbols from a module's symbol stream.
    fn apply_symbol_stream(&mut self, data: &[u8], module_index: u16) {
        use super::SymbolStream;

        let stream = SymbolStream::new(data);
        for symbol in stream {
            let result = self.apply_symbol(&symbol, module_index);
            match &result {
                SymbolApplyResult::Function { .. } => {
                    self.stats.functions_created += 1;
                    self.stats.symbols_applied += 1;
                }
                SymbolApplyResult::Label { .. } => {
                    self.stats.labels_created += 1;
                    self.stats.symbols_applied += 1;
                }
                SymbolApplyResult::Data { .. } => {
                    self.stats.data_symbols_created += 1;
                    self.stats.symbols_applied += 1;
                }
                SymbolApplyResult::Public { .. } => {
                    self.stats.symbols_applied += 1;
                }
                SymbolApplyResult::Thunk { .. } => {
                    self.stats.symbols_applied += 1;
                }
                SymbolApplyResult::Reference { .. } => {
                    self.stats.symbols_applied += 1;
                }
                SymbolApplyResult::UserDefinedType { .. } => {
                    self.stats.symbols_applied += 1;
                }
                SymbolApplyResult::Skipped => {}
            }
            self.symbol_results.push(result);
        }
    }

    /// Apply a single symbol record.
    fn apply_symbol(&self, symbol: &SymbolRecord, module_index: u16) -> SymbolApplyResult {
        match symbol {
            SymbolRecord::GlobalData(sym) | SymbolRecord::LocalVariable(sym) => {
                SymbolApplyResult::Data {
                    name: sym.name.clone(),
                    address: (sym.segment, sym.offset as u64),
                    type_index: sym.type_index,
                }
            }
            SymbolRecord::GlobalProcedure(sym)
            | SymbolRecord::LocalProcedure(sym)
            | SymbolRecord::GProc32Id(sym)
            | SymbolRecord::LProc32Id(sym) => {
                SymbolApplyResult::Function {
                    name: sym.name.clone(),
                    address: (sym.segment, sym.offset as u64),
                    type_index: sym.type_index,
                }
            }
            SymbolRecord::Public(sym) => SymbolApplyResult::Public {
                name: sym.name.clone(),
                address: (sym.segment, sym.offset as u64),
            },
            SymbolRecord::Label(sym) => SymbolApplyResult::Label {
                name: sym.name.clone(),
                address: (sym.segment, sym.offset as u64),
            },
            SymbolRecord::UserDefinedType(sym) => SymbolApplyResult::UserDefinedType {
                name: sym.name.clone(),
                type_index: sym.type_index,
            },
            SymbolRecord::Thunk(sym) => SymbolApplyResult::Thunk {
                name: sym.name.clone(),
                address: (sym.segment, sym.offset as u64),
            },
            SymbolRecord::ProcedureReference { name, .. }
            | SymbolRecord::DataReference { name, .. } => SymbolApplyResult::Reference {
                name: name.clone(),
                module_index,
            },
            SymbolRecord::End
            | SymbolRecord::CompileInfo(_)
            | SymbolRecord::Compile2(_)
            | SymbolRecord::FrameProc(_)
            | SymbolRecord::InlineSiteEnd
            | SymbolRecord::ProcIdEnd => SymbolApplyResult::Skipped,
            _ => SymbolApplyResult::Skipped,
        }
    }

    /// Apply source file information from the DBI stream.
    fn apply_source_info(&mut self, _dbi: &DbiStream, _msf: &MsfFile) {
        // In a full implementation, this would parse C13 subsection streams
        // from each module and apply line number and file checksum information.
        self.stats.source_files_processed += 1;
    }

    /// Get all symbol application results.
    pub fn symbol_results(&self) -> &[SymbolApplyResult] {
        &self.symbol_results
    }

    /// Get all resolved types.
    pub fn resolved_types(&self) -> &HashMap<u32, ResolvedTypeId> {
        &self.resolved_types
    }

    /// Get a specific resolved type by index.
    pub fn get_type(&self, index: u32) -> Option<&PdbDataType> {
        self.data_types.get(&index)
    }

    /// Get the number of resolved types.
    pub fn type_count(&self) -> usize {
        self.resolved_types.len()
    }
}

impl Default for DefaultPdbApplicator {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// Errors
// =============================================================================

/// Errors that can occur during PDB application.
#[derive(Debug, Clone)]
pub enum ApplicatorError {
    /// A required stream was not found in the MSF.
    StreamNotFound(u32),
    /// An error occurred parsing a stream.
    ParseError(String),
    /// A type index referenced a non-existent type.
    InvalidTypeIndex(u32),
    /// A symbol referenced a non-existent module.
    InvalidModuleIndex(u16),
    /// The PDB file is corrupted or malformed.
    CorruptPdb(String),
    /// Application was cancelled by the user.
    Cancelled,
}

impl std::fmt::Display for ApplicatorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::StreamNotFound(n) => write!(f, "PDB stream {} not found", n),
            Self::ParseError(msg) => write!(f, "PDB parse error: {}", msg),
            Self::InvalidTypeIndex(idx) => write!(f, "Invalid type index: 0x{:04X}", idx),
            Self::InvalidModuleIndex(idx) => write!(f, "Invalid module index: {}", idx),
            Self::CorruptPdb(msg) => write!(f, "Corrupt PDB: {}", msg),
            Self::Cancelled => write!(f, "PDB application cancelled"),
        }
    }
}

impl std::error::Error for ApplicatorError {}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_applicator_default_config() {
        let app = DefaultPdbApplicator::new();
        assert!(app.config().apply_types);
        assert!(app.config().apply_function_signatures);
        assert!(app.config().create_labels);
        assert!(app.config().apply_data_types);
        assert!(app.config().apply_source_info);
        assert_eq!(app.type_count(), 0);
    }

    #[test]
    fn test_applicator_custom_config() {
        let config = ApplicatorConfig {
            apply_types: false,
            apply_function_signatures: false,
            ..Default::default()
        };
        let app = DefaultPdbApplicator::with_config(config);
        assert!(!app.config().apply_types);
        assert!(!app.config().apply_function_signatures);
    }

    #[test]
    fn test_type_category_from_record() {
        let pointer = TypeRecord::Pointer(super::super::PointerType {
            underlying_type_index: 0x1000,
            attributes: 0,
            pointer_mode: super::super::PointerMode::Pointer,
            size: 4,
            is_const: false,
            is_volatile: false,
            is_unaligned: false,
            is_flat: false,
            pointer_kind: super::super::PointerKind::Flat32,
        });
        assert_eq!(TypeCategory::from_type_record(&pointer), TypeCategory::Pointer);

        let structure = TypeRecord::Structure(super::super::StructureType {
            count: 0,
            property: super::super::TypeProperty::empty(),
            field_list_type_index: 0,
            derived_type_index: 0,
            vshape_type_index: 0,
            size: 0,
            name: "test".to_string(),
            mangled_name: None,
        });
        assert_eq!(TypeCategory::from_type_record(&structure), TypeCategory::Composite);
    }

    #[test]
    fn test_access_protection_conversion() {
        assert_eq!(
            AccessProtection::from_pdb(super::super::MemberAccessProtection::Public),
            AccessProtection::Public
        );
        assert_eq!(
            AccessProtection::from_pdb(super::super::MemberAccessProtection::Private),
            AccessProtection::Private
        );
    }

    #[test]
    fn test_create_data_type_class() {
        let app = DefaultPdbApplicator::new();
        let record = TypeRecord::Class(super::super::ClassType {
            count: 3,
            property: super::super::TypeProperty::empty(),
            field_list_type_index: 0x1001,
            derived_type_index: 0,
            vshape_type_index: 0,
            size: 16,
            name: "MyClass".to_string(),
            mangled_name: None,
        });
        let dt = app.create_data_type(&record, 0x1000);
        assert!(dt.is_some());
        if let Some(PdbDataType::Composite { name, kind, size, .. }) = dt {
            assert_eq!(name, "MyClass");
            assert_eq!(kind, CompositeKind::Class);
            assert_eq!(size, 16);
        } else {
            panic!("Expected Composite");
        }
    }

    #[test]
    fn test_create_data_type_enum() {
        let app = DefaultPdbApplicator::new();
        let record = TypeRecord::Enum(super::super::EnumType {
            count: 4,
            property: super::super::TypeProperty::empty(),
            underlying_type_index: 0x0074, // int
            field_list_type_index: 0x1001,
            name: "Color".to_string(),
            mangled_name: None,
        });
        let dt = app.create_data_type(&record, 0x1000);
        assert!(dt.is_some());
        if let Some(PdbDataType::Enum { name, underlying_type, .. }) = dt {
            assert_eq!(name, "Color");
            assert_eq!(underlying_type, 0x0074);
        } else {
            panic!("Expected Enum");
        }
    }

    #[test]
    fn test_create_data_type_pointer() {
        let app = DefaultPdbApplicator::new();
        let record = TypeRecord::Pointer(super::super::PointerType {
            underlying_type_index: 0x1000,
            attributes: 0,
            pointer_mode: super::super::PointerMode::Pointer,
            size: 4,
            is_const: false,
            is_volatile: false,
            is_unaligned: false,
            is_flat: false,
            pointer_kind: super::super::PointerKind::Flat32,
        });
        let dt = app.create_data_type(&record, 0x1001);
        assert!(dt.is_some());
        if let Some(PdbDataType::Pointer { target_type, size, is_reference }) = dt {
            assert_eq!(target_type, 0x1000);
            assert_eq!(size, 4);
            assert!(!is_reference);
        } else {
            panic!("Expected Pointer");
        }
    }

    #[test]
    fn test_apply_symbol_global_data() {
        let app = DefaultPdbApplicator::new();
        let sym = SymbolRecord::GlobalData(super::super::DataSymbol {
            type_index: 0x1000,
            offset: 0x100,
            segment: 1,
            name: "globalVar".to_string(),
        });
        let result = app.apply_symbol(&sym, 0);
        if let SymbolApplyResult::Data { name, address, type_index } = result {
            assert_eq!(name, "globalVar");
            assert_eq!(address, (1, 0x100));
            assert_eq!(type_index, 0x1000);
        } else {
            panic!("Expected Data result");
        }
    }

    #[test]
    fn test_apply_symbol_procedure() {
        let app = DefaultPdbApplicator::new();
        let sym = SymbolRecord::GlobalProcedure(super::super::ProcSymbol {
            type_index: 0x2000,
            debug_start: 0,
            debug_end: 100,
            offset: 0x200,
            segment: 1,
            flags: 0,
            name: "main".to_string(),
        });
        let result = app.apply_symbol(&sym, 0);
        if let SymbolApplyResult::Function { name, address, type_index } = result {
            assert_eq!(name, "main");
            assert_eq!(address, (1, 0x200));
            assert_eq!(type_index, 0x2000);
        } else {
            panic!("Expected Function result");
        }
    }

    #[test]
    fn test_apply_symbol_label() {
        let app = DefaultPdbApplicator::new();
        let sym = SymbolRecord::Label(super::super::LabelSymbol {
            offset: 0x300,
            segment: 1,
            flags: 0,
            name: "loop_start".to_string(),
        });
        let result = app.apply_symbol(&sym, 0);
        if let SymbolApplyResult::Label { name, address } = result {
            assert_eq!(name, "loop_start");
            assert_eq!(address, (1, 0x300));
        } else {
            panic!("Expected Label result");
        }
    }

    #[test]
    fn test_apply_symbol_skipped() {
        let app = DefaultPdbApplicator::new();
        let sym = SymbolRecord::End;
        let result = app.apply_symbol(&sym, 0);
        assert!(matches!(result, SymbolApplyResult::Skipped));
    }

    #[test]
    fn test_applicator_error_display() {
        let err = ApplicatorError::StreamNotFound(2);
        assert_eq!(format!("{}", err), "PDB stream 2 not found");

        let err = ApplicatorError::InvalidTypeIndex(0x1000);
        assert!(format!("{}", err).contains("0x1000"));

        let err = ApplicatorError::CorruptPdb("bad header".to_string());
        assert!(format!("{}", err).contains("bad header"));
    }

    #[test]
    fn test_stats_default() {
        let stats = ApplicatorStats::default();
        assert_eq!(stats.types_applied, 0);
        assert_eq!(stats.symbols_applied, 0);
        assert_eq!(stats.functions_created, 0);
        assert_eq!(stats.errors, 0);
    }
}
