//! Symbol Applier Factory -- dispatches PDB symbol records to type-specific appliers.
//!
//! Ports Ghidra's `ghidra.app.util.pdb.pdbapplicator.SymbolApplierFactory`.
//!
//! The factory examines each incoming [`SymbolRecord`] and routes it to the
//! appropriate applier implementation based on the symbol kind. Each applier
//! knows how to interpret its specific symbol variant and produce the
//! corresponding program artifacts (functions, labels, data symbols, etc.).

use std::collections::HashMap;
use std::fmt;

use super::super::abstract_pdb::PdbReaderContext;
use super::super::{
    SymbolRecord, DataSymbol, ProcSymbol, PublicSymbol, LabelSymbol,
    RegSymbol, RegRelSymbol, BpRelSymbol, ConstantSymbol, UdtSymbol,
    ThreadSymbol, ThunkSymbol, CompileInfo, FrameProcInfo,
};

// =============================================================================
// Errors
// =============================================================================

/// Errors that can occur when applying a symbol record.
#[derive(Debug, Clone)]
pub enum SymbolApplyError {
    /// The symbol kind is not supported by any registered applier.
    Unsupported,
    /// The symbol references an invalid type index.
    InvalidTypeIndex(u32),
    /// The symbol data is malformed or truncated.
    Malformed(String),
    /// Application was cancelled.
    Cancelled,
    /// An internal error occurred.
    InternalError(String),
}

impl fmt::Display for SymbolApplyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsupported => write!(f, "Unsupported symbol kind"),
            Self::InvalidTypeIndex(idx) => write!(f, "Invalid type index: 0x{:04X}", idx),
            Self::Malformed(msg) => write!(f, "Malformed symbol: {}", msg),
            Self::Cancelled => write!(f, "Symbol application cancelled"),
            Self::InternalError(msg) => write!(f, "Internal error: {}", msg),
        }
    }
}

impl std::error::Error for SymbolApplyError {}

// =============================================================================
// Symbol Application Result
// =============================================================================

/// The result of successfully applying a symbol record.
#[derive(Debug, Clone)]
pub enum SymbolApplicationResult {
    /// A function was created or updated.
    Function {
        /// The function name.
        name: String,
        /// The address (segment:offset).
        address: (u16, u64),
        /// The type index for the function signature.
        type_index: u32,
    },
    /// A label was created.
    Label {
        /// The label name.
        name: String,
        /// The address (segment:offset).
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
    /// A public symbol was recorded.
    Public {
        /// The symbol name.
        name: String,
        /// The address (segment:offset).
        address: (u16, u64),
    },
    /// A user-defined type reference.
    UserDefinedType {
        /// The UDT name.
        name: String,
        /// The type index.
        type_index: u32,
    },
    /// A thunk function was created.
    Thunk {
        /// The thunk name.
        name: String,
        /// The address (segment:offset).
        address: (u16, u64),
    },
    /// A constant was registered.
    Constant {
        /// The constant name.
        name: String,
        /// The type index.
        type_index: u32,
        /// The constant value.
        value: u64,
    },
    /// A register-relative variable.
    RegisterRelative {
        /// The variable name.
        name: String,
        /// The register.
        register: u16,
        /// The offset from the register.
        offset: i32,
        /// The type index.
        type_index: u32,
    },
    /// A procedure/data reference was recorded.
    Reference {
        /// The reference name.
        name: String,
        /// The module index.
        module_index: u16,
    },
    /// A thread-local storage symbol.
    ThreadStorage {
        /// The symbol name.
        name: String,
        /// The address (segment:offset).
        address: (u16, u64),
        /// The type index.
        type_index: u32,
    },
    /// The symbol was skipped (not applicable or already handled).
    Skipped,
}

// =============================================================================
// Symbol Applier Trait
// =============================================================================

/// Trait for individual symbol applier implementations.
///
/// Each applier handles a specific kind of PDB symbol record.
pub trait SymbolApplier {
    /// Apply a symbol record and return the result.
    ///
    /// `context` provides access to the full PDB reader context for
    /// resolving cross-references (e.g., looking up type records).
    fn apply(
        &self,
        symbol: &SymbolRecord,
        context: Option<&PdbReaderContext>,
    ) -> Result<SymbolApplicationResult, SymbolApplyError>;

    /// Get a human-readable name for this applier.
    fn name(&self) -> &'static str;
}

// =============================================================================
// Data Symbol Applier
// =============================================================================

/// Applies data symbol records (S_GDATA32, S_LDATA32).
struct DataSymbolApplier;

impl SymbolApplier for DataSymbolApplier {
    fn apply(
        &self,
        symbol: &SymbolRecord,
        _context: Option<&PdbReaderContext>,
    ) -> Result<SymbolApplicationResult, SymbolApplyError> {
        match symbol {
            SymbolRecord::GlobalData(sym) | SymbolRecord::LocalVariable(sym) => {
                Ok(SymbolApplicationResult::Data {
                    name: sym.name.clone(),
                    address: (sym.segment, sym.offset as u64),
                    type_index: sym.type_index,
                })
            }
            _ => Err(SymbolApplyError::Malformed("Expected data symbol".into())),
        }
    }

    fn name(&self) -> &'static str {
        "DataSymbolApplier"
    }
}

// =============================================================================
// Procedure Symbol Applier
// =============================================================================

/// Applies procedure/function symbol records (S_GPROC32, S_LPROC32).
struct ProcedureSymbolApplier;

impl SymbolApplier for ProcedureSymbolApplier {
    fn apply(
        &self,
        symbol: &SymbolRecord,
        _context: Option<&PdbReaderContext>,
    ) -> Result<SymbolApplicationResult, SymbolApplyError> {
        match symbol {
            SymbolRecord::GlobalProcedure(sym)
            | SymbolRecord::LocalProcedure(sym)
            | SymbolRecord::GProc32Id(sym)
            | SymbolRecord::LProc32Id(sym)
            | SymbolRecord::ManagedProcedure(sym) => {
                Ok(SymbolApplicationResult::Function {
                    name: sym.name.clone(),
                    address: (sym.segment, sym.offset as u64),
                    type_index: sym.type_index,
                })
            }
            _ => Err(SymbolApplyError::Malformed("Expected procedure symbol".into())),
        }
    }

    fn name(&self) -> &'static str {
        "ProcedureSymbolApplier"
    }
}

// =============================================================================
// Public Symbol Applier
// =============================================================================

/// Applies public symbol records (S_PUB32).
struct PublicSymbolApplier;

impl SymbolApplier for PublicSymbolApplier {
    fn apply(
        &self,
        symbol: &SymbolRecord,
        _context: Option<&PdbReaderContext>,
    ) -> Result<SymbolApplicationResult, SymbolApplyError> {
        match symbol {
            SymbolRecord::Public(sym) => {
                Ok(SymbolApplicationResult::Public {
                    name: sym.name.clone(),
                    address: (sym.segment, sym.offset as u64),
                })
            }
            _ => Err(SymbolApplyError::Malformed("Expected public symbol".into())),
        }
    }

    fn name(&self) -> &'static str {
        "PublicSymbolApplier"
    }
}

// =============================================================================
// Label Symbol Applier
// =============================================================================

/// Applies label symbol records (S_LABEL32).
struct LabelSymbolApplier;

impl SymbolApplier for LabelSymbolApplier {
    fn apply(
        &self,
        symbol: &SymbolRecord,
        _context: Option<&PdbReaderContext>,
    ) -> Result<SymbolApplicationResult, SymbolApplyError> {
        match symbol {
            SymbolRecord::Label(sym) => {
                Ok(SymbolApplicationResult::Label {
                    name: sym.name.clone(),
                    address: (sym.segment, sym.offset as u64),
                })
            }
            _ => Err(SymbolApplyError::Malformed("Expected label symbol".into())),
        }
    }

    fn name(&self) -> &'static str {
        "LabelSymbolApplier"
    }
}

// =============================================================================
// UDT Symbol Applier
// =============================================================================

/// Applies user-defined type symbol records (S_UDT).
struct UdtSymbolApplier;

impl SymbolApplier for UdtSymbolApplier {
    fn apply(
        &self,
        symbol: &SymbolRecord,
        _context: Option<&PdbReaderContext>,
    ) -> Result<SymbolApplicationResult, SymbolApplyError> {
        match symbol {
            SymbolRecord::UserDefinedType(sym) => {
                Ok(SymbolApplicationResult::UserDefinedType {
                    name: sym.name.clone(),
                    type_index: sym.type_index,
                })
            }
            _ => Err(SymbolApplyError::Malformed("Expected UDT symbol".into())),
        }
    }

    fn name(&self) -> &'static str {
        "UdtSymbolApplier"
    }
}

// =============================================================================
// Thunk Symbol Applier
// =============================================================================

/// Applies thunk symbol records (S_THUNK32).
struct ThunkSymbolApplier;

impl SymbolApplier for ThunkSymbolApplier {
    fn apply(
        &self,
        symbol: &SymbolRecord,
        _context: Option<&PdbReaderContext>,
    ) -> Result<SymbolApplicationResult, SymbolApplyError> {
        match symbol {
            SymbolRecord::Thunk(sym) => {
                Ok(SymbolApplicationResult::Thunk {
                    name: sym.name.clone(),
                    address: (sym.segment, sym.offset as u64),
                })
            }
            _ => Err(SymbolApplyError::Malformed("Expected thunk symbol".into())),
        }
    }

    fn name(&self) -> &'static str {
        "ThunkSymbolApplier"
    }
}

// =============================================================================
// Constant Symbol Applier
// =============================================================================

/// Applies constant symbol records (S_CONSTANT).
struct ConstantSymbolApplier;

impl SymbolApplier for ConstantSymbolApplier {
    fn apply(
        &self,
        symbol: &SymbolRecord,
        _context: Option<&PdbReaderContext>,
    ) -> Result<SymbolApplicationResult, SymbolApplyError> {
        match symbol {
            SymbolRecord::Constant(sym) => {
                Ok(SymbolApplicationResult::Constant {
                    name: sym.name.clone(),
                    type_index: sym.type_index,
                    value: sym.value,
                })
            }
            _ => Err(SymbolApplyError::Malformed("Expected constant symbol".into())),
        }
    }

    fn name(&self) -> &'static str {
        "ConstantSymbolApplier"
    }
}

// =============================================================================
// Reference Symbol Applier
// =============================================================================

/// Applies procedure and data reference symbols (S_PROCREF, S_DATAREF).
struct ReferenceSymbolApplier;

impl SymbolApplier for ReferenceSymbolApplier {
    fn apply(
        &self,
        symbol: &SymbolRecord,
        _context: Option<&PdbReaderContext>,
    ) -> Result<SymbolApplicationResult, SymbolApplyError> {
        match symbol {
            SymbolRecord::ProcedureReference { name, module_index, .. }
            | SymbolRecord::DataReference { name, module_index, .. } => {
                Ok(SymbolApplicationResult::Reference {
                    name: name.clone(),
                    module_index: *module_index,
                })
            }
            _ => Err(SymbolApplyError::Malformed("Expected reference symbol".into())),
        }
    }

    fn name(&self) -> &'static str {
        "ReferenceSymbolApplier"
    }
}

// =============================================================================
// Thread Storage Symbol Applier
// =============================================================================

/// Applies thread-local storage symbol records (S_LTHREAD32, S_GTHREAD32).
struct ThreadStorageSymbolApplier;

impl SymbolApplier for ThreadStorageSymbolApplier {
    fn apply(
        &self,
        symbol: &SymbolRecord,
        _context: Option<&PdbReaderContext>,
    ) -> Result<SymbolApplicationResult, SymbolApplyError> {
        match symbol {
            SymbolRecord::ThreadStorage(sym) => {
                Ok(SymbolApplicationResult::ThreadStorage {
                    name: sym.name.clone(),
                    address: (sym.segment, sym.offset as u64),
                    type_index: sym.type_index,
                })
            }
            _ => Err(SymbolApplyError::Malformed("Expected thread storage symbol".into())),
        }
    }

    fn name(&self) -> &'static str {
        "ThreadStorageSymbolApplier"
    }
}

// =============================================================================
// Managed Data Symbol Applier
// =============================================================================

/// Applies managed data symbol records.
struct ManagedDataSymbolApplier;

impl SymbolApplier for ManagedDataSymbolApplier {
    fn apply(
        &self,
        symbol: &SymbolRecord,
        _context: Option<&PdbReaderContext>,
    ) -> Result<SymbolApplicationResult, SymbolApplyError> {
        match symbol {
            SymbolRecord::ManagedData(sym) => {
                Ok(SymbolApplicationResult::Data {
                    name: sym.name.clone(),
                    address: (sym.segment, sym.offset as u64),
                    type_index: sym.type_index,
                })
            }
            _ => Err(SymbolApplyError::Malformed("Expected managed data symbol".into())),
        }
    }

    fn name(&self) -> &'static str {
        "ManagedDataSymbolApplier"
    }
}

// =============================================================================
// Symbol Applier Factory
// =============================================================================

/// Factory that dispatches PDB symbol records to the appropriate applier.
///
/// Maintains a registry of [`SymbolApplier`] implementations keyed by
/// the symbol variants they handle. When a symbol record arrives, the
/// factory determines its kind and routes it to the correct applier.
///
/// Ports Ghidra's `SymbolApplierFactory` which serves as the central
/// dispatch for all symbol processing in the PDB applicator.
pub struct SymbolApplierFactory {
    /// Whether this factory has been initialized.
    initialized: bool,
    /// Count of symbols processed by this factory.
    processed_count: u64,
    /// Count of symbols that were successfully applied.
    applied_count: u64,
    /// Count of symbols that were skipped (unsupported).
    skipped_count: u64,
}

impl SymbolApplierFactory {
    /// Create a new symbol applier factory.
    pub fn new() -> Self {
        Self {
            initialized: true,
            processed_count: 0,
            applied_count: 0,
            skipped_count: 0,
        }
    }

    /// Apply a symbol record using the appropriate applier.
    ///
    /// Returns `Ok(true)` if the symbol was applied, `Ok(false)` if skipped.
    pub fn apply_symbol(
        &mut self,
        symbol: &SymbolRecord,
        context: Option<&PdbReaderContext>,
    ) -> Result<bool, SymbolApplyError> {
        self.processed_count += 1;

        let result = self.dispatch_symbol(symbol, context)?;

        match result {
            SymbolApplicationResult::Skipped => {
                self.skipped_count += 1;
                Ok(false)
            }
            _ => {
                self.applied_count += 1;
                Ok(true)
            }
        }
    }

    /// Dispatch a symbol to the correct applier based on its variant.
    fn dispatch_symbol(
        &self,
        symbol: &SymbolRecord,
        context: Option<&PdbReaderContext>,
    ) -> Result<SymbolApplicationResult, SymbolApplyError> {
        match symbol {
            // Data symbols
            SymbolRecord::GlobalData(_)
            | SymbolRecord::LocalVariable(_)
            | SymbolRecord::ManagedData(_) => {
                let applier: &dyn SymbolApplier = match symbol {
                    SymbolRecord::ManagedData(_) => &ManagedDataSymbolApplier,
                    _ => &DataSymbolApplier,
                };
                applier.apply(symbol, context)
            }

            // Procedure symbols
            SymbolRecord::GlobalProcedure(_)
            | SymbolRecord::LocalProcedure(_)
            | SymbolRecord::GProc32Id(_)
            | SymbolRecord::LProc32Id(_)
            | SymbolRecord::ManagedProcedure(_) => {
                ProcedureSymbolApplier.apply(symbol, context)
            }

            // Public symbols
            SymbolRecord::Public(_) => {
                PublicSymbolApplier.apply(symbol, context)
            }

            // Label symbols
            SymbolRecord::Label(_) => {
                LabelSymbolApplier.apply(symbol, context)
            }

            // UDT symbols
            SymbolRecord::UserDefinedType(_) => {
                UdtSymbolApplier.apply(symbol, context)
            }

            // Thunk symbols
            SymbolRecord::Thunk(_) => {
                ThunkSymbolApplier.apply(symbol, context)
            }

            // Constant symbols
            SymbolRecord::Constant(_) => {
                ConstantSymbolApplier.apply(symbol, context)
            }

            // Reference symbols
            SymbolRecord::ProcedureReference { .. }
            | SymbolRecord::DataReference { .. } => {
                ReferenceSymbolApplier.apply(symbol, context)
            }

            // Thread storage
            SymbolRecord::ThreadStorage(_) => {
                ThreadStorageSymbolApplier.apply(symbol, context)
            }

            // Skipped symbol types
            SymbolRecord::End
            | SymbolRecord::CompileInfo(_)
            | SymbolRecord::Compile2(_)
            | SymbolRecord::FrameProc(_)
            | SymbolRecord::InlineSiteEnd
            | SymbolRecord::ProcIdEnd => {
                Ok(SymbolApplicationResult::Skipped)
            }

            // All other symbols are currently unsupported
            _ => Ok(SymbolApplicationResult::Skipped),
        }
    }

    /// Get the total number of symbols processed.
    pub fn processed_count(&self) -> u64 {
        self.processed_count
    }

    /// Get the number of symbols successfully applied.
    pub fn applied_count(&self) -> u64 {
        self.applied_count
    }

    /// Get the number of symbols skipped.
    pub fn skipped_count(&self) -> u64 {
        self.skipped_count
    }

    /// Reset the factory counters.
    pub fn reset_counters(&mut self) {
        self.processed_count = 0;
        self.applied_count = 0;
        self.skipped_count = 0;
    }
}

impl Default for SymbolApplierFactory {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for SymbolApplierFactory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SymbolApplierFactory")
            .field("initialized", &self.initialized)
            .field("processed", &self.processed_count)
            .field("applied", &self.applied_count)
            .field("skipped", &self.skipped_count)
            .finish()
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_factory_default() {
        let factory = SymbolApplierFactory::new();
        assert_eq!(factory.processed_count(), 0);
        assert_eq!(factory.applied_count(), 0);
        assert_eq!(factory.skipped_count(), 0);
    }

    #[test]
    fn test_apply_global_data() {
        let mut factory = SymbolApplierFactory::new();
        let sym = SymbolRecord::GlobalData(DataSymbol {
            type_index: 0x1000,
            offset: 0x100,
            segment: 1,
            name: "globalVar".to_string(),
        });
        let result = factory.apply_symbol(&sym, None);
        assert!(result.is_ok());
        assert!(result.unwrap()); // applied
        assert_eq!(factory.applied_count(), 1);
        assert_eq!(factory.processed_count(), 1);
    }

    #[test]
    fn test_apply_procedure() {
        let mut factory = SymbolApplierFactory::new();
        let sym = SymbolRecord::GlobalProcedure(ProcSymbol {
            type_index: 0x2000,
            debug_start: 0,
            debug_end: 100,
            offset: 0x200,
            segment: 1,
            flags: 0,
            name: "main".to_string(),
        });
        let result = factory.apply_symbol(&sym, None);
        assert!(result.is_ok());
        assert!(result.unwrap());
        assert_eq!(factory.applied_count(), 1);
    }

    #[test]
    fn test_apply_public() {
        let mut factory = SymbolApplierFactory::new();
        let sym = SymbolRecord::Public(PublicSymbol {
            flags: 0,
            offset: 0x300,
            segment: 1,
            name: "printf".to_string(),
        });
        let result = factory.apply_symbol(&sym, None);
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn test_apply_label() {
        let mut factory = SymbolApplierFactory::new();
        let sym = SymbolRecord::Label(LabelSymbol {
            offset: 0x400,
            segment: 1,
            flags: 0,
            name: "loop_start".to_string(),
        });
        let result = factory.apply_symbol(&sym, None);
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn test_apply_udt() {
        let mut factory = SymbolApplierFactory::new();
        let sym = SymbolRecord::UserDefinedType(UdtSymbol {
            type_index: 0x1001,
            name: "MyStruct".to_string(),
        });
        let result = factory.apply_symbol(&sym, None);
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn test_apply_thunk() {
        let mut factory = SymbolApplierFactory::new();
        let sym = SymbolRecord::Thunk(ThunkSymbol {
            parent_offset: 0,
            end_offset: 0,
            next_offset: 0,
            offset: 0x500,
            segment: 1,
            length: 5,
            thunk_type: 0,
            name: "_thunk_foo".to_string(),
            variant_offset: 0,
        });
        let result = factory.apply_symbol(&sym, None);
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn test_apply_constant() {
        let mut factory = SymbolApplierFactory::new();
        let sym = SymbolRecord::Constant(ConstantSymbol {
            type_index: 0x0074, // int
            value: 42,
            name: "ANSWER".to_string(),
        });
        let result = factory.apply_symbol(&sym, None);
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn test_apply_reference() {
        let mut factory = SymbolApplierFactory::new();
        let sym = SymbolRecord::ProcedureReference {
            name: "external_func".to_string(),
            module_index: 3,
            type_index: 0x2000,
        };
        let result = factory.apply_symbol(&sym, None);
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn test_apply_thread_storage() {
        let mut factory = SymbolApplierFactory::new();
        let sym = SymbolRecord::ThreadStorage(ThreadSymbol {
            type_index: 0x1000,
            offset: 0x10,
            segment: 2,
            name: "tls_var".to_string(),
        });
        let result = factory.apply_symbol(&sym, None);
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn test_apply_end_skipped() {
        let mut factory = SymbolApplierFactory::new();
        let sym = SymbolRecord::End;
        let result = factory.apply_symbol(&sym, None);
        assert!(result.is_ok());
        assert!(!result.unwrap()); // skipped
        assert_eq!(factory.skipped_count(), 1);
    }

    #[test]
    fn test_apply_compile_skipped() {
        let mut factory = SymbolApplierFactory::new();
        let sym = SymbolRecord::CompileInfo(CompileInfo {
            flags: 0,
            machine: 0x8664,
            frontend_major: 19,
            frontend_minor: 0,
            frontend_build: 0,
            backend_major: 19,
            backend_minor: 0,
            backend_build: 0,
            version_string: "Microsoft (R) C/C++".to_string(),
        });
        let result = factory.apply_symbol(&sym, None);
        assert!(result.is_ok());
        assert!(!result.unwrap()); // skipped
    }

    #[test]
    fn test_reset_counters() {
        let mut factory = SymbolApplierFactory::new();
        let sym = SymbolRecord::End;
        factory.apply_symbol(&sym, None).unwrap();
        assert_eq!(factory.processed_count(), 1);

        factory.reset_counters();
        assert_eq!(factory.processed_count(), 0);
        assert_eq!(factory.applied_count(), 0);
        assert_eq!(factory.skipped_count(), 0);
    }

    #[test]
    fn test_dispatch_data() {
        let factory = SymbolApplierFactory::new();
        let sym = SymbolRecord::GlobalData(DataSymbol {
            type_index: 0x1000,
            offset: 0,
            segment: 1,
            name: "x".to_string(),
        });
        let result = factory.dispatch_symbol(&sym, None);
        assert!(result.is_ok());
        match result.unwrap() {
            SymbolApplicationResult::Data { name, .. } => assert_eq!(name, "x"),
            _ => panic!("Expected Data result"),
        }
    }

    #[test]
    fn test_dispatch_function() {
        let factory = SymbolApplierFactory::new();
        let sym = SymbolRecord::GlobalProcedure(ProcSymbol {
            type_index: 0x2000,
            debug_start: 0,
            debug_end: 50,
            offset: 0x100,
            segment: 1,
            flags: 0,
            name: "func".to_string(),
        });
        let result = factory.dispatch_symbol(&sym, None);
        assert!(result.is_ok());
        match result.unwrap() {
            SymbolApplicationResult::Function { name, address, type_index } => {
                assert_eq!(name, "func");
                assert_eq!(address, (1, 0x100));
                assert_eq!(type_index, 0x2000);
            }
            _ => panic!("Expected Function result"),
        }
    }

    #[test]
    fn test_error_display() {
        let err = SymbolApplyError::InvalidTypeIndex(0x1000);
        assert!(format!("{}", err).contains("0x1000"));

        let err = SymbolApplyError::Malformed("bad".into());
        assert!(format!("{}", err).contains("bad"));

        let err = SymbolApplyError::Unsupported;
        assert!(format!("{}", err).contains("Unsupported"));
    }

    #[test]
    fn test_debug_format() {
        let factory = SymbolApplierFactory::new();
        let dbg = format!("{:?}", factory);
        assert!(dbg.contains("SymbolApplierFactory"));
    }
}
