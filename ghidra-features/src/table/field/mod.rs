//! Program-location-based table column definitions.
//!
//! This sub-module is a Rust port of Ghidra's `ghidra.util.table.field`
//! Java package, providing:
//!
//! - **Core types** ([`core`]): [`AddressBasedLocation`], [`ReferenceEndpoint`],
//!   [`IncomingReferenceEndpoint`], [`OutgoingReferenceEndpoint`],
//!   [`ReferenceAddressPair`], [`CodeUnitTableCellData`].
//!
//! - **Traits** ([`traits`]): [`ProgramBasedDynamicTableColumn`],
//!   [`ProgramLocationTableColumn`], [`Settings`], [`ServiceProvider`],
//!   [`ProgramInfo`], [`RefType`], [`SymbolType`], [`SourceType`].
//!
//! - **Settings** ([`settings_defs`]): Column settings definitions
//!   controlling display options (byte count, code unit count,
//!   inline/thunk/noreturn annotations, address range endpoints, etc.).
//!
//! - **Address columns** ([`address_columns`]): [`AddressTableColumn`],
//!   [`LabelTableColumn`], [`NamespaceTableColumn`], [`EOLCommentTableColumn`].
//!
//! - **Function columns** ([`function_columns`]): [`FunctionInfo`],
//!   [`FunctionNameTableColumn`], [`FunctionSignatureTableColumn`],
//!   [`FunctionPurgeTableColumn`], plus boolean status columns.
//!
//! - **Reference columns** ([`reference_columns`]): Source/destination
//!   address, bytes, label, function, preview, and type columns for
//!   cross-reference tables.
//!
//! - **Code unit columns** ([`code_unit_columns`]): [`CodeUnitTableColumn`],
//!   [`BytesTableColumn`], [`ByteCountProgramLocationBasedTableColumn`].
//!
//! - **Memory columns** ([`memory_columns`]): Section name, source section,
//!   and memory block type columns.
//!
//! - **Misc columns** ([`misc_columns`]): [`SourceTypeTableColumn`],
//!   [`SymbolTypeTableColumn`], [`MonospacedByteRenderer`].

pub mod core;
pub mod traits;
pub mod settings_defs;
pub mod address_columns;
pub mod function_columns;
pub mod reference_columns;
pub mod code_unit_columns;
pub mod memory_columns;
pub mod misc_columns;

// Re-export the most-used types at the field level.
pub use core::{
    AddressBasedLocation, ReferenceEndpoint, IncomingReferenceEndpoint,
    OutgoingReferenceEndpoint, ReferenceAddressPair, CodeUnitTableCellData,
    ReferenceKind,
};
pub use traits::{
    ProgramBasedDynamicTableColumn, ProgramLocationTableColumn,
    ProgramLocationTableColumnExt, ProgramBasedDynamicTableColumnExt,
    Settings, ServiceProvider, ProgramInfo, RefType, SymbolType, SourceType,
    SettingsValue,
};
pub use settings_defs::{
    SettingsDefinition, EnumSettingsDefinition, BooleanSettingsDefinition,
    AddressRangeEndpointSettingsDefinition, ByteCountSettingsDefinition,
    CodeUnitCountSettingsDefinition, CodeUnitOffsetSettingsDefinition,
    FunctionInlineSettingsDefinition, FunctionThunkSettingsDefinition,
    FunctionNoReturnSettingsDefinition, MemoryOffsetSettingsDefinition,
    ADDRESS_RANGE_ENDPOINT_DEF, BYTE_COUNT_DEF, CODE_UNIT_COUNT_DEF,
    CODE_UNIT_OFFSET_DEF, FUNCTION_INLINE_DEF, FUNCTION_THUNK_DEF,
    FUNCTION_NORETURN_DEF, MEMORY_OFFSET_DEF, BEGIN_CHOICE_INDEX, END_CHOICE_INDEX,
};
pub use address_columns::{
    AddressTableColumn, AddressTableDataTableColumn, AddressTableLengthTableColumn,
    LabelTableColumn, NamespaceTableColumn, EOLCommentTableColumn,
};
pub use function_columns::{
    FunctionInfo, FunctionNameTableColumn, FunctionSignatureTableColumn,
    FunctionCallingConventionTableColumn, FunctionPurgeTableColumn,
    FunctionParameterCountTableColumn, FunctionParameterStackSizeColumn,
    FunctionLocalStackSizeColumn, FunctionBodySizeTableColumn,
    FunctionTagTableColumn, IsFunctionInlineTableColumn,
    IsFunctionNonReturningTableColumn, IsFunctionVarargsTableColumn,
    IsFunctionCustomStorageTableColumn,
};
pub use reference_columns::{
    ReferenceFromAddressTableColumn, ReferenceToAddressTableColumn,
    ReferenceFromBytesTableColumn, ReferenceToBytesTableColumn,
    ReferenceFromLabelTableColumn, ReferenceFromFunctionTableColumn,
    ReferenceFromPreviewTableColumn, ReferenceToPreviewTableColumn,
    ReferenceTypeTableColumn, ReferenceCountToAddressTableColumn,
    OffcutReferenceCountToAddressTableColumn, PreviewTableColumn,
};
pub use code_unit_columns::{
    CodeUnitTableColumn, BytesTableColumn, ByteCountProgramLocationBasedTableColumn,
};
pub use memory_columns::{
    MemoryBlockType, MemoryBlockInfo,
    MemorySectionProgramLocationBasedTableColumn,
    MemorySourceProgramLocationBasedTableColumn,
    MemoryTypeProgramLocationBasedTableColumn,
};
pub use misc_columns::{SourceTypeTableColumn, SymbolTypeTableColumn, MonospacedByteRenderer};
