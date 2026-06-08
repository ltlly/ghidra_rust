//! SOM (HP PA-RISC System Object Module) format ported from Ghidra's
//! `ghidra.app.util.bin.format.som` package.
//!
//! HP PA-RISC System Object Module format used on HP-UX and MPE/iX systems.
//!
//! Provides types for parsing SOM binary headers, spaces, subspaces,
//! symbols, compilation units, and dynamic loader structures.
//!
//! Reference: [The 32-bit PA-RISC Run-time Architecture Document](https://web.archive.org/web/20050502101134/http://devresource.hp.com/drc/STK/docs/archive/rad_11_0_32.pdf)

pub mod som_aux_header;
pub mod som_aux_id;
pub mod som_compilation_unit;
pub mod som_constants;
pub mod som_dlt_entry;
pub mod som_dynamic_loader_header;
pub mod som_dynamic_relocation;
pub mod som_exception;
pub mod som_export_entry;
pub mod som_export_entry_ext;
pub mod som_header;
pub mod som_import_entry;
pub mod som_module_entry;
pub mod som_plt_entry;
pub mod som_shlib_list_entry;
pub mod som_space;
pub mod som_subspace;
pub mod som_symbol;
pub mod som_sys_clock;

pub use som_aux_header::{
    read_next_aux_header, SomAuxHeader, SomExecAuxHeader, SomLinkerFootprintAuxHeader,
    SomProductSpecificsAuxHeader, SomUnknownAuxHeader,
};
pub use som_aux_id::{SomAuxId, SOM_AUX_ID_SIZE};
pub use som_compilation_unit::{SomCompilationUnit, SOM_COMPILATION_UNIT_SIZE};
pub use som_constants::{
    dr_type_name, is_valid_som_magic, is_valid_version_id, magic_name, symbol_scope_name,
    symbol_type_name, SomConstants,
};
pub use som_dlt_entry::{SomDltEntry, SOM_DLT_ENTRY_SIZE};
pub use som_dynamic_loader_header::{SomDynamicLoaderHeader, SOM_DYNAMIC_LOADER_HEADER_SIZE};
pub use som_dynamic_relocation::{SomDynamicRelocation, SOM_DYNAMIC_RELOCATION_SIZE};
pub use som_exception::SomException;
pub use som_export_entry::{SomExportEntry, SOM_EXPORT_ENTRY_SIZE};
pub use som_export_entry_ext::{SomExportEntryExt, SOM_EXPORT_ENTRY_EXT_SIZE};
pub use som_header::{SomHeader, SOM_HEADER_SIZE};
pub use som_import_entry::{SomImportEntry, SOM_IMPORT_ENTRY_SIZE};
pub use som_module_entry::{SomModuleEntry, SOM_MODULE_ENTRY_SIZE};
pub use som_plt_entry::{SomPltEntry, SOM_PLT_ENTRY_SIZE};
pub use som_shlib_list_entry::{SomShlibListEntry, SOM_SHLIB_LIST_ENTRY_SIZE};
pub use som_space::{SomSpace, SOM_SPACE_SIZE};
pub use som_subspace::{SomSubspace, SOM_SUBSPACE_SIZE};
pub use som_symbol::{SomSymbol, SOM_SYMBOL_SIZE};
pub use som_sys_clock::{SomSysClock, SOM_SYS_CLOCK_SIZE};
