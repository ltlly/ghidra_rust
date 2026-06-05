//! BSim client table types.
//!
//! Ports `ghidra.features.bsim.query.client.tables`:
//! - [`SQLComplexTable`]: generic complex SQL table
//! - [`SqlValue`]: typed SQL value
//! - [`CachedStatement`]: cached prepared SQL statement
//! - [`StatementSupplier`]: statement supplier callback
//! - [`ExeToCategoryTable`]: executable-to-category mapping
//! - [`SQLStringTable`]: simple string lookup table
//! - [`KeyValueTable`]: key-value metadata table
//! - [`OptionalTable`]: optional function metadata
//! - [`IdfLookupTable`]: IDF weight lookup
//! - [`WeightTable`]: LSH feature weight table
//! - [`CallgraphTable`]: function callgraph edges
//! - [`DescriptionTable`]: function description metadata
//! - [`ExeTable`]: executable metadata

pub mod complex_table;

pub use complex_table::{
    CachedStatement, CallgraphTable, DescriptionTable, ExeTable, ExeToCategoryTable, IdfLookupTable,
    KeyValueTable, OptionalTable, SQLComplexTable, SQLStringTable, SqlValue, StatementSupplier,
    WeightTable,
};
