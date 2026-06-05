//! BSim SQL table definitions and queries.
//!
//! Ports `ghidra.features.bsim.query.client.tables` package.

pub mod callgraph_table;
pub mod description_table;
pub mod exe_table;
pub mod idf_lookup_table;
pub mod key_value_table;
pub mod optional_table;
pub mod sql_complex_table;
pub mod sql_string_table;
pub mod vector_store;
pub mod weight_table;

pub use exe_table::{ExeTable, ExeTableOrderColumn, ExecutableRow};
pub use idf_lookup_table::{IdfLookupRow, IdfLookupTable};
pub use key_value_table::KeyValueTable;
pub use optional_table::{OptionalRow, OptionalTable};
pub use sql_string_table::SqlStringTable;

/// SQL table name constants.
pub mod table_names {
    /// Executable metadata table.
    pub const EXECUTABLE: &str = "executable";
    /// Function metadata table.
    pub const FUNCTION: &str = "function";
    /// Signature vector table.
    pub const SIGNATURE: &str = "signature";
    /// LSH bucket table.
    pub const LSH: &str = "lsh";
    /// Category table.
    pub const CATEGORY: &str = "category";
    /// Tag table.
    pub const TAG: &str = "tag";
    /// Optional metadata table.
    pub const OPTIONAL: &str = "optional";
}

/// Common SQL clauses for BSim queries.
#[derive(Debug, Clone)]
pub struct BSimSqlClause;

impl BSimSqlClause {
    /// Generate a SELECT clause for the executable table.
    pub fn select_executable() -> &'static str {
        "SELECT idexehash, exehash, exename, architecture, compiler, category, description, datesubmit FROM executable"
    }

    /// Generate a SELECT clause for the function table.
    pub fn select_function() -> &'static str {
        "SELECT idfunc, idexehash, address, funcname, signature, numinstructions, numbasicblocks, numcalls, md5hash FROM function"
    }

    /// Generate a SELECT clause for the signature table.
    pub fn select_signature() -> &'static str {
        "SELECT idsig, idfunc, sigtype, vector, norm FROM signature"
    }

    /// Generate a query for functions by executable hash.
    pub fn functions_by_exe() -> &'static str {
        "SELECT f.* FROM function f JOIN executable e ON f.idexehash = e.idexehash WHERE e.exehash = $1"
    }

    /// Generate a query for signatures by function ID.
    pub fn signatures_by_function() -> &'static str {
        "SELECT * FROM signature WHERE idfunc = $1"
    }

    /// Generate a query for nearest neighbors via LSH.
    pub fn nearest_by_lsh() -> &'static str {
        "SELECT s.idsig, s.idfunc, s.sigtype, s.vector, s.norm
         FROM signature s
         JOIN lsh l ON s.idsig = l.idsig
         WHERE l.bucket = $1 AND l.band = $2"
    }

    /// Generate a count query for the executable table.
    pub fn count_executables() -> &'static str {
        "SELECT COUNT(*) FROM executable"
    }

    /// Generate a count query for the function table.
    pub fn count_functions() -> &'static str {
        "SELECT COUNT(*) FROM function"
    }

    /// Generate a delete query for an executable.
    pub fn delete_executable() -> &'static str {
        "DELETE FROM executable WHERE exehash = $1"
    }

    /// Generate an insert for the executable table.
    pub fn insert_executable() -> &'static str {
        "INSERT INTO executable (exehash, exename, architecture, compiler, category, description)
         VALUES ($1, $2, $3, $4, $5, $6)
         ON CONFLICT (exehash) DO NOTHING
         RETURNING idexehash"
    }

    /// Generate an insert for the function table.
    pub fn insert_function() -> &'static str {
        "INSERT INTO function (idexehash, address, funcname, signature, numinstructions, numbasicblocks, numcalls, md5hash)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
         RETURNING idfunc"
    }

    /// Generate an insert for the signature table.
    pub fn insert_signature() -> &'static str {
        "INSERT INTO signature (idfunc, sigtype, vector, norm)
         VALUES ($1, $2, $3, $4)
         RETURNING idsig"
    }
}

/// Column name constants for the executable table.
pub mod executable_columns {
    pub const ID: &str = "idexehash";
    pub const HASH: &str = "exehash";
    pub const NAME: &str = "exename";
    pub const ARCHITECTURE: &str = "architecture";
    pub const COMPILER: &str = "compiler";
    pub const CATEGORY: &str = "category";
    pub const DESCRIPTION: &str = "description";
    pub const DATE_SUBMIT: &str = "datesubmit";
}

/// Column name constants for the function table.
pub mod function_columns {
    pub const ID: &str = "idfunc";
    pub const EXE_HASH_ID: &str = "idexehash";
    pub const ADDRESS: &str = "address";
    pub const NAME: &str = "funcname";
    pub const SIGNATURE: &str = "signature";
    pub const NUM_INSTRUCTIONS: &str = "numinstructions";
    pub const NUM_BASIC_BLOCKS: &str = "numbasicblocks";
    pub const NUM_CALLS: &str = "numcalls";
    pub const MD5_HASH: &str = "md5hash";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_name_constants() {
        assert_eq!(table_names::EXECUTABLE, "executable");
        assert_eq!(table_names::FUNCTION, "function");
        assert_eq!(table_names::SIGNATURE, "signature");
        assert_eq!(table_names::LSH, "lsh");
    }

    #[test]
    fn sql_clauses_non_empty() {
        assert!(!BSimSqlClause::select_executable().is_empty());
        assert!(!BSimSqlClause::select_function().is_empty());
        assert!(!BSimSqlClause::select_signature().is_empty());
        assert!(!BSimSqlClause::insert_executable().is_empty());
        assert!(!BSimSqlClause::insert_function().is_empty());
        assert!(!BSimSqlClause::insert_signature().is_empty());
    }

    #[test]
    fn sql_clauses_contain_table_names() {
        assert!(BSimSqlClause::select_executable().contains("executable"));
        assert!(BSimSqlClause::select_function().contains("function"));
        assert!(BSimSqlClause::nearest_by_lsh().contains("lsh"));
    }

    #[test]
    fn column_name_constants() {
        assert_eq!(executable_columns::ID, "idexehash");
        assert_eq!(executable_columns::NAME, "exename");
        assert_eq!(function_columns::ID, "idfunc");
        assert_eq!(function_columns::NAME, "funcname");
    }

    #[test]
    fn count_queries() {
        assert!(BSimSqlClause::count_executables().contains("COUNT"));
        assert!(BSimSqlClause::count_functions().contains("COUNT"));
    }

    #[test]
    fn delete_query() {
        assert!(BSimSqlClause::delete_executable().contains("DELETE"));
        assert!(BSimSqlClause::delete_executable().contains("exehash"));
    }
}
