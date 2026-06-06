//! DropDatabase -- request to drop a BSim database.
//!
//! Ports `ghidra.features.bsim.query.protocol.DropDatabase`.
//!
//! This protocol message is sent to the server to request deletion of an
//! entire BSim database.  The `database_name` field identifies which database
//! should be dropped.  The server responds with a `ResponseDropDatabase`
//! message indicating success or failure.

pub use super::core::DropDatabaseRequest as DropDatabase;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_drop_database_basic() {
        let dd = DropDatabase::new("test_db");
        assert_eq!(dd.database_name, "test_db");
    }

    #[test]
    fn test_drop_database_equality() {
        let dd1 = DropDatabase::new("test_db");
        let dd2 = DropDatabase::new("test_db");
        assert_eq!(dd1.database_name, dd2.database_name);
    }

    #[test]
    fn test_drop_database_clone() {
        let dd = DropDatabase::new("db1");
        let cloned = dd.clone();
        assert_eq!(cloned.database_name, "db1");
    }

    #[test]
    fn test_drop_database_debug() {
        let dd = DropDatabase::new("mydb");
        let debug_str = format!("{:?}", dd);
        assert!(debug_str.contains("mydb"));
    }

    #[test]
    fn test_drop_database_name_not_empty() {
        let dd = DropDatabase::new("valid_name-123");
        assert!(!dd.database_name.is_empty());
    }

    #[test]
    fn test_drop_database_different_names() {
        let dd1 = DropDatabase::new("db_a");
        let dd2 = DropDatabase::new("db_b");
        assert_ne!(dd1.database_name, dd2.database_name);
    }

    #[test]
    fn test_drop_database_from_string() {
        let name = String::from("production_db");
        let dd = DropDatabase::new(name);
        assert_eq!(dd.database_name, "production_db");
    }
}
