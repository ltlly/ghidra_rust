//! CreateDatabase -- request to create a new BSim database.
//!
//! Ports `ghidra.features.bsim.query.protocol.CreateDatabase`.

pub use super::core::CreateDatabaseRequest as CreateDatabase;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_database_basic() {
        let cd = CreateDatabase::new("test_db");
        assert_eq!(cd.database_name, "test_db");
    }

    #[test]
    fn test_create_database_equality() {
        let cd1 = CreateDatabase::new("test_db");
        let cd2 = CreateDatabase::new("test_db");
        assert_eq!(cd1.database_name, cd2.database_name);
    }

    #[test]
    fn test_create_database_clone() {
        let cd = CreateDatabase::new("db1");
        let cloned = cd.clone();
        assert_eq!(cloned.database_name, "db1");
    }

    #[test]
    fn test_create_database_debug() {
        let cd = CreateDatabase::new("mydb");
        let debug_str = format!("{:?}", cd);
        assert!(debug_str.contains("mydb"));
    }

    #[test]
    fn test_create_database_name_validation() {
        let cd = CreateDatabase::new("valid_name-123");
        assert!(!cd.database_name.is_empty());
    }
}
