//! PasswordChange -- request to change the database password.
//!
//! Ports `ghidra.features.bsim.query.protocol.PasswordChange`.
//! Requests a password change for a specific user. Should be used in
//! conjunction with connection encryption (SSL) to protect data in transit.

pub use super::core::PasswordChangeRequest as PasswordChange;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_password_change_new() {
        let pc = PasswordChange::new("old_pass", "new_pass");
        assert_eq!(pc.old_password, "old_pass");
        assert_eq!(pc.new_password, "new_pass");
    }

    #[test]
    fn test_password_change_save_xml() {
        let pc = PasswordChange::new("secret1", "secret2");
        let mut xml = String::new();
        pc.save_xml(&mut xml);
        assert!(xml.contains("passwordchange"));
        assert!(xml.contains("secret1"));
        assert!(xml.contains("secret2"));
    }

    #[test]
    fn test_password_change_clone() {
        let pc = PasswordChange::new("old", "new");
        let cloned = pc.clone();
        assert_eq!(cloned.old_password, "old");
        assert_eq!(cloned.new_password, "new");
    }

    #[test]
    fn test_password_change_debug() {
        let pc = PasswordChange::new("a", "b");
        let dbg = format!("{:?}", pc);
        assert!(dbg.contains("a"));
    }
}
