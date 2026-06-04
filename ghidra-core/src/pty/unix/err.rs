//! POSIX error checking helpers.
//!
//! Port of Ghidra's `ghidra.pty.unix.Err`.

use std::io;

/// Check a POSIX return value and convert negative results to `io::Error`.
///
/// If the result is negative, returns an `io::Error` using the current `errno`.
/// Otherwise returns the result value.
pub fn check_lt0(result: libc::c_int) -> io::Result<libc::c_int> {
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_check_lt0_positive() {
        let result = check_lt0(42);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 42);
    }

    #[test]
    fn test_check_lt0_zero() {
        let result = check_lt0(0);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 0);
    }

    #[test]
    fn test_check_lt0_negative() {
        let result = check_lt0(-1);
        assert!(result.is_err());
    }
}
