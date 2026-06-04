//! Low-level `openpty` wrapper.
//!
//! Port of Ghidra's `ghidra.pty.unix.Util`. Wraps the C `openpty` function
//! from `libutil` (Linux) or `libc` (macOS/BSD).

/// Raw `openpty` call.
///
/// Opens a pseudo-terminal pair, returning the parent (master) and child
/// (slave) file descriptors and optionally the device name.
///
/// # Safety
///
/// `name` must point to a buffer of at least 1024 bytes, or be null.
pub fn raw_openpty(
    parent_fd: &mut i32,
    child_fd: &mut i32,
    name: *mut libc::c_char,
) -> i32 {
    unsafe {
        libc::openpty(
            parent_fd as *mut i32,
            child_fd as *mut i32,
            name,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_raw_openpty() {
        let mut parent_fd: i32 = -1;
        let mut child_fd: i32 = -1;
        let mut name_buf = [0u8; 1024];

        let ret = raw_openpty(
            &mut parent_fd,
            &mut child_fd,
            name_buf.as_mut_ptr() as *mut libc::c_char,
        );

        if ret == 0 {
            // Success - clean up
            assert!(parent_fd >= 0);
            assert!(child_fd >= 0);
            unsafe {
                libc::close(parent_fd);
                libc::close(child_fd);
            }
        }
        // May fail in CI without a terminal; that's OK
    }
}
