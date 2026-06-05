//! Console service trait definition.
//!
//! Port of Ghidra's `ghidra.app.services.ConsoleService`.

use std::io::Write;

/// Service interface for the I/O console.
///
/// Provides methods for displaying messages, errors, and exceptions in
/// the console pane, as well as access to stdout/stderr writers.
pub trait ConsoleService {
    /// Add a regular message to the console.
    ///
    /// The message is prefixed with `originator> ` and a newline is appended.
    fn add_message(&mut self, originator: &str, message: &str);

    /// Add an error message to the console (typically displayed in red).
    ///
    /// The message is prefixed with `originator> ` and a newline is appended.
    fn add_error_message(&mut self, originator: &str, message: &str);

    /// Add an exception to the console.
    fn add_exception(&mut self, originator: &str, message: &str);

    /// Clear all messages from the console.
    fn clear_messages(&mut self);

    /// Print a partial message (no trailing newline).
    fn print(&mut self, msg: &str);

    /// Print a partial error message (no trailing newline).
    fn print_error(&mut self, errmsg: &str);

    /// Print a message with a trailing newline.
    fn println(&mut self, msg: &str);

    /// Print an error message with a trailing newline.
    fn println_error(&mut self, errmsg: &str);

    /// Get a writer for standard output.
    fn get_stdout(&self) -> Box<dyn Write>;

    /// Get a writer for standard error.
    fn get_stderr(&self) -> Box<dyn Write>;

    /// Get text from the console buffer.
    ///
    /// Returns the text starting at `offset` for `length` characters,
    /// or `None` if the range is invalid.
    fn get_text(&self, offset: usize, length: usize) -> Option<String>;

    /// Get the total length of text in the console buffer.
    fn get_text_length(&self) -> usize;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::rc::Rc;

    /// A mock console service for testing the trait interface.
    struct MockConsoleService {
        messages: Rc<RefCell<Vec<String>>>,
        errors: Rc<RefCell<Vec<String>>>,
        exceptions: Rc<RefCell<Vec<String>>>,
        stdout_buf: Rc<RefCell<Vec<u8>>>,
        stderr_buf: Rc<RefCell<Vec<u8>>>,
    }

    impl MockConsoleService {
        fn new() -> Self {
            Self {
                messages: Rc::new(RefCell::new(Vec::new())),
                errors: Rc::new(RefCell::new(Vec::new())),
                exceptions: Rc::new(RefCell::new(Vec::new())),
                stdout_buf: Rc::new(RefCell::new(Vec::new())),
                stderr_buf: Rc::new(RefCell::new(Vec::new())),
            }
        }
    }

    impl ConsoleService for MockConsoleService {
        fn add_message(&mut self, originator: &str, message: &str) {
            self.messages
                .borrow_mut()
                .push(format!("{}> {}", originator, message));
        }

        fn add_error_message(&mut self, originator: &str, message: &str) {
            self.errors
                .borrow_mut()
                .push(format!("{}> {}", originator, message));
        }

        fn add_exception(&mut self, originator: &str, message: &str) {
            self.exceptions
                .borrow_mut()
                .push(format!("{}> {}", originator, message));
        }

        fn clear_messages(&mut self) {
            self.messages.borrow_mut().clear();
            self.errors.borrow_mut().clear();
            self.exceptions.borrow_mut().clear();
        }

        fn print(&mut self, msg: &str) {
            self.stdout_buf.borrow_mut().extend_from_slice(msg.as_bytes());
        }

        fn print_error(&mut self, errmsg: &str) {
            self.stderr_buf
                .borrow_mut()
                .extend_from_slice(errmsg.as_bytes());
        }

        fn println(&mut self, msg: &str) {
            self.stdout_buf
                .borrow_mut()
                .extend_from_slice(msg.as_bytes());
            self.stdout_buf.borrow_mut().push(b'\n');
        }

        fn println_error(&mut self, errmsg: &str) {
            self.stderr_buf
                .borrow_mut()
                .extend_from_slice(errmsg.as_bytes());
            self.stderr_buf.borrow_mut().push(b'\n');
        }

        fn get_stdout(&self) -> Box<dyn Write> {
            Box::new(MockWriter(self.stdout_buf.clone()))
        }

        fn get_stderr(&self) -> Box<dyn Write> {
            Box::new(MockWriter(self.stderr_buf.clone()))
        }

        fn get_text(&self, offset: usize, length: usize) -> Option<String> {
            let full: String = self
                .messages
                .borrow()
                .iter()
                .chain(self.errors.borrow().iter())
                .cloned()
                .collect::<Vec<_>>()
                .join("\n");
            if offset + length > full.len() {
                return None;
            }
            Some(full[offset..offset + length].to_string())
        }

        fn get_text_length(&self) -> usize {
            let msgs_len: usize = self.messages.borrow().iter().map(|s| s.len() + 1).sum();
            let errs_len: usize = self.errors.borrow().iter().map(|s| s.len() + 1).sum();
            msgs_len + errs_len
        }
    }

    struct MockWriter(Rc<RefCell<Vec<u8>>>);

    impl Write for MockWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.borrow_mut().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn test_mock_add_message() {
        let mut svc = MockConsoleService::new();
        svc.add_message("test", "hello");
        svc.add_message("test", "world");
        let msgs = svc.messages.borrow();
        assert_eq!(msgs.len(), 2);
        assert_eq!(msgs[0], "test> hello");
        assert_eq!(msgs[1], "test> world");
    }

    #[test]
    fn test_mock_add_error_message() {
        let mut svc = MockConsoleService::new();
        svc.add_error_message("test", "bad input");
        let errs = svc.errors.borrow();
        assert_eq!(errs.len(), 1);
        assert_eq!(errs[0], "test> bad input");
    }

    #[test]
    fn test_mock_add_exception() {
        let mut svc = MockConsoleService::new();
        svc.add_exception("test", "NullPointerException");
        let excs = svc.exceptions.borrow();
        assert_eq!(excs.len(), 1);
        assert_eq!(excs[0], "test> NullPointerException");
    }

    #[test]
    fn test_mock_clear_messages() {
        let mut svc = MockConsoleService::new();
        svc.add_message("test", "msg1");
        svc.add_error_message("test", "err1");
        svc.add_exception("test", "exc1");
        svc.clear_messages();
        assert!(svc.messages.borrow().is_empty());
        assert!(svc.errors.borrow().is_empty());
        assert!(svc.exceptions.borrow().is_empty());
    }

    #[test]
    fn test_mock_print() {
        let mut svc = MockConsoleService::new();
        svc.print("partial ");
        svc.println("complete");
        let buf = svc.stdout_buf.borrow();
        let text = String::from_utf8_lossy(&buf);
        assert_eq!(text, "partial complete\n");
    }

    #[test]
    fn test_mock_print_error() {
        let mut svc = MockConsoleService::new();
        svc.print_error("err part ");
        svc.println_error("err end");
        let buf = svc.stderr_buf.borrow();
        let text = String::from_utf8_lossy(&buf);
        assert_eq!(text, "err part err end\n");
    }

    #[test]
    fn test_mock_stdout_writer() {
        let mut svc = MockConsoleService::new();
        {
            let mut writer = svc.get_stdout();
            write!(writer, "written via stdout").unwrap();
            writer.flush().unwrap();
        }
        let buf = svc.stdout_buf.borrow();
        assert_eq!(String::from_utf8_lossy(&buf), "written via stdout");
    }

    #[test]
    fn test_mock_stderr_writer() {
        let mut svc = MockConsoleService::new();
        {
            let mut writer = svc.get_stderr();
            write!(writer, "error via stderr").unwrap();
        }
        let buf = svc.stderr_buf.borrow();
        assert_eq!(String::from_utf8_lossy(&buf), "error via stderr");
    }

    #[test]
    fn test_mock_get_text_length_empty() {
        let svc = MockConsoleService::new();
        assert_eq!(svc.get_text_length(), 0);
    }

    #[test]
    fn test_mock_get_text_length_with_messages() {
        let mut svc = MockConsoleService::new();
        svc.add_message("a", "b");
        // "a> b" is 4 chars + 1 newline = 5
        assert_eq!(svc.get_text_length(), 5);
    }

    #[test]
    fn test_mock_get_text_out_of_bounds() {
        let mut svc = MockConsoleService::new();
        svc.add_message("a", "b");
        assert!(svc.get_text(0, 100).is_none());
    }

    #[test]
    fn test_mock_get_text_valid_range() {
        let mut svc = MockConsoleService::new();
        svc.add_message("test", "msg");
        // "test> msg" = 9 chars
        assert!(svc.get_text(0, 9).is_some());
    }
}
