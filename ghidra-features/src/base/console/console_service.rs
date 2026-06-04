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
    // ConsoleService is a trait; tested through ConsoleComponentProvider.
}
