//! Windows ConPTY (Pseudo Console) implementation.
//!
//! Port of Ghidra's `ghidra.pty.windows` Java package.
//!
//! This module provides a Windows-specific PTY implementation using the
//! Windows ConPTY API. On non-Windows platforms, the types are still
//! available but operations will return errors.

use std::io;

use crate::pty::{Pty, PtyChild, PtyEndpoint, PtyFactory, PtyParent, PtySession, TermMode};

/// Default pseudo-console dimensions.
const DEFAULT_COLS: u16 = 80;
const DEFAULT_ROWS: u16 = 25;

/// PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE value for CreateProcess.
const PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE: u32 = 0x20016;

/// A wrapper around a Windows HANDLE.
///
/// On non-Windows platforms, this is a stub that stores a raw pointer value.
#[derive(Debug)]
pub struct Handle {
    raw: usize,
}

impl Handle {
    /// Create a new handle wrapper.
    pub fn new(raw: usize) -> Self {
        Self { raw }
    }

    /// Get the raw handle value.
    pub fn raw(&self) -> usize {
        self.raw
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        #[cfg(target_os = "windows")]
        unsafe {
            if self.raw != 0 {
                winapi::um::handleapi::CloseHandle(self.raw as _);
            }
        }
    }
}

/// A Windows Pipe (read and write handles).
pub struct Pipe {
    read_handle: Handle,
    write_handle: Handle,
}

impl Pipe {
    /// Create a new Windows pipe.
    pub fn create() -> io::Result<Self> {
        #[cfg(target_os = "windows")]
        {
            // On Windows, use CreatePipe
            unimplemented!("Windows pipe creation requires Win32 API")
        }
        #[cfg(not(target_os = "windows"))]
        {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Windows pipes are not available on this platform",
            ))
        }
    }

    /// Get the read handle.
    pub fn read_handle(&self) -> &Handle {
        &self.read_handle
    }

    /// Get the write handle.
    pub fn write_handle(&self) -> &Handle {
        &self.write_handle
    }

    /// Close both handles.
    pub fn close(&self) {
        // Handles are closed on drop
    }
}

/// A handle to a Windows Pseudo Console.
pub struct PseudoConsoleHandle {
    handle: Handle,
}

impl PseudoConsoleHandle {
    /// Wrap a raw handle.
    pub fn new(handle: Handle) -> Self {
        Self { handle }
    }

    /// Resize the pseudo console.
    pub fn resize(&self, _rows: u16, _cols: u16) -> io::Result<()> {
        #[cfg(target_os = "windows")]
        {
            unimplemented!("Windows ConPTY resize requires Win32 API")
        }
        #[cfg(not(target_os = "windows"))]
        {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "ConPTY is not available on this platform",
            ))
        }
    }

    /// Get the raw handle.
    pub fn handle(&self) -> &Handle {
        &self.handle
    }
}

/// One end of a ConPTY connection.
pub struct ConPtyEndpoint {
    input: Handle,
    output: Handle,
    pseudo_console: PseudoConsoleHandle,
}

impl ConPtyEndpoint {
    /// Create a new ConPTY endpoint.
    pub fn new(input: Handle, output: Handle, pseudo_console: PseudoConsoleHandle) -> Self {
        Self {
            input,
            output,
            pseudo_console,
        }
    }
}

impl PtyEndpoint for ConPtyEndpoint {
    fn output_stream(&mut self) -> Box<dyn io::Write> {
        // On Windows, this would wrap the output handle
        // On other platforms, return a stub
        Box::new(io::sink())
    }

    fn input_stream(&mut self) -> Box<dyn io::Read> {
        // On Windows, this would wrap the input handle
        // On other platforms, return a stub
        Box::new(io::empty())
    }
}

/// The parent end of a ConPTY.
pub struct ConPtyParent {
    endpoint: ConPtyEndpoint,
}

impl ConPtyParent {
    /// Create a new ConPTY parent.
    pub fn new(endpoint: ConPtyEndpoint) -> Self {
        Self { endpoint }
    }
}

impl PtyEndpoint for ConPtyParent {
    fn output_stream(&mut self) -> Box<dyn io::Write> {
        self.endpoint.output_stream()
    }

    fn input_stream(&mut self) -> Box<dyn io::Read> {
        self.endpoint.input_stream()
    }
}

impl PtyParent for ConPtyParent {}

/// The child end of a ConPTY.
pub struct ConPtyChild {
    endpoint: ConPtyEndpoint,
}

impl ConPtyChild {
    /// Create a new ConPTY child.
    pub fn new(endpoint: ConPtyEndpoint) -> Self {
        Self { endpoint }
    }
}

impl PtyEndpoint for ConPtyChild {
    fn output_stream(&mut self) -> Box<dyn io::Write> {
        self.endpoint.output_stream()
    }

    fn input_stream(&mut self) -> Box<dyn io::Read> {
        self.endpoint.input_stream()
    }
}

impl PtyChild for ConPtyChild {
    fn session(
        &self,
        _args: &[&str],
        _env: &[(&str, &str)],
        _working_directory: Option<&std::path::Path>,
        _mode: &[TermMode],
    ) -> io::Result<Box<dyn PtySession>> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "ConPTY session spawning requires Windows platform",
        ))
    }

    fn null_session(&self, _mode: &[TermMode]) -> io::Result<String> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "ConPTY does not have a name",
        ))
    }

    fn set_window_size(&self, cols: u16, rows: u16) {
        let _ = self.endpoint.pseudo_console.resize(rows, cols);
    }
}

/// A Windows ConPTY pseudo-terminal.
pub struct ConPty {
    pipe_to_child: Pipe,
    pipe_from_child: Pipe,
    pseudo_console: PseudoConsoleHandle,
    closed: bool,
    parent: ConPtyParent,
    child: ConPtyChild,
}

impl ConPty {
    /// Open a new ConPTY with the given dimensions.
    pub fn openpty(cols: i16, rows: i16) -> io::Result<Self> {
        // This is a stub - actual Windows ConPTY creation requires Win32 API calls
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!(
                "ConPTY openpty({}, {}) requires Windows platform with Win32 API",
                cols, rows
            ),
        ))
    }
}

impl Pty for ConPty {
    fn parent(&mut self) -> &mut dyn PtyParent {
        &mut self.parent
    }

    fn child(&mut self) -> &mut dyn PtyChild {
        &mut self.child
    }

    fn close(&mut self) -> io::Result<()> {
        if self.closed {
            return Ok(());
        }
        self.pseudo_console.handle.raw = 0; // Mark as closed
        self.closed = true;
        Ok(())
    }
}

/// Windows ConPTY factory.
pub struct ConPtyFactory;

impl PtyFactory for ConPtyFactory {
    fn openpty(&self, cols: u16, rows: u16) -> io::Result<Box<dyn Pty>> {
        let (c, r) = if cols == 0 || rows == 0 {
            (DEFAULT_COLS, DEFAULT_ROWS)
        } else {
            (cols, rows)
        };

        ConPty::openpty(c as i16, r as i16).map(|pty| Box::new(pty) as Box<dyn Pty>)
    }

    fn description(&self) -> &str {
        "local (Windows)"
    }
}

/// ANSI escape sequence buffered input stream.
///
/// Port of Ghidra's `AnsiBufferedInputStream`. Processes ANSI escape
/// sequences from a ConPTY output stream, providing cleaned line-based
/// text output. Tracks a cursor position within the line buffer, matching
/// Java's `ByteBuffer.position()` semantics.
pub struct AnsiBufferedInputStream<R: io::Read> {
    inner: R,
    mode: AnsiMode,
    line_baked: Vec<u8>,
    line_buf: Vec<u8>,
    /// Cursor position within `line_buf`.
    cursor: usize,
    esc_buf: Vec<u8>,
    title_buf: Vec<u8>,
    pos: usize,
}

/// ANSI parser state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AnsiMode {
    Chars,
    Esc,
    Csi,
    CsiParam,
    CsiQ,
    Osc,
    WindowTitle,
    WindowTitleEsc,
}

impl<R: io::Read> AnsiBufferedInputStream<R> {
    /// Create a new ANSI buffered input stream.
    pub fn new(inner: R) -> Self {
        Self {
            inner,
            mode: AnsiMode::Chars,
            line_baked: Vec::new(),
            line_buf: Vec::new(),
            cursor: 0,
            esc_buf: Vec::new(),
            title_buf: Vec::new(),
            pos: 0,
        }
    }

    /// Process the next byte from the input stream.
    fn process_next(&mut self) -> io::Result<bool> {
        let mut buf = [0u8; 1];
        let n = self.inner.read(&mut buf)?;
        if n == 0 {
            return Ok(false);
        }
        let c = buf[0];

        match self.mode {
            AnsiMode::Chars => self.process_char(c),
            AnsiMode::Esc => self.process_esc(c),
            AnsiMode::Csi => self.process_csi(c),
            AnsiMode::CsiParam => self.process_csi_param(c),
            AnsiMode::CsiQ => self.process_csi_q(c),
            AnsiMode::Osc => self.process_osc(c),
            AnsiMode::WindowTitle => self.process_window_title(c),
            AnsiMode::WindowTitleEsc => self.process_window_title_esc(c),
        }

        self.pos += 1;
        Ok(true)
    }

    fn process_char(&mut self, c: u8) {
        match c {
            b'\x08' => {
                // Backspace: move cursor back if the previous char is a space
                if self.cursor > 0 && self.line_buf[self.cursor - 1] == b' ' {
                    self.cursor -= 1;
                }
            }
            b'\n' => self.bake_line(),
            b'\r' => {
                self.cursor = 0;
            }
            0x1b => self.mode = AnsiMode::Esc,
            _ => self.append_char(c),
        }
    }

    fn append_char(&mut self, c: u8) {
        if self.cursor >= self.line_buf.len() {
            self.line_buf.push(c);
        } else {
            self.line_buf[self.cursor] = c;
        }
        self.cursor += 1;
    }

    fn process_esc(&mut self, c: u8) {
        match c {
            b'[' => self.mode = AnsiMode::Csi,
            b']' => self.mode = AnsiMode::Osc,
            _ => {
                log::warn!("Saw ESC {} at {}", c, self.pos);
                self.mode = AnsiMode::Chars;
            }
        }
    }

    fn process_csi(&mut self, c: u8) {
        match c {
            b'?' => self.mode = AnsiMode::CsiQ,
            _ => self.process_csi_param(c),
        }
    }

    fn process_csi_param(&mut self, c: u8) {
        match c {
            b'A'..=b'Z' | b'a'..=b'z' => {
                self.execute_csi_command(c);
                self.mode = AnsiMode::Chars;
            }
            _ => self.esc_buf.push(c),
        }
    }

    fn execute_csi_command(&mut self, cmd: u8) {
        let param = String::from_utf8_lossy(&self.esc_buf).to_string();
        self.esc_buf.clear();

        match cmd {
            b'A' => {
                // Cursor up - not supported for single-line buffer
            }
            b'B' => {
                // Cursor down - not supported for single-line buffer
            }
            b'C' => {
                // Cursor forward: pad with spaces up to new cursor position
                let delta: usize = param.parse().unwrap_or(1);
                let new_pos = self.cursor + delta;
                if new_pos > self.line_buf.len() {
                    self.line_buf.resize(new_pos, b' ');
                }
                self.cursor = new_pos;
            }
            b'D' => {
                // Cursor backward
                let delta: usize = param.parse().unwrap_or(1);
                self.cursor = self.cursor.saturating_sub(delta);
            }
            b'G' => {
                // Cursor char absolute (1-based)
                let abs: usize = param.parse().unwrap_or(1);
                self.cursor = abs.saturating_sub(1);
                if self.cursor > self.line_buf.len() {
                    self.line_buf.resize(self.cursor, b' ');
                }
            }
            b'H' => {
                // Cursor position (row, col) - for single-line, just set column
                let parts: Vec<&str> = param.split(';').collect();
                let col = if parts.len() >= 2 {
                    parts[1].parse::<usize>().unwrap_or(1)
                } else if parts.len() == 1 && !parts[0].is_empty() {
                    parts[0].parse::<usize>().unwrap_or(1)
                } else {
                    1
                };
                self.cursor = col.saturating_sub(1);
                if self.cursor > self.line_buf.len() {
                    self.line_buf.resize(self.cursor, b' ');
                }
            }
            b'J' => {
                // Erase in display - treat as erase in line for single-line
                self.line_buf.clear();
                self.cursor = 0;
            }
            b'K' => {
                // Erase in line
                match param.as_str() {
                    "0" | "" => {
                        // Erase from cursor to end
                        self.line_buf.truncate(self.cursor);
                    }
                    "1" => {
                        // Erase from start to cursor
                        if self.cursor < self.line_buf.len() {
                            self.line_buf.drain(..self.cursor);
                        } else {
                            self.line_buf.clear();
                        }
                        self.cursor = 0;
                    }
                    "2" => {
                        self.line_buf.clear();
                        self.cursor = 0;
                    }
                    _ => {}
                }
            }
            b'X' => {
                // Erase character: overwrite cursor..cursor+count with spaces
                let count: usize = param.parse().unwrap_or(0);
                let end = (self.cursor + count).min(self.line_buf.len());
                for i in self.cursor..end {
                    self.line_buf[i] = b' ';
                }
            }
            b'm' => {
                // Set graphics rendition - ignore
            }
            b'h' | b'l' => {
                // Private mode set/reset - ignore
            }
            _ => {
                // Unknown CSI command, ignore
            }
        }
    }

    fn process_csi_q(&mut self, c: u8) {
        match c {
            b'h' | b'l' => {
                self.esc_buf.clear();
                self.mode = AnsiMode::Chars;
            }
            _ => self.esc_buf.push(c),
        }
    }

    fn process_osc(&mut self, c: u8) {
        match c {
            b';' => {
                self.esc_buf.clear();
                self.mode = AnsiMode::WindowTitle;
            }
            _ => self.esc_buf.push(c),
        }
    }

    fn process_window_title(&mut self, c: u8) {
        match c {
            0x07 => {
                // Bell - end of title
                self.title_buf.clear();
                self.mode = AnsiMode::Chars;
            }
            0x1b => self.mode = AnsiMode::WindowTitleEsc,
            _ => self.title_buf.push(c),
        }
    }

    fn process_window_title_esc(&mut self, c: u8) {
        match c {
            b'\\' => {
                self.title_buf.clear();
                self.mode = AnsiMode::Chars;
            }
            _ => {
                log::warn!("Saw <ST> ... ESC {} at {}", c, self.pos);
                self.mode = AnsiMode::Chars;
            }
        }
    }

    fn bake_line(&mut self) {
        // Determine effective length: use the cursor as the logical limit,
        // but also consider the actual buffer length if the cursor is beyond it.
        let effective_len = self.cursor.max(self.line_buf.len());

        // Guess the end by finding the last non-whitespace character.
        let mut end = 0;
        for i in (0..effective_len.min(self.line_buf.len())).rev() {
            if self.line_buf[i] != b' ' && self.line_buf[i] != 0 {
                end = i + 1;
                break;
            }
        }

        // Truncate to the effective end
        self.line_buf.truncate(end);
        self.line_buf.push(b'\n');

        self.line_baked = std::mem::take(&mut self.line_buf);
        self.cursor = 0;
    }

    fn fill_buffer(&mut self) -> io::Result<bool> {
        while self.line_baked.is_empty() {
            if !self.process_next()? {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

impl<R: io::Read> io::Read for AnsiBufferedInputStream<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.line_baked.is_empty() {
            if !self.fill_buffer()? {
                return Ok(0);
            }
        }
        let n = std::cmp::min(self.line_baked.len(), buf.len());
        buf[..n].copy_from_slice(&self.line_baked[..n]);
        self.line_baked.drain(..n);
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    #[test]
    fn test_con_pty_factory_description() {
        let factory = ConPtyFactory;
        assert_eq!(factory.description(), "local (Windows)");
    }

    #[test]
    fn test_handle_creation() {
        let h = Handle::new(42);
        assert_eq!(h.raw(), 42);
    }

    #[test]
    fn test_ansi_stream_plain_text() {
        let data = b"hello world\n";
        let mut stream = AnsiBufferedInputStream::new(&data[..]);
        let mut output = String::new();
        stream.read_to_string(&mut output).unwrap();
        assert_eq!(output, "hello world\n");
    }

    #[test]
    fn test_ansi_stream_backspace_over_space() {
        // Backspace only moves cursor back if previous char is a space
        let data = b"hello \x08o\n";
        let mut stream = AnsiBufferedInputStream::new(&data[..]);
        let mut output = String::new();
        stream.read_to_string(&mut output).unwrap();
        // ' ' then backspace (space check passes), cursor moves back, 'o' overwrites ' '
        assert_eq!(output, "helloo\n");
    }

    #[test]
    fn test_ansi_stream_backspace_no_effect() {
        // Backspace does NOT move cursor if previous char is not a space
        let data = b"hellox\x08o\n";
        let mut stream = AnsiBufferedInputStream::new(&data[..]);
        let mut output = String::new();
        stream.read_to_string(&mut output).unwrap();
        // 'x' is not space, so backspace is ignored; 'o' appends
        assert_eq!(output, "helloxo\n");
    }

    #[test]
    fn test_ansi_stream_carriage_return() {
        // \r moves cursor to 0; "new" overwrites positions 0,1,2; the rest
        // ("_text") remains. bake_line strips trailing non-newline whitespace,
        // but "_" is not whitespace, so it stays.
        let data = b"old_text\rnew\n";
        let mut stream = AnsiBufferedInputStream::new(&data[..]);
        let mut output = String::new();
        stream.read_to_string(&mut output).unwrap();
        assert_eq!(output, "new_text\n");
    }

    #[test]
    fn test_ansi_stream_carriage_return_full_overwrite() {
        // \r then overwrite the entire content
        let data = b"old\rnew\n";
        let mut stream = AnsiBufferedInputStream::new(&data[..]);
        let mut output = String::new();
        stream.read_to_string(&mut output).unwrap();
        assert_eq!(output, "new\n");
    }

    #[test]
    fn test_ansi_stream_cursor_forward() {
        // "ab" then cursor forward 2 (pad 2 spaces), then "cd" writes at
        // positions 4 and 5 (spaces at 2,3 remain in the buffer).
        let data = b"ab\x1b[2Ccd\n";
        let mut stream = AnsiBufferedInputStream::new(&data[..]);
        let mut output = String::new();
        stream.read_to_string(&mut output).unwrap();
        assert_eq!(output, "ab  cd\n");
    }

    #[test]
    fn test_ansi_stream_cursor_forward_then_backspace() {
        // "ab" then cursor forward 2 (spaces at 2,3), backspace (prev is space, moves back),
        // backspace again (prev is space, moves back again), "XY" overwrites spaces.
        let data = b"ab\x1b[2C\x08\x08XY\n";
        let mut stream = AnsiBufferedInputStream::new(&data[..]);
        let mut output = String::new();
        stream.read_to_string(&mut output).unwrap();
        assert_eq!(output, "abXY\n");
    }

    #[test]
    fn test_ansi_stream_erase_in_line_from_cursor() {
        // \e[0K or \e[K erases from cursor to end of line.
        // After "hello" (cursor=5), erase from cursor = nothing to erase.
        let data = b"hello\x1b[K\n";
        let mut stream = AnsiBufferedInputStream::new(&data[..]);
        let mut output = String::new();
        stream.read_to_string(&mut output).unwrap();
        assert_eq!(output, "hello\n");
    }

    #[test]
    fn test_ansi_stream_erase_in_line_with_content_after() {
        // Write "hello world", move cursor back to after "hello", erase to end
        let data = b"hello world\x1b[6D\x1b[K\n";
        let mut stream = AnsiBufferedInputStream::new(&data[..]);
        let mut output = String::new();
        stream.read_to_string(&mut output).unwrap();
        assert_eq!(output, "hello\n");
    }

    #[test]
    fn test_ansi_stream_erase_entire_line() {
        // \e[2K erases entire line
        let data = b"hello\x1b[2K\n";
        let mut stream = AnsiBufferedInputStream::new(&data[..]);
        let mut output = String::new();
        stream.read_to_string(&mut output).unwrap();
        assert_eq!(output, "\n");
    }

    #[test]
    fn test_ansi_stream_multiple_lines() {
        let data = b"line1\nline2\nline3\n";
        let mut stream = AnsiBufferedInputStream::new(&data[..]);
        let mut output = String::new();
        stream.read_to_string(&mut output).unwrap();
        assert_eq!(output, "line1\nline2\nline3\n");
    }

    #[test]
    fn test_ansi_stream_empty_input() {
        let data = b"";
        let mut stream = AnsiBufferedInputStream::new(&data[..]);
        let mut output = String::new();
        stream.read_to_string(&mut output).unwrap();
        assert_eq!(output, "");
    }

    #[test]
    fn test_ansi_stream_csi_private_mode() {
        // CSI ? 25 h (show cursor) should be silently ignored
        let data = b"\x1b[?25hhello\n";
        let mut stream = AnsiBufferedInputStream::new(&data[..]);
        let mut output = String::new();
        stream.read_to_string(&mut output).unwrap();
        assert_eq!(output, "hello\n");
    }

    #[test]
    fn test_ansi_stream_graphics_rendition() {
        // CSI 31 m (red text) should be silently ignored
        let data = b"\x1b[31mhello\x1b[0m\n";
        let mut stream = AnsiBufferedInputStream::new(&data[..]);
        let mut output = String::new();
        stream.read_to_string(&mut output).unwrap();
        assert_eq!(output, "hello\n");
    }
}
