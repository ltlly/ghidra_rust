//! Clipboard provider for the decompiler view.
//!
//! Ports `ghidra.app.plugin.core.decompile.DecompilerClipboardProvider`.

/// Provides clipboard operations for decompiler content.
///
/// Manages copying decompiled C code text to and from the system clipboard.
#[derive(Debug, Default)]
pub struct DecompilerClipboardProvider {
    /// The last copied text content.
    clipboard_content: Option<String>,
    /// Whether to include addresses in copied text.
    pub include_addresses: bool,
    /// Whether to include comments in copied text.
    pub include_comments: bool,
}

impl DecompilerClipboardProvider {
    /// Create a new clipboard provider.
    pub fn new() -> Self {
        Self::default()
    }

    /// Copy text to the clipboard.
    pub fn copy(&mut self, text: &str) {
        self.clipboard_content = Some(text.to_string());
    }

    /// Get the current clipboard content.
    pub fn paste(&self) -> Option<&str> {
        self.clipboard_content.as_deref()
    }

    /// Whether the clipboard has content.
    pub fn has_content(&self) -> bool {
        self.clipboard_content.is_some()
    }

    /// Clear the clipboard.
    pub fn clear(&mut self) {
        self.clipboard_content = None;
    }

    /// Copy decompiled function as C text.
    pub fn copy_as_c(&mut self, c_code: &str) {
        self.copy(c_code);
    }

    /// Copy with function signature header.
    pub fn copy_with_signature(&mut self, signature: &str, body: &str) {
        let text = format!("{}\n{}", signature, body);
        self.copy(&text);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_clipboard_copy_paste() {
        let mut provider = DecompilerClipboardProvider::new();
        assert!(!provider.has_content());

        provider.copy("int main() { return 0; }");
        assert!(provider.has_content());
        assert_eq!(provider.paste(), Some("int main() { return 0; }"));
    }

    #[test]
    fn test_clipboard_clear() {
        let mut provider = DecompilerClipboardProvider::new();
        provider.copy("test");
        provider.clear();
        assert!(!provider.has_content());
        assert!(provider.paste().is_none());
    }

    #[test]
    fn test_copy_as_c() {
        let mut provider = DecompilerClipboardProvider::new();
        provider.copy_as_c("void foo() {}");
        assert_eq!(provider.paste(), Some("void foo() {}"));
    }

    #[test]
    fn test_copy_with_signature() {
        let mut provider = DecompilerClipboardProvider::new();
        provider.copy_with_signature("int add(int a, int b)", "  return a + b;");
        assert!(provider.paste().unwrap().contains("int add(int a, int b)"));
    }
}
