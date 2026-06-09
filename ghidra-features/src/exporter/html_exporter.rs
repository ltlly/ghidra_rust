//! HTML exporter implementation.
//!
//! Exports the program listing as an HTML document.
//!
//! Ported from `ghidra.app.util.exporter.HtmlExporter`.

use std::io::Write;

use crate::base::analyzer::{AddressSet, Program};
use crate::loader::framework::MessageLog as LoaderMessageLog;

use super::{Exporter, ExporterError, MemoryModel, ProgramTextOptions};

/// Exports the program listing as an HTML document.
///
/// Ported from `ghidra.app.util.exporter.HtmlExporter`.
pub struct HtmlExporter {
    options: ProgramTextOptions,
    pub address_color: String,
    pub mnemonic_color: String,
    pub comment_color: String,
}

impl HtmlExporter {
    pub fn new() -> Self {
        Self {
            options: ProgramTextOptions::default(),
            address_color: "#808080".into(),
            mnemonic_color: "#0000FF".into(),
            comment_color: "#008000".into(),
        }
    }
}

impl Default for HtmlExporter {
    fn default() -> Self {
        Self::new()
    }
}

impl Exporter for HtmlExporter {
    fn name(&self) -> &str {
        "HTML"
    }

    fn default_extension(&self) -> &str {
        "html"
    }

    fn export(
        &self,
        program: &Program,
        addr_set: Option<&AddressSet>,
        memory: Option<&MemoryModel>,
        writer: &mut dyn Write,
        log: &mut LoaderMessageLog,
    ) -> Result<bool, ExporterError> {
        let set = match addr_set {
            Some(s) => s.clone(),
            None => program.memory.clone(),
        };

        writeln!(writer, "<!DOCTYPE html>")?;
        writeln!(writer, "<html>")?;
        writeln!(writer, "<head>")?;
        writeln!(writer, "  <meta charset=\"UTF-8\">")?;
        writeln!(
            writer,
            "  <title>{} - Ghidra Export</title>",
            escape_html(&program.name)
        )?;
        writeln!(writer, "  <style>")?;
        writeln!(writer, "    body {{ font-family: monospace; background: #1e1e1e; color: #d4d4d4; padding: 10px; }}")?;
        writeln!(writer, "    .addr {{ color: {}; }}", self.address_color)?;
        writeln!(
            writer,
            "    .mnemonic {{ color: {}; font-weight: bold; }}",
            self.mnemonic_color
        )?;
        writeln!(writer, "    .comment {{ color: {}; }}", self.comment_color)?;
        writeln!(writer, "    .bytes {{ color: #808080; }}")?;
        writeln!(writer, "    pre {{ margin: 0; }}")?;
        writeln!(writer, "  </style>")?;
        writeln!(writer, "</head>")?;
        writeln!(writer, "<body>")?;
        writeln!(
            writer,
            "<h2>Listing: {}</h2>",
            escape_html(&program.name)
        )?;
        writeln!(writer, "<pre>")?;

        for range in set.iter() {
            let mut addr = range.start;
            while addr.offset <= range.end.offset {
                if let Some(byte) = memory.and_then(|m| m.get_byte(&addr)) {
                    write!(writer, "<span class=\"addr\">{:08x}</span>  ", addr.offset)?;
                    write!(writer, "<span class=\"bytes\">{:02x}</span>  ", byte)?;
                    if let Some(sym) = program.symbols.get(&addr) {
                        write!(
                            writer,
                            "<span class=\"mnemonic\">{}</span>",
                            escape_html(sym)
                        )?;
                    }
                    writeln!(writer)?;
                }
                addr = addr.add(1);
            }
        }

        writeln!(writer, "</pre>")?;
        writeln!(writer, "</body>")?;
        writeln!(writer, "</html>")?;

        log.append_msg("Exported program as HTML");
        Ok(true)
    }
}

fn escape_html(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::base::analyzer::{Address, AddressRange, Language};

    fn make_test_program() -> Program {
        let lang = Language {
            processor: "x86".into(),
            variant: "LE".into(),
            size: 64,
        };
        let mut prog = Program::new("test_binary", lang);
        prog.image_base = 0x400000;
        prog.memory
            .add_range(AddressRange::new(Address::new(0x400000), Address::new(0x40001F)));
        prog.symbols.insert(Address::new(0x400000), "_start".into());
        prog.symbols.insert(Address::new(0x400010), "main".into());
        prog
    }

    fn make_test_memory() -> MemoryModel {
        let mut mem = MemoryModel::new();
        for i in 0u8..32 {
            mem.set_byte(&Address::new(0x400000 + i as u64), i);
        }
        mem
    }

    #[test]
    fn test_html_exporter() {
        let prog = make_test_program();
        let mem = make_test_memory();
        let exporter = HtmlExporter::new();
        assert_eq!(exporter.name(), "HTML");
        assert_eq!(exporter.default_extension(), "html");

        let mut output = Vec::new();
        let mut log = LoaderMessageLog::new();
        let result = exporter.export(&prog, None, Some(&mem), &mut output, &mut log);
        assert!(result.is_ok());

        let text = String::from_utf8(output).unwrap();
        assert!(text.contains("<!DOCTYPE html>"));
        assert!(text.contains("test_binary"));
        assert!(text.contains("_start"));
    }

    #[test]
    fn test_escape_html() {
        assert_eq!(escape_html("a<b>c"), "a&lt;b&gt;c");
        assert_eq!(escape_html("a&b"), "a&amp;b");
    }
}
