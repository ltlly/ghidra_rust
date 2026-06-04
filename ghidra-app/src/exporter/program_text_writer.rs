//! ProgramTextWriter — writes a formatted program listing to a file.
//!
//! Ported from Ghidra's `ProgramTextWriter.java`. Iterates over code units
//! in the program listing and writes formatted text lines including addresses,
//! bytes, labels, mnemonics, operands, comments, and cross-references.

use super::line_dispenser::{clip, get_fill, ReferenceLineDispenser};
use super::options::ProgramTextOptions;
use ghidra_core::listing::ListingRow;
use ghidra_core::program::Program;
use std::fs;
use std::io::{self, Write};
use std::path::Path;

const BYTES_DELIM: &str = "";

/// HTML anchor begin tag.
fn begin_anchor(addr: &str) -> String {
    format!(r#"<A NAME="{}">"#, addr)
}
/// HTML anchor end tag.
const END_ANCHOR: &str = r#""></A>"#;

/// Writes a program listing to a file in either plain text or HTML format.
///
/// This mirrors Ghidra's `ProgramTextWriter`, iterating the program listing
/// and emitting formatted lines with address, bytes, labels, mnemonics,
/// operands, comments, and cross-references.
pub struct ProgramTextWriter {
    options: ProgramTextOptions,
}

impl ProgramTextWriter {
    /// Create a new writer with the given options.
    pub fn new(options: ProgramTextOptions) -> Self {
        Self { options }
    }

    /// Write the program listing to a file.
    ///
    /// * `file` — output file path
    /// * `program` — the program to export
    /// * `start_addr` / `end_addr` — optional address range restriction
    ///
    /// Returns the number of lines written.
    pub fn write(
        &self,
        file: &Path,
        program: &Program,
        start_addr: Option<u64>,
        end_addr: Option<u64>,
    ) -> io::Result<usize> {
        let mut writer = io::BufWriter::new(fs::File::create(file)?);
        let opts = &self.options;
        let mut line_count = 0usize;

        // HTML header
        if opts.is_html {
            writeln!(writer, "<html><BODY BGCOLOR=#ffffe0>")?;
            writeln!(writer, "<FONT FACE=COURIER SIZE=3><STRONG><PRE>")?;
        }

        // Collect and sort listing rows
        let mut rows: Vec<&ListingRow> = program.listing.rows.values().collect();
        rows.sort_by_key(|r| r.address);

        // Filter by address range if specified
        let rows: Vec<&&ListingRow> = rows
            .iter()
            .filter(|row| {
                let addr = row.address.offset;
                if let Some(start) = start_addr {
                    if addr < start {
                        return false;
                    }
                }
                if let Some(end) = end_addr {
                    if addr > end {
                        return false;
                    }
                }
                true
            })
            .collect();

        for row in &rows {
            let addr = row.address.offset;

            // HTML anchor
            if opts.is_html {
                let href = format!("{:x}", addr);
                write!(writer, "{}", begin_anchor(&href))?;
                write!(writer, "{}", END_ANCHOR)?;
            }

            // Address field
            let addr_str = if opts.show_block_name_in_operands {
                // Try to find the block name
                let block_name = program
                    .memory_blocks
                    .values()
                    .find(|b| addr >= b.range.start.offset && addr <= b.range.end.offset)
                    .map(|b| b.name.as_str());
                match block_name {
                    Some(name) => format!("{}:{:x}", name, addr),
                    None => format!("{:x}", addr),
                }
            } else {
                format!("{:x}", addr)
            };
            write!(writer, "{}", clip(&addr_str, opts.addr_width, true, true))?;

            // Bytes field
            if opts.bytes_width > 0 {
                let bytes_hex: String = row
                    .bytes
                    .iter()
                    .enumerate()
                    .map(|(i, b)| {
                        if i > 0 {
                            format!("{}{:02x}", BYTES_DELIM, b)
                        } else {
                            format!("{:02x}", b)
                        }
                    })
                    .collect();
                write!(writer, "{}", clip(&bytes_hex, opts.bytes_width, true, true))?;
            }

            // Label field
            if opts.label_width > 0 {
                let label_text = row
                    .label
                    .as_ref()
                    .map(|l| format!("{}{}", l, opts.label_suffix))
                    .unwrap_or_default();
                write!(writer, "{}", clip(&label_text, opts.label_width, true, true))?;
            }

            // Pre-mnemonic fill
            if opts.pre_mnemonic_width > 0 {
                write!(writer, "{}", get_fill(opts.pre_mnemonic_width))?;
            }

            // Mnemonic
            if opts.mnemonic_width > 0 {
                let mnemonic_text = clip(&row.mnemonic.text, opts.mnemonic_width.saturating_sub(1), false, true);
                write!(
                    writer,
                    "{}{}",
                    mnemonic_text,
                    get_fill(opts.mnemonic_width.saturating_sub(row.mnemonic.text.len()))
                )?;
            }

            // Operands
            if opts.operand_width > 0 {
                write!(writer, "{}", clip(&row.operands, opts.operand_width, true, true))?;
            }

            // End-of-line comment
            if opts.show_comments {
                if let Some(ref comment) = row.comment {
                    if !comment.is_empty() {
                        let comment_text = format!("{}{}", opts.comment_prefix, comment);
                        write!(
                            writer,
                            "{}",
                            clip(&comment_text, opts.eol_width, true, true)
                        )?;
                    }
                }
            }

            writeln!(writer)?;
            line_count += 1;

            // Back references (if we have the data)
            if opts.show_back_references {
                let back_refs = ReferenceLineDispenser::for_code_unit(program, addr, false, opts);
                if back_refs.has_more_lines() {
                    let mut refs = back_refs;
                    while refs.has_more_lines() {
                        if let Some(line) = refs.get_next_line() {
                            writeln!(writer, "{}", line)?;
                            line_count += 1;
                        }
                    }
                    refs.dispose();
                }
            }
        }

        // HTML footer
        if opts.is_html {
            writeln!(writer, "</PRE></STRONG></FONT></BODY></html>")?;
        }

        writer.flush()?;
        Ok(line_count)
    }

    /// Write a listing with structured data (sub-data fields, plates).
    ///
    /// This is a more detailed output mode that includes plate comments,
    /// function signatures, pre/post comments, and structure fields.
    pub fn write_detailed(
        &self,
        file: &Path,
        program: &Program,
        start_addr: Option<u64>,
        end_addr: Option<u64>,
    ) -> io::Result<usize> {
        let mut writer = io::BufWriter::new(fs::File::create(file)?);
        let opts = &self.options;
        let mut line_count = 0usize;

        // HTML header
        if opts.is_html {
            writeln!(writer, "<html><BODY BGCOLOR=#ffffe0>")?;
            writeln!(writer, "<FONT FACE=COURIER SIZE=3><STRONG><PRE>")?;
        }

        let mut rows: Vec<&ListingRow> = program.listing.rows.values().collect();
        rows.sort_by_key(|r| r.address);

        let addr_fill = get_fill(opts.addr_width + opts.bytes_width);

        for row in &rows {
            let addr = row.address.offset;

            if let Some(start) = start_addr {
                if addr < start {
                    continue;
                }
            }
            if let Some(end) = end_addr {
                if addr > end {
                    continue;
                }
            }

            // HTML anchor
            if opts.is_html {
                write!(writer, "{}{:x}{}", begin_anchor(""), addr, END_ANCHOR)?;
            }

            // Plate comment (function entry header)
            if opts.show_properties {
                // Check if this is a function entry point by looking at labels
                let is_func_entry = program
                    .symbol_table
                    .symbols
                    .values()
                    .any(|s| s.address().offset == addr && s.kind() == ghidra_core::symbol::SymbolType::Function);

                if is_func_entry {
                    // Write plate header
                    let plate_width = opts.pre_mnemonic_width
                        + opts.mnemonic_width
                        + opts.operand_width
                        + opts.eol_width;
                    if plate_width > 0 {
                        let stars = "*".repeat(plate_width);
                        let plate_fill = get_fill(opts.addr_width + opts.bytes_width);
                        writeln!(writer, "{}{}{}", plate_fill, opts.comment_prefix, stars)?;
                        line_count += 1;

                        // Function name
                        let func_name = program
                            .symbol_table
                            .symbols
                            .values()
                            .find(|s| s.address().offset == addr && s.kind() == ghidra_core::symbol::SymbolType::Function)
                            .map(|s| s.name().clone())
                            .unwrap_or_else(|| "FUNCTION".to_string());

                        let s = clip(&func_name, plate_width.saturating_sub(2), false, true);
                        let before = (plate_width.saturating_sub(2).saturating_sub(s.len())) / 2;
                        let after = plate_width.saturating_sub(2).saturating_sub(s.len()).saturating_sub(before);
                        writeln!(
                            writer,
                            "{}{}*{}{}{}*",
                            plate_fill,
                            opts.comment_prefix,
                            get_fill(before),
                            s,
                            get_fill(after)
                        )?;
                        line_count += 1;

                        writeln!(writer, "{}{}{}", plate_fill, opts.comment_prefix, stars)?;
                        line_count += 1;
                    }
                }
            }

            // Pre-comment
            if opts.show_comments {
                if let Some(ref comment) = row.comment {
                    // If the comment looks like a pre-comment (contains newlines
                    // or is associated with this address), write it before the line
                    if comment.contains('\n') {
                        for line in comment.lines() {
                            writeln!(writer, "{}{}{}", addr_fill, opts.comment_prefix, line)?;
                            line_count += 1;
                        }
                    }
                }
            }

            // Main disassembly line
            let mut main_line = String::new();

            // Address
            let addr_str = format!("{:x}", addr);
            main_line.push_str(&clip(&addr_str, opts.addr_width, true, true));

            // Bytes
            if opts.bytes_width > 0 {
                let bytes_hex: String = row
                    .bytes
                    .iter()
                    .map(|b| format!("{:02x}", b))
                    .collect::<Vec<_>>()
                    .join(BYTES_DELIM);
                main_line.push_str(&clip(&bytes_hex, opts.bytes_width, true, true));
            }

            // Label
            if opts.label_width > 0 {
                let label_text = row
                    .label
                    .as_ref()
                    .map(|l| format!("{}{}", l, opts.label_suffix))
                    .unwrap_or_default();
                main_line.push_str(&clip(&label_text, opts.label_width, true, true));
            }

            // Pre-mnemonic
            if opts.pre_mnemonic_width > 0 {
                main_line.push_str(&get_fill(opts.pre_mnemonic_width));
            }

            // Mnemonic
            if opts.mnemonic_width > 0 {
                let m = clip(
                    &row.mnemonic.text,
                    opts.mnemonic_width.saturating_sub(1),
                    false,
                    true,
                );
                main_line.push_str(&m);
                main_line.push_str(&get_fill(
                    opts.mnemonic_width.saturating_sub(row.mnemonic.text.len()),
                ));
            }

            // Operands
            if opts.operand_width > 0 {
                main_line.push_str(&clip(&row.operands, opts.operand_width, true, true));
            }

            // EOL comment
            if opts.show_comments {
                if let Some(ref comment) = row.comment {
                    if !comment.contains('\n') && !comment.is_empty() {
                        let comment_text = format!("{}{}", opts.comment_prefix, comment);
                        main_line.push_str(&clip(&comment_text, opts.eol_width, true, true));
                    }
                }
            }

            if !main_line.is_empty() {
                writeln!(writer, "{}", main_line)?;
                line_count += 1;
            }

            // Post-comment
            if opts.show_comments {
                if let Some(ref comment) = row.comment {
                    if comment.contains('\n') {
                        // Multi-line comments are treated as both pre and post
                        // The post portion was already handled
                    }
                }
            }
        }

        // HTML footer
        if opts.is_html {
            writeln!(writer, "</PRE></STRONG></FONT></BODY></html>")?;
        }

        writer.flush()?;
        Ok(line_count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ghidra_core::addr::{Address, AddressRange};
    use ghidra_core::listing::ListingRow;
    use ghidra_core::program::{MemoryBlock, MemoryPermissions, Program};

    fn make_test_program() -> Program {
        let mut prog = Program::new("test.bin", Address::new(0x400000));
        prog.memory_blocks.insert(
            ".text".to_string(),
            MemoryBlock {
                name: ".text".to_string(),
                range: AddressRange::new(Address::new(0x400000), Address::new(0x4000ff)),
                permissions: MemoryPermissions::RX,
                initialized: true,
                data: Vec::new(),
            },
        );

        prog.listing.add(
            Address::new(0x400000),
            ListingRow::new(Address::new(0x400000), vec![0x55], "push", "rbp"),
        );
        prog.listing.add(
            Address::new(0x400001),
            ListingRow::new(
                Address::new(0x400001),
                vec![0x48, 0x89, 0xe5],
                "mov",
                "rbp, rsp",
            ),
        );
        prog.listing.add(
            Address::new(0x400004),
            ListingRow::new(
                Address::new(0x400004),
                vec![0xb8, 0x00, 0x00, 0x00, 0x00],
                "mov",
                "eax, 0x0",
            ),
        );

        prog.symbol_table
            .add(ghidra_core::symbol::Symbol::function("main", Address::new(0x400000)));

        prog
    }

    #[test]
    fn test_write_plaintext() {
        let prog = make_test_program();
        let opts = ProgramTextOptions::plaintext();
        let writer = ProgramTextWriter::new(opts);
        let tmp = std::env::temp_dir().join("ghidra_test_listing.txt");
        let count = writer.write(&tmp, &prog, None, None).unwrap();

        let content = fs::read_to_string(&tmp).unwrap();
        assert!(content.contains("push"));
        assert!(content.contains("rbp"));
        assert!(content.contains("mov"));
        assert!(count >= 3);

        let _ = fs::remove_file(&tmp);
    }

    #[test]
    fn test_write_html() {
        let prog = make_test_program();
        let opts = ProgramTextOptions::html();
        let writer = ProgramTextWriter::new(opts);
        let tmp = std::env::temp_dir().join("ghidra_test_listing.html");
        writer.write(&tmp, &prog, None, None).unwrap();

        let content = fs::read_to_string(&tmp).unwrap();
        assert!(content.contains("<html>"));
        assert!(content.contains("push"));
        assert!(content.contains("</html>"));

        let _ = fs::remove_file(&tmp);
    }

    #[test]
    fn test_write_address_restricted() {
        let prog = make_test_program();
        let opts = ProgramTextOptions::plaintext();
        let writer = ProgramTextWriter::new(opts);
        let tmp = std::env::temp_dir().join("ghidra_test_listing_restricted.txt");
        let count = writer.write(&tmp, &prog, Some(0x400000), Some(0x400001)).unwrap();

        let content = fs::read_to_string(&tmp).unwrap();
        assert!(content.contains("push"));
        assert!(count >= 1);

        let _ = fs::remove_file(&tmp);
    }

    #[test]
    fn test_write_detailed() {
        let prog = make_test_program();
        let opts = ProgramTextOptions::plaintext();
        let writer = ProgramTextWriter::new(opts);
        let tmp = std::env::temp_dir().join("ghidra_test_listing_detailed.txt");
        let count = writer.write_detailed(&tmp, &prog, None, None).unwrap();

        let content = fs::read_to_string(&tmp).unwrap();
        assert!(content.contains("push"));
        assert!(count >= 3);

        let _ = fs::remove_file(&tmp);
    }
}
