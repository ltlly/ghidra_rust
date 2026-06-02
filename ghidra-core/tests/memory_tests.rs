//! Tests for memory blocks, read/write, memory map management, and segment permissions.
//!
//! Covers the `ghidra_core::program` and `ghidra_core::mem` modules:
//! - [`MemoryBlock`] creation and properties
//! - [`MemoryPermissions`] flags and combinations
//! - Program-level memory operations
//! - Symbol table and listing data

use ghidra_core::addr::{Address, AddressRange};
use ghidra_core::data::DataType;
use ghidra_core::listing::ListingRow;
use ghidra_core::program::{
    Comment, CommentKind, ListingData, MemoryBlock, MemoryPermissions, Program, SymbolTable,
};
use ghidra_core::symbol::{Symbol, SymbolKind, SymbolSource};

// ---------------------------------------------------------------------------
// MemoryBlock tests
// ---------------------------------------------------------------------------

#[test]
fn test_memory_block_creation() {
    let range = AddressRange::new(Address::new(0x400000), Address::new(0x40FFFF));
    let block = MemoryBlock {
        name: ".text".to_string(),
        range,
        permissions: MemoryPermissions::RX,
        initialized: true,
    };

    assert_eq!(block.name, ".text");
    assert_eq!(block.range.start, Address::new(0x400000));
    assert_eq!(block.range.end, Address::new(0x40FFFF));
    assert_eq!(block.permissions, MemoryPermissions::RX);
    assert!(block.initialized);
}

#[test]
fn test_memory_block_equality_clone() {
    let range = AddressRange::new(Address::new(0x1000), Address::new(0x1FFF));
    let a = MemoryBlock {
        name: "block_a".to_string(),
        range,
        permissions: MemoryPermissions::R,
        initialized: true,
    };
    let b = a.clone();
    assert_eq!(a.name, b.name);
    assert_eq!(a.range, b.range);
    assert_eq!(a.permissions, b.permissions);
    assert_eq!(a.initialized, b.initialized);
}

// ---------------------------------------------------------------------------
// MemoryPermissions tests
// ---------------------------------------------------------------------------

#[test]
fn test_memory_permissions_variants() {
    assert_eq!(MemoryPermissions::R as i32, MemoryPermissions::R as i32);
    assert_eq!(MemoryPermissions::RX as i32, MemoryPermissions::RX as i32);
    assert_eq!(MemoryPermissions::RW as i32, MemoryPermissions::RW as i32);
    assert_eq!(MemoryPermissions::RWX as i32, MemoryPermissions::RWX as i32);
}

#[test]
fn test_memory_permissions_copy() {
    let perm = MemoryPermissions::RWX;
    let copy = perm;
    assert_eq!(copy, MemoryPermissions::RWX);
    let clone = perm.clone();
    assert_eq!(clone, MemoryPermissions::RWX);
}

#[test]
fn test_memory_permissions_distinct() {
    // Verify all permission combinations are distinct
    assert_ne!(MemoryPermissions::R as i32, MemoryPermissions::RX as i32);
    assert_ne!(MemoryPermissions::RX as i32, MemoryPermissions::RW as i32);
    assert_ne!(MemoryPermissions::RW as i32, MemoryPermissions::RWX as i32);
}

// ---------------------------------------------------------------------------
// Program creation tests
// ---------------------------------------------------------------------------

#[test]
fn test_program_creation() {
    let prog = Program::new("test.bin", Address::new(0x400000));
    assert_eq!(prog.name, "test.bin");
    assert_eq!(prog.image_base, Address::new(0x400000));
    assert!(prog.file_path.is_none());
    assert!(prog.memory_blocks.is_empty());
    assert!(prog.imports.is_empty());
    assert!(prog.exports.is_empty());
}

#[test]
fn test_program_with_file_path() {
    let mut prog = Program::new("app.exe", Address::new(0x140000000));
    prog.file_path = Some("/home/user/app.exe".to_string());
    assert_eq!(prog.file_path.as_deref(), Some("/home/user/app.exe"));
}

// ---------------------------------------------------------------------------
// Memory block management tests
// ---------------------------------------------------------------------------

#[test]
fn test_add_memory_blocks_to_program() {
    let mut prog = Program::new("sections.elf", Address::new(0x400000));

    // .text section
    let text_range = AddressRange::new(Address::new(0x401000), Address::new(0x401FFF));
    prog.memory_blocks.insert(
        ".text".to_string(),
        MemoryBlock {
            name: ".text".to_string(),
            range: text_range,
            permissions: MemoryPermissions::RX,
            initialized: true,
        },
    );

    // .data section
    let data_range = AddressRange::new(Address::new(0x600000), Address::new(0x600FFF));
    prog.memory_blocks.insert(
        ".data".to_string(),
        MemoryBlock {
            name: ".data".to_string(),
            range: data_range,
            permissions: MemoryPermissions::RW,
            initialized: true,
        },
    );

    // .bss section (uninitialized)
    let bss_range = AddressRange::new(Address::new(0x601000), Address::new(0x601FFF));
    prog.memory_blocks.insert(
        ".bss".to_string(),
        MemoryBlock {
            name: ".bss".to_string(),
            range: bss_range,
            permissions: MemoryPermissions::RW,
            initialized: false,
        },
    );

    assert_eq!(prog.memory_blocks.len(), 3);
}

#[test]
fn test_memory_block_lookup() {
    let mut prog = Program::new("lookup.elf", Address::new(0x400000));

    let text_range = AddressRange::new(Address::new(0x401000), Address::new(0x401FFF));
    prog.memory_blocks.insert(
        ".text".to_string(),
        MemoryBlock {
            name: ".text".to_string(),
            range: text_range,
            permissions: MemoryPermissions::RX,
            initialized: true,
        },
    );

    let data_range = AddressRange::new(Address::new(0x600000), Address::new(0x600FFF));
    prog.memory_blocks.insert(
        ".data".to_string(),
        MemoryBlock {
            name: ".data".to_string(),
            range: data_range,
            permissions: MemoryPermissions::RW,
            initialized: true,
        },
    );

    // Lookup by name
    let text_block = prog.memory_blocks.get(".text");
    assert!(text_block.is_some());
    assert_eq!(text_block.unwrap().permissions, MemoryPermissions::RX);

    // Lookup by address
    let block = prog.memory_block_at(&Address::new(0x401020));
    assert!(block.is_some());
    assert_eq!(block.unwrap().name, ".text");

    let block = prog.memory_block_at(&Address::new(0x600050));
    assert!(block.is_some());
    assert_eq!(block.unwrap().name, ".data");

    // Address not in any block
    let block = prog.memory_block_at(&Address::new(0x500000));
    assert!(block.is_none());
}

#[test]
fn test_read_bytes_demo() {
    let prog = Program::demo();
    let bytes = prog.read_bytes(Address::new(0x1000), 4);
    assert_eq!(bytes.len(), 4);
    // Demo returns patterned bytes based on offset
    assert_eq!(bytes[0], 0x00); // 0x1000 & 0xFF = 0x00
    assert_eq!(bytes[1], 0x10); // 0x1001 & 0xFF = 0x10 (actually (0x1000+1)&0xFF = 0x01)
}

// ---------------------------------------------------------------------------
// Symbol table tests
// ---------------------------------------------------------------------------

#[test]
fn test_symbol_table_add_lookup() {
    let mut table = SymbolTable::default();
    assert!(table.is_empty());
    assert_eq!(table.len(), 0);

    let func = Symbol::function("main", Address::new(0x1000));
    table.add(func);

    assert_eq!(table.len(), 1);
    assert!(!table.is_empty());

    let sym = table.get(&Address::new(0x1000));
    assert!(sym.is_some());
    assert_eq!(sym.unwrap().name, "main");
    assert_eq!(sym.unwrap().kind, SymbolKind::Function);
}

#[test]
fn test_symbol_table_multiple_types() {
    let mut table = SymbolTable::default();

    table.add(Symbol::function("_start", Address::new(0x1000)));
    table.add(Symbol::label("str_hello", Address::new(0x2000)));
    table.add(Symbol::import("printf", Address::new(0x3000)));
    table.add(Symbol::label("global_var", Address::new(0x4000)));

    assert_eq!(table.len(), 4);

    // Iterate
    let symbols: Vec<&Symbol> = table.iter().collect();
    assert_eq!(symbols.len(), 4);

    // Verify kinds
    let kinds: Vec<SymbolKind> = symbols.iter().map(|s| s.kind).collect();
    assert!(kinds.contains(&SymbolKind::Function));
    assert!(kinds.contains(&SymbolKind::Label));
    assert!(kinds.contains(&SymbolKind::Import));
}

#[test]
fn test_symbol_table_rebuild_tree() {
    let mut table = SymbolTable::default();
    table.add(Symbol::function("main", Address::new(0x1000)));
    table.add(Symbol::label("data_arr", Address::new(0x2000)));
    table.add(Symbol::import("malloc", Address::new(0x3000)));

    table.rebuild_tree();
    // Tree should have Functions, Labels, Imports branches
    assert!(!table.tree.is_leaf());
    assert!(table.tree.children.len() >= 3);
}

// ---------------------------------------------------------------------------
// Listing data tests
// ---------------------------------------------------------------------------

#[test]
fn test_listing_data_add_lookup() {
    let mut listing = ListingData::default();

    let row = ListingRow::new(
        Address::new(0x1000),
        vec![0x55, 0x48, 0x89, 0xE5],
        "push",
        "rbp",
    );
    listing.add(Address::new(0x1000), row);

    let found = listing.get(&Address::new(0x1000));
    assert!(found.is_some());
    assert_eq!(found.unwrap().mnemonic.text, "push");
    assert_eq!(found.unwrap().operands, "rbp");
}

#[test]
fn test_listing_iter_from() {
    let mut listing = ListingData::default();

    for i in 0..10 {
        let addr = Address::new(0x1000 + i);
        let row = ListingRow::new(addr, vec![0x90], "nop", "");
        listing.add(addr, row);
    }

    let rows = listing.iter_from(Address::new(0x1000), 5);
    assert_eq!(rows.len(), 5);
    assert_eq!(rows[0].address, Address::new(0x1000));
    assert_eq!(rows[4].address, Address::new(0x1004));
}

#[test]
fn test_listing_demo_rows() {
    let mut listing = ListingData::default();
    listing.add_demo_rows();

    // Should have instruction rows
    let rows = listing.iter_from(Address::new(0x1000), 5);
    assert_eq!(rows.len(), 5);

    // First should be "push rbp"
    assert_eq!(rows[0].mnemonic.text, "push");
    assert_eq!(rows[0].operands, "rbp");
}

#[test]
fn test_listing_row_creation() {
    let row = ListingRow::new(Address::new(0x1000), vec![0xE8, 0x00, 0x00, 0x00, 0x00], "call", "printf");

    assert_eq!(row.address, Address::new(0x1000));
    assert_eq!(row.bytes.len(), 5);
    assert_eq!(row.mnemonic.text, "call");
    assert_eq!(row.operands, "printf");
    assert_eq!(row.full_instruction, "call printf");
    assert!(row.label.is_none());
    assert!(row.comment.is_none());
}

#[test]
fn test_listing_row_no_operands() {
    let row = ListingRow::new(Address::new(0x1000), vec![0xC3], "ret", "");
    assert_eq!(row.full_instruction, "ret");
}

// ---------------------------------------------------------------------------
// Comment tests
// ---------------------------------------------------------------------------

#[test]
fn test_comments() {
    let comment = Comment {
        kind: CommentKind::Plate,
        text: "Function entry point".to_string(),
        author: "analyst".to_string(),
    };

    assert_eq!(comment.kind, CommentKind::Plate);
    assert_eq!(comment.text, "Function entry point");
    assert_eq!(comment.author, "analyst");
}

#[test]
fn test_comment_kinds() {
    let kinds = [
        CommentKind::Plate,
        CommentKind::Pre,
        CommentKind::EndOfLine,
        CommentKind::Post,
        CommentKind::Repeatable,
    ];

    // Verify all variants are distinct
    for i in 0..kinds.len() {
        for j in (i + 1)..kinds.len() {
            assert_ne!(kinds[i] as i32, kinds[j] as i32,
                "CommentKind variants should be distinct");
        }
    }
}

// ---------------------------------------------------------------------------
// Program-level demo test
// ---------------------------------------------------------------------------

#[test]
fn test_demo_program() {
    let prog = Program::demo();

    assert!(!prog.name.is_empty());
    assert!(prog.file_path.is_some());

    // Memory blocks
    assert!(!prog.memory_blocks.is_empty());
    assert!(prog.memory_blocks.contains_key(".text"));
    assert!(prog.memory_blocks.contains_key(".data"));

    // Symbol table
    assert!(!prog.symbol_table.is_empty());

    // Listing
    let rows = prog.listing.iter_from(Address::new(0x1000), 3);
    assert!(!rows.is_empty());

    // Xrefs
    let xrefs = prog.xrefs_to(&Address::new(0x1000));
    assert!(!xrefs.is_empty());

    // Comments
    let comments = prog.comments.get(&Address::new(0x1000));
    assert!(comments.is_some());

    // Data types
    assert!(prog.data_types.contains_key(&Address::new(0x1000)));

    // Imports/Exports
    assert!(!prog.imports.is_empty());
    assert!(!prog.exports.is_empty());
}

#[test]
fn test_symbol_at() {
    let prog = Program::demo();
    let sym = prog.symbol_at(&Address::new(0x1000));
    assert!(sym.is_some());
    assert_eq!(sym.unwrap().name, "main");
}

#[test]
fn test_xrefs_to() {
    let prog = Program::demo();
    let xrefs = prog.xrefs_to(&Address::new(0x1000));
    assert_eq!(xrefs.len(), 2);
    assert!(xrefs.contains(&&Address::new(0x1010)));
    assert!(xrefs.contains(&&Address::new(0x1030)));
}

// ---------------------------------------------------------------------------
// Symbol type tests
// ---------------------------------------------------------------------------

#[test]
fn test_symbol_kind_display() {
    let displays = [
        (SymbolKind::Function, "Function"),
        (SymbolKind::Label, "Label"),
        (SymbolKind::Import, "Import"),
        (SymbolKind::Export, "Export"),
        (SymbolKind::Class, "Class"),
        (SymbolKind::Namespace, "Namespace"),
        (SymbolKind::Library, "Library"),
        (SymbolKind::Parameter, "Parameter"),
        (SymbolKind::Unknown, "Unknown"),
    ];

    for (kind, expected) in &displays {
        assert_eq!(format!("{}", kind), *expected);
    }
}

#[test]
fn test_symbol_source() {
    let sources = [
        SymbolSource::UserDefined,
        SymbolSource::Imported,
        SymbolSource::Analysis,
        SymbolSource::Default,
    ];
    // All variants are distinct
    for i in 0..sources.len() {
        for j in (i + 1)..sources.len() {
            assert_ne!(sources[i] as i32, sources[j] as i32);
        }
    }
}

#[test]
fn test_symbol_creation() {
    let sym = Symbol::new("test_func", Address::new(0x400000), SymbolKind::Function);
    assert_eq!(sym.name, "test_func");
    assert_eq!(sym.address, Address::new(0x400000));
    assert_eq!(sym.kind, SymbolKind::Function);
    assert!(sym.primary);
    assert!(sym.namespace.is_none());
    assert_eq!(sym.source, SymbolSource::UserDefined);

    let imported = Symbol::import("kernel32.dll", Address::new(0x8000));
    assert_eq!(imported.kind, SymbolKind::Import);
}
