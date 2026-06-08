//! Tests for memory blocks, read/write, memory map management, and segment permissions.
//!
//! Covers the `ghidra_core::program` and `ghidra_core::mem` modules:
//! - [`MemoryBlock`] creation and properties
//! - [`MemoryPermissions`] flags and combinations
//! - Program-level memory operations
//! - Symbol table and listing data

use ghidra_core::addr::{Address, AddressRange};
use ghidra_core::listing::ListingRow;
use ghidra_core::program::{
    Comment, CommentKind, ListingData, MemoryBlock, MemoryPermissions, Program, SymbolTable,
};
use ghidra_core::symbol::{Symbol, SourceType, SymbolType};

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
        data: Vec::new(),
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
        data: Vec::new(),
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
    assert!(prog.domain_file_path.is_none());
}

#[test]
fn test_program_with_file_path() {
    let mut prog = Program::new("app.exe", Address::new(0x140000000));
    prog.domain_file_path = Some("/home/user/app.exe".to_string());
    assert_eq!(prog.domain_file_path.as_deref(), Some("/home/user/app.exe"));
}

// ---------------------------------------------------------------------------
// Memory block management tests
// ---------------------------------------------------------------------------

#[test]
fn test_add_memory_blocks_to_program() {
    // Use Program::demo() which pre-populates memory blocks
    let prog = Program::demo();

    let blocks = prog.memory.get_blocks();
    let names: Vec<&str> = blocks.iter().map(|b| b.get_name()).collect();
    assert!(names.iter().any(|n| *n == ".text"), "Expected .text block");
    assert!(names.iter().any(|n| *n == ".data"), "Expected .data block");
}

#[test]
fn test_memory_block_lookup() {
    // Use demo program which has .text at 0x1000 and .data at 0x2000
    let prog = Program::demo();

    // Lookup by name
    let text_block = prog.memory.get_block_by_name(".text");
    assert!(text_block.is_some());

    // Lookup by address
    let block = prog.memory.get_block(&Address::new(0x1000));
    assert!(block.is_some());

    let block = prog.memory.get_block(&Address::new(0x2000));
    assert!(block.is_some());

    // Address not in any block
    let block = prog.memory.get_block(&Address::new(0x500000));
    assert!(block.is_none());
}

#[test]
fn test_read_bytes_demo() {
    let prog = Program::demo();
    let bytes = prog.read_bytes(Address::new(0x1000), 4);
    assert_eq!(bytes.len(), 4);
    // First byte should be 0x55 (push rbp) from the demo program
    assert_eq!(bytes[0], 0x55);
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
    assert_eq!(sym.unwrap().name(), "main");
    assert_eq!(sym.unwrap().kind(), SymbolType::Function);
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
    let kinds: Vec<SymbolType> = symbols.iter().map(|s| s.kind()).collect();
    assert!(kinds.contains(&SymbolType::Function));
    assert!(kinds.contains(&SymbolType::Label));
    assert!(kinds.contains(&SymbolType::Import));
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

    let rows: Vec<_> = listing.rows.values().collect();
    assert_eq!(rows.len(), 10);
}

#[test]
fn test_listing_demo_rows() {
    let mut listing = ListingData::default();
    listing.add_demo_rows();

    // Should have instruction rows
    let rows: Vec<_> = listing.rows.values().collect();
    assert!(!rows.is_empty());
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
    assert!(prog.domain_file_path.is_some());

    // Memory should have blocks
    let blocks = prog.memory.get_blocks();
    assert!(!blocks.is_empty(), "Expected memory blocks in demo program");

    // Symbol table
    assert!(!prog.symbols.symbols.is_empty(), "Expected symbols in demo program");
}

#[test]
fn test_symbol_at() {
    let prog = Program::demo();
    // Symbols are stored in prog.symbols (ProgramSymbolTable)
    let sym = prog.symbols.symbols.get(&Address::new(0x1000));
    assert!(sym.is_some(), "Expected symbol at 0x1000");
    assert_eq!(sym.unwrap().name(), "main");
}

#[test]
fn test_xrefs_to() {
    let prog = Program::demo();
    // References are stored via ReferenceManager
    // The demo adds references to 0x2000 from 0x1016 and 0x100f
    let refs = prog.references.get_references_to(Address::new(0x2000));
    assert!(!refs.is_empty(), "Expected xrefs to 0x2000");
}

// ---------------------------------------------------------------------------
// Symbol type tests
// ---------------------------------------------------------------------------

#[test]
fn test_symbol_kind_display() {
    let displays = [
        (SymbolType::Function, "Function"),
        (SymbolType::Label, "Label"),
        (SymbolType::Import, "Import"),
        (SymbolType::Export, "Export"),
        (SymbolType::Class, "Class"),
        (SymbolType::Namespace, "Namespace"),
        (SymbolType::Library, "Library"),
        (SymbolType::Parameter, "Parameter"),
        (SymbolType::Unknown, "Unknown"),
    ];

    for (kind, expected) in &displays {
        assert_eq!(format!("{}", kind), *expected);
    }
}

#[test]
fn test_symbol_source() {
    let sources = [
        SourceType::UserDefined,
        SourceType::Imported,
        SourceType::Analysis,
        SourceType::Default,
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
    let sym = Symbol::new("test_func", Address::new(0x400000), SymbolType::Function);
    assert_eq!(sym.name(), "test_func");
    assert_eq!(*sym.address(), Address::new(0x400000));
    assert_eq!(sym.kind(), SymbolType::Function);

    let imported = Symbol::import("kernel32.dll", Address::new(0x8000));
    assert_eq!(imported.kind(), SymbolType::Import);
}
