# Ghidra Rust Architecture

This document describes the internal architecture of Ghidra Rust: crate organization, core types, data flow, and design decisions.

## Table of Contents

- [Crate Dependency Graph](#crate-dependency-graph)
- [Core Types](#core-types)
- [Decompiler Pipeline](#decompiler-pipeline)
- [Processor Module Structure](#processor-module-structure)
- [Binary Format Loaders](#binary-format-loaders)
- [GUI Component Tree](#gui-component-tree)
- [Server API Design](#server-api-design)
- [Data Flow Diagrams](#data-flow-diagrams)

## Crate Dependency Graph

```
                          ┌─────────────────────────────────┐
                          │         ghidra-app              │
                          │  CLI (clap) + Server (axum)     │
                          │  Binary: ghidra-server          │
                          └──────┬──────┬──────┬───────────┘
                                 │      │      │
                  ┌──────────────┘      │      └──────────────┐
                  │                     │                     │
                  v                     v                     v
    ┌─────────────────────┐  ┌──────────────────┐  ┌────────────────────┐
    │     ghidra-gui      │  │ ghidra-emulation │  │ ghidra-processors  │
    │  egui/eframe GUI    │  │  P-code emulator │  │  ISA modules       │
    └──────────┬──────────┘  └────────┬─────────┘  └────────┬───────────┘
               │                      │                      │
               │            ┌─────────┴─────────┐            │
               │            │                   │            │
               v            v                   v            v
    ┌──────────────────────────────────────────────────────────────────┐
    │                       ghidra-decompile                           │
    │  SLEIGH parser | P-code IR | CFG | SSA | Data-flow | C output   │
    └────────────────────────────────┬─────────────────────────────────┘
                                     │
                                     │
                                     v
    ┌──────────────────────────────────────────────────────────────────┐
    │                         ghidra-core                              │
    │  Address | DataType | Program | SymbolTable | Database | Graph   │
    └──────────────────────────────────────────────────────────────────┘
```

### Crate Descriptions

**`ghidra-core`** -- The foundation. No dependency on any other workspace crate. Provides:
- Address spaces, addresses, and address ranges
- Data type system (primitives, pointers, arrays, structs, unions, enums, typedefs, function definitions)
- Symbol tables and hierarchical symbol tree
- Program model (memory blocks, listing, cross-references, comments, imports/exports)
- Database layer (SQLite-backed, mapping Ghidra's custom B-tree concepts)
- Graph utilities (call graph, control-flow graph primitives via petgraph)
- Filesystem abstraction and generic system utility types
- Error types (thiserror-based)

**`ghidra-decompile`** -- The decompiler pipeline. Depends on `ghidra-core`. Provides:
- SLEIGH specification language parser (`.slaspec` and compiled `.sla` files)
- P-code intermediate representation (65+ opcodes, varnodes, operations, sequences)
- P-code emitter trait for code generation from SLEIGH constructors
- Control-flow graph construction and analysis (dominators, loops)
- SSA (Static Single Assignment) form construction
- Data-flow analysis engine (def-use chains, reaching definitions, live ranges)
- Constant propagation, copy propagation, dead-code elimination
- Type recovery and stack variable analysis
- Structured C token output with control-flow structuring

**`ghidra-emulation`** -- P-code emulator. Depends on `ghidra-core` and `ghidra-decompile`. Provides:
- Step-through execution of P-code operations
- Register and memory state tracking
- Breakpoint management with conditions and hit counts
- State save/restore (snapshots)

**`ghidra-features`** -- Analysis features and binary parsers. Depends on `ghidra-core` and `ghidra-decompile`. Provides:
- Binary format parsers: ELF, PE/COFF, Mach-O (full and thin), raw binary
- PDB debug symbol parsing
- Auto-analysis framework with pluggable analyzers
- Version tracking support
- SARIF export

**`ghidra-processors`** -- Architecture-specific processor modules. Depends on `ghidra-core`, `ghidra-decompile`, and `ghidra-features`. Provides:
- Common `ProcessorModule` trait and shared types (`Register`, `RegisterBank`, `Language`, `Endian`)
- Per-architecture modules: x86, ARM, AArch64, M68000, SuperH, Hexagon, TriCore, V850, Xtensa
- Each module contains: register definitions, instruction mnemonics, loaders, analyzers

**`ghidra-gui`** -- GUI application. Depends on `ghidra-core`, `ghidra-decompile`, and `ghidra-features`. Provides:
- `GhidraApp` -- main application state implementing `eframe::App`
- Docking framework (plugins, components, layouts, tools, actions)
- Views: listing, decompiler, bytes/hex, symbol tree
- Menu bar and toolbar with navigation, search, analysis actions
- Console panel with log filtering
- Data type manager panel with tree browser

**`ghidra-app`** -- Application binary entry point. Depends on all other crates. Provides:
- CLI argument parsing via clap (`server` and `gui` subcommands)
- Headless HTTP server with full REST API via axum
- Session management, binary loading, analysis orchestration

## Core Types

### Address (`ghidra_core::addr`)

```
AddressSpace { name: String, pointer_size: usize, big_endian: bool }
Address { offset: u64 }
AddressRange { start: Address, end: Address }
AddressFactory { spaces: HashMap<String, AddressSpace> }
```

Spaces model Ghidra's multi-space architecture: RAM (`"ram"`), register space (`"register"`), constant space (`"const"`), and temporaries (`"unique"`). An `Address` is a 64-bit offset within an implicit space.

### Data Types (`ghidra_core::data`)

```
DataType                    -- trait for type introspections
  DataTypeKind              -- Int, UInt, Float, Bool, Char, Pointer, Array, Struct, Union, Enum, Typedef, FunctionDef, Void, Undefined
  DataTypePath              -- hierarchical path: "Global"::"stdint"::"uint32_t"
  DataTypeTreeNode          -- tree node: name, path, optional data type, children
  DataTypeManager           -- trait: resolve, add, remove types
    BuiltInDataTypeManager  -- built-in C types (char, short, int, long, float, double, etc.)
    StandaloneDataTypeManager -- user-managed type archive
```

### Program (`ghidra_core::program`)

```
Program {
    name: String,
    file_path: Option<String>,
    image_base: Address,
    memory_blocks: HashMap<String, MemoryBlock>,
    symbol_table: SymbolTable,
    listing: ListingData,
    xrefs: HashMap<Address, Vec<Address>>,
    comments: HashMap<Address, Vec<Comment>>,
    data_types: HashMap<Address, Arc<dyn DataType>>,
    imports: Vec<String>,
    exports: Vec<String>,
}

MemoryBlock {
    name: String,
    range: AddressRange,
    permissions: MemoryPermissions,   // R | RX | RW | RWX
    initialized: bool,
}

ListingData {
    rows: HashMap<Address, ListingRow>,
    // ListingRow has: address, bytes, label, mnemonic, operands, full_instruction, comment
}

Symbol {
    name: String,
    address: Address,
    kind: SymbolKind,          // Function | Label | Import | Export | Class | Namespace | Library | Parameter | Unknown
    primary: bool,
    namespace: Option<String>,
    source: SymbolSource,      // UserDefined | Imported | Analysis | Default
}
```

### Database (`ghidra_core::database`)

SQLite-backed layer replacing Ghidra's custom B-tree:

```
Database    -- wraps rusqlite::Connection
Table       -- maps to a SQL table
Schema      -- column layout definition
Field       -- Ghidra field type -> SQLite column type mapping
DBRecord    -- wraps a rusqlite::Row
Transaction -- wraps rusqlite::Transaction
Buffer      -- large blob storage (chained buffers)
```

## Decompiler Pipeline

The decompiler transforms raw machine bytes into readable C source code through a multi-stage pipeline:

```
                             ┌──────────────────────┐
                             │   Raw Machine Bytes  │
                             └──────────┬───────────┘
                                        │
                    ┌───────────────────▼───────────────────┐
                    │         SLEIGH Runtime Engine          │
                    │                                       │
                    │  1. Fetch instruction bytes            │
                    │  2. Pattern-match constructors         │
                    │     against tokenized bytes            │
                    │  3. Extract operand field values       │
                    │  4. Apply context operations           │
                    │  5. Instantiate constructor template   │
                    │     as P-code operations               │
                    └───────────────────┬───────────────────┘
                                        │
                             ┌──────────▼──────────┐
                             │    P-code Sequences  │
                             │  (per instruction)   │
                             └──────────┬──────────┘
                                        │
                    ┌───────────────────▼───────────────────┐
                    │    Control-Flow Graph Construction     │
                    │                                       │
                    │  1. Identify basic blocks              │
                    │  2. Build CFG from branch targets      │
                    │  3. Compute dominator tree             │
                    │  4. Identify loops (natural loops)     │
                    └───────────────────┬───────────────────┘
                                        │
                    ┌───────────────────▼───────────────────┐
                    │        SSA Form Construction          │
                    │                                       │
                    │  1. Insert phi-nodes (MULTIEQUAL)      │
                    │  2. Rename varnodes for unique defs    │
                    │  3. Build def-use chains               │
                    └───────────────────┬───────────────────┘
                                        │
                    ┌───────────────────▼───────────────────┐
                    │         Data-Flow Analysis             │
                    │                                       │
                    │  1. Reaching definitions               │
                    │  2. Live range computation             │
                    │  3. Constant propagation               │
                    │  4. Copy propagation                   │
                    │  5. Dead-code elimination              │
                    │  6. Expression simplification          │
                    │  7. Value-set analysis (VSA)           │
                    └───────────────────┬───────────────────┘
                                        │
                    ┌───────────────────▼───────────────────┐
                    │          Type Recovery                 │
                    │                                       │
                    │  1. Stack variable detection           │
                    │  2. Parameter identification           │
                    │  3. Data type inference from usage     │
                    │  4. Structure/array reconstruction     │
                    └───────────────────┬───────────────────┘
                                        │
                    ┌───────────────────▼───────────────────┐
                    │         C Code Output                  │
                    │                                       │
                    │  1. Control-flow structuring           │
                    │     (if/else, while, do/while, for,    │
                    │      switch/case, goto)               │
                    │  2. Variable naming and scoping        │
                    │  3. Token generation (CToken)          │
                    │  4. Indentation and formatting         │
                    │  5. Comment annotation with addresses  │
                    └───────────────────┬───────────────────┘
                                        │
                             ┌──────────▼──────────┐
                             │   C Source Code     │
                             │  (human-readable)   │
                             └─────────────────────┘
```

### SLEIGH Module Structure (`ghidra_decompile::sleigh`)

```
sleigh/
  mod.rs              -- Re-exports, module documentation
  construct.rs        -- Constructor types: patterns, templates, operands, token fields
  context.rs          -- Context database, tracked variables, context operations
  pcode.rs            -- Fundamental P-code types (Varnode, OpCode, PcodeOp)
  slaspec_parser.rs   -- .slaspec file parser (grammar-based, using pest)
  sleigh.rs           -- Main SleighEngine: loader, disassembly orchestration, FlowState
  translator.rs       -- TranslateEngine: byte-to-P-code translation, parse tree walker
```

### P-code IR Types (`ghidra_decompile::pcode`)

```
OpCode                   -- 65+ operation codes with classification helpers
  is_branch()            -- Branch, Cbranch, BranchInd
  is_call()              -- Call, CallInd, CallOther
  is_return()            -- Return
  is_flow()              -- Any control-flow operation
  is_arithmetic()        -- IntAdd, IntSub, IntMul, IntDiv, IntSdiv, IntRem, IntSrem, IntNegate, IntCarry, IntScarry, IntSborrow
  is_float()             -- FloatAdd, FloatSub, FloatMul, FloatDiv, FloatNegate, FloatAbs, FloatSqrt, etc.
  is_logical()           -- IntAnd, IntOr, IntXor, BoolAnd, BoolOr, BoolXor, BoolNegate
  is_comparison()        -- IntEqual, IntNotEqual, IntSless, IntSlessEqual, IntLess, IntLessEqual, Float* equivalents
  is_shift()             -- IntLeft, IntRight, IntSright
  has_side_effects()     -- Store, Call, CallInd, CallOther, Branch, Cbranch, BranchInd, Return, New
  is_commutative()       -- IntAdd, IntMul, IntAnd, IntOr, IntXor, FloatAdd, FloatMul, Bool*, IntEqual, IntNotEqual, FloatEqual, FloatNotEqual, Piece
  input_count_hint()     -- Typical number of input varnodes
  output_count_hint()    -- Typical number of output varnodes (0, 1, or variable)

Varnode                  -- (AddressSpace, offset: u64, size: u32)
  is_constant()          -- space == "const"
  is_register()          -- space == "register"
  is_unique()            -- space == "unique" (SSA temporary)
  is_ram()               -- space == "ram"
  constant_value()       -- value if constant, else None
  overlaps(other)        -- True if varnodes overlap in same space

PcodeOperation           -- (opcode, output: Option<Varnode>, inputs: Vec<Varnode>, address: Option<Address>)

PcodeSequence            -- operations + instruction_address + byte length

SequenceBuilder          -- Builder pattern for constructing PcodeSequence (copy, load, store, int_add, int_sub, branch, call, return, etc.)

PcodeEmitter trait       -- Interface for components emitting P-code from SLEIGH constructors
```

### Analysis Module (`ghidra_decompile::analysis`)

```
analysis/
  mod.rs               -- Module documentation
  dataflow_engine.rs   -- DataFlowEngine: varnode data-flow graph, def-use chains, reaching definitions,
                          live ranges, constant propagation
  type_recovery.rs     -- Type recovery from P-code usage patterns
```

### C Output Module (`ghidra_decompile::cpp`)

```
CToken                  -- Token types: Keyword, Type, Identifier, Number, StringLiteral,
                           Comment, Operator, Punctuation, Newline, Space, Address, Indent, Dedent, Raw
format_function()       -- Entry point: P-code -> formatted C string
```

## Processor Module Structure

Each processor module implements the `ProcessorModule` trait and provides:

```
ghidra-processors/
  common.rs             -- ProcessorModule trait, Register, RegisterBank, Language, Endian
  x86/
    mod.rs              -- Module documentation, re-exports
    registers.rs        -- Complete register bank (RAX..R15, sub-registers, flags, segment, control, debug, MMX, XMM, YMM, ZMM)
    instructions.rs     -- Full x86 mnemonic enumeration, encoding helpers, addressing mode types, DecodedInstruction
    loader.rs           -- Binary format detection, instruction decoding, function boundary detection, calling convention detection
    analyzer.rs         -- StackFrame, VariableAnalyzer, FunctionDetector, JumpTable, reference collection
  arm/                  -- ARMv4 through ARMv8, Thumb, Thumb-2
  aarch64/              -- AArch64 (A64 instruction set)
  m68k/                 -- 68000 through ColdFire
  superh/               -- SH-1 through SH-4A
  hexagon/              -- Qualcomm Hexagon DSP (V5, V6x)
  tricore/              -- Infineon TriCore v1.3, v1.6
  v850/                 -- NEC/Renesas V850, V850E, V850E2
  xtensa/               -- Tensilica Xtensa LX6, LX7
```

### `ProcessorModule` Trait

```rust
pub trait ProcessorModule {
    fn name() -> &'static str;                // Human-readable processor name
    fn registers() -> RegisterBank;           // Full register definitions
    fn languages() -> Vec<Language>;          // Supported language/compiler variants
    fn instructions() -> Vec<InstructionMnemonic>;  // All instruction mnemonics
}
```

### `Language` Type

```rust
pub struct Language {
    pub id: String,              // e.g., "hexagon:LE:32:V5"
    pub description: String,     // Human-readable
    pub version: String,         // ISA version
    pub endian: Endian,          // Little, Big, or Bi
    pub pointer_size: u32,       // 32 or 64 bits
}
```

## Binary Format Loaders

Located in `ghidra-features/src/fileformats/`:

```
fileformats/
  mod.rs          -- Module overview
  elf.rs          -- ELF parser (32/64-bit, LE/BE): headers, sections, symbols, relocations, dynamic entries
  pe.rs           -- PE/COFF parser (32/64-bit): DOS header, NT headers, sections, imports, exports, resources
  macho.rs        -- Mach-O parser: header, load commands, segments, sections, symbols
  macho_full.rs   -- Full Mach-O support including FAT binary handling, code signature, dyld info
  raw.rs          -- Raw binary blob loader with configurable image base
```

Each parser uses nom for zero-copy binary parsing. The entry point for each format is a `parse_*` function that takes a `&[u8]` buffer and returns a structured representation. Loaders then populate a `Program` from the parsed structures.

## GUI Component Tree

The GUI is built with egui (immediate-mode) and follows Ghidra's docking paradigm:

```
GhidraApp (eframe::App)
  |
  |-- Top Menu Bar (menu::render_menu_bar)
  |     |-- File: New Project, Open Project, Open File, Save, Save As, Export, Close, Exit
  |     |-- Edit: Undo, Redo, Cut, Copy, Paste, Delete, Select All
  |     |-- Navigation: Find, Find Next, Go To
  |     |-- Analysis: Auto Analyze, One Shot, Clear Analysis, Configure Analyzers
  |     |-- Window: Function Graph, Data Type Manager, Memory Map, Register Manager, Script Manager
  |     |-- Help: About, Key Bindings
  |
  |-- Toolbar (render_toolbar)
  |     |-- Navigation: Back, Forward, Home
  |     |-- Address bar (GoTo)
  |     |-- Search box + Next/Prev
  |
  |-- Central Panel
  |     |-- Top: Listing View (render_listing_view)
  |     |     |-- Columns: Address | Bytes | Label | Mnemonic | Operands | XRefs | Comment
  |     |     |-- Context menu on right-click:
  |     |           Rename Label, Set Comment, Create Function, Disassemble, Clear,
  |     |           Set Data Type, Add Bookmark, Analyze From Here, Patch Instruction,
  |     |           Show References, Show XRefs, Copy Address, Copy Instruction
  |     |
  |     \-- Bottom: Decompiler View (render_decompiler_view)
  |           |-- C pseudocode display
  |           |-- Address annotations in comments
  |
  |-- Left Panel: Symbol Tree (symboltree)
  |     |-- Hierarchical tree: Functions, Labels, Imports, Exports
  |     \-- Click to navigate
  |
  |-- Right Panel (optional): Data Type Manager
  |     |-- Built-in type tree browser
  |     \-- Filter by name
  |
  |-- Bottom Panel
  |     |-- Console Panel (collapsible)
  |     |     |-- Severity filter: Debug, Info, Warning, Error
  |     |     \-- Color-coded messages with timestamps
  |     |
  |     \-- Status Bar
  |           |-- Program name, current address, symbol count
  |           \-- Task monitor progress bar with cancel button
  |
  \-- Overlays
        |-- About dialog
        \-- Search results window
```

### Docking Framework (`ghidra_gui::docking`)

```
docking/
  mod.rs         -- Module exports
  action.rs      -- DockAction: focus, close, maximize, restore, split
  component.rs   -- DockComponent: title, content area, state, actions
  layout.rs      -- DockLayout: tree of split panes containing components
  plugin.rs      -- DockPlugin: loadable plugin with component contributions
  tool.rs        -- DockTool: manages the layout, plugins, and action dispatch
```

### Key GUI Structs

```
GhidraApp {
    program: Option<Arc<RwLock<Program>>>,
    listing: ListingView,          // Disassembly viewer state
    decompiler: DecompilerView,    // C pseudocode viewer
    symbol_tree: SymbolTreePanel,  // Symbol hierarchy
    bytes_view: BytesView,         // Hex dump
    data_types: DataTypePanel,     // Type browser
    console: ConsolePanel,         // Log panel
    current_address: Address,
    status_message: String,
    task_monitor: TaskMonitorState,
    toolbar: ToolbarState,
    key_bindings: KeyBindings,
}
```

## Server API Design

The headless server is built on axum with tokio for async I/O. All API responses are JSON.

### Architecture

```
Client (curl, SDK, GUI)
  |
  | HTTP (REST JSON)
  |
  v
axum Router
  |
  |-- State: AppState { manager: Arc<Mutex<ProjectManager>> }
  |-- CORS: open (Any origin, method, header)
  |
  v
Handlers (async functions)
  |
  |-- ProjectManager { sessions: HashMap<String, AnalysisSession> }
  |     |-- AnalysisSession { id, name, program: Option<Program>, status, ... }
  |
  \-- build_demo_program() -- synthetic program builder for demonstration/testing
```

### API Endpoints

| Method | Path | Description |
|---|---|---|
| `POST` | `/api/sessions` | Create a new analysis session |
| `GET` | `/api/sessions/{id}` | Get session status and metadata |
| `DELETE` | `/api/sessions/{id}` | Close and remove a session |
| `POST` | `/api/sessions/{id}/load` | Load a binary file into the session |
| `POST` | `/api/sessions/{id}/analyze` | Run analysis (depth: quick, standard, deep) |
| `GET` | `/api/sessions/{id}/disassembly?start=X&end=Y` | Get disassembly for address range |
| `POST` | `/api/sessions/{id}/decompile/{addr}` | Decompile function at address |
| `GET` | `/api/sessions/{id}/symbols` | List all symbols |
| `GET` | `/api/sessions/{id}/functions` | List all functions |
| `GET` | `/api/sessions/{id}/xrefs/to/{addr}` | Get cross-references to address |
| `GET` | `/api/sessions/{id}/search?q=X&type=Y&limit=N` | Search (string, hex, instruction, pattern) |
| `GET` | `/api/health` | Health check (version, active sessions) |

### Session Lifecycle

```
POST /api/sessions           -> CREATED (status: loading)
POST /api/sessions/{id}/load  -> Ready (with program)
POST /api/sessions/{id}/analyze -> Analyzing -> Ready
GET  /api/sessions/{id}/...   -> Query results
DELETE /api/sessions/{id}     -> Closed
```

### Request/Response Format

**Create Session:**
```json
// Request
{"name": "my-analysis", "file_path": "/path/to/binary"}

// Response
{
  "id": "uuid-v4",
  "name": "my-analysis",
  "status": "ready",
  "program_name": "binary",
  "image_base": "0x100000",
  "memory_blocks": 3,
  "symbol_count": 7,
  "created_at": "2025-01-01T00:00:00+00:00",
  "last_activity": "2025-01-01T00:00:00+00:00"
}
```

**Decompile Response:**
```json
{
  "session_id": "uuid-v4",
  "address": "0x1000",
  "function_name": "main",
  "source_code": "long main(int argc, char **argv)\n{\n    int result;\n    ...\n}"
}
```

## Data Flow Diagrams

### Binary Loading Flow

```
User provides file path
        |
        v
File extension detection (.elf, .exe, .dylib, .bin, .dex, etc.)
        |
        v
Format-specific parser (elf::parse_elf, pe::parse_pe, etc.)
  |-- Reads file header
  |-- Parses sections/segments
  |-- Extracts symbols, imports, exports
  |-- Resolves relocations
        |
        v
Loader populates Program:
  |-- memory_blocks (from sections/segments)
  |-- symbol_table (from symbol table)
  |-- imports, exports
  |-- listing (initial disassembly)
  |-- image_base
        |
        v
Auto-analysis runs:
  |-- Function entry point detection
  |-- Disassembly from entry points
  |-- Cross-reference collection
  |-- Stack frame analysis
  |-- Type recovery
        |
        v
Program is ready for querying/decompilation
```

### Disassembly Flow

```
Query: address range [start, end]
        |
        v
Lookup in Program::listing.rows (HashMap<Address, ListingRow>)
        |
        v
Filter rows where row.address.offset is in [start, end]
        |
        v
For each row, build DisassemblyRow:
  {
    address: formatted hex string,
    bytes: hex-encoded byte sequence,
    label: optional symbol name,
    mnemonic: instruction mnemonic text,
    operands: operand string,
    full_instruction: complete assembly string
  }
        |
        v
Return JSON array
```

### Decompilation Flow

```
Address of function entry point
        |
        v
SLEIGH disassembly of function body (SleighEngine::disassemble)
        |
        v
P-code sequences for each instruction
        |
        v
Control-flow graph construction
  |-- Identify basic blocks from terminators (branch/call/return)
  |-- Build directed graph edges for all branch targets
  |-- Compute dominator tree and loop nesting
        |
        v
SSA form construction
  |-- Insert MULTIEQUAL (phi) nodes at join points
  |-- Rename varnodes so each definition is unique
        |
        v
Data-flow analysis passes:
  |-- Def-use chain computation
  |-- Reaching definitions (iterative fixed-point)
  |-- Live range analysis
  |-- Constant propagation (fold known values)
  |-- Dead-code elimination (remove unused defs)
  |-- Expression simplification
        |
        v
Type recovery:
  |-- Stack variable identification (from frame-relative accesses)
  |-- Parameter identification (from calling convention)
  |-- Data type inference (from operation widths and usage)
        |
        v
Control-flow structuring:
  |-- Pattern-match control-flow subgraphs:
  |     if (condition) { ... }
  |     if (condition) { ... } else { ... }
  |     while (condition) { ... }
  |     do { ... } while (condition)
  |     for (init; cond; step) { ... }
  |     switch (expr) { case ...: }
  |-- Goto for unstructured flow
        |
        v
C token generation (CToken stream):
  |-- Function signature: return_type name(params)
  |-- Local variable declarations
  |-- Structured control flow with braces and indentation
  |-- Expressions from P-code (binary ops, casts, derefs, field access)
  |-- Address annotations in comments
        |
        v
Format tokens into string (indentation, newlines, spacing)
        |
        v
Return C source code string
```

### Server Request Flow

```
HTTP Request arrives
        |
        v
axum router matches path and method
        |
        v
Extract Path parameters (session_id, address, etc.)
Extract Query parameters (search terms, address ranges)
Extract State (AppState with ProjectManager)
        |
        v
Handler acquires tokio::sync::Mutex lock on ProjectManager
        |
        v
Lookup session by ID
  |-- Not found -> 404 error response
  |-- Found -> proceed
        |
        v
Handler processes request:
  |-- Validate inputs (parse addresses, check preconditions)
  |-- Access Program from session
  |-- Perform requested operation (query listing, symbols, xrefs, etc.)
  |-- Build response struct
        |
        v
Release mutex lock
        |
        v
Return JSON response with appropriate HTTP status code
```

## Key Design Decisions

1. **SQLite over custom B-tree:** Ghidra (Java) uses a custom B-tree database. Ghidra Rust maps this to SQLite via rusqlite, which is faster to develop, battle-tested, and simpler to maintain.

2. **No `unsafe` code:** The workspace lint `unsafe_code = "deny"` enforces a fully safe Rust codebase. All FFI (if any future) must be isolated in dedicated crates.

3. **`missing_docs = "warn"`:** All public API items require documentation comments, enforced at the workspace level.

4. **Async server with tokio + axum:** The headless server uses async Rust for efficient concurrent session handling. Session state is protected by `tokio::sync::Mutex`.

5. **Immediate-mode GUI with egui:** Unlike Ghidra's retained-mode Swing GUI, the Rust GUI uses egui's immediate-mode approach for simpler state management and lower latency.

6. **Workspace organization:** Each major subsystem is a separate crate with clear dependency boundaries. The root crate (`ghidra-rust`) is an integration test workspace that does not produce a binary -- `ghidra-app` is the binary producer.

7. **Processor-specific code isolation:** Each processor's register definitions, instruction mnemonics, loaders, and analyzers are self-contained in their own module. The `ProcessorModule` trait provides a uniform interface.
