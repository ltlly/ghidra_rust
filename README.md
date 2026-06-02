# Ghidra Rust

> ⚠️ **纯属娱乐项目 — 仅供烧 Token 使用**
>
> 本项目由 Claude Code 自动生成，使用 30+ 并行 Workflow、50+ Sub-Agent，消耗了数千万 Token。
> 目的是测试和展示当前 AI 模型在大型软件工程任务上的能力边界。
> **不可用于生产环境，所有代码均由 AI 生成，未经人工审查，存在大量编译错误和逻辑缺陷。**
>
> This is a **purely recreational project — for token burning only**.
> Generated entirely by Claude Code using 30+ parallel workflows and 50+ sub-agents, consuming tens of millions of tokens.
> The purpose is to test and demonstrate the current limits of AI models on large-scale software engineering tasks.
> **Not suitable for production use. All code is AI-generated without human review — expect compilation errors and logical flaws everywhere.**

## Overview

Ghidra Rust is an attempt to reimplement the NSA's Ghidra reverse engineering framework entirely in Rust using AI code generation. It was created in a single session by dispatching parallel Claude Code workflows — no human wrote a single line of code. The project serves as an exploration of AI capabilities: how far can we push automated code generation at scale?

**Result:** ~170 files, ~180,000 lines of Rust generated across 7 crates, covering decompiler, 27 CPU architectures, binary format parsers, GUI, and REST API. ghidra-core compiles with warnings; other crates still have hundreds of compilation errors.

## Features

### Decompiler
- **SLEIGH processor specification language** -- .slaspec parser, compiler, and runtime engine
- **P-code intermediate representation** -- 65+ operation codes covering data movement, integer arithmetic, floating-point, bitwise logic, control flow, and SSA
- **Control-flow graph** construction with dominator analysis, loop detection, and SSA form
- **Data-flow analysis** -- def-use chains, reaching definitions, live ranges, constant propagation, dead-code elimination
- **Type recovery** and stack variable analysis
- **Structured C output** generation with control-flow structuring (if/else, while/for, switch/case, goto)

### Multi-Architecture Support
- **25+ processor architectures** with register banks, instruction mnemonics, and SLEIGH specifications
- Loader, analyzer, and instruction decoder implementations for each architecture
- See [Supported Architectures](#supported-architectures) for the full list

### Binary Format Support
- **ELF** (32-bit and 64-bit, little-endian and big-endian)
- **PE/COFF** (32-bit and 64-bit)
- **Mach-O** (32-bit and 64-bit, FAT binaries)
- **Raw binary** loading with configurable image base
- **PDB** and **DWARF** debug information parsing
- **DEX** / **APK** (Android)

### GUI (egui-based)
- Docking framework inspired by Ghidra's docking system
- **Listing view** -- disassembly with labels, operands, xrefs, comments
- **Decompiler view** -- C pseudocode output with syntax-aware formatting
- **Symbol tree panel** -- hierarchical function, label, import, and export tree
- **Bytes/hex view** -- raw hex editor
- **Data type manager** -- built-in C type library browser
- **Console panel** -- filtered log with severity levels
- **Toolbar** -- navigation, search, address goto
- **Context menus** -- rename, comment, create function, disassemble, patch

### Headless Server (REST API)
- Built on **axum** + **tokio** for async HTTP
- Session management (create, query, close analysis sessions)
- Binary loading with multi-format support
- Disassembly retrieval by address range
- Function decompilation with configurable depth
- Symbol, function, and cross-reference listing
- String, hex, instruction, and pattern search
- Export to multiple formats

### Additional Features
- **Auto-analysis framework** -- pluggable analyzers with configurable depth (quick, standard, deep)
- **Cross-reference tracking** -- call, jump, and data references
- **Project management** -- SQLite-backed database for persistent analysis state
- **Emulation engine** -- step-through P-code execution with breakpoints and state save/restore
- **Version tracking** and binary similarity analysis
- **SARIF export** for integration with CI/CD and security tools

## Quick Start

### Prerequisites
- Rust toolchain 1.75+ (install via [rustup](https://rustup.rs))
- System dependencies: `libgtk-3-dev` or equivalent for native windowing (GUI only)

### Install from crates.io

```bash
cargo install ghidra-rust
```

### CLI Usage

**Start the headless server:**

```bash
ghidra-server server --host 127.0.0.1 --port 3000
```

**Launch the GUI:**

```bash
ghidra-server gui
```

**Quick analysis via the API:**

```bash
# Create a session and load a binary
curl -X POST http://localhost:3000/api/sessions \
  -H "Content-Type: application/json" \
  -d '{"name": "my-analysis", "file_path": "/path/to/binary"}'

# List symbols
curl http://localhost:3000/api/sessions/{session-id}/symbols

# Decompile a function at address 0x1000
curl -X POST http://localhost:3000/api/sessions/{session-id}/decompile/0x1000 \
  -H "Content-Type: application/json" \
  -d '{"style": "default"}'

# Search for strings
curl "http://localhost:3000/api/sessions/{session-id}/search?q=main&type=string"
```

## Architecture Overview

Ghidra Rust is organized as a Cargo workspace with the following crates:

| Crate | Description |
|---|---|
| **`ghidra-core`** | Foundational types: addresses, data types, symbols, program model, memory blocks, database layer, filesystem, graphs |
| **`ghidra-decompile`** | Decompiler pipeline: SLEIGH parser/runtime, P-code IR, data-flow/control-flow analysis, C output generation |
| **`ghidra-emulation`** | P-code emulation engine: step-through execution, breakpoints, register/memory state tracking |
| **`ghidra-features`** | Analysis features: binary format parsers (ELF, PE, Mach-O, raw), PDB/DWARF debug info, auto-analysis framework, version tracking |
| **`ghidra-processors`** | Processor modules: register definitions, instruction mnemonics, loaders, analyzers, SLEIGH specifications |
| **`ghidra-gui`** | egui-based GUI: docking framework, listing view, decompiler view, symbol tree, byte view, menus |
| **`ghidra-app`** | Application entry point: CLI (clap), headless HTTP server (axum), GUI launcher |

Dependency graph:

```
ghidra-app
  |-- ghidra-gui
  |     |-- ghidra-core
  |     |-- ghidra-decompile
  |     \-- ghidra-features
  |-- ghidra-decompile
  |     \-- ghidra-core
  |-- ghidra-emulation
  |     |-- ghidra-core
  |     \-- ghidra-decompile
  |-- ghidra-processors
  |     |-- ghidra-core
  |     |-- ghidra-decompile
  |     \-- ghidra-features
  \-- ghidra-features
        |-- ghidra-core
        \-- ghidra-decompile
```

For a detailed breakdown, see [ARCHITECTURE.md](ARCHITECTURE.md).

## Supported Architectures

| Processor | Variants | Status |
|---|---|---|
| **x86 / x86-64** | 8086 through Sapphire Rapids (AVX-512, AMX) | Complete |
| **ARM** | ARMv4 through ARMv8, Thumb, Thumb-2 | Implemented |
| **AArch64** | ARM 64-bit (A64) | Implemented |
| **M68000** | 68000, 68010, 68020, 68030, 68040, ColdFire | Implemented |
| **SuperH** | SH-1, SH-2, SH-3, SH-4, SH-4A | Implemented |
| **Hexagon** | Qualcomm Hexagon DSP (V5, V6x) | Implemented |
| **TriCore** | Infineon TriCore (v1.3, v1.6) | Implemented |
| **V850** | NEC/Renesas V850, V850E, V850E2 | Implemented |
| **Xtensa** | Tensilica Xtensa LX6, LX7 | Implemented |

Additional architectures available through Ghidra's SLEIGH `.sla` files (25+ total):
- MIPS (32-bit and 64-bit, microMIPS)
- PowerPC (32-bit and 64-bit, VLE)
- SPARC (v8 and v9)
- RISC-V (32-bit and 64-bit, compressed)
- AVR8, AVR32
- PIC (12, 16, 24, 30, 32)
- MSP430, MSP430X
- 6502, 65C02, 6805, 68HC11, 68HC12, HCS08, HCS12
- Z80, 8048, 8051, 8085
- TI TMS320C28, TMS320C54x
- PA-RISC
- CR16C
- JVM / Dalvik bytecode
- BPF (eBPF)
- And more...

## Supported Binary Formats

| Format | Extensions | Features |
|---|---|---|
| **ELF** | .elf, .o, .so, .ko | 32/64-bit, LE/BE, sections, symbols, relocations, dynamic linking |
| **PE / COFF** | .exe, .dll, .sys, .obj | 32/64-bit, imports, exports, resources, TLS, exception tables |
| **Mach-O** | (macOS/iOS binaries) | 32/64-bit, FAT binaries, Objective-C metadata |
| **Raw Binary** | .bin, .rom, .img | Configurable image base and load address |
| **DEX / APK** | .dex, .apk | Android Dalvik bytecode |
| **PDB** | .pdb | Microsoft Program Database debug symbols |
| **DWARF** | (embedded) | DWARF 2/3/4/5 debug information |
| **SARIF** | .sarif | Static Analysis Results Interchange Format (export) |

## Building from Source

```bash
# Clone the repository
git clone https://github.com/your-org/ghidra_rust.git
cd ghidra_rust

# Build all crates
cargo build --release

# Run tests
cargo test --workspace

# Build with specific features
cargo build --release --features gui

# The binary will be at:
#   target/release/ghidra-server

# Run the headless server
./target/release/ghidra-server server --port 3000

# Run the GUI (requires system windowing libraries)
./target/release/ghidra-server gui
```

### Platform Notes

**Linux:** Install development headers for your windowing system:
```bash
sudo apt install libgtk-3-dev libxcb-render0-dev libxcb-shape0-dev libxcb-xfixes0-dev
```

**macOS:** No additional dependencies required.

**Windows:** Install the MSVC build tools via Visual Studio Build Tools or `rustup default stable-msvc`.

## Project Structure

```
ghidra_rust/
  Cargo.toml          # Workspace root + integration test crate
  src/                # Integration test library (re-exports all crates)
  tests/              # Integration tests
  ghidra-core/        # Core framework (addresses, data types, program model)
  ghidra-decompile/   # Decompiler (SLEIGH, P-code, analysis, C output)
  ghidra-emulation/   # P-code emulator
  ghidra-features/    # Binary format parsers, PDB, analyzers
  ghidra-processors/  # Architecture-specific processor modules
  ghidra-gui/         # egui-based GUI
  ghidra-app/         # CLI + server entry point
  ghidra_src/         # Upstream Ghidra reference (SLEIGH specs, docs)
```

## License

This project is licensed under the Apache License, Version 2.0. See the [LICENSE](ghidra_src/ghidra/LICENSE) file for the full text.

Ghidra Rust is an independent reimplementation inspired by the NSA's Ghidra software reverse engineering framework, which is also available under the Apache License 2.0. This project does not include or redistribute Ghidra's Java source code; it uses Ghidra's SLEIGH `.slaspec`/`.sla` processor specification files and documentation as reference data.

## Contributing

Contributions are welcome. Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on code style, testing, and the pull request process.

## Acknowledgments

- **NSA Research Directorate** for creating and open-sourcing [Ghidra](https://github.com/NationalSecurityAgency/ghidra)
- The Ghidra community for maintaining the extensive SLEIGH processor specification library
- The Rust community for the libraries that make this project possible:
  - [egui](https://github.com/emilk/egui) -- immediate-mode GUI
  - [axum](https://github.com/tokio-rs/axum) -- web framework
  - [nom](https://github.com/rust-bakery/nom) -- parser combinators
  - [pest](https://pest.rs) -- PEG parser generator
  - [petgraph](https://github.com/petgraph/petgraph) -- graph data structures
  - [rusqlite](https://github.com/rusqlite/rusqlite) -- SQLite bindings
  - [tokio](https://tokio.rs) -- async runtime
