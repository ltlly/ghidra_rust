# Contributing to Ghidra Rust

Thank you for your interest in contributing. This document outlines the process and standards for contributing to the Ghidra Rust project.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Workflow](#development-workflow)
- [Code Style](#code-style)
- [Testing](#testing)
- [Pull Request Process](#pull-request-process)
- [Issue Reporting](#issue-reporting)
- [Commit Messages](#commit-messages)
- [Documentation](#documentation)
- [Release Process](#release-process)

## Code of Conduct

This project adheres to the [Rust Code of Conduct](https://www.rust-lang.org/policies/code-of-conduct). Please be respectful and constructive in all interactions.

## Getting Started

### Prerequisites

- **Rust 1.75+** -- install via [rustup](https://rustup.rs)
- **rustfmt** -- `rustup component add rustfmt`
- **clippy** -- `rustup component add clippy`
- **Git** -- for version control

### Setting Up the Development Environment

```bash
# Clone the repository
git clone https://github.com/your-org/ghidra_rust.git
cd ghidra_rust

# Build all crates
cargo build --workspace

# Run the full test suite
cargo test --workspace

# Verify code formatting
cargo fmt --all -- --check

# Run clippy lints
cargo clippy --workspace --all-targets -- -D warnings
```

### Project Layout

The project is a Cargo workspace with the following crates:

```
ghidra_rust/
  ghidra-core/        # Core framework (addresses, data types, program model, database)
  ghidra-decompile/   # Decompiler (SLEIGH, P-code, analysis, C output)
  ghidra-emulation/   # P-code emulation engine
  ghidra-features/    # Binary format parsers, debug info, analyzers
  ghidra-processors/  # Architecture-specific processor modules
  ghidra-gui/         # egui-based graphical interface
  ghidra-app/         # CLI entry point and headless server
  src/                # Integration test library root
  tests/              # Workspace-level integration tests
```

Dependencies flow primarily upward: `ghidra-core` has no internal dependencies; `ghidra-decompile` depends on `ghidra-core`; higher-level crates depend on the ones below. See [ARCHITECTURE.md](ARCHITECTURE.md) for the full dependency graph.

## Development Workflow

### Branching

1. **Fork** the repository (external contributors) or create a branch (core contributors)
2. Create a **feature branch** from `main`:
   ```bash
   git checkout -b feature/your-feature-name
   ```
3. Make your changes, commit, and push
4. Open a **pull request** targeting `main`

### Branch Naming Convention

- `feature/description` -- new functionality
- `fix/description` -- bug fixes
- `docs/description` -- documentation changes
- `refactor/description` -- code restructuring without feature changes
- `perf/description` -- performance improvements
- `test/description` -- test additions or improvements
- `chore/description` -- maintenance tasks (deps, CI, etc.)

## Code Style

### rustfmt

All code must be formatted with **rustfmt** using the default settings. Run before committing:

```bash
cargo fmt --all
```

### clippy

All code must pass **clippy** with zero warnings. Run before committing:

```bash
cargo clippy --workspace --all-targets -- -D warnings
```

### Workspace Lints

The following workspace-level lints are enforced in `Cargo.toml`:

```toml
[workspace.lints.rust]
unsafe_code = "deny"
missing_docs = "warn"
```

**`unsafe_code = "deny"`** means no `unsafe` blocks anywhere in the codebase. If you find a legitimate need for `unsafe`, discuss it in an issue first.

**`missing_docs = "warn"`** means all public items must have doc comments. Use `///` for item-level docs and `//!` for module-level docs.

### General Guidelines

- **Use Rust 2021 edition** idioms
- **Prefer descriptive variable names** over single-letter names (except in mathematical or well-known contexts like loop indices)
- **Limit function length** to roughly 50 lines or fewer; extract helpers for longer functions
- **Use `thiserror`** for library error types; use `anyhow` for application-level error propagation
- **Derive common traits** explicitly (`Debug`, `Clone`, `PartialEq`, `Eq`, `Hash`) instead of relying on implicit behavior
- **Use `impl Into<T>`** for public API parameters where it improves ergonomics
- **Prefer `&str` over `&String`** in function parameters
- **Use type aliases** for complex generic types that appear repeatedly
- **Group imports** logically: std first, then external crates, then crate-internal, separated by blank lines
- **Use `#[derive(Default)]`** where the derived implementation is correct

### Module Documentation

Each public module should have a `//!` doc comment explaining its purpose:

```rust
//! Address types for Ghidra Rust.
//!
//! Models Ghidra's address space + offset model. An [`Address`] represents
//! a location in a program, which may span multiple address spaces.
```

### Struct Documentation

Each public struct, enum, and function should have a `///` doc comment:

```rust
/// A memory address consisting of an address space and an offset.
pub struct Address {
    /// The raw offset within the address space.
    pub offset: u64,
}
```

## Testing

### Test Requirements

- **All new features must include tests** -- unit tests in the same file (`#[cfg(test)] mod tests`) or integration tests in `tests/`
- **Bug fixes must include a regression test** that fails before the fix and passes after
- **Tests must pass** on the CI before a PR can be merged
- **Aim for high coverage** of critical paths (decompiler, SLEIGH, binary parsers)

### Running Tests

```bash
# Run all tests
cargo test --workspace

# Run tests for a specific crate
cargo test -p ghidra-core
cargo test -p ghidra-decompile

# Run tests with output
cargo test --workspace -- --nocapture

# Run a specific test
cargo test -p ghidra-decompile test_opcode_roundtrip_u8

# Run tests with backtrace on failure
RUST_BACKTRACE=1 cargo test --workspace
```

### Test Organization

- **Unit tests** go in a `#[cfg(test)] mod tests` block at the bottom of each source file
- **Crate-level integration tests** go in the crate's `tests/` directory
- **Workspace-level integration tests** go in the root `tests/` directory
- **Test data files** should be minimal and placed alongside test code or in a `tests/data/` directory

### Writing Good Tests

- **Name tests descriptively** -- `test_opcode_roundtrip_u8` is clearer than `test_opcode`
- **Use assertions with messages** -- `assert_eq!(a, b, "roundtrip failed for {:?}", op)` provides useful diagnostics
- **Test edge cases** -- null addresses, empty sequences, maximum values, invalid inputs
- **Property-based tests** are encouraged for format parsers and mathematical operations
- **Avoid test interdependency** -- each test should set up its own state

## Pull Request Process

### Before Submitting

1. **Run the full CI check locally:**
   ```bash
   cargo fmt --all -- --check
   cargo clippy --workspace --all-targets -- -D warnings
   cargo test --workspace
   cargo build --workspace --release
   ```

2. **Update documentation** if your changes affect public APIs, add new features, or change behavior

3. **Add or update tests** for your changes

4. **Rebase on main** to avoid merge conflicts:
   ```bash
   git fetch origin
   git rebase origin/main
   ```

### PR Description

Your pull request description should include:

- **What** the change does (summary)
- **Why** the change is needed (motivation)
- **How** it was implemented (brief technical overview)
- **Testing** performed (what tests were run, manual testing steps)
- **Breaking changes** if any (changes to public APIs or behavior)

### Review Process

1. A maintainer will review your PR
2. Address any feedback with additional commits or by amending (prefer new commits during review)
3. CI must pass (format, clippy, test, build)
4. At least one approving review is required
5. Squash-merge into `main` (maintainer action)

### After Merge

- Delete your feature branch
- Celebrate your contribution

## Issue Reporting

### Bug Reports

When reporting a bug, please include:

- **Ghidra Rust version** (`ghidra-server --version`)
- **Rust version** (`rustc --version`)
- **Platform** (Linux distribution, macOS version, Windows version)
- **Steps to reproduce** -- minimal example or command sequence
- **Expected behavior**
- **Actual behavior** -- error messages, stack traces, incorrect output
- **Binary file** if relevant and safe to share (or a description of the binary)

### Feature Requests

When requesting a feature:

- **Describe the use case** -- what problem does this solve?
- **Proposed behavior** -- what should the feature do?
- **Alternatives considered** -- have you considered other approaches?
- **Is this feature present in upstream Ghidra?** If so, how should it differ in this Rust implementation?

## Commit Messages

Follow the [Conventional Commits](https://www.conventionalcommits.org/) format:

```
<type>(<scope>): <description>

[optional body]

[optional footer(s)]
```

**Types:**
- `feat` -- new feature
- `fix` -- bug fix
- `docs` -- documentation only
- `refactor` -- code change that neither fixes a bug nor adds a feature
- `perf` -- performance improvement
- `test` -- adding or correcting tests
- `chore` -- maintenance (deps, CI, build)
- `style` -- formatting, whitespace (no code change)

**Examples:**

```
feat(decompile): add constant propagation pass

Implements value-set analysis for tracking constant values
through the P-code varnode graph. Enables folding of
constant expressions in the C output stage.

Closes #42
```

```
fix(elf): handle section header string table index overflow

When shstrndx exceeds SHN_LORESERVE (0xff00), use the
e_shstrndx value from the section header instead.

Fixes #123
```

```
docs(readme): add quick start guide and architecture overview
```

## Documentation

### API Documentation

- All public items must have doc comments (`missing_docs = "warn"` at workspace level)
- Use `cargo doc --workspace --open` to preview rendered documentation
- Include code examples in doc comments using ``` ```rust ``` blocks
- Use intra-doc links (`[`Type`]`, `[`module`]`, `[`crate`]`) for cross-references

### Architecture Documentation

- Significant design decisions should be documented in `ARCHITECTURE.md`
- Major changes to crate structure or dependencies must update `ARCHITECTURE.md`
- New processor modules should be listed in `README.md` under Supported Architectures

## Release Process

Releases are coordinated by maintainers.

1. Update version numbers in all `Cargo.toml` files
2. Update `CHANGELOG.md` (if present)
3. Run the full CI pipeline
4. Create a git tag: `git tag v0.2.0`
5. Push the tag: `git push origin v0.2.0`
6. Publish crates to crates.io (in dependency order):
   ```bash
   cargo publish -p ghidra-core
   cargo publish -p ghidra-decompile
   cargo publish -p ghidra-emulation
   cargo publish -p ghidra-features
   cargo publish -p ghidra-processors
   cargo publish -p ghidra-gui
   cargo publish -p ghidra-app
   ```

## Questions?

If you have questions about contributing, open an issue with the `question` label or reach out to the maintainers directly.

Thank you for contributing to Ghidra Rust.
