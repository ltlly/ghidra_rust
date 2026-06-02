//! Nintendo / game-console format parsers.
//!
//! Covers six Nintendo platforms spanning Game Boy Advance through Nintendo Switch:
//!
//! | Platform        | Module | Format(s)                         |
//! |-----------------|--------|-----------------------------------|
//! | GBA             | `gba`  | GBA ROM (cartridge header)        |
//! | NDS             | `nds`  | NDS ROM (cartridge header)        |
//! | 3DS             | `3ds`  | NCSD/CCI cartridge, NCCH/CXI content |
//! | GameCube / Wii  | `dol`  | DOL executable                    |
//! | Wii U           | `rpx`  | RPX / RPL (Cafe OS ELF variant)   |
//! | Nintendo Switch  | `nso`  | NSO (static), NRO (relocatable)   |
//!
//! Every sub-module exports a `parse_*` entry-point that consumes a `&[u8]`
//! blob and returns a structured representation.  Wrappers that implement
//! the crate-level [`BinaryLoader`](ghidra_features::BinaryLoader) trait live
//! in the parent [`crate::fileformats`] module.
//!
//! Ported from Ghidra's `ghidra.app.util.bin.format` and
//! `ghidra.app.util.bin.format.gba/nds/ncsd/...` packages.

#[path = "3ds.rs"]
pub mod n3ds;
pub mod dol;
pub mod gba;
pub mod nds;
pub mod nso;
pub mod rpx;

/// Re-export the most common types so callers can do
/// `use ghidra_features::fileformats::nintendo::*;`.
pub use dol::*;
pub use gba::*;
pub use n3ds::*;
pub use nds::*;
pub use nso::*;
pub use rpx::*;
