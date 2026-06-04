//! Offset table plugin -- creates offset references from data selections.
//!
//! Ported from `OffsetTablePlugin` and `OffsetTableDialog`. Creates data of
//! a specified size at selected addresses and adds references to
//! `base_address + offset_value`.

use crate::base::references::commands::{AddOffsetMemRefCmd, CompoundCommand};

use ghidra_core::addr::{Address, AddressSet};
use ghidra_core::symbol::{DataRefType, RefType, ReferenceManager, SourceType, SymbolError};
use serde::{Deserialize, Serialize};
use std::fmt;

/// Supported data sizes for offset tables.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum OffsetDataSize {
    /// 1-byte (byte) offsets.
    Byte = 1,
    /// 2-byte (word) offsets.
    Word = 2,
    /// 4-byte (dword) offsets.
    DWord = 4,
    /// 8-byte (qword) offsets.
    QWord = 8,
}

impl OffsetDataSize {
    /// Returns the size in bytes.
    pub fn size_bytes(self) -> u32 {
        self as u32
    }

    /// Try to create from a byte count.
    pub fn from_bytes(bytes: u32) -> Option<Self> {
        match bytes {
            1 => Some(Self::Byte),
            2 => Some(Self::Word),
            4 => Some(Self::DWord),
            8 => Some(Self::QWord),
            _ => None,
        }
    }
}

impl fmt::Display for OffsetDataSize {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Byte => write!(f, "Byte"),
            Self::Word => write!(f, "Word"),
            Self::DWord => write!(f, "DWord"),
            Self::QWord => write!(f, "QWord"),
        }
    }
}

/// Configuration for creating an offset table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OffsetTableConfig {
    /// The base address that offsets are relative to.
    pub base_address: Address,
    /// The data size for each offset entry.
    pub data_size: OffsetDataSize,
    /// Whether to interpret offsets as signed.
    pub signed: bool,
    /// The address ranges to apply the offset table to.
    pub selection: AddressSet,
}

impl OffsetTableConfig {
    /// Create a new offset table configuration.
    pub fn new(
        base_address: Address,
        data_size: OffsetDataSize,
        signed: bool,
        selection: AddressSet,
    ) -> Self {
        Self {
            base_address,
            data_size,
            signed,
            selection,
        }
    }
}

/// Offset table plugin state.
///
/// Corresponds to `OffsetTablePlugin`. Provides the logic for creating offset
/// references from a data selection with a user-supplied base address.
#[derive(Debug, Clone)]
pub struct OffsetTablePlugin {
    /// Last selected data size (persists across invocations).
    last_selected_size: OffsetDataSize,
    /// Last signed setting.
    last_signed: bool,
}

impl Default for OffsetTablePlugin {
    fn default() -> Self {
        Self {
            last_selected_size: OffsetDataSize::DWord,
            last_signed: true,
        }
    }
}

impl OffsetTablePlugin {
    /// Create a new offset table plugin.
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the last selected data size.
    pub fn last_selected_size(&self) -> OffsetDataSize {
        self.last_selected_size
    }

    /// Set the last selected data size.
    pub fn set_last_selected_size(&mut self, size: OffsetDataSize) {
        self.last_selected_size = size;
    }

    /// Returns the last signed setting.
    pub fn last_signed(&self) -> bool {
        self.last_signed
    }

    /// Set the signed setting.
    pub fn set_last_signed(&mut self, signed: bool) {
        self.last_signed = signed;
    }

    /// Build the commands to create an offset table.
    ///
    /// For each data-size-aligned address in the selection, a data item is
    /// conceptually created and a reference is added to
    /// `base_address + offset_value`.
    ///
    /// Returns a compound command containing all the reference-adding commands.
    ///
    /// Note: In a full implementation, data items would also be created.
    /// Here we only generate the reference commands.
    pub fn build_offset_table_commands(
        &self,
        config: &OffsetTableConfig,
        offset_values: &[(Address, i64)],
    ) -> CompoundCommand {
        let mut compound = CompoundCommand::new("Create Offset References");

        for &(data_addr, offset_value) in offset_values {
            let eff_offset = if config.signed {
                offset_value
            } else {
                offset_value as i64
            };

            let to_addr = config.base_address.add(eff_offset as u64);

            compound.add(AddOffsetMemRefCmd::new(
                data_addr,
                to_addr,
                false,
                RefType::Data(DataRefType::Data),
                SourceType::UserDefined,
                0,
                eff_offset,
            ));
        }

        compound
    }

    /// Apply the offset table to the reference manager.
    pub fn apply_offset_table(
        &mut self,
        config: &OffsetTableConfig,
        offset_values: &[(Address, i64)],
        ref_mgr: &mut ReferenceManager,
    ) -> Result<bool, SymbolError> {
        self.last_selected_size = config.data_size;
        self.last_signed = config.signed;
        let compound = self.build_offset_table_commands(config, offset_values);
        compound.apply_to(ref_mgr)
    }
}

impl fmt::Display for OffsetTablePlugin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "OffsetTablePlugin [size={}, signed={}]",
            self.last_selected_size, self.last_signed
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_offset_data_size_from_bytes() {
        assert_eq!(OffsetDataSize::from_bytes(1), Some(OffsetDataSize::Byte));
        assert_eq!(OffsetDataSize::from_bytes(4), Some(OffsetDataSize::DWord));
        assert_eq!(OffsetDataSize::from_bytes(3), None);
    }

    #[test]
    fn test_offset_data_size_display() {
        assert_eq!(format!("{}", OffsetDataSize::DWord), "DWord");
    }

    #[test]
    fn test_offset_table_plugin_defaults() {
        let plugin = OffsetTablePlugin::new();
        assert_eq!(plugin.last_selected_size(), OffsetDataSize::DWord);
        assert!(plugin.last_signed());
    }

    #[test]
    fn test_build_offset_table_commands() {
        let plugin = OffsetTablePlugin::new();
        let selection = AddressSet::from_range(Address::new(0x1000), Address::new(0x100F));
        let config = OffsetTableConfig::new(
            Address::new(0x4000),
            OffsetDataSize::DWord,
            true,
            selection,
        );

        // Simulate 4 offset entries (each at 4-byte intervals)
        let offset_values = vec![
            (Address::new(0x1000), 0x10),
            (Address::new(0x1004), 0x20),
            (Address::new(0x1008), 0x30),
            (Address::new(0x100C), 0x40),
        ];

        let compound = plugin.build_offset_table_commands(&config, &offset_values);
        assert_eq!(compound.size(), 4);
    }

    #[test]
    fn test_apply_offset_table() {
        let mut plugin = OffsetTablePlugin::new();
        let selection = AddressSet::from_range(Address::new(0x1000), Address::new(0x1007));
        let config = OffsetTableConfig::new(
            Address::new(0x4000),
            OffsetDataSize::Word,
            true,
            selection,
        );

        let offset_values = vec![
            (Address::new(0x1000), 0x100),
            (Address::new(0x1002), 0x200),
            (Address::new(0x1004), 0x300),
            (Address::new(0x1006), 0x400),
        ];

        let mut ref_mgr = ReferenceManager::new();
        let result = plugin.apply_offset_table(&config, &offset_values, &mut ref_mgr);
        assert!(result.unwrap());
        assert_eq!(plugin.last_selected_size(), OffsetDataSize::Word);
    }

    #[test]
    fn test_offset_table_display() {
        let plugin = OffsetTablePlugin::new();
        let display = format!("{}", plugin);
        assert!(display.contains("OffsetTablePlugin"));
    }

    #[test]
    fn test_offset_table_signed_negative() {
        let mut plugin = OffsetTablePlugin::new();
        let selection = AddressSet::from_range(Address::new(0x1000), Address::new(0x1003));
        let config = OffsetTableConfig::new(
            Address::new(0x4000),
            OffsetDataSize::DWord,
            true,
            selection,
        );

        let offset_values = vec![(Address::new(0x1000), -16i64)];
        let mut ref_mgr = ReferenceManager::new();
        let result = plugin.apply_offset_table(&config, &offset_values, &mut ref_mgr);
        assert!(result.unwrap());
    }
}
