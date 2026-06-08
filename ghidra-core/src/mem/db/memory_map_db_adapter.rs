//! Database adapter for memory map persistence.
//!
//! Mirrors `ghidra.program.database.mem.MemoryMapDBAdapter`. This trait
//! abstracts the database layer so that multiple schema versions can be
//! supported. Each concrete adapter (V0, V1, V2, V3) implements this
//! trait to read/write block and sub-block records.

use crate::addr::Address;
use crate::error::GhidraError;
use crate::mem::db::memory_block_db::MemoryBlockDB;
use crate::mem::db::sub_memory_block::SubMemoryBlock;
use crate::mem::MemoryBlockType;

// ============================================================================
// DB Record column indices (mirrors MemoryMapDBAdapterV3 column constants)
// ============================================================================

/// Block record column indices.
pub const NAME_COL: usize = 0;
pub const COMMENTS_COL: usize = 1;
pub const SOURCE_COL: usize = 2;
pub const FLAGS_COL: usize = 3;
pub const START_ADDR_COL: usize = 4;
pub const LENGTH_COL: usize = 5;
pub const SEGMENT_COL: usize = 6;

/// Sub-block record column indices.
pub const SUB_PARENT_ID_COL: usize = 0;
pub const SUB_TYPE_COL: usize = 1;
pub const SUB_LENGTH_COL: usize = 2;
pub const SUB_START_OFFSET_COL: usize = 3;
pub const SUB_INT_DATA1_COL: usize = 4;
pub const SUB_LONG_DATA2_COL: usize = 5;

/// Sub-block type constants.
pub const SUB_TYPE_BIT_MAPPED: u8 = 0;
pub const SUB_TYPE_BYTE_MAPPED: u8 = 1;
pub const SUB_TYPE_BUFFER: u8 = 2;
pub const SUB_TYPE_UNINITIALIZED: u8 = 3;
pub const SUB_TYPE_FILE_BYTES: u8 = 4;

// ============================================================================
// DBRecord — simplified record type for the adapter
// ============================================================================

/// A database record representing a memory block or sub-block.
///
/// In Ghidra's Java implementation this is `db.DBRecord`. Here we use a
/// simplified key-value record backed by arrays.
#[derive(Debug, Clone)]
pub struct DBRecord {
    /// The record's unique key.
    key: u64,
    /// Long field values (indexed by column).
    long_values: Vec<u64>,
    /// Byte field values (indexed by column).
    byte_values: Vec<u8>,
    /// String field values (indexed by column).
    string_values: Vec<Option<String>>,
}

impl DBRecord {
    /// Create a new record with the given key and column counts.
    pub fn new(key: u64, num_long: usize, num_byte: usize, num_string: usize) -> Self {
        Self {
            key,
            long_values: vec![0u64; num_long],
            byte_values: vec![0u8; num_byte],
            string_values: vec![None; num_string],
        }
    }

    /// Returns the record key.
    pub fn get_key(&self) -> u64 {
        self.key
    }

    /// Set the record key.
    pub fn set_key(&mut self, key: u64) {
        self.key = key;
    }

    /// Get a long field value.
    pub fn get_long_value(&self, col: usize) -> u64 {
        self.long_values.get(col).copied().unwrap_or(0)
    }

    /// Set a long field value.
    pub fn set_long_value(&mut self, col: usize, value: u64) {
        if col < self.long_values.len() {
            self.long_values[col] = value;
        }
    }

    /// Get an int (i32) field value from a long column.
    pub fn get_int_value(&self, col: usize) -> i32 {
        self.get_long_value(col) as i32
    }

    /// Set an int (i32) field value in a long column.
    pub fn set_int_value(&mut self, col: usize, value: i32) {
        self.set_long_value(col, value as u32 as u64);
    }

    /// Get a byte field value.
    pub fn get_byte_value(&self, col: usize) -> u8 {
        self.byte_values.get(col).copied().unwrap_or(0)
    }

    /// Set a byte field value.
    pub fn set_byte_value(&mut self, col: usize, value: u8) {
        if col < self.byte_values.len() {
            self.byte_values[col] = value;
        }
    }

    /// Get a string field value.
    pub fn get_string(&self, col: usize) -> Option<&str> {
        self.string_values
            .get(col)
            .and_then(|s| s.as_deref())
    }

    /// Set a string field value.
    pub fn set_string(&mut self, col: usize, value: Option<String>) {
        if col < self.string_values.len() {
            self.string_values[col] = value;
        }
    }
}

// ============================================================================
// DBBuffer — simplified database buffer
// ============================================================================

/// A database buffer holding raw bytes.
///
/// Mirrors `db.DBBuffer`. In the real Ghidra implementation, DBBuffer is a
/// chained buffer that stores data across multiple database pages. Here we
/// simplify to a `Vec<u8>`.
#[derive(Debug, Clone)]
pub struct DBBuffer {
    /// The buffer ID (record key).
    id: u32,
    /// The backing byte data.
    data: Vec<u8>,
}

impl DBBuffer {
    /// Create a new buffer with the given size and fill value.
    pub fn new(id: u32, size: usize, fill_value: u8) -> Self {
        Self {
            id,
            data: vec![fill_value; size],
        }
    }

    /// Create a buffer from existing data.
    pub fn from_data(id: u32, data: Vec<u8>) -> Self {
        Self { id, data }
    }

    /// Returns the buffer ID.
    pub fn get_id(&self) -> u32 {
        self.id
    }

    /// Returns the buffer size.
    pub fn size(&self) -> usize {
        self.data.len()
    }

    /// Get a byte at the given offset.
    pub fn get_byte(&self, offset: usize) -> Result<u8, GhidraError> {
        self.data
            .get(offset)
            .copied()
            .ok_or_else(|| GhidraError::DatabaseError(format!("DBBuffer offset {} out of bounds", offset)))
    }

    /// Set a byte at the given offset.
    pub fn put_byte(&mut self, offset: usize, value: u8) -> Result<(), GhidraError> {
        if offset >= self.data.len() {
            return Err(GhidraError::DatabaseError(format!(
                "DBBuffer offset {} out of bounds",
                offset
            )));
        }
        self.data[offset] = value;
        Ok(())
    }

    /// Copy bytes from the buffer into `dest[off..off+len]`.
    pub fn get(&self, offset: usize, dest: &mut [u8], off: usize, len: usize) {
        let available = self.data.len().saturating_sub(offset);
        let actual = len.min(available);
        if actual > 0 {
            dest[off..off + actual].copy_from_slice(&self.data[offset..offset + actual]);
        }
    }

    /// Copy bytes from `src[off..off+len]` into the buffer at `offset`.
    pub fn put(&mut self, offset: usize, src: &[u8], off: usize, len: usize) {
        let available = self.data.len().saturating_sub(offset);
        let actual = len.min(available);
        if actual > 0 {
            self.data[offset..offset + actual].copy_from_slice(&src[off..off + actual]);
        }
    }

    /// Append another buffer's data.
    pub fn append(&mut self, other: &DBBuffer) {
        self.data.extend_from_slice(&other.data);
    }

    /// Split the buffer at `offset`, returning the right half.
    /// `self` retains the left half.
    pub fn split(&mut self, offset: usize) -> DBBuffer {
        let remaining = self.data.split_off(offset);
        DBBuffer {
            id: 0, // new id assigned by adapter
            data: remaining,
        }
    }

    /// Delete (clear) the buffer data.
    pub fn delete(&mut self) {
        self.data.clear();
        self.data.shrink_to_fit();
    }
}

// ============================================================================
// MemoryMapDBAdapter trait
// ============================================================================

/// The database adapter interface for the memory map.
///
/// Mirrors `ghidra.program.database.mem.MemoryMapDBAdapter`. Concrete
/// implementations handle the actual database I/O for each schema version.
pub trait MemoryMapDBAdapter: Send {
    /// Refresh the in-memory cache of block records from the database.
    fn refresh_memory(&mut self) -> Result<(), GhidraError>;

    /// Returns all memory blocks sorted by start address.
    fn get_memory_blocks(&mut self) -> Result<Vec<MemoryBlockDB>, GhidraError>;

    /// Create a new initialized block with data from a byte slice.
    fn create_initialized_block(
        &mut self,
        name: &str,
        start: Address,
        data: &[u8],
        flags: u8,
    ) -> Result<MemoryBlockDB, GhidraError>;

    /// Create a new initialized block backed by a database buffer.
    fn create_initialized_block_from_buffer(
        &mut self,
        name: &str,
        start: Address,
        buf: DBBuffer,
        flags: u8,
    ) -> Result<MemoryBlockDB, GhidraError>;

    /// Create a new memory block (default, mapped, uninitialized, etc.).
    fn create_block(
        &mut self,
        block_type: MemoryBlockType,
        name: &str,
        start: Address,
        length: u64,
        mapped_address: Option<Address>,
        initialize_bytes: bool,
        flags: u8,
        encoded_mapping_scheme: u16,
    ) -> Result<MemoryBlockDB, GhidraError>;

    /// Create a new memory block from a split operation.
    fn create_block_from_split(
        &mut self,
        name: &str,
        start: Address,
        length: u64,
        flags: u8,
        sub_blocks: Vec<Box<dyn SubMemoryBlock>>,
    ) -> Result<MemoryBlockDB, GhidraError>;

    /// Delete the given memory block and its sub-blocks.
    fn delete_memory_block(&mut self, block: &mut MemoryBlockDB) -> Result<(), GhidraError>;

    /// Update a block record in the database.
    fn update_block_record(&mut self, record: &DBRecord) -> Result<(), GhidraError>;

    /// Create a new database buffer with the given size and fill value.
    fn create_buffer(&mut self, size: usize, fill_value: u8) -> Result<DBBuffer, GhidraError>;

    /// Delete a sub-block record by key.
    fn delete_sub_block(&mut self, key: u64) -> Result<(), GhidraError>;

    /// Update a sub-block record in the database.
    fn update_sub_block_record(&mut self, record: &DBRecord) -> Result<(), GhidraError>;

    /// Create a new sub-block record.
    fn create_sub_block_record(
        &mut self,
        parent_id: u64,
        starting_offset: u64,
        length: u64,
        sub_type: u8,
        data1: u32,
        data2: u64,
    ) -> Result<DBRecord, GhidraError>;

    /// Create a new file-bytes-backed block.
    fn create_file_bytes_block(
        &mut self,
        name: &str,
        start: Address,
        length: u64,
        file_bytes_id: u64,
        file_bytes_offset: u64,
        flags: u8,
    ) -> Result<MemoryBlockDB, GhidraError>;

    /// Get a database buffer by ID.
    fn get_buffer(&self, buffer_id: u32) -> Result<DBBuffer, GhidraError>;

    /// Delete the underlying database table.
    fn delete_table(&mut self) -> Result<(), GhidraError>;

    /// Returns the current adapter schema version.
    fn version(&self) -> u32;
}

// ============================================================================
// InMemoryAdapter — a non-persisted in-memory adapter for testing
// ============================================================================

/// A fully in-memory adapter implementation for testing.
///
/// Does not require a database handle. All data is stored in memory.
#[derive(Debug)]
pub struct InMemoryAdapter {
    /// Next record key to assign.
    next_key: u64,
    /// Block records, keyed by record key.
    block_records: Vec<DBRecord>,
    /// Sub-block records, keyed by record key.
    sub_block_records: Vec<DBRecord>,
    /// Buffers, keyed by buffer ID.
    buffers: Vec<DBBuffer>,
    /// Next buffer ID to assign.
    next_buffer_id: u32,
}

impl InMemoryAdapter {
    /// Create a new empty in-memory adapter.
    pub fn new() -> Self {
        Self {
            next_key: 1,
            block_records: Vec::new(),
            sub_block_records: Vec::new(),
            buffers: Vec::new(),
            next_buffer_id: 1,
        }
    }

    fn alloc_key(&mut self) -> u64 {
        let key = self.next_key;
        self.next_key += 1;
        key
    }

    fn alloc_buffer_id(&mut self) -> u32 {
        let id = self.next_buffer_id;
        self.next_buffer_id += 1;
        id
    }
}

impl Default for InMemoryAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl MemoryMapDBAdapter for InMemoryAdapter {
    fn refresh_memory(&mut self) -> Result<(), GhidraError> {
        // No-op for in-memory adapter.
        Ok(())
    }

    fn get_memory_blocks(&mut self) -> Result<Vec<MemoryBlockDB>, GhidraError> {
        // Return empty -- blocks are managed by MemoryMapDB in the full implementation.
        Ok(Vec::new())
    }

    fn create_initialized_block(
        &mut self,
        name: &str,
        start: Address,
        data: &[u8],
        flags: u8,
    ) -> Result<MemoryBlockDB, GhidraError> {
        let key = self.alloc_key();
        let length = data.len() as u64;

        // Create block record
        let mut record = DBRecord::new(key, 8, 2, 4);
        record.set_string(NAME_COL, Some(name.to_string()));
        record.set_string(COMMENTS_COL, None);
        record.set_string(SOURCE_COL, None);
        record.set_byte_value(FLAGS_COL, flags);
        record.set_long_value(START_ADDR_COL, start.offset);
        record.set_long_value(LENGTH_COL, length);
        self.block_records.push(record);

        // Create buffer and buffer sub-block record
        let buf_id = self.alloc_buffer_id();
        let buf = DBBuffer::from_data(buf_id, data.to_vec());
        self.buffers.push(buf);

        let mut sub_record = DBRecord::new(self.alloc_key(), 8, 2, 4);
        sub_record.set_long_value(SUB_PARENT_ID_COL, key);
        sub_record.set_byte_value(SUB_TYPE_COL, SUB_TYPE_BUFFER);
        sub_record.set_long_value(SUB_LENGTH_COL, length);
        sub_record.set_long_value(SUB_START_OFFSET_COL, 0);
        sub_record.set_long_value(SUB_INT_DATA1_COL, buf_id as u64);
        sub_record.set_long_value(SUB_LONG_DATA2_COL, 0);
        self.sub_block_records.push(sub_record);

        // Build the MemoryBlockDB in-memory
        let end = start.add(length.saturating_sub(1));
        Ok(MemoryBlockDB::new(
            key,
            name.to_string(),
            start,
            end,
            length,
            flags,
            true, // initialized
            false, // not mapped
            None, // no mapped source
            None, // no mapping scheme
        ))
    }

    fn create_initialized_block_from_buffer(
        &mut self,
        name: &str,
        start: Address,
        buf: DBBuffer,
        flags: u8,
    ) -> Result<MemoryBlockDB, GhidraError> {
        let key = self.alloc_key();
        let length = buf.size() as u64;

        let mut record = DBRecord::new(key, 8, 2, 4);
        record.set_string(NAME_COL, Some(name.to_string()));
        record.set_byte_value(FLAGS_COL, flags);
        record.set_long_value(START_ADDR_COL, start.offset);
        record.set_long_value(LENGTH_COL, length);
        self.block_records.push(record);

        let buf_id = buf.get_id();
        self.buffers.push(buf);

        let end = start.add(length.saturating_sub(1));
        Ok(MemoryBlockDB::new(
            key,
            name.to_string(),
            start,
            end,
            length,
            flags,
            true,
            false,
            None,
            None,
        ))
    }

    fn create_block(
        &mut self,
        block_type: MemoryBlockType,
        name: &str,
        start: Address,
        length: u64,
        mapped_address: Option<Address>,
        initialize_bytes: bool,
        flags: u8,
        encoded_mapping_scheme: u16,
    ) -> Result<MemoryBlockDB, GhidraError> {
        let key = self.alloc_key();
        let end = start.add(length.saturating_sub(1));

        let mut record = DBRecord::new(key, 8, 2, 4);
        record.set_string(NAME_COL, Some(name.to_string()));
        record.set_byte_value(FLAGS_COL, flags);
        record.set_long_value(START_ADDR_COL, start.offset);
        record.set_long_value(LENGTH_COL, length);
        self.block_records.push(record);

        // Determine sub-block type
        let sub_type = match block_type {
            MemoryBlockType::BitMapped => SUB_TYPE_BIT_MAPPED,
            MemoryBlockType::ByteMapped => SUB_TYPE_BYTE_MAPPED,
            MemoryBlockType::Default => {
                if initialize_bytes {
                    SUB_TYPE_BUFFER
                } else {
                    SUB_TYPE_UNINITIALIZED
                }
            }
        };

        let mut sub_record = DBRecord::new(self.alloc_key(), 8, 2, 4);
        sub_record.set_long_value(SUB_PARENT_ID_COL, key);
        sub_record.set_byte_value(SUB_TYPE_COL, sub_type);
        sub_record.set_long_value(SUB_LENGTH_COL, length);
        sub_record.set_long_value(SUB_START_OFFSET_COL, 0);
        if sub_type == SUB_TYPE_BUFFER {
            let buf_id = self.alloc_buffer_id();
            let buf = DBBuffer::new(buf_id, length as usize, 0);
            self.buffers.push(buf);
            sub_record.set_long_value(SUB_INT_DATA1_COL, buf_id as u64);
        }
        if sub_type == SUB_TYPE_BYTE_MAPPED {
            sub_record.set_long_value(SUB_INT_DATA1_COL, encoded_mapping_scheme as u64);
        }
        if let Some(ma) = mapped_address {
            sub_record.set_long_value(SUB_LONG_DATA2_COL, ma.offset);
        }
        self.sub_block_records.push(sub_record);

        Ok(MemoryBlockDB::new(
            key,
            name.to_string(),
            start,
            end,
            length,
            flags,
            block_type == MemoryBlockType::Default && initialize_bytes,
            block_type == MemoryBlockType::BitMapped
                || block_type == MemoryBlockType::ByteMapped,
            mapped_address,
            None,
        ))
    }

    fn create_block_from_split(
        &mut self,
        name: &str,
        start: Address,
        length: u64,
        flags: u8,
        _sub_blocks: Vec<Box<dyn SubMemoryBlock>>,
    ) -> Result<MemoryBlockDB, GhidraError> {
        let key = self.alloc_key();
        let end = start.add(length.saturating_sub(1));

        let mut record = DBRecord::new(key, 8, 2, 4);
        record.set_string(NAME_COL, Some(name.to_string()));
        record.set_byte_value(FLAGS_COL, flags);
        record.set_long_value(START_ADDR_COL, start.offset);
        record.set_long_value(LENGTH_COL, length);
        self.block_records.push(record);

        Ok(MemoryBlockDB::new(
            key,
            name.to_string(),
            start,
            end,
            length,
            flags,
            true,
            false,
            None,
            None,
        ))
    }

    fn delete_memory_block(&mut self, block: &mut MemoryBlockDB) -> Result<(), GhidraError> {
        self.block_records.retain(|r| r.get_key() != block.id());
        self.sub_block_records
            .retain(|r| r.get_long_value(SUB_PARENT_ID_COL) != block.id());
        block.invalidate();
        Ok(())
    }

    fn update_block_record(&mut self, record: &DBRecord) -> Result<(), GhidraError> {
        if let Some(existing) = self
            .block_records
            .iter_mut()
            .find(|r| r.get_key() == record.get_key())
        {
            *existing = record.clone();
        }
        Ok(())
    }

    fn create_buffer(&mut self, size: usize, fill_value: u8) -> Result<DBBuffer, GhidraError> {
        let id = self.alloc_buffer_id();
        let buf = DBBuffer::new(id, size, fill_value);
        self.buffers.push(buf.clone());
        Ok(buf)
    }

    fn delete_sub_block(&mut self, key: u64) -> Result<(), GhidraError> {
        self.sub_block_records.retain(|r| r.get_key() != key);
        Ok(())
    }

    fn update_sub_block_record(&mut self, record: &DBRecord) -> Result<(), GhidraError> {
        if let Some(existing) = self
            .sub_block_records
            .iter_mut()
            .find(|r| r.get_key() == record.get_key())
        {
            *existing = record.clone();
        }
        Ok(())
    }

    fn create_sub_block_record(
        &mut self,
        parent_id: u64,
        starting_offset: u64,
        length: u64,
        sub_type: u8,
        data1: u32,
        data2: u64,
    ) -> Result<DBRecord, GhidraError> {
        let key = self.alloc_key();
        let mut record = DBRecord::new(key, 8, 2, 4);
        record.set_long_value(SUB_PARENT_ID_COL, parent_id);
        record.set_byte_value(SUB_TYPE_COL, sub_type);
        record.set_long_value(SUB_LENGTH_COL, length);
        record.set_long_value(SUB_START_OFFSET_COL, starting_offset);
        record.set_long_value(SUB_INT_DATA1_COL, data1 as u64);
        record.set_long_value(SUB_LONG_DATA2_COL, data2);
        self.sub_block_records.push(record.clone());
        Ok(record)
    }

    fn create_file_bytes_block(
        &mut self,
        name: &str,
        start: Address,
        length: u64,
        file_bytes_id: u64,
        file_bytes_offset: u64,
        flags: u8,
    ) -> Result<MemoryBlockDB, GhidraError> {
        let key = self.alloc_key();
        let end = start.add(length.saturating_sub(1));

        let mut record = DBRecord::new(key, 8, 2, 4);
        record.set_string(NAME_COL, Some(name.to_string()));
        record.set_byte_value(FLAGS_COL, flags);
        record.set_long_value(START_ADDR_COL, start.offset);
        record.set_long_value(LENGTH_COL, length);
        self.block_records.push(record);

        let mut sub_record = DBRecord::new(self.alloc_key(), 8, 2, 4);
        sub_record.set_long_value(SUB_PARENT_ID_COL, key);
        sub_record.set_byte_value(SUB_TYPE_COL, SUB_TYPE_FILE_BYTES);
        sub_record.set_long_value(SUB_LENGTH_COL, length);
        sub_record.set_long_value(SUB_START_OFFSET_COL, 0);
        sub_record.set_long_value(SUB_INT_DATA1_COL, 0);
        sub_record.set_long_value(SUB_LONG_DATA2_COL, file_bytes_offset);
        self.sub_block_records.push(sub_record);

        Ok(MemoryBlockDB::new(
            key,
            name.to_string(),
            start,
            end,
            length,
            flags,
            true,
            false,
            None,
            None,
        ))
    }

    fn get_buffer(&self, buffer_id: u32) -> Result<DBBuffer, GhidraError> {
        self.buffers
            .iter()
            .find(|b| b.get_id() == buffer_id)
            .cloned()
            .ok_or_else(|| {
                GhidraError::DatabaseError(format!("Buffer {} not found", buffer_id))
            })
    }

    fn delete_table(&mut self) -> Result<(), GhidraError> {
        self.block_records.clear();
        self.sub_block_records.clear();
        self.buffers.clear();
        Ok(())
    }

    fn version(&self) -> u32 {
        3
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_db_record_fields() {
        let mut rec = DBRecord::new(42, 8, 2, 4);
        rec.set_long_value(START_ADDR_COL, 0x1000);
        rec.set_long_value(LENGTH_COL, 256);
        rec.set_byte_value(FLAGS_COL, 0x07);
        rec.set_string(NAME_COL, Some(".text".to_string()));

        assert_eq!(rec.get_key(), 42);
        assert_eq!(rec.get_long_value(START_ADDR_COL), 0x1000);
        assert_eq!(rec.get_long_value(LENGTH_COL), 256);
        assert_eq!(rec.get_byte_value(FLAGS_COL), 0x07);
        assert_eq!(rec.get_string(NAME_COL), Some(".text"));
    }

    #[test]
    fn test_db_buffer_basic() {
        let mut buf = DBBuffer::new(1, 256, 0xAA);
        assert_eq!(buf.size(), 256);
        assert_eq!(buf.get_byte(0).unwrap(), 0xAA);
        buf.put_byte(0, 0x42).unwrap();
        assert_eq!(buf.get_byte(0).unwrap(), 0x42);
    }

    #[test]
    fn test_db_buffer_get_put() {
        let mut buf = DBBuffer::new(1, 16, 0x00);
        let src = [0xDE, 0xAD, 0xBE, 0xEF];
        buf.put(0, &src, 0, 4);
        let mut dest = [0u8; 4];
        buf.get(0, &mut dest, 0, 4);
        assert_eq!(dest, src);
    }

    #[test]
    fn test_db_buffer_split() {
        let mut buf = DBBuffer::new(1, 8, 0x42);
        let right = buf.split(4);
        assert_eq!(buf.size(), 4);
        assert_eq!(right.size(), 4);
        assert_eq!(buf.get_byte(0).unwrap(), 0x42);
        assert_eq!(right.get_byte(0).unwrap(), 0x42);
    }

    #[test]
    fn test_db_buffer_append() {
        let mut buf1 = DBBuffer::from_data(1, vec![1, 2, 3]);
        let buf2 = DBBuffer::from_data(2, vec![4, 5, 6]);
        buf1.append(&buf2);
        assert_eq!(buf1.size(), 6);
        assert_eq!(buf1.get_byte(3).unwrap(), 4);
    }

    #[test]
    fn test_in_memory_adapter_version() {
        let adapter = InMemoryAdapter::new();
        assert_eq!(adapter.version(), 3);
    }

    #[test]
    fn test_in_memory_adapter_create_block() {
        let mut adapter = InMemoryAdapter::new();
        let block = adapter
            .create_block(
                MemoryBlockType::Default,
                ".text",
                Address::new(0x1000),
                256,
                None,
                false,
                0x07,
                0,
            )
            .unwrap();
        assert_eq!(block.name(), ".text");
        assert_eq!(block.size(), 256);
    }

    #[test]
    fn test_in_memory_adapter_delete_table() {
        let mut adapter = InMemoryAdapter::new();
        adapter
            .create_block(
                MemoryBlockType::Default,
                ".text",
                Address::new(0x1000),
                256,
                None,
                false,
                0x07,
                0,
            )
            .unwrap();
        adapter.delete_table().unwrap();
        assert!(adapter.block_records.is_empty());
        assert!(adapter.sub_block_records.is_empty());
    }

    #[test]
    fn test_in_memory_adapter_sub_block_record() {
        let mut adapter = InMemoryAdapter::new();
        let rec = adapter
            .create_sub_block_record(100, 0, 1024, SUB_TYPE_BUFFER, 42, 0)
            .unwrap();
        assert_eq!(rec.get_long_value(SUB_PARENT_ID_COL), 100);
        assert_eq!(rec.get_long_value(SUB_LENGTH_COL), 1024);
        assert_eq!(rec.get_byte_value(SUB_TYPE_COL), SUB_TYPE_BUFFER);
        assert_eq!(rec.get_long_value(SUB_INT_DATA1_COL), 42);
    }

    #[test]
    fn test_column_constants() {
        // Ensure column indices are consistent.
        assert_eq!(NAME_COL, 0);
        assert_eq!(FLAGS_COL, 3);
        assert_eq!(START_ADDR_COL, 4);
        assert_eq!(LENGTH_COL, 5);
        assert_eq!(SUB_PARENT_ID_COL, 0);
        assert_eq!(SUB_TYPE_COL, 1);
    }
}
