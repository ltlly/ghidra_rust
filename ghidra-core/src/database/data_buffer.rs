//! DataBuffer — low-level binary buffer for the Ghidra database.
//!
//! Port of Java `db.buffers.DataBuffer`. Provides an accessible binary buffer
//! for use with a BufferMgr and BufferFile. Supports read/write operations
//! on byte, short, int, and long values in big-endian format, as well as
//! bulk copy/move operations.
//!
//! ## Buffer Layout
//!
//! The buffer stores raw bytes in a `Vec<u8>` and tracks:
//! - `id`: the buffer identifier
//! - `dirty`: whether the buffer has been modified since last flush
//! - `empty`: whether the buffer is unused/deleted

use std::fmt;

// ============================================================================
// DataBuffer
// ============================================================================

/// An accessible binary buffer for use with BufferMgr and BufferFile.
///
/// Port of Java `db.buffers.DataBuffer`. Provides get/put operations for
/// primitive types in big-endian byte order, plus bulk copy and move.
#[derive(Debug, Clone)]
pub struct DataBuffer {
    /// Buffer identifier.
    id: i32,
    /// Raw byte storage.
    data: Vec<u8>,
    /// True if buffer has been modified since last flush.
    dirty: bool,
    /// True if buffer is empty/unused.
    empty: bool,
}

impl DataBuffer {
    /// Create a new empty data buffer with the specified size.
    ///
    /// Port of Java `DataBuffer(int bufsize)`.
    pub fn new(bufsize: usize) -> Self {
        Self {
            id: 0,
            data: vec![0u8; bufsize],
            dirty: false,
            empty: false,
        }
    }

    /// Create a data buffer wrapping the given byte array.
    ///
    /// Port of Java `DataBuffer(byte[] data)`.
    pub fn from_data(data: Vec<u8>) -> Self {
        Self {
            id: 0,
            data,
            dirty: false,
            empty: false,
        }
    }

    /// Create a data buffer with the given id and size.
    pub fn with_id(id: i32, bufsize: usize) -> Self {
        Self {
            id,
            data: vec![0u8; bufsize],
            dirty: false,
            empty: false,
        }
    }

    // ---- ID accessors ----

    /// Get the buffer ID.
    ///
    /// Port of Java `DataBuffer.getId()`.
    pub fn get_id(&self) -> i32 {
        self.id
    }

    /// Set the buffer ID.
    ///
    /// Port of Java `DataBuffer.setId(int)`.
    pub fn set_id(&mut self, id: i32) {
        self.id = id;
    }

    // ---- State accessors ----

    /// Return true if this buffer contains modified data.
    ///
    /// Port of Java `DataBuffer.isDirty()`.
    pub fn is_dirty(&self) -> bool {
        self.dirty
    }

    /// Set the dirty flag.
    ///
    /// Port of Java `DataBuffer.setDirty(boolean)`.
    pub fn set_dirty(&mut self, state: bool) {
        self.dirty = state;
    }

    /// Return true if this buffer is empty/unused.
    ///
    /// Port of Java `DataBuffer.isEmpty()`.
    pub fn is_empty_buffer(&self) -> bool {
        self.empty
    }

    /// Set the empty flag.
    ///
    /// Port of Java `DataBuffer.setEmpty(boolean)`.
    pub fn set_empty(&mut self, state: bool) {
        self.empty = state;
    }

    // ---- Size ----

    /// Get the length of the buffer in bytes.
    ///
    /// Port of Java `DataBuffer.length()`.
    pub fn length(&self) -> usize {
        self.data.len()
    }

    // ---- Bulk read ----

    /// Copy bytes from the buffer into the provided array.
    ///
    /// Port of Java `DataBuffer.get(int offset, byte[] bytes)`.
    pub fn get(&self, offset: usize, bytes: &mut [u8]) {
        bytes.copy_from_slice(&self.data[offset..offset + bytes.len()]);
    }

    /// Copy bytes from the buffer into the provided array at a specific offset.
    ///
    /// Port of Java `DataBuffer.get(int offset, byte[] data, int dataOffset, int length)`.
    pub fn get_into(&self, offset: usize, data: &mut [u8], data_offset: usize, length: usize) {
        data[data_offset..data_offset + length]
            .copy_from_slice(&self.data[offset..offset + length]);
    }

    /// Get a slice of the buffer data.
    ///
    /// Port of Java `DataBuffer.get(int offset, int length)`.
    pub fn get_slice(&self, offset: usize, length: usize) -> &[u8] {
        &self.data[offset..offset + length]
    }

    /// Get a mutable slice of the buffer data.
    pub fn get_slice_mut(&mut self, offset: usize, length: usize) -> &mut [u8] {
        &mut self.data[offset..offset + length]
    }

    /// Get a reference to the underlying data array.
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Get a mutable reference to the underlying data array.
    pub fn data_mut(&mut self) -> &mut [u8] {
        &mut self.data
    }

    // ---- Primitive reads (big-endian) ----

    /// Read a single byte at the specified offset.
    ///
    /// Port of Java `DataBuffer.getByte(int)`.
    pub fn get_byte(&self, offset: usize) -> u8 {
        self.data[offset]
    }

    /// Read a 16-bit short at the specified offset (big-endian).
    ///
    /// Port of Java `DataBuffer.getShort(int)`.
    pub fn get_short(&self, offset: usize) -> i16 {
        i16::from_be_bytes([self.data[offset], self.data[offset + 1]])
    }

    /// Read a 32-bit int at the specified offset (big-endian).
    ///
    /// Port of Java `DataBuffer.getInt(int)`.
    pub fn get_int(&self, offset: usize) -> i32 {
        i32::from_be_bytes([
            self.data[offset],
            self.data[offset + 1],
            self.data[offset + 2],
            self.data[offset + 3],
        ])
    }

    /// Read a 64-bit long at the specified offset (big-endian).
    ///
    /// Port of Java `DataBuffer.getLong(int)`.
    pub fn get_long(&self, offset: usize) -> i64 {
        i64::from_be_bytes([
            self.data[offset],
            self.data[offset + 1],
            self.data[offset + 2],
            self.data[offset + 3],
            self.data[offset + 4],
            self.data[offset + 5],
            self.data[offset + 6],
            self.data[offset + 7],
        ])
    }

    // ---- Bulk write ----

    /// Write bytes into the buffer at the specified offset.
    ///
    /// Port of Java `DataBuffer.put(int offset, byte[] bytes)`.
    /// Returns the next available offset.
    pub fn put(&mut self, offset: usize, bytes: &[u8]) -> usize {
        self.dirty = true;
        self.data[offset..offset + bytes.len()].copy_from_slice(bytes);
        offset + bytes.len()
    }

    /// Write bytes from a source array into the buffer.
    ///
    /// Port of Java `DataBuffer.put(int offset, byte[] bytes, int dataOffset, int length)`.
    /// Returns the next available offset.
    pub fn put_from(&mut self, offset: usize, bytes: &[u8], data_offset: usize, length: usize) -> usize {
        self.dirty = true;
        self.data[offset..offset + length]
            .copy_from_slice(&bytes[data_offset..data_offset + length]);
        offset + length
    }

    // ---- Primitive writes (big-endian) ----

    /// Write a single byte at the specified offset.
    ///
    /// Port of Java `DataBuffer.putByte(int, byte)`.
    /// Returns the next available offset.
    pub fn put_byte(&mut self, offset: usize, b: u8) -> usize {
        self.dirty = true;
        self.data[offset] = b;
        offset + 1
    }

    /// Write a 16-bit short at the specified offset (big-endian).
    ///
    /// Port of Java `DataBuffer.putShort(int, short)`.
    /// Returns the next available offset.
    pub fn put_short(&mut self, offset: usize, v: i16) -> usize {
        self.dirty = true;
        let bytes = v.to_be_bytes();
        self.data[offset] = bytes[0];
        self.data[offset + 1] = bytes[1];
        offset + 2
    }

    /// Write a 32-bit int at the specified offset (big-endian).
    ///
    /// Port of Java `DataBuffer.putInt(int, int)`.
    /// Returns the next available offset.
    pub fn put_int(&mut self, offset: usize, v: i32) -> usize {
        self.dirty = true;
        let bytes = v.to_be_bytes();
        self.data[offset] = bytes[0];
        self.data[offset + 1] = bytes[1];
        self.data[offset + 2] = bytes[2];
        self.data[offset + 3] = bytes[3];
        offset + 4
    }

    /// Write a 64-bit long at the specified offset (big-endian).
    ///
    /// Port of Java `DataBuffer.putLong(int, long)`.
    /// Returns the next available offset.
    pub fn put_long(&mut self, offset: usize, v: i64) -> usize {
        self.dirty = true;
        let bytes = v.to_be_bytes();
        for i in 0..8 {
            self.data[offset + i] = bytes[i];
        }
        offset + 8
    }

    // ---- Operations ----

    /// Clear the buffer by setting all bytes to zero.
    ///
    /// Port of Java `DataBuffer.clear()`.
    pub fn clear(&mut self) {
        self.dirty = true;
        self.data.fill(0);
    }

    /// Move data within this buffer from one region to another.
    ///
    /// Port of Java `DataBuffer.move(int src, int dest, int length)`.
    pub fn move_data(&mut self, src: usize, dest: usize, length: usize) {
        self.dirty = true;
        self.data.copy_within(src..src + length, dest);
    }

    /// Copy data from another buffer into this buffer.
    ///
    /// Port of Java `DataBuffer.copy(int offset, DataBuffer buf, int bufOffset, int length)`.
    pub fn copy_from(&mut self, offset: usize, src: &DataBuffer, src_offset: usize, length: usize) {
        self.dirty = true;
        self.data[offset..offset + length]
            .copy_from_slice(&src.data[src_offset..src_offset + length]);
    }

    /// Perform an unsigned comparison of a region of this buffer against
    /// the provided data.
    ///
    /// Port of Java `DataBuffer.unsignedCompareTo(byte[], int, int)`.
    /// Returns negative if less, zero if equal, positive if greater.
    pub fn unsigned_compare_to(&self, other_data: &[u8], offset: usize, len: usize) -> i32 {
        let other_len = other_data.len();
        let n = len.min(other_len);
        for i in 0..n {
            let b = self.data[offset + i] as i32;
            let other_byte = other_data[i] as i32;
            if b != other_byte {
                return b - other_byte;
            }
        }
        (len as i32) - (other_len as i32)
    }
}

impl fmt::Display for DataBuffer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "DataBuffer(id={}, len={}, dirty={}, empty={})",
            self.id,
            self.data.len(),
            self.dirty,
            self.empty
        )
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_buffer() {
        let buf = DataBuffer::new(256);
        assert_eq!(buf.length(), 256);
        assert_eq!(buf.get_id(), 0);
        assert!(!buf.is_dirty());
        assert!(!buf.is_empty_buffer());
    }

    #[test]
    fn test_from_data() {
        let data = vec![1, 2, 3, 4, 5];
        let buf = DataBuffer::from_data(data);
        assert_eq!(buf.length(), 5);
        assert_eq!(buf.get_byte(0), 1);
        assert_eq!(buf.get_byte(4), 5);
    }

    #[test]
    fn test_with_id() {
        let buf = DataBuffer::with_id(42, 128);
        assert_eq!(buf.get_id(), 42);
        assert_eq!(buf.length(), 128);
    }

    #[test]
    fn test_id_accessor() {
        let mut buf = DataBuffer::new(64);
        buf.set_id(100);
        assert_eq!(buf.get_id(), 100);
    }

    #[test]
    fn test_dirty_flag() {
        let mut buf = DataBuffer::new(64);
        assert!(!buf.is_dirty());
        buf.set_dirty(true);
        assert!(buf.is_dirty());
    }

    #[test]
    fn test_empty_flag() {
        let mut buf = DataBuffer::new(64);
        assert!(!buf.is_empty_buffer());
        buf.set_empty(true);
        assert!(buf.is_empty_buffer());
    }

    #[test]
    fn test_get_byte() {
        let mut buf = DataBuffer::new(16);
        buf.data[0] = 0x42;
        assert_eq!(buf.get_byte(0), 0x42);
    }

    #[test]
    fn test_get_put_short() {
        let mut buf = DataBuffer::new(16);
        buf.put_short(0, 0x1234);
        assert_eq!(buf.get_short(0), 0x1234);
        assert!(buf.is_dirty());
    }

    #[test]
    fn test_get_put_int() {
        let mut buf = DataBuffer::new(16);
        buf.put_int(0, 0x12345678);
        assert_eq!(buf.get_int(0), 0x12345678);
    }

    #[test]
    fn test_get_put_long() {
        let mut buf = DataBuffer::new(32);
        buf.put_long(0, 0x0102030405060708);
        assert_eq!(buf.get_long(0), 0x0102030405060708);
    }

    #[test]
    fn test_put_byte_returns_next_offset() {
        let mut buf = DataBuffer::new(16);
        let next = buf.put_byte(0, 0xFF);
        assert_eq!(next, 1);
        assert_eq!(buf.get_byte(0), 0xFF);
    }

    #[test]
    fn test_bulk_get() {
        let data = vec![10, 20, 30, 40, 50];
        let buf = DataBuffer::from_data(data);
        let mut out = [0u8; 3];
        buf.get(1, &mut out);
        assert_eq!(out, [20, 30, 40]);
    }

    #[test]
    fn test_bulk_get_into() {
        let data = vec![10, 20, 30, 40, 50];
        let buf = DataBuffer::from_data(data);
        let mut out = [0u8; 5];
        buf.get_into(1, &mut out, 2, 3);
        assert_eq!(out, [0, 0, 20, 30, 40]);
    }

    #[test]
    fn test_get_slice() {
        let data = vec![1, 2, 3, 4, 5];
        let buf = DataBuffer::from_data(data);
        let slice = buf.get_slice(1, 3);
        assert_eq!(slice, &[2, 3, 4]);
    }

    #[test]
    fn test_put_bulk() {
        let mut buf = DataBuffer::new(16);
        let next = buf.put(0, &[0xAA, 0xBB, 0xCC]);
        assert_eq!(next, 3);
        assert_eq!(buf.get_byte(0), 0xAA);
        assert_eq!(buf.get_byte(1), 0xBB);
        assert_eq!(buf.get_byte(2), 0xCC);
    }

    #[test]
    fn test_clear() {
        let mut buf = DataBuffer::from_data(vec![1, 2, 3, 4]);
        buf.clear();
        assert_eq!(buf.data(), &[0, 0, 0, 0]);
        assert!(buf.is_dirty());
    }

    #[test]
    fn test_move_data() {
        let mut buf = DataBuffer::from_data(vec![0, 1, 2, 3, 4, 5, 0, 0]);
        buf.move_data(0, 6, 2);
        assert_eq!(buf.get_byte(6), 1);
        assert_eq!(buf.get_byte(7), 2);
    }

    #[test]
    fn test_copy_from() {
        let src = DataBuffer::from_data(vec![10, 20, 30, 40]);
        let mut dst = DataBuffer::new(8);
        dst.copy_from(2, &src, 1, 2);
        assert_eq!(dst.get_byte(2), 20);
        assert_eq!(dst.get_byte(3), 30);
    }

    #[test]
    fn test_unsigned_compare_to() {
        let buf = DataBuffer::from_data(vec![0x01, 0x02, 0x03]);
        assert_eq!(buf.unsigned_compare_to(&[0x01, 0x02, 0x03], 0, 3), 0);
        assert!(buf.unsigned_compare_to(&[0x01, 0x01, 0x03], 0, 3) > 0);
        assert!(buf.unsigned_compare_to(&[0x01, 0x03, 0x03], 0, 3) < 0);
    }

    #[test]
    fn test_display() {
        let buf = DataBuffer::with_id(5, 128);
        let s = format!("{}", buf);
        assert!(s.contains("id=5"));
        assert!(s.contains("len=128"));
    }
}
