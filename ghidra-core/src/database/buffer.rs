//! Buffer abstractions (stubs).

/// A byte buffer trait.
pub trait Buffer {
    fn id(&self) -> i64;
    fn length(&self) -> usize;
}

/// Simple in-memory buffer.
#[derive(Debug)]
pub struct CacheBuffer {
    buffer_id: i64,
    data: Vec<u8>,
}

impl CacheBuffer {
    pub fn new(buffer_id: i64, size: usize) -> Self {
        Self { buffer_id, data: vec![0u8; size] }
    }
}

impl Buffer for CacheBuffer {
    fn id(&self) -> i64 { self.buffer_id }
    fn length(&self) -> usize { self.data.len() }
}

/// Chained buffer placeholder.
#[derive(Debug)]
pub struct ChainedBuffer {
    buffer_id: i64,
    size: usize,
}

impl ChainedBuffer {
    pub fn new(buffer_id: i64, size: usize) -> Self {
        Self { buffer_id, size }
    }
    pub fn buffer_id(&self) -> i64 { self.buffer_id }
}

impl Buffer for ChainedBuffer {
    fn id(&self) -> i64 { self.buffer_id }
    fn length(&self) -> usize { self.size }
}
