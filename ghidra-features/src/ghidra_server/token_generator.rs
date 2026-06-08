//! Token generation and validation for authentication challenge-response.
//!
//! Ported from `ghidra.server.security.TokenGenerator`.
//!
//! Provides single-use tokens with embedded timestamps for secure
//! authentication flows (PKI, SSH). Tokens are valid for a limited
//! time-to-live and can only be consumed once.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Maximum token time-to-live in milliseconds (60 seconds, matching Java).
const MAX_TTL_MS: u64 = 60_000;

/// Total token size in bytes (matching Java's TOKEN_SIZE = 64).
const TOKEN_SIZE: usize = 64;

/// Size of the timestamp prefix in bytes.
const TIMESTAMP_SIZE: usize = 8;

/// Size of the random portion of the token.
const RANDOM_SIZE: usize = TOKEN_SIZE - TIMESTAMP_SIZE;

// ---------------------------------------------------------------------------
// Token
// ---------------------------------------------------------------------------

/// Wrapper around a byte-array token for value-based hashing/equality.
///
/// Matches Java's inner `Token` class.
#[derive(Clone)]
struct Token {
    data: Vec<u8>,
}

impl Token {
    fn new(data: &[u8]) -> Self {
        Self {
            data: data.to_vec(),
        }
    }
}

impl PartialEq for Token {
    fn eq(&self, other: &Self) -> bool {
        self.data == other.data
    }
}

impl Eq for Token {}

impl std::hash::Hash for Token {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.data.hash(state);
    }
}

// ---------------------------------------------------------------------------
// CachedTokenSet
// ---------------------------------------------------------------------------

/// Tracks issued tokens and ensures one-time consumption within a limited lifespan.
///
/// Matches Java's inner `CachedTokenSet` class.  Uses a `HashMap` protected
/// by a `Mutex` and a background cleanup thread.
struct CachedTokenSet {
    cache: Mutex<HashMap<Token, Instant>>,
}

impl CachedTokenSet {
    fn new() -> Arc<Self> {
        let set = Arc::new(Self {
            cache: Mutex::new(HashMap::new()),
        });

        // Spawn a cleanup thread that runs every 5 seconds (matching Java).
        let weak_set = Arc::downgrade(&set);
        thread::spawn(move || {
            while let Some(set) = weak_set.upgrade() {
                thread::sleep(Duration::from_secs(5));
                set.cleanup();
            }
        });

        set
    }

    /// Insert a new token into the cache.
    fn add(&self, token: &[u8]) {
        let mut cache = self.cache.lock().unwrap();
        cache.insert(Token::new(token), Instant::now());
    }

    /// Attempt to consume a token.  Returns `true` if the token was present
    /// and still valid (within TTL).  The token is removed on retrieval.
    fn consume(&self, token: &[u8]) -> bool {
        let mut cache = self.cache.lock().unwrap();
        let key = Token::new(token);
        if let Some(stored_at) = cache.remove(&key) {
            (stored_at.elapsed().as_millis() as u64) < MAX_TTL_MS
        } else {
            false
        }
    }

    /// Remove expired tokens from the cache.
    fn cleanup(&self) {
        let mut cache = self.cache.lock().unwrap();
        cache.retain(|_, stored_at| (stored_at.elapsed().as_millis() as u64) < MAX_TTL_MS);
    }
}

// ---------------------------------------------------------------------------
// TokenGenerator
// ---------------------------------------------------------------------------

/// Generates and validates single-use authentication tokens.
///
/// Matches Java's `TokenGenerator` class.  Each token is 64 bytes:
/// 8 bytes of big-endian timestamp followed by 56 bytes of random data.
pub struct TokenGenerator {
    cache: Arc<CachedTokenSet>,
}

impl TokenGenerator {
    /// Create a new `TokenGenerator`.
    pub fn new() -> Self {
        Self {
            cache: CachedTokenSet::new(),
        }
    }

    /// Generate a new single-use token with an embedded timestamp.
    ///
    /// Returns a `TOKEN_SIZE`-byte vector.
    pub fn get_new_token(&self) -> Vec<u8> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        let mut token = vec![0u8; TOKEN_SIZE];

        // Write timestamp as big-endian u64 into the first 8 bytes.
        put_u64_be(&mut token, 0, timestamp);

        // Fill remaining bytes with random data.
        fill_random_bytes(&mut token[TIMESTAMP_SIZE..]);

        self.cache.add(&token);
        token
    }

    /// Validate and consume a token.
    ///
    /// Returns `true` if the token was previously issued, has not yet been
    /// consumed, and is still within its TTL.  The token is consumed on
    /// the first call; subsequent calls with the same token return `false`.
    pub fn is_valid_token(&self, token: &[u8]) -> bool {
        if token.len() != TOKEN_SIZE {
            return false;
        }
        if !self.cache.consume(token) {
            return false;
        }
        let issue_time = get_u64_be(token, 0);
        if issue_time == 0 {
            return false;
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        let diff = now.saturating_sub(issue_time);
        diff < MAX_TTL_MS
    }
}

impl Default for TokenGenerator {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Byte helpers
// ---------------------------------------------------------------------------

/// Write a `u64` as big-endian into `data` at `offset`.
fn put_u64_be(data: &mut [u8], offset: usize, v: u64) {
    data[offset] = (v >> 56) as u8;
    data[offset + 1] = (v >> 48) as u8;
    data[offset + 2] = (v >> 40) as u8;
    data[offset + 3] = (v >> 32) as u8;
    data[offset + 4] = (v >> 24) as u8;
    data[offset + 5] = (v >> 16) as u8;
    data[offset + 6] = (v >> 8) as u8;
    data[offset + 7] = v as u8;
}

/// Read a big-endian `u64` from `data` at `offset`.
fn get_u64_be(data: &[u8], offset: usize) -> u64 {
    ((data[offset] as u64) << 56)
        | ((data[offset + 1] as u64) << 48)
        | ((data[offset + 2] as u64) << 40)
        | ((data[offset + 3] as u64) << 32)
        | ((data[offset + 4] as u64) << 24)
        | ((data[offset + 5] as u64) << 16)
        | ((data[offset + 6] as u64) << 8)
        | (data[offset + 7] as u64)
}

/// Fill a byte slice with cryptographically secure random bytes.
fn fill_random_bytes(buf: &mut [u8]) {
    use std::io::Read;
    // Use /dev/urandom on Unix; this is cryptographically secure on Linux.
    let mut f = std::fs::File::open("/dev/urandom").expect("failed to open /dev/urandom");
    f.read_exact(buf).expect("failed to read random bytes");
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_roundtrip() {
        let gen = TokenGenerator::new();
        let token = gen.get_new_token();
        assert_eq!(token.len(), TOKEN_SIZE);
        assert!(gen.is_valid_token(&token));
    }

    #[test]
    fn test_token_single_use() {
        let gen = TokenGenerator::new();
        let token = gen.get_new_token();
        assert!(gen.is_valid_token(&token));
        // Second consumption should fail.
        assert!(!gen.is_valid_token(&token));
    }

    #[test]
    fn test_token_wrong_size() {
        let gen = TokenGenerator::new();
        assert!(!gen.is_valid_token(&[0u8; 10]));
    }

    #[test]
    fn test_token_unknown() {
        let gen = TokenGenerator::new();
        let fake = vec![0u8; TOKEN_SIZE];
        assert!(!gen.is_valid_token(&fake));
    }

    #[test]
    fn test_put_get_u64_be_roundtrip() {
        let mut buf = [0u8; 8];
        let val: u64 = 0x0102030405060708;
        put_u64_be(&mut buf, 0, val);
        assert_eq!(get_u64_be(&buf, 0), val);
    }

    #[test]
    fn test_put_get_u64_be_zero() {
        let mut buf = [0u8; 8];
        put_u64_be(&mut buf, 0, 0);
        assert_eq!(get_u64_be(&buf, 0), 0);
    }

    #[test]
    fn test_put_get_u64_be_max() {
        let mut buf = [0u8; 8];
        put_u64_be(&mut buf, 0, u64::MAX);
        assert_eq!(get_u64_be(&buf, 0), u64::MAX);
    }

    #[test]
    fn test_fill_random_bytes() {
        let mut buf = [0u8; 64];
        fill_random_bytes(&mut buf);
        // Extremely unlikely to be all zeros.
        assert_ne!(buf, [0u8; 64]);
    }
}
