//! Character iterator for Microsoft mangled symbol parsing.
//!
//! Ported from `MDCharacterIterator.java`.

/// Sentinel character indicating the iterator has reached the end.
pub const DONE: char = '\0';

/// A forward-stepping character iterator over a mangled symbol string.
///
/// Corresponds to Java's `MDCharacterIterator`.
#[derive(Debug, Clone)]
pub struct CharacterIterator {
    chars: Vec<char>,
    index: usize,
}

impl CharacterIterator {
    /// Create a new iterator over the given string.
    pub fn new(s: &str) -> Self {
        Self {
            chars: s.chars().collect(),
            index: 0,
        }
    }

    /// Get the current index.
    pub fn index(&self) -> usize {
        self.index
    }

    /// Set the current index.
    pub fn set_index(&mut self, index: usize) {
        assert!(
            index <= self.chars.len(),
            "index {} out of range 0..{}",
            index,
            self.chars.len()
        );
        self.index = index;
    }

    /// Get the length of the underlying string.
    pub fn len(&self) -> usize {
        self.chars.len()
    }

    /// Returns true if the iterator is empty.
    pub fn is_empty(&self) -> bool {
        self.chars.is_empty()
    }

    /// Returns true if the iterator has reached the end.
    pub fn done(&self) -> bool {
        self.index >= self.chars.len()
    }

    /// Returns the character at the current index without advancing.
    /// Returns `DONE` if at end.
    pub fn peek(&self) -> char {
        if self.index >= self.chars.len() {
            DONE
        } else {
            self.chars[self.index]
        }
    }

    /// Returns the character at `current_index + look_ahead` without advancing.
    /// Returns `DONE` if the computed position is out of range.
    pub fn peek_at(&self, look_ahead: usize) -> char {
        let pos = self.index + look_ahead;
        if pos >= self.chars.len() {
            DONE
        } else {
            self.chars[pos]
        }
    }

    /// Returns the character at the current index and advances by one.
    /// Returns `DONE` if already at end.
    pub fn get_and_increment(&mut self) -> char {
        if self.index >= self.chars.len() {
            DONE
        } else {
            let ch = self.chars[self.index];
            self.index += 1;
            ch
        }
    }

    /// Advance by one. Does not return the character. Does not check bounds.
    pub fn increment(&mut self) {
        self.index += 1;
    }

    /// Advance by `count` characters. Does not check bounds.
    pub fn increment_by(&mut self, count: usize) {
        self.index += count;
    }

    /// Returns the character at the current index and advances.
    /// This is the same as `get_and_increment` but follows the Java naming.
    pub fn next(&mut self) -> char {
        self.get_and_increment()
    }

    /// Returns true if the given substring appears at the current position.
    pub fn starts_with(&self, substring: &str) -> bool {
        let sub_chars: Vec<char> = substring.chars().collect();
        if self.index + sub_chars.len() > self.chars.len() {
            return false;
        }
        for (i, &ch) in sub_chars.iter().enumerate() {
            if self.chars[self.index + i] != ch {
                return false;
            }
        }
        true
    }

    /// Returns a string slice of the remaining characters (for debugging/display).
    pub fn remaining(&self) -> String {
        self.chars[self.index..].iter().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_peek_and_next() {
        let mut iter = CharacterIterator::new("ABC");
        assert_eq!(iter.peek(), 'A');
        assert_eq!(iter.index(), 0);

        assert_eq!(iter.next(), 'A');
        assert_eq!(iter.peek(), 'B');
        assert_eq!(iter.index(), 1);

        assert_eq!(iter.next(), 'B');
        assert_eq!(iter.next(), 'C');
        assert_eq!(iter.next(), DONE);
        assert!(iter.done());
    }

    #[test]
    fn test_peek_at() {
        let iter = CharacterIterator::new("ABC");
        assert_eq!(iter.peek_at(0), 'A');
        assert_eq!(iter.peek_at(1), 'B');
        assert_eq!(iter.peek_at(2), 'C');
        assert_eq!(iter.peek_at(3), DONE);
    }

    #[test]
    fn test_starts_with() {
        let mut iter = CharacterIterator::new("HelloWorld");
        assert!(iter.starts_with("Hello"));
        assert!(!iter.starts_with("World"));

        iter.increment_by(5);
        assert!(iter.starts_with("World"));
        assert!(!iter.starts_with("Hello"));
    }

    #[test]
    fn test_increment_by() {
        let mut iter = CharacterIterator::new("12345");
        iter.increment_by(3);
        assert_eq!(iter.peek(), '4');
        assert_eq!(iter.index(), 3);
    }

    #[test]
    fn test_empty() {
        let iter = CharacterIterator::new("");
        assert!(iter.done());
        assert_eq!(iter.peek(), DONE);
    }
}
