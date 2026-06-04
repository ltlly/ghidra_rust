//! Console word extraction for navigation.
//!
//! Port of Ghidra's `ghidra.app.plugin.core.console.ConsoleWord`.
//!
//! Represents a word found in the console text, along with its position.
//! Used for double-click navigation to addresses and symbols.

/// A word found in the console text along with its character positions.
///
/// Used to identify clickable words in the console output, such as
/// addresses or symbol names, for navigation purposes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsoleWord {
    /// The word text.
    pub word: String,
    /// The start position (inclusive) in the console text.
    pub start_position: usize,
    /// The end position (exclusive) in the console text.
    pub end_position: usize,
}

impl ConsoleWord {
    /// Create a new console word.
    pub fn new(word: impl Into<String>, start_position: usize, end_position: usize) -> Self {
        Self {
            word: word.into(),
            start_position,
            end_position,
        }
    }

    /// Return a copy of this word with leading and trailing special characters removed.
    ///
    /// Special characters are: `]`, `[`, `,`, `.`
    ///
    /// The start and end positions are adjusted accordingly.
    pub fn without_special_characters(&self) -> ConsoleWord {
        let mut trimmed = self.word.clone();
        let mut new_start = self.start_position;
        let mut new_end = self.end_position;

        // Trim from the back
        while trimmed.ends_with(Self::is_special_char) {
            trimmed.pop();
            new_end -= 1;
        }

        // Trim from the front
        while trimmed.starts_with(Self::is_special_char) {
            trimmed.remove(0);
            new_start += 1;
        }

        ConsoleWord::new(trimmed, new_start, new_end)
    }

    fn is_special_char(c: char) -> bool {
        c == ']' || c == '[' || c == ',' || c == '.'
    }
}

impl std::fmt::Display for ConsoleWord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}({},{})",
            self.word, self.start_position, self.end_position
        )
    }
}

/// Extract a word at the given position from the text, delimited by whitespace.
///
/// Returns `None` if the position is out of bounds or no word is found.
pub fn get_word_at_position(text: &str, position: usize) -> Option<ConsoleWord> {
    if text.is_empty() || position >= text.len() {
        return None;
    }

    let chars: Vec<char> = text.chars().collect();
    if position >= chars.len() {
        return None;
    }

    // Find start of word
    let mut start = position;
    while start > 0 && !chars[start - 1].is_whitespace() {
        start -= 1;
    }

    // Find end of word
    let mut end = position;
    while end < chars.len() - 1 && !chars[end].is_whitespace() {
        end += 1;
    }
    // Include the character at end if it's not whitespace
    if end < chars.len() && !chars[end].is_whitespace() {
        end += 1;
    }

    let word: String = chars[start..end].iter().collect();
    let trimmed = word.trim();

    if trimmed.is_empty() {
        return None;
    }

    // Adjust start to account for leading whitespace in the extracted slice
    let leading_ws = word.len() - word.trim_start().len();
    let actual_start = start + leading_ws;

    Some(ConsoleWord::new(trimmed, actual_start, actual_start + trimmed.len()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_console_word_creation() {
        let word = ConsoleWord::new("hello", 0, 5);
        assert_eq!(word.word, "hello");
        assert_eq!(word.start_position, 0);
        assert_eq!(word.end_position, 5);
    }

    #[test]
    fn test_console_word_display() {
        let word = ConsoleWord::new("test", 10, 14);
        assert_eq!(format!("{}", word), "test(10,14)");
    }

    #[test]
    fn test_without_special_characters_back() {
        let word = ConsoleWord::new("hello]", 0, 6);
        let trimmed = word.without_special_characters();
        assert_eq!(trimmed.word, "hello");
        assert_eq!(trimmed.start_position, 0);
        assert_eq!(trimmed.end_position, 5);
    }

    #[test]
    fn test_without_special_characters_front() {
        let word = ConsoleWord::new("[hello", 0, 6);
        let trimmed = word.without_special_characters();
        assert_eq!(trimmed.word, "hello");
        assert_eq!(trimmed.start_position, 1);
        assert_eq!(trimmed.end_position, 6);
    }

    #[test]
    fn test_without_special_characters_both() {
        let word = ConsoleWord::new("[hello]", 0, 7);
        let trimmed = word.without_special_characters();
        assert_eq!(trimmed.word, "hello");
        assert_eq!(trimmed.start_position, 1);
        assert_eq!(trimmed.end_position, 6);
    }

    #[test]
    fn test_without_special_characters_comma_dot() {
        let word = ConsoleWord::new(",hello.", 0, 7);
        let trimmed = word.without_special_characters();
        assert_eq!(trimmed.word, "hello");
        assert_eq!(trimmed.start_position, 1);
        assert_eq!(trimmed.end_position, 6);
    }

    #[test]
    fn test_without_special_characters_none() {
        let word = ConsoleWord::new("hello", 0, 5);
        let trimmed = word.without_special_characters();
        assert_eq!(trimmed.word, "hello");
        assert_eq!(trimmed.start_position, 0);
        assert_eq!(trimmed.end_position, 5);
    }

    #[test]
    fn test_without_special_characters_all_special() {
        let word = ConsoleWord::new("[].,", 0, 4);
        let trimmed = word.without_special_characters();
        assert_eq!(trimmed.word, "");
    }

    #[test]
    fn test_get_word_at_position_simple() {
        let text = "hello world";
        let word = get_word_at_position(text, 2).unwrap();
        assert_eq!(word.word, "hello");
        assert_eq!(word.start_position, 0);
    }

    #[test]
    fn test_get_word_at_position_second_word() {
        let text = "hello world";
        let word = get_word_at_position(text, 7).unwrap();
        assert_eq!(word.word, "world");
    }

    #[test]
    fn test_get_word_at_position_empty() {
        assert!(get_word_at_position("", 0).is_none());
    }

    #[test]
    fn test_get_word_at_position_out_of_bounds() {
        assert!(get_word_at_position("hi", 10).is_none());
    }

    #[test]
    fn test_get_word_at_position_whitespace() {
        let text = "  hello  ";
        let word = get_word_at_position(text, 4).unwrap();
        assert_eq!(word.word, "hello");
    }

    #[test]
    fn test_word_with_brackets() {
        let text = "see [main] for details";
        let word = get_word_at_position(text, 5).unwrap();
        let trimmed = word.without_special_characters();
        assert_eq!(trimmed.word, "main");
    }
}
