//! ThemeValueUtils: utility functions for parsing theme value strings.
//!
//! Ported from `generic.theme.ThemeValueUtils`.

/// Parse a source string into groups delimited by `start_char` and `end_char`.
///
/// For example, `"(ab (cd))(ef)((gh))"` with parens produces: `["ab (cd)", "ef", "(gh)"]`.
pub fn parse_groupings(source: &str, start_char: char, end_char: char) -> Result<Vec<String>, String> {
    let mut results = Vec::new();
    let chars: Vec<char> = source.chars().collect();
    let mut index = 0;

    while index < chars.len() {
        let group_start = match find_next_non_whitespace(&chars, index) {
            Some(i) => i,
            None => break,
        };
        if chars[group_start] != start_char {
            return Err(format!("Expected '{}' at position {}", start_char, group_start));
        }
        let group_end = match find_matching_end(&chars, group_start + 1, start_char, end_char) {
            Some(i) => i,
            None => return Err(format!("Unmatched '{}' at position {}", start_char, group_start)),
        };
        let inner: String = chars[group_start + 1..group_end].iter().collect();
        results.push(inner);
        index = group_end + 1;
    }
    Ok(results)
}

fn find_matching_end(chars: &[char], start: usize, open: char, close: char) -> Option<usize> {
    let mut level = 0usize;
    for i in start..chars.len() {
        if chars[i] == open { level += 1; }
        else if chars[i] == close {
            if level == 0 { return Some(i); }
            level -= 1;
        }
    }
    None
}

fn find_next_non_whitespace(chars: &[char], start: usize) -> Option<usize> {
    (start..chars.len()).find(|&i| !chars[i].is_whitespace())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_simple_groups() {
        let r = parse_groupings("(ab)(cd)", '(', ')').unwrap();
        assert_eq!(r, vec!["ab", "cd"]);
    }

    #[test]
    fn parse_nested_groups() {
        let r = parse_groupings("(ab (cd))(ef)((gh))", '(', ')').unwrap();
        assert_eq!(r, vec!["ab (cd)", "ef", "(gh)"]);
    }

    #[test]
    fn parse_empty() {
        let r = parse_groupings("", '(', ')').unwrap();
        assert!(r.is_empty());
    }

    #[test]
    fn parse_unmatched() {
        assert!(parse_groupings("(abc", '(', ')').is_err());
    }
}
