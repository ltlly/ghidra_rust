//! Search formats -- parsers for different input representations.
//!
//! Ported from `ghidra.features.base.memsearch.format`.
//!
//! Each [`SearchFormat`] can parse user input text into a [`ByteMatcher`](crate::memsearch::matcher::ByteMatcher)
//! and convert match bytes back to display strings.

mod search_format;
mod hex;
mod binary;
mod decimal;
mod string_fmt;
mod regex_fmt;
mod float;
mod number_parse_result;

pub use search_format::{SearchFormat, SearchFormatType};
pub use hex::HexSearchFormat;
pub use binary::BinarySearchFormat;
pub use decimal::DecimalSearchFormat;
pub use string_fmt::StringSearchFormat;
pub use regex_fmt::RegExSearchFormat;
pub use float::FloatSearchFormat;
pub use number_parse_result::NumberParseResult;
