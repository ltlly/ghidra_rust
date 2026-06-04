//! Error and exception types for the assembler framework.
//!
//! Corresponds to Java's `AssemblyError`, `AssemblyException`,
//! `AssemblySyntaxException`, `AssemblySemanticException`, and
//! `AssemblySelectionError`.

use std::fmt;

// ---------------------------------------------------------------------------
// AssemblyError  (programmer error -- analogous to Java RuntimeException)
// ---------------------------------------------------------------------------

/// An exception for programmer errors regarding an assembler.
///
/// This corresponds to a bug in the assembler implementation or
/// misuse of the API (e.g., passing an incomplete context mask).
#[derive(Debug, Clone)]
pub struct AssemblyError(pub String);

impl fmt::Display for AssemblyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Assembly error: {}", self.0)
    }
}

impl std::error::Error for AssemblyError {}

// ---------------------------------------------------------------------------
// AssemblySelectionError  (subclass of AssemblyError)
// ---------------------------------------------------------------------------

/// Thrown when a programmer selects an improper instruction during assembly.
///
/// This is a specialisation of [`AssemblyError`] that indicates the
/// [`AssemblySelector`](crate::base::assembler::AssemblySelector) chose
/// an invalid or incompatible instruction from the set of candidates.
#[derive(Debug, Clone)]
pub struct AssemblySelectionError(pub String);

impl fmt::Display for AssemblySelectionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Assembly selection error: {}", self.0)
    }
}

impl std::error::Error for AssemblySelectionError {}

// ---------------------------------------------------------------------------
// AssemblySyntaxException
// ---------------------------------------------------------------------------

/// A textual assembly instruction is not well-formed.
///
/// This exception is thrown during parsing when the mnemonic or operand
/// syntax does not match any known grammar rule.  The contained
/// collection of [`AssemblyParseResult`](crate::base::assembler::sleigh::parse::AssemblyParseResult)s
/// may provide partial parse trees and diagnostic messages.
#[derive(Debug, Clone)]
pub struct AssemblySyntaxException {
    message: String,
    errors: Vec<String>,
}

impl AssemblySyntaxException {
    /// Create a new syntax exception with a human-readable message.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            errors: Vec::new(),
        }
    }

    /// Create from a set of parse error descriptions.
    pub fn from_errors(errors: Vec<String>) -> Self {
        let message = if errors.is_empty() {
            "Unknown assembly syntax error".to_string()
        } else {
            format!("{} parse error(s): {}", errors.len(), errors.join("; "))
        };
        Self { message, errors }
    }

    /// Return the collection of error descriptions.
    pub fn errors(&self) -> &[String] {
        &self.errors
    }
}

impl fmt::Display for AssemblySyntaxException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Assembly syntax error: {}", self.message)
    }
}

impl std::error::Error for AssemblySyntaxException {}

// ---------------------------------------------------------------------------
// AssemblySemanticException
// ---------------------------------------------------------------------------

/// A well-formed instruction cannot be assembled (semantic error).
///
/// This exception is thrown when parsing succeeds but resolution
/// produces only erroneous results, e.g., an out-of-range immediate
/// value or an incompatible context register constraint.
#[derive(Debug, Clone)]
pub struct AssemblySemanticException {
    message: String,
    errors: Vec<String>,
}

impl AssemblySemanticException {
    /// Create a new semantic exception with a human-readable message.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            errors: Vec::new(),
        }
    }

    /// Create from a collection of resolved error descriptions.
    pub fn from_errors(errors: Vec<String>) -> Self {
        let message = if errors.is_empty() {
            "Unknown assembly semantic error".to_string()
        } else {
            format!(
                "{} semantic error(s): {}",
                errors.len(),
                errors.join("; ")
            )
        };
        Self { message, errors }
    }

    /// Return the collection of error descriptions.
    pub fn errors(&self) -> &[String] {
        &self.errors
    }
}

impl fmt::Display for AssemblySemanticException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Assembly semantic error: {}", self.message)
    }
}

impl std::error::Error for AssemblySemanticException {}

// ---------------------------------------------------------------------------
// Combined AssemblerResult type alias
// ---------------------------------------------------------------------------

/// A convenience alias for operations that can produce any assembly error.
pub type AssemblerResult<T> = Result<T, AssemblerError>;

/// The umbrella error type encompassing all assembler error variants.
#[derive(Debug, Clone)]
pub enum AssemblerError {
    /// Programmer / API misuse error.
    Error(AssemblyError),
    /// Selection error from the selector.
    Selection(AssemblySelectionError),
    /// Syntax error during parsing.
    Syntax(AssemblySyntaxException),
    /// Semantic error during resolution.
    Semantic(AssemblySemanticException),
    /// Address overflow (the assembled block exceeds the address space).
    AddressOverflow(String),
    /// Memory write failure.
    MemoryAccess(String),
}

impl fmt::Display for AssemblerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Error(e) => write!(f, "{}", e),
            Self::Selection(e) => write!(f, "{}", e),
            Self::Syntax(e) => write!(f, "{}", e),
            Self::Semantic(e) => write!(f, "{}", e),
            Self::AddressOverflow(msg) => write!(f, "Address overflow: {}", msg),
            Self::MemoryAccess(msg) => write!(f, "Memory access error: {}", msg),
        }
    }
}

impl std::error::Error for AssemblerError {}

impl From<AssemblyError> for AssemblerError {
    fn from(e: AssemblyError) -> Self {
        Self::Error(e)
    }
}

impl From<AssemblySelectionError> for AssemblerError {
    fn from(e: AssemblySelectionError) -> Self {
        Self::Selection(e)
    }
}

impl From<AssemblySyntaxException> for AssemblerError {
    fn from(e: AssemblySyntaxException) -> Self {
        Self::Syntax(e)
    }
}

impl From<AssemblySemanticException> for AssemblerError {
    fn from(e: AssemblySemanticException) -> Self {
        Self::Semantic(e)
    }
}
