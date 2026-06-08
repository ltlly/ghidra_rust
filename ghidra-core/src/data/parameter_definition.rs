//! Parameter definitions for function signatures.
//!
//! Port of Ghidra's `ParameterDefinition.java` and `ParameterDefinitionImpl.java`.

use std::fmt;
use std::sync::Arc;

use super::types::DataType;

/// Sentinel value indicating that a parameter ordinal has not been assigned.
pub const UNASSIGNED_ORDINAL: usize = usize::MAX;

// ============================================================================
// ParameterDefinition (trait)
// ============================================================================

/// Specifies a parameter which can be used to specify a function definition.
///
/// Port of Ghidra's `ParameterDefinition.java` interface.
pub trait ParameterDefinition: fmt::Debug + fmt::Display + Send + Sync {
    /// Get the parameter ordinal (index within the function signature).
    fn get_ordinal(&self) -> usize;

    /// Get the data type of this parameter.
    fn get_data_type(&self) -> &Arc<dyn DataType>;

    /// Set the data type of this parameter.
    fn set_data_type(&mut self, data_type: Arc<dyn DataType>);

    /// Get the name of this parameter.
    fn get_name(&self) -> &str;

    /// Set the name of this parameter.
    fn set_name(&mut self, name: Option<String>);

    /// Get the length of this parameter in bytes.
    fn get_length(&self) -> usize {
        self.get_data_type().get_size()
    }

    /// Get the comment for this parameter.
    fn get_comment(&self) -> Option<&str>;

    /// Set the comment for this parameter.
    fn set_comment(&mut self, comment: Option<String>);

    /// Check if this parameter is equivalent to another by ordinal and data type.
    /// Name is not considered.
    fn is_equivalent(&self, other: &dyn ParameterDefinition) -> bool {
        if self.get_ordinal() != other.get_ordinal() {
            return false;
        }
        self.get_data_type()
            .is_equivalent(other.get_data_type().as_ref())
    }
}

// ============================================================================
// ParameterDefinitionImpl
// ============================================================================

/// A concrete implementation of `ParameterDefinition`.
///
/// Port of Ghidra's `ParameterDefinitionImpl.java`.
#[derive(Debug, Clone)]
pub struct ParameterDefinitionImpl {
    /// The parameter ordinal.
    ordinal: usize,
    /// The parameter name (None if not set).
    name: Option<String>,
    /// The parameter data type.
    data_type: Arc<dyn DataType>,
    /// The parameter comment (None if not set).
    comment: Option<String>,
}

impl ParameterDefinitionImpl {
    /// Create a new parameter definition with an unassigned ordinal.
    pub fn new(
        name: impl Into<String>,
        data_type: Arc<dyn DataType>,
    ) -> Self {
        Self {
            ordinal: UNASSIGNED_ORDINAL,
            name: Some(name.into()),
            data_type,
            comment: None,
        }
    }

    /// Create a new parameter definition with a comment and unassigned ordinal.
    pub fn with_comment(
        name: impl Into<String>,
        data_type: Arc<dyn DataType>,
        comment: impl Into<String>,
    ) -> Self {
        Self {
            ordinal: UNASSIGNED_ORDINAL,
            name: Some(name.into()),
            data_type,
            comment: Some(comment.into()),
        }
    }

    /// Create a new parameter definition with a specific ordinal.
    pub fn with_ordinal(
        name: impl Into<String>,
        data_type: Arc<dyn DataType>,
        ordinal: usize,
    ) -> Self {
        Self {
            ordinal,
            name: Some(name.into()),
            data_type,
            comment: None,
        }
    }

    /// Create a fully specified parameter definition.
    pub fn full(
        name: impl Into<String>,
        data_type: Arc<dyn DataType>,
        ordinal: usize,
        comment: Option<String>,
    ) -> Self {
        Self {
            ordinal,
            name: Some(name.into()),
            data_type,
            comment,
        }
    }

    /// Check if the ordinal has been assigned.
    pub fn is_assigned(&self) -> bool {
        self.ordinal != UNASSIGNED_ORDINAL
    }
}

impl ParameterDefinition for ParameterDefinitionImpl {
    fn get_ordinal(&self) -> usize {
        self.ordinal
    }

    fn get_data_type(&self) -> &Arc<dyn DataType> {
        &self.data_type
    }

    fn set_data_type(&mut self, data_type: Arc<dyn DataType>) {
        self.data_type = data_type;
    }

    fn get_name(&self) -> &str {
        self.name.as_deref().unwrap_or("")
    }

    fn set_name(&mut self, name: Option<String>) {
        self.name = name;
    }

    fn get_length(&self) -> usize {
        self.data_type.get_size()
    }

    fn get_comment(&self) -> Option<&str> {
        self.comment.as_deref()
    }

    fn set_comment(&mut self, comment: Option<String>) {
        self.comment = comment;
    }
}

impl fmt::Display for ParameterDefinitionImpl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = self.get_name();
        if name.is_empty() {
            write!(f, "{}", self.data_type.name())
        } else {
            write!(f, "{} {}", self.data_type.name(), name)
        }
    }
}

impl PartialEq for ParameterDefinitionImpl {
    fn eq(&self, other: &Self) -> bool {
        self.ordinal == other.ordinal
            && self.name == other.name
            && self.data_type.is_equivalent(other.data_type.as_ref())
    }
}

impl Eq for ParameterDefinitionImpl {}

impl PartialOrd for ParameterDefinitionImpl {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ParameterDefinitionImpl {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.ordinal.cmp(&other.ordinal)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data::builtin_types::*;

    #[test]
    fn test_parameter_new() {
        let dt: Arc<dyn DataType> = Arc::new(IntegerDataType::new());
        let param = ParameterDefinitionImpl::new("x", dt);
        assert_eq!(param.get_name(), "x");
        assert_eq!(param.get_length(), 4);
        assert!(!param.is_assigned());
    }

    #[test]
    fn test_parameter_with_comment() {
        let dt: Arc<dyn DataType> = Arc::new(IntegerDataType::new());
        let param = ParameterDefinitionImpl::with_comment("x", dt, "the x value");
        assert_eq!(param.get_comment(), Some("the x value"));
    }

    #[test]
    fn test_parameter_with_ordinal() {
        let dt: Arc<dyn DataType> = Arc::new(IntegerDataType::new());
        let param = ParameterDefinitionImpl::with_ordinal("x", dt, 3);
        assert_eq!(param.get_ordinal(), 3);
        assert!(param.is_assigned());
    }

    #[test]
    fn test_parameter_set_name() {
        let dt: Arc<dyn DataType> = Arc::new(IntegerDataType::new());
        let mut param = ParameterDefinitionImpl::new("x", dt);
        assert_eq!(param.get_name(), "x");
        param.set_name(None);
        assert_eq!(param.get_name(), "");
        param.set_name(Some("y".into()));
        assert_eq!(param.get_name(), "y");
    }

    #[test]
    fn test_parameter_set_data_type() {
        let dt1: Arc<dyn DataType> = Arc::new(IntegerDataType::new());
        let dt2: Arc<dyn DataType> = Arc::new(LongLongDataType::new());
        let mut param = ParameterDefinitionImpl::new("x", dt1);
        assert_eq!(param.get_length(), 4);
        param.set_data_type(dt2);
        assert_eq!(param.get_length(), 8);
    }

    #[test]
    fn test_parameter_set_comment() {
        let dt: Arc<dyn DataType> = Arc::new(IntegerDataType::new());
        let mut param = ParameterDefinitionImpl::new("x", dt);
        assert!(param.get_comment().is_none());
        param.set_comment(Some("a comment".into()));
        assert_eq!(param.get_comment(), Some("a comment"));
        param.set_comment(None);
        assert!(param.get_comment().is_none());
    }

    #[test]
    fn test_parameter_display() {
        let dt: Arc<dyn DataType> = Arc::new(IntegerDataType::new());
        let param = ParameterDefinitionImpl::new("x", dt);
        assert_eq!(format!("{}", param), "int x");

        let dt2: Arc<dyn DataType> = Arc::new(IntegerDataType::new());
        let param2 = ParameterDefinitionImpl::with_ordinal("", dt2, 0);
        assert_eq!(format!("{}", param2), "int");
    }

    #[test]
    fn test_parameter_equivalence() {
        let dt1: Arc<dyn DataType> = Arc::new(IntegerDataType::new());
        let dt2: Arc<dyn DataType> = Arc::new(IntegerDataType::new());
        let p1 = ParameterDefinitionImpl::with_ordinal("a", dt1, 0);
        let p2 = ParameterDefinitionImpl::with_ordinal("b", dt2, 0);
        assert!(p1.is_equivalent(&p2)); // same ordinal and equivalent types
    }

    #[test]
    fn test_parameter_not_equivalent_different_ordinal() {
        let dt1: Arc<dyn DataType> = Arc::new(IntegerDataType::new());
        let dt2: Arc<dyn DataType> = Arc::new(IntegerDataType::new());
        let p1 = ParameterDefinitionImpl::with_ordinal("a", dt1, 0);
        let p2 = ParameterDefinitionImpl::with_ordinal("a", dt2, 1);
        assert!(!p1.is_equivalent(&p2));
    }

    #[test]
    fn test_parameter_ordering() {
        let dt: Arc<dyn DataType> = Arc::new(IntegerDataType::new());
        let p0 = ParameterDefinitionImpl::with_ordinal("a", dt.clone(), 0);
        let p1 = ParameterDefinitionImpl::with_ordinal("b", dt.clone(), 1);
        assert!(p0 < p1);
    }

    #[test]
    fn test_parameter_equality() {
        let dt: Arc<dyn DataType> = Arc::new(IntegerDataType::new());
        let p1 = ParameterDefinitionImpl::with_ordinal("a", dt.clone(), 0);
        let p2 = ParameterDefinitionImpl::with_ordinal("a", dt.clone(), 0);
        assert_eq!(p1, p2);
    }
}
