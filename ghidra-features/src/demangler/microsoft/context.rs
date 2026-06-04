//! Parsing context for Microsoft demangling.
//!
//! Manages backreferences and context stack for demangling.
//! Ported from `MDContext.java`.

/// The type of parsing context.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContextType {
    /// Default context.
    Default,
    /// Modifier context (pointer/reference types).
    Modifier,
    /// Function context.
    Function,
    /// Template context.
    Template,
}

/// A parsing context that tracks backreference names and types.
///
/// Corresponds to Java's `MDContext`.
#[derive(Debug, Clone)]
pub struct DemangleContext {
    /// Context type.
    pub ctx_type: ContextType,
    /// Backreference name stack.
    backref_names: Vec<String>,
    /// Backreference function parameter types.
    backref_fn_params: Vec<usize>,
    /// Backreference template parameter types.
    backref_template_params: Vec<usize>,
}

impl DemangleContext {
    /// Create a new default context.
    pub fn new() -> Self {
        Self {
            ctx_type: ContextType::Default,
            backref_names: Vec::new(),
            backref_fn_params: Vec::new(),
            backref_template_params: Vec::new(),
        }
    }

    /// Create a new context of the specified type, inheriting backreferences
    /// from a parent context.
    pub fn with_type(parent: &DemangleContext, ctx_type: ContextType) -> Self {
        Self {
            ctx_type,
            backref_names: parent.backref_names.clone(),
            backref_fn_params: parent.backref_fn_params.clone(),
            backref_template_params: parent.backref_template_params.clone(),
        }
    }

    /// Add a backreference name.
    pub fn add_backref_name(&mut self, name: String) {
        self.backref_names.push(name);
    }

    /// Get a backreference name by index.
    pub fn get_backref_name(&self, index: usize) -> Result<&str, String> {
        if index >= self.backref_names.len() {
            Err(format!(
                "Backref Names stack violation: index {} >= len {}",
                index,
                self.backref_names.len()
            ))
        } else {
            Ok(&self.backref_names[index])
        }
    }

    /// Add a backreference function parameter type index.
    pub fn add_backref_fn_param(&mut self, type_index: usize) {
        self.backref_fn_params.push(type_index);
    }

    /// Get a backreference function parameter type index.
    pub fn get_backref_fn_param(&self, index: usize) -> Result<usize, String> {
        if index >= self.backref_fn_params.len() {
            Err(format!(
                "Parameter stack violation: index {} >= len {}",
                index,
                self.backref_fn_params.len()
            ))
        } else {
            Ok(self.backref_fn_params[index])
        }
    }

    /// Add a backreference template parameter type index.
    pub fn add_backref_template_param(&mut self, type_index: usize) {
        self.backref_template_params.push(type_index);
    }

    /// Get a backreference template parameter type index.
    pub fn get_backref_template_param(&self, index: usize) -> Result<usize, String> {
        if index >= self.backref_template_params.len() {
            Err(format!(
                "Template parameter stack violation: index {} >= len {}",
                index,
                self.backref_template_params.len()
            ))
        } else {
            Ok(self.backref_template_params[index])
        }
    }
}

impl Default for DemangleContext {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_backref_names() {
        let mut ctx = DemangleContext::new();
        ctx.add_backref_name("foo".to_string());
        ctx.add_backref_name("bar".to_string());

        assert_eq!(ctx.get_backref_name(0).unwrap(), "foo");
        assert_eq!(ctx.get_backref_name(1).unwrap(), "bar");
        assert!(ctx.get_backref_name(2).is_err());
    }

    #[test]
    fn test_context_inheritance() {
        let mut parent = DemangleContext::new();
        parent.add_backref_name("inherited".to_string());

        let child = DemangleContext::with_type(&parent, ContextType::Function);
        assert_eq!(child.get_backref_name(0).unwrap(), "inherited");
        assert_eq!(child.ctx_type, ContextType::Function);
    }

    #[test]
    fn test_backref_fn_params() {
        let mut ctx = DemangleContext::new();
        ctx.add_backref_fn_param(42);
        assert_eq!(ctx.get_backref_fn_param(0).unwrap(), 42);
        assert!(ctx.get_backref_fn_param(1).is_err());
    }
}
