//! Immutable view of function data for the function editor.
//!
//! Ported from `FunctionDataView.java` in
//! `ghidra.app.plugin.core.function.editor`.
//!
//! Provides a snapshot of function metadata (name, return type,
//! calling convention, parameters, inline/no-return flags) that can
//! be compared against the current state to detect changes.

use super::{ParamInfo, VarnodeInfo, VarnodeType};
use std::fmt;

/// Immutable view of function data used by the function editor model.
///
/// Ported from `FunctionDataView.java`.  This captures a snapshot of a
/// function's metadata at construction time and provides equality
/// comparison for change detection.
///
/// # Example
///
/// ```
/// use ghidra_features::base::function::editor::*;
///
/// let view = FunctionDataView::new(
///     "main",
///     "int",
///     "__cdecl",
///     vec![],
///     ParamInfo::new("ret", "int", VarnodeInfo::register("EAX", 4), -1),
/// );
/// assert_eq!(view.name(), "main");
/// assert!(!view.has_var_args());
/// ```
#[derive(Debug, Clone)]
pub struct FunctionDataView {
    /// The function name.
    name: String,
    /// The calling convention name.
    calling_convention_name: String,
    /// Whether the function uses custom variable storage.
    allow_custom_storage: bool,
    /// Whether the function has varargs.
    has_var_args: bool,
    /// Whether the function is inline.
    is_inline: bool,
    /// Whether the function is no-return.
    has_no_return: bool,
    /// The call fixup name, if any.
    call_fixup_name: Option<String>,
    /// The return parameter info.
    return_info: ParamInfo,
    /// The function parameters (excluding return).
    parameters: Vec<ParamInfo>,
    /// Number of auto-parameters at the beginning of the parameter list.
    auto_param_count: usize,
}

impl FunctionDataView {
    /// Creates a new function data view.
    pub fn new(
        name: impl Into<String>,
        calling_convention: impl Into<String>,
        _cc_name: impl Into<String>,
        parameters: Vec<ParamInfo>,
        return_info: ParamInfo,
    ) -> Self {
        let auto_count = parameters.iter().filter(|p| p.is_forced_indirect()).count();
        Self {
            name: name.into(),
            calling_convention_name: calling_convention.into(),
            allow_custom_storage: false,
            has_var_args: false,
            is_inline: false,
            has_no_return: false,
            call_fixup_name: None,
            return_info,
            parameters,
            auto_param_count: auto_count,
        }
    }

    /// Creates a view from `FunctionData`.
    pub fn from_function_data(
        fd: &super::FunctionData,
    ) -> Self {
        let return_var = fd.parameters().iter().find(|p| p.is_return());
        let return_info = match return_var {
            Some(rv) => ParamInfo::new(
                rv.name().unwrap_or("ret"),
                rv.data_type_name(),
                rv.storage().clone(),
                -1,
            ),
            None => ParamInfo::new("ret", fd.return_type(), VarnodeInfo::register("EAX", 4), -1),
        };

        let params: Vec<ParamInfo> = fd
            .parameters()
            .iter()
            .filter(|p| !p.is_return())
            .enumerate()
            .map(|(i, p)| {
                ParamInfo::new(
                    p.name().unwrap_or(&format!("param_{}", i)),
                    p.data_type_name(),
                    p.storage().clone(),
                    i as i32,
                )
            })
            .collect();

        let auto_count = params.iter().filter(|p| p.is_forced_indirect()).count();

        Self {
            name: fd.name().to_string(),
            calling_convention_name: fd.calling_convention().to_string(),
            allow_custom_storage: fd.is_custom_storage(),
            has_var_args: fd.has_var_args(),
            is_inline: fd.is_inline(),
            has_no_return: fd.is_no_return(),
            call_fixup_name: fd.call_fixup().map(|s| s.to_string()),
            return_info,
            parameters: params,
            auto_param_count: auto_count,
        }
    }

    /// Returns the function name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns a display name (uses "FUN_<addr>" if empty).
    pub fn display_name(&self) -> &str {
        if self.name.is_empty() {
            "FUN_00000000"
        } else {
            &self.name
        }
    }

    /// Returns the calling convention name.
    pub fn calling_convention_name(&self) -> &str {
        &self.calling_convention_name
    }

    /// Whether the function uses custom variable storage.
    pub fn can_customize_storage(&self) -> bool {
        self.allow_custom_storage
    }

    /// Whether the function has varargs.
    pub fn has_var_args(&self) -> bool {
        self.has_var_args
    }

    /// Whether the function is inline.
    pub fn is_inline(&self) -> bool {
        self.is_inline
    }

    /// Whether the function is no-return.
    pub fn has_no_return(&self) -> bool {
        self.has_no_return
    }

    /// Returns the call fixup name.
    pub fn call_fixup_name(&self) -> Option<&str> {
        self.call_fixup_name.as_deref()
    }

    /// Whether the function has a call fixup.
    pub fn has_call_fixup(&self) -> bool {
        self.call_fixup_name.is_some()
    }

    /// Returns the return parameter info.
    pub fn return_info(&self) -> &ParamInfo {
        &self.return_info
    }

    /// Returns the function parameters.
    pub fn parameters(&self) -> &[ParamInfo] {
        &self.parameters
    }

    /// Returns the auto-parameter count.
    pub fn auto_param_count(&self) -> usize {
        self.auto_param_count
    }

    /// Returns the total parameter count (including auto-params).
    pub fn param_count(&self) -> usize {
        self.parameters.len()
    }

    /// Whether the function has any parameters.
    pub fn has_parameters(&self) -> bool {
        !self.parameters.is_empty()
    }

    /// Generates the function signature text representation.
    ///
    /// This mirrors the Java `getFunctionSignatureText()` method.
    pub fn function_signature_text(&self) -> String {
        let mut buf = String::new();
        buf.push_str(self.return_info.formal_data_type());
        buf.push(' ');
        buf.push_str(self.display_name());
        buf.push('(');

        let mut ordinal = 0;
        let mut skip = self.auto_param_count;
        for param in &self.parameters {
            if skip > 0 {
                skip -= 1;
                continue;
            }
            if ordinal != 0 {
                buf.push_str(", ");
            }
            buf.push_str(param.formal_data_type());
            buf.push(' ');
            buf.push_str(&param.name());
            ordinal += 1;
        }

        if self.has_var_args {
            if !self.parameters.is_empty() {
                buf.push_str(", ");
            }
            buf.push_str("...");
        } else if self.parameters.is_empty() || ordinal == 0 {
            buf.push_str("void");
        }

        buf.push(')');
        buf
    }

    /// Fixes up parameter ordinals to be sequential.
    pub fn fixup_ordinals(&mut self) {
        for (i, param) in self.parameters.iter_mut().enumerate() {
            param.set_ordinal(i as i32);
        }
    }
}

impl PartialEq for FunctionDataView {
    fn eq(&self, other: &Self) -> bool {
        if self.name != other.name
            || self.calling_convention_name != other.calling_convention_name
            || self.has_var_args != other.has_var_args
            || self.parameters.len() != other.parameters.len()
            || self.auto_param_count != other.auto_param_count
            || self.is_inline != other.is_inline
            || self.has_no_return != other.has_no_return
            || self.allow_custom_storage != other.allow_custom_storage
            || self.call_fixup_name != other.call_fixup_name
        {
            return false;
        }

        // Compare return info
        if !self.return_info.is_same(&other.return_info) {
            return false;
        }

        // Compare parameters
        for (a, b) in self.parameters.iter().zip(other.parameters.iter()) {
            if !a.is_same(b) {
                return false;
            }
        }

        true
    }
}

impl Eq for FunctionDataView {}

impl fmt::Display for FunctionDataView {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.function_signature_text())
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn make_return_info() -> ParamInfo {
        ParamInfo::new("ret", "int", VarnodeInfo::register("EAX", 4), -1)
    }

    fn make_param(name: &str, ordinal: i32) -> ParamInfo {
        ParamInfo::new(name, "int", VarnodeInfo::register("EDI", 4), ordinal)
    }

    #[test]
    fn test_function_data_view_basic() {
        let view = FunctionDataView::new("main", "__cdecl", "cdecl", vec![], make_return_info());
        assert_eq!(view.name(), "main");
        assert_eq!(view.calling_convention_name(), "__cdecl");
        assert!(!view.has_var_args());
        assert!(!view.is_inline());
        assert!(!view.has_no_return());
        assert!(!view.has_call_fixup());
    }

    #[test]
    fn test_function_data_view_with_params() {
        let params = vec![make_param("argc", 0), make_param("argv", 1)];
        let view = FunctionDataView::new("main", "__cdecl", "cdecl", params, make_return_info());
        assert_eq!(view.param_count(), 2);
        assert!(view.has_parameters());
        assert_eq!(view.parameters()[0].name(), "argc");
        assert_eq!(view.parameters()[1].name(), "argv");
    }

    #[test]
    fn test_function_data_view_no_params() {
        let view = FunctionDataView::new("func", "default", "default", vec![], make_return_info());
        assert!(!view.has_parameters());
        assert_eq!(view.param_count(), 0);
    }

    #[test]
    fn test_function_data_view_signature_text() {
        let params = vec![make_param("argc", 0), make_param("argv", 1)];
        let view = FunctionDataView::new("main", "__cdecl", "cdecl", params, make_return_info());
        let sig = view.function_signature_text();
        assert!(sig.contains("int"));
        assert!(sig.contains("main"));
        assert!(sig.contains("argc"));
        assert!(sig.contains("argv"));
    }

    #[test]
    fn test_function_data_view_signature_void_params() {
        let view = FunctionDataView::new("func", "default", "default", vec![], make_return_info());
        let sig = view.function_signature_text();
        assert!(sig.contains("void"));
    }

    #[test]
    fn test_function_data_view_signature_varargs() {
        let mut view =
            FunctionDataView::new("printf", "__cdecl", "cdecl", vec![], make_return_info());
        view.has_var_args = true;
        let sig = view.function_signature_text();
        assert!(sig.contains("..."));
    }

    #[test]
    fn test_function_data_view_display_name() {
        let view = FunctionDataView::new("main", "default", "default", vec![], make_return_info());
        assert_eq!(view.display_name(), "main");

        let empty_view =
            FunctionDataView::new("", "default", "default", vec![], make_return_info());
        assert_eq!(empty_view.display_name(), "FUN_00000000");
    }

    #[test]
    fn test_function_data_view_flags() {
        let mut view =
            FunctionDataView::new("func", "default", "default", vec![], make_return_info());
        view.is_inline = true;
        view.has_no_return = true;
        view.has_var_args = true;
        view.call_fixup_name = Some("__x86_return".to_string());

        assert!(view.is_inline());
        assert!(view.has_no_return());
        assert!(view.has_var_args());
        assert!(view.has_call_fixup());
        assert_eq!(view.call_fixup_name(), Some("__x86_return"));
    }

    #[test]
    fn test_function_data_view_equality() {
        let view1 = FunctionDataView::new("main", "__cdecl", "cdecl", vec![], make_return_info());
        let view2 = FunctionDataView::new("main", "__cdecl", "cdecl", vec![], make_return_info());
        assert_eq!(view1, view2);
    }

    #[test]
    fn test_function_data_view_inequality_name() {
        let view1 = FunctionDataView::new("main", "__cdecl", "cdecl", vec![], make_return_info());
        let view2 = FunctionDataView::new("other", "__cdecl", "cdecl", vec![], make_return_info());
        assert_ne!(view1, view2);
    }

    #[test]
    fn test_function_data_view_inequality_params() {
        let view1 = FunctionDataView::new("func", "default", "default", vec![], make_return_info());
        let params = vec![make_param("x", 0)];
        let view2 =
            FunctionDataView::new("func", "default", "default", params, make_return_info());
        assert_ne!(view1, view2);
    }

    #[test]
    fn test_function_data_view_inequality_inline() {
        let mut view1 =
            FunctionDataView::new("func", "default", "default", vec![], make_return_info());
        view1.is_inline = true;
        let view2 = FunctionDataView::new("func", "default", "default", vec![], make_return_info());
        assert_ne!(view1, view2);
    }

    #[test]
    fn test_function_data_view_fixup_ordinals() {
        let mut params = vec![
            ParamInfo::new("a", "int", VarnodeInfo::register("EDI", 4), 5),
            ParamInfo::new("b", "int", VarnodeInfo::register("ESI", 4), 10),
        ];
        let mut view =
            FunctionDataView::new("func", "default", "default", params, make_return_info());
        view.fixup_ordinals();
        assert_eq!(view.parameters()[0].ordinal(), 0);
        assert_eq!(view.parameters()[1].ordinal(), 1);
    }

    #[test]
    fn test_function_data_view_display() {
        let params = vec![make_param("x", 0)];
        let view = FunctionDataView::new("add", "default", "default", params, make_return_info());
        let display = format!("{}", view);
        assert!(display.contains("add"));
        assert!(display.contains("x"));
    }

    #[test]
    fn test_function_data_view_custom_storage() {
        let mut view =
            FunctionDataView::new("func", "default", "default", vec![], make_return_info());
        assert!(!view.can_customize_storage());
        view.allow_custom_storage = true;
        assert!(view.can_customize_storage());
    }

    #[test]
    fn test_function_data_view_auto_param_count() {
        let mut param = make_param("auto", 0);
        param.set_forced_indirect(true);
        let params = vec![param, make_param("manual", 1)];
        let view = FunctionDataView::new("func", "default", "default", params, make_return_info());
        assert_eq!(view.auto_param_count(), 1);
    }

    #[test]
    fn test_function_data_view_signature_with_auto_params() {
        let mut param = make_param("auto", 0);
        param.set_forced_indirect(true);
        let params = vec![param, make_param("argc", 1)];
        let view = FunctionDataView::new("main", "__cdecl", "cdecl", params, make_return_info());
        let sig = view.function_signature_text();
        // Auto params should be skipped in the signature text
        assert!(sig.contains("argc"));
    }
}
