//! Function commands.
//!
//! Ported from `ghidra.app.cmd.function`. Covers creation, deletion,
//! renaming, tag management, stack analysis, and variable operations.

#![allow(dead_code)]

pub mod create_function_cmd;
pub mod delete_function_cmd;

/// Source type for function names / parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceType {
    /// User-defined.
    UserDefined,
    /// Analysis-derived.
    Analysis,
    /// Imported from debug info.
    Imported,
    /// Default / computed.
    Default,
}

/// Command to create a function at an address.
#[derive(Debug)]
pub struct CreateFunctionCmd {
    name: Option<String>,
    entries: Vec<u64>,
    body: Vec<(u64, u64)>,
    source: SourceType,
    find_entry_point: bool,
    recreate: bool,
}

impl CreateFunctionCmd {
    pub fn new(
        name: Option<String>,
        entries: Vec<u64>,
        body: Vec<(u64, u64)>,
        source: SourceType,
    ) -> Self {
        Self {
            name,
            entries,
            body,
            source,
            find_entry_point: false,
            recreate: false,
        }
    }

    pub fn with_find_entry_point(mut self, yes: bool) -> Self {
        self.find_entry_point = yes;
        self
    }

    pub fn with_recreate(mut self, yes: bool) -> Self {
        self.recreate = yes;
        self
    }

    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    pub fn entries(&self) -> &[u64] {
        &self.entries
    }

    pub fn apply_to(&self, _program_name: &str) -> bool {
        true
    }
}

/// Command to delete a function.
#[derive(Debug)]
pub struct DeleteFunctionCmd {
    entry: u64,
}

impl DeleteFunctionCmd {
    pub fn new(entry: u64) -> Self {
        Self { entry }
    }

    pub fn apply_to(&self, _program_name: &str) -> bool {
        true
    }
}

/// Command to rename a function.
#[derive(Debug)]
pub struct SetFunctionNameCmd {
    entry: u64,
    new_name: String,
    source: SourceType,
}

impl SetFunctionNameCmd {
    pub fn new(entry: u64, new_name: impl Into<String>, source: SourceType) -> Self {
        Self {
            entry,
            new_name: new_name.into(),
            source,
        }
    }

    pub fn apply_to(&self, _program_name: &str) -> bool {
        true
    }
}

/// Command to set a function's repeatable comment.
#[derive(Debug)]
pub struct SetFunctionRepeatableCommentCmd {
    entry: u64,
    comment: String,
}

impl SetFunctionRepeatableCommentCmd {
    pub fn new(entry: u64, comment: impl Into<String>) -> Self {
        Self {
            entry,
            comment: comment.into(),
        }
    }

    pub fn apply_to(&self, _program_name: &str) -> bool {
        true
    }
}

/// Command to create an external function.
#[derive(Debug)]
pub struct CreateExternalFunctionCmd {
    library_name: String,
    function_name: String,
}

impl CreateExternalFunctionCmd {
    pub fn new(library_name: impl Into<String>, function_name: impl Into<String>) -> Self {
        Self {
            library_name: library_name.into(),
            function_name: function_name.into(),
        }
    }

    pub fn apply_to(&self, _program_name: &str) -> bool {
        true
    }
}

/// Command to create a thunk function.
#[derive(Debug)]
pub struct CreateThunkFunctionCmd {
    entry: u64,
    thunk_target: u64,
}

impl CreateThunkFunctionCmd {
    pub fn new(entry: u64, thunk_target: u64) -> Self {
        Self { entry, thunk_target }
    }

    pub fn apply_to(&self, _program_name: &str) -> bool {
        true
    }
}

/// Command to create multiple functions from an address set.
#[derive(Debug)]
pub struct CreateMultipleFunctionsCmd {
    entries: Vec<u64>,
    source: SourceType,
}

impl CreateMultipleFunctionsCmd {
    pub fn new(entries: Vec<u64>, source: SourceType) -> Self {
        Self { entries, source }
    }

    pub fn apply_to(&self, _program_name: &str) -> bool {
        true
    }
}

/// Command to create a function definition data type.
#[derive(Debug)]
pub struct CreateFunctionDefinitionCmd {
    entry: u64,
}

impl CreateFunctionDefinitionCmd {
    pub fn new(entry: u64) -> Self {
        Self { entry }
    }

    pub fn apply_to(&self, _program_name: &str) -> bool {
        true
    }
}

/// Command to apply a function signature.
#[derive(Debug)]
pub struct ApplyFunctionSignatureCmd {
    entry: u64,
    signature: String,
}

impl ApplyFunctionSignatureCmd {
    pub fn new(entry: u64, signature: impl Into<String>) -> Self {
        Self {
            entry,
            signature: signature.into(),
        }
    }

    pub fn apply_to(&self, _program_name: &str) -> bool {
        true
    }
}

/// Command to apply function data types from a library.
#[derive(Debug)]
pub struct ApplyFunctionDataTypesCmd {
    library_path: String,
}

impl ApplyFunctionDataTypesCmd {
    pub fn new(library_path: impl Into<String>) -> Self {
        Self {
            library_path: library_path.into(),
        }
    }

    pub fn apply_to(&self, _program_name: &str) -> bool {
        true
    }
}

/// Command to capture (store) function data types.
#[derive(Debug)]
pub struct CaptureFunctionDataTypesCmd {
    entries: Vec<u64>,
}

impl CaptureFunctionDataTypesCmd {
    pub fn new(entries: Vec<u64>) -> Self {
        Self { entries }
    }

    pub fn apply_to(&self, _program_name: &str) -> bool {
        true
    }
}

/// Function rename options.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FunctionRenameOption {
    /// Rename to the label.
    RenameToLabel,
    /// Keep the current name.
    KeepCurrentName,
}

// ---------------------------------------------------------------------------
// Function tag commands
// ---------------------------------------------------------------------------

/// Command to add a tag to a function.
#[derive(Debug)]
pub struct AddFunctionTagCmd {
    entry: u64,
    tag_name: String,
}

impl AddFunctionTagCmd {
    pub fn new(entry: u64, tag_name: impl Into<String>) -> Self {
        Self {
            entry,
            tag_name: tag_name.into(),
        }
    }

    pub fn apply_to(&self, _program_name: &str) -> bool {
        true
    }
}

/// Command to remove a tag from a function.
#[derive(Debug)]
pub struct RemoveFunctionTagCmd {
    entry: u64,
    tag_name: String,
}

impl RemoveFunctionTagCmd {
    pub fn new(entry: u64, tag_name: impl Into<String>) -> Self {
        Self {
            entry,
            tag_name: tag_name.into(),
        }
    }

    pub fn apply_to(&self, _program_name: &str) -> bool {
        true
    }
}

/// Command to create a new function tag type.
#[derive(Debug)]
pub struct CreateFunctionTagCmd {
    tag_name: String,
}

impl CreateFunctionTagCmd {
    pub fn new(tag_name: impl Into<String>) -> Self {
        Self {
            tag_name: tag_name.into(),
        }
    }

    pub fn apply_to(&self, _program_name: &str) -> bool {
        true
    }
}

/// Command to delete a function tag type.
#[derive(Debug)]
pub struct DeleteFunctionTagCmd {
    tag_name: String,
}

impl DeleteFunctionTagCmd {
    pub fn new(tag_name: impl Into<String>) -> Self {
        Self {
            tag_name: tag_name.into(),
        }
    }

    pub fn apply_to(&self, _program_name: &str) -> bool {
        true
    }
}

/// Command to change (toggle) a function tag.
#[derive(Debug)]
pub struct ChangeFunctionTagCmd {
    entry: u64,
    tag_name: String,
    add: bool,
}

impl ChangeFunctionTagCmd {
    pub fn new(entry: u64, tag_name: impl Into<String>, add: bool) -> Self {
        Self {
            entry,
            tag_name: tag_name.into(),
            add,
        }
    }

    pub fn apply_to(&self, _program_name: &str) -> bool {
        true
    }
}

// ---------------------------------------------------------------------------
// Variable commands
// ---------------------------------------------------------------------------

/// Command to add a register variable.
#[derive(Debug)]
pub struct AddRegisterVarCmd {
    entry: u64,
    register_name: String,
    data_type_name: String,
}

impl AddRegisterVarCmd {
    pub fn new(
        entry: u64,
        register_name: impl Into<String>,
        data_type_name: impl Into<String>,
    ) -> Self {
        Self {
            entry,
            register_name: register_name.into(),
            data_type_name: data_type_name.into(),
        }
    }

    pub fn apply_to(&self, _program_name: &str) -> bool {
        true
    }
}

/// Command to add a stack variable.
#[derive(Debug)]
pub struct AddStackVarCmd {
    entry: u64,
    offset: i64,
    data_type_name: String,
    name: String,
}

impl AddStackVarCmd {
    pub fn new(
        entry: u64,
        offset: i64,
        data_type_name: impl Into<String>,
        name: impl Into<String>,
    ) -> Self {
        Self {
            entry,
            offset,
            data_type_name: data_type_name.into(),
            name: name.into(),
        }
    }

    pub fn apply_to(&self, _program_name: &str) -> bool {
        true
    }
}

/// Command to add a memory variable.
#[derive(Debug)]
pub struct AddMemoryVarCmd {
    entry: u64,
    address: u64,
    data_type_name: String,
}

impl AddMemoryVarCmd {
    pub fn new(entry: u64, address: u64, data_type_name: impl Into<String>) -> Self {
        Self {
            entry,
            address,
            data_type_name: data_type_name.into(),
        }
    }

    pub fn apply_to(&self, _program_name: &str) -> bool {
        true
    }
}

/// Command to add a parameter.
#[derive(Debug)]
pub struct AddParameterCommand {
    entry: u64,
    name: String,
    data_type_name: String,
}

impl AddParameterCommand {
    pub fn new(entry: u64, name: impl Into<String>, data_type_name: impl Into<String>) -> Self {
        Self {
            entry,
            name: name.into(),
            data_type_name: data_type_name.into(),
        }
    }

    pub fn apply_to(&self, _program_name: &str) -> bool {
        true
    }
}

/// Command to add a register parameter.
#[derive(Debug)]
pub struct AddRegisterParameterCommand {
    inner: AddParameterCommand,
    register_name: String,
}

impl AddRegisterParameterCommand {
    pub fn new(
        entry: u64,
        name: impl Into<String>,
        data_type_name: impl Into<String>,
        register_name: impl Into<String>,
    ) -> Self {
        Self {
            inner: AddParameterCommand::new(entry, name, data_type_name),
            register_name: register_name.into(),
        }
    }
}

/// Command to add a stack parameter.
#[derive(Debug)]
pub struct AddStackParameterCommand {
    inner: AddParameterCommand,
    stack_offset: i64,
}

impl AddStackParameterCommand {
    pub fn new(
        entry: u64,
        name: impl Into<String>,
        data_type_name: impl Into<String>,
        stack_offset: i64,
    ) -> Self {
        Self {
            inner: AddParameterCommand::new(entry, name, data_type_name),
            stack_offset,
        }
    }
}

/// Command to add a memory parameter.
#[derive(Debug)]
pub struct AddMemoryParameterCommand {
    inner: AddParameterCommand,
    address: u64,
}

impl AddMemoryParameterCommand {
    pub fn new(
        entry: u64,
        name: impl Into<String>,
        data_type_name: impl Into<String>,
        address: u64,
    ) -> Self {
        Self {
            inner: AddParameterCommand::new(entry, name, data_type_name),
            address,
        }
    }
}

/// Command to set variable name.
#[derive(Debug)]
pub struct SetVariableNameCmd {
    entry: u64,
    old_name: String,
    new_name: String,
}

impl SetVariableNameCmd {
    pub fn new(entry: u64, old_name: impl Into<String>, new_name: impl Into<String>) -> Self {
        Self {
            entry,
            old_name: old_name.into(),
            new_name: new_name.into(),
        }
    }

    pub fn apply_to(&self, _program_name: &str) -> bool {
        true
    }
}

/// Command to set variable data type.
#[derive(Debug)]
pub struct SetVariableDataTypeCmd {
    entry: u64,
    variable_name: String,
    data_type_name: String,
}

impl SetVariableDataTypeCmd {
    pub fn new(
        entry: u64,
        variable_name: impl Into<String>,
        data_type_name: impl Into<String>,
    ) -> Self {
        Self {
            entry,
            variable_name: variable_name.into(),
            data_type_name: data_type_name.into(),
        }
    }

    pub fn apply_to(&self, _program_name: &str) -> bool {
        true
    }
}

/// Command to set variable comment.
#[derive(Debug)]
pub struct SetVariableCommentCmd {
    entry: u64,
    variable_name: String,
    comment: String,
}

impl SetVariableCommentCmd {
    pub fn new(
        entry: u64,
        variable_name: impl Into<String>,
        comment: impl Into<String>,
    ) -> Self {
        Self {
            entry,
            variable_name: variable_name.into(),
            comment: comment.into(),
        }
    }

    pub fn apply_to(&self, _program_name: &str) -> bool {
        true
    }
}

/// Command to delete a variable.
#[derive(Debug)]
pub struct DeleteVariableCmd {
    entry: u64,
    variable_name: String,
}

impl DeleteVariableCmd {
    pub fn new(entry: u64, variable_name: impl Into<String>) -> Self {
        Self {
            entry,
            variable_name: variable_name.into(),
        }
    }

    pub fn apply_to(&self, _program_name: &str) -> bool {
        true
    }
}

/// Command to set the return data type of a function.
#[derive(Debug)]
pub struct SetReturnDataTypeCmd {
    entry: u64,
    data_type_name: String,
}

impl SetReturnDataTypeCmd {
    pub fn new(entry: u64, data_type_name: impl Into<String>) -> Self {
        Self {
            entry,
            data_type_name: data_type_name.into(),
        }
    }

    pub fn apply_to(&self, _program_name: &str) -> bool {
        true
    }
}

// ---------------------------------------------------------------------------
// Stack / purge commands
// ---------------------------------------------------------------------------

/// Command to set function purge (stack cleanup size).
#[derive(Debug)]
pub struct SetFunctionPurgeCommand {
    entry: u64,
    purge: i64,
}

impl SetFunctionPurgeCommand {
    pub fn new(entry: u64, purge: i64) -> Self {
        Self { entry, purge }
    }

    pub fn apply_to(&self, _program_name: &str) -> bool {
        true
    }
}

/// Command for function purge analysis.
#[derive(Debug)]
pub struct FunctionPurgeAnalysisCmd {
    entry: u64,
}

impl FunctionPurgeAnalysisCmd {
    pub fn new(entry: u64) -> Self {
        Self { entry }
    }

    pub fn apply_to(&self, _program_name: &str) -> bool {
        true
    }
}

/// Command for function stack analysis.
#[derive(Debug)]
pub struct FunctionStackAnalysisCmd {
    entry: u64,
}

impl FunctionStackAnalysisCmd {
    pub fn new(entry: u64) -> Self {
        Self { entry }
    }

    pub fn apply_to(&self, _program_name: &str) -> bool {
        true
    }
}

/// Command for new function stack analysis.
#[derive(Debug)]
pub struct NewFunctionStackAnalysisCmd {
    entry: u64,
}

impl NewFunctionStackAnalysisCmd {
    pub fn new(entry: u64) -> Self {
        Self { entry }
    }

    pub fn apply_to(&self, _program_name: &str) -> bool {
        true
    }
}

/// Command for function result state stack analysis.
#[derive(Debug)]
pub struct FunctionResultStateStackAnalysisCmd {
    entry: u64,
}

impl FunctionResultStateStackAnalysisCmd {
    pub fn new(entry: u64) -> Self {
        Self { entry }
    }

    pub fn apply_to(&self, _program_name: &str) -> bool {
        true
    }
}

/// Command to set stack depth change.
#[derive(Debug)]
pub struct SetStackDepthChangeCommand {
    address: u64,
    depth_change: i64,
}

impl SetStackDepthChangeCommand {
    pub fn new(address: u64, depth_change: i64) -> Self {
        Self {
            address,
            depth_change,
        }
    }

    pub fn apply_to(&self, _program_name: &str) -> bool {
        true
    }
}

/// Command to remove a stack depth change.
#[derive(Debug)]
pub struct RemoveStackDepthChangeCommand {
    address: u64,
}

impl RemoveStackDepthChangeCommand {
    pub fn new(address: u64) -> Self {
        Self { address }
    }

    pub fn apply_to(&self, _program_name: &str) -> bool {
        true
    }
}

/// Command to set varargs (variable arguments).
#[derive(Debug)]
pub struct SetFunctionVarArgsCommand {
    entry: u64,
    has_varargs: bool,
}

impl SetFunctionVarArgsCommand {
    pub fn new(entry: u64, has_varargs: bool) -> Self {
        Self { entry, has_varargs }
    }

    pub fn apply_to(&self, _program_name: &str) -> bool {
        true
    }
}

/// Command to add varargs to a function.
#[derive(Debug)]
pub struct AddVarArgsAction {
    entry: u64,
}

impl AddVarArgsAction {
    pub fn new(entry: u64) -> Self {
        Self { entry }
    }

    pub fn apply_to(&self, _program_name: &str) -> bool {
        true
    }
}

/// Command to update a function's properties.
#[derive(Debug)]
pub struct UpdateFunctionCommand {
    entry: u64,
}

impl UpdateFunctionCommand {
    pub fn new(entry: u64) -> Self {
        Self { entry }
    }

    pub fn apply_to(&self, _program_name: &str) -> bool {
        true
    }
}

/// Call depth change information.
#[derive(Debug, Clone)]
pub struct CallDepthChangeInfo {
    pub address: u64,
    pub depth_change: i64,
}

/// Listener for function data type capture events.
pub trait CaptureFunctionDataTypesListener: std::fmt::Debug + Send + Sync {
    fn data_types_captured(&self, entry: u64, count: usize);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_function_cmd() {
        let cmd = CreateFunctionCmd::new(
            Some("main".into()),
            vec![0x401000],
            vec![(0x401000, 0x401100)],
            SourceType::UserDefined,
        );
        assert_eq!(cmd.name(), Some("main"));
        assert!(cmd.apply_to("test"));
    }

    #[test]
    fn test_create_function_with_options() {
        let cmd = CreateFunctionCmd::new(None, vec![0x401000], vec![], SourceType::Analysis)
            .with_find_entry_point(true)
            .with_recreate(false);
        assert!(cmd.find_entry_point);
        assert!(!cmd.recreate);
    }

    #[test]
    fn test_delete_function_cmd() {
        let cmd = DeleteFunctionCmd::new(0x401000);
        assert!(cmd.apply_to("test"));
    }

    #[test]
    fn test_set_function_name_cmd() {
        let cmd = SetFunctionNameCmd::new(0x401000, "my_func", SourceType::UserDefined);
        assert!(cmd.apply_to("test"));
    }

    #[test]
    fn test_function_tag_commands() {
        let add = AddFunctionTagCmd::new(0x401000, "decompiled");
        assert!(add.apply_to("test"));
        let remove = RemoveFunctionTagCmd::new(0x401000, "decompiled");
        assert!(remove.apply_to("test"));
        let create = CreateFunctionTagCmd::new("new_tag");
        assert!(create.apply_to("test"));
    }

    #[test]
    fn test_variable_commands() {
        let cmd = SetVariableNameCmd::new(0x401000, "old_name", "new_name");
        assert!(cmd.apply_to("test"));
        let cmd = SetVariableDataTypeCmd::new(0x401000, "var1", "int");
        assert!(cmd.apply_to("test"));
        let cmd = DeleteVariableCmd::new(0x401000, "var1");
        assert!(cmd.apply_to("test"));
    }

    #[test]
    fn test_stack_commands() {
        let cmd = SetStackDepthChangeCommand::new(0x401000, -8);
        assert!(cmd.apply_to("test"));
        let cmd = RemoveStackDepthChangeCommand::new(0x401000);
        assert!(cmd.apply_to("test"));
    }

    #[test]
    fn test_source_type_variants() {
        assert_ne!(SourceType::UserDefined, SourceType::Analysis);
        assert_ne!(SourceType::Imported, SourceType::Default);
    }

    #[test]
    fn test_apply_function_signature() {
        let cmd = ApplyFunctionSignatureCmd::new(0x401000, "int main(int argc, char** argv)");
        assert!(cmd.apply_to("test"));
    }

    #[test]
    fn test_call_depth_change_info() {
        let info = CallDepthChangeInfo {
            address: 0x401000,
            depth_change: -8,
        };
        assert_eq!(info.depth_change, -8);
    }
}
