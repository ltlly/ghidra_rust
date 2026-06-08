//! Decompiler UI Plugin -- Rust port of Ghidra's
//! `ghidra.app.plugin.core.decompile` package.
//!
//! Provides the user-facing decompiler panel that produces a high-level C
//! interpretation of assembly functions.  This module models the plugin,
//! provider, controller, action context, clipboard provider, overlay
//! painter, search infrastructure, highlight service, and the set of
//! decompiler actions (rename, retype, commit, search, etc.).
//!
//! # Architecture
//!
//! ```text
//! DecompilePlugin
//!   ├── PrimaryDecompilerProvider (connected)
//!   └── Vec<DecompilerProvider> (disconnected / snapshots)
//!         ├── DecompilerController
//!         │     ├── DecompilerPanel (renders clang tokens)
//!         │     ├── DecompileResultCache
//!         │     └── DecompilerClipboardProvider
//!         ├── DecompilerSearcher
//!         ├── HighlightServiceManager
//!         ├── DisplayTypeCastsAction
//!         └── OverlayMessagePainter
//!
//! Actions
//!   ├── actions.rs          (rename, retype, commit, search, convert, etc.)
//!   ├── graph_actions.rs    (PCode CFG/DFG graph types and actions)
//!   ├── graph_tasks.rs      (PCode CFG/DFG/Combined graph building tasks)
//!   ├── structure_actions.rs (create structure from variable)
//!   └── export_actions.rs   (export to C, debug, clone, properties, slice colors)
//!
//! Validation & Scripting
//!   ├── validator.rs        (post-analysis validators: DecompilerValidator,
//!   │                        DecompilerParameterIDValidator)
//!   ├── flat_api.rs         (FlatDecompilerAPI -- simplified scripting interface)
//!   └── parallel_decompiler.rs (ParallelDecompiler, ChunkingParallelDecompiler,
//!                                DecompilerPool, DecompilerCallback)
//!
//! Margin & Service Infrastructure
//!   ├── decompiler_margin_service.rs (DecompilerMarginService,
//!   │                                  DecompilerMarginProvider trait,
//!   │                                  margin painting and interactions)
//!   ├── decompiler_options_listener.rs (OptionsChangeListener,
//!   │                                    DecompilerOptionsState,
//!   │                                    option sync and refresh modes)
//!   └── decompiler_service_listener.rs (ServiceListener,
//!                                        DecompilerServiceManager,
//!                                        graph broker + hover service tracking)
//! ```

pub mod abstract_action;
pub mod action_context;
pub mod actions;
pub mod callback_handler;
pub mod clipboard_provider;
pub mod convert_constant;
pub mod convert_constant_action;
pub mod controller;
pub mod decomp_interface;
pub mod decompile_exception;
pub mod decompile_process;
pub mod decompiler_location;
pub mod decompiler_manager;
pub mod decompiler_margin_service;
pub mod decompiler_options;
pub mod decompiler_options_listener;
pub mod decompiler_service_listener;
pub mod decompiler_utils;
pub mod display_type_casts;
pub mod export_actions;
pub mod find_dialog;
pub mod flat_api;
pub mod graph_actions;
pub mod graph_tasks;
pub mod highlight;
pub mod highlight_navigation_actions;
pub mod hover_provider;
pub mod label_actions;
pub mod line_number_margin;
pub mod location_memento;
pub mod overlay_painter;
pub mod panel;
pub mod parallel_decompiler;
pub mod pcode_slice_actions;
pub mod plugin;
pub mod pretty_printer;
pub mod primary_provider;
pub mod program_listener;
pub mod provider;
pub mod rename_tasks;
pub mod search;
pub mod secondary_highlight;
pub mod secondary_highlight_actions;
pub mod select_all_action;
pub mod slice_color_provider;
pub mod structure_actions;
pub mod validator;

// Re-export the most important public types at the module root.
pub use action_context::{
    ClangTokenKind, ClangTokenRef, DecompilerActionContext, FunctionRef,
    VariableKind as TokenVariableKind,
};
pub use actions::{
    ActionRegistry, BackwardsSliceAction, CloneDecompilerAction, CommitLocalsAction,
    CommitParamsAction, ConvertBinaryAction, ConvertCharAction, ConvertDecAction,
    ConvertDoubleAction, ConvertFloatAction, ConvertHexAction, ConvertOctAction,
    CreatePointerRelative, DecompilerAction, DecompilerActionResult, DeletePrototypeOverrideAction,
    DialogKind, DialogRequest, EditDataTypeAction, EditFieldAction, EditBitFieldAction,
    EditPrototypeOverrideAction, ExportToCAction, FindAction, FindReferencesToAddressAction,
    FindReferencesToDataTypeAction, FindReferencesToHighSymbolAction, ForceUnionAction,
    ForwardSliceAction, GoToNextBraceAction, GoToPreviousBraceAction,
    HighlightDefinedUseAction, IsolateVariableAction, OverridePrototypeAction,
    RemoveEquateAction, RemoveLabelAction, RenameBitFieldAction, RenameFieldAction,
    RenameFunctionAction, RenameGlobalAction, RenameLocalAction, RetypeFieldAction,
    RetypeGlobalAction, RetypeLocalAction, RetypeReturnAction, SelectAllAction, SetEquateAction,
    SpecifyCPrototypeAction,
};
pub use clipboard_provider::DecompilerClipboardProvider;
pub use controller::{DecompileData, DecompileResults, DecompilerController};
pub use display_type_casts::{DisplayTypeCastsAction, TypeCastOptions};
pub use export_actions::{
    CloneDecompilerAction as ExportCloneAction, DebugDecompilerAction, EditPropertiesAction,
    ExportResult, ExportToCAction as ExportToCFileAction, SliceHighlightColorProvider as ExportSliceHighlightColorProvider,
};
pub use graph_actions::{
    BasicBlockInfo, DfgEdgeType, DfgVertexType, GraphLabelPosition, LayoutAlgorithmName,
    PCodeCfgAction, PCodeCfgDisplayListener, PCodeCfgGraphSubType, PCodeCfgGraphType,
    PCodeDfgAction, PCodeDfgDisplayListener, PCodeDfgDisplayOptions, PCodeDfgGraphType,
    VertexShape,
};
pub use graph_tasks::{
    AttributedGraph, GraphBasicBlock, GraphEdge, GraphPcodeOp, GraphPcodeOpcode, GraphTaskResult,
    GraphVertex, PCodeCfgGraphTask, PCodeCombinedGraphTask, PCodeDfgGraphTask,
    SelectedPCodeDfgGraphTask, VarnodeKind, VarnodeTranslator,
};
pub use highlight::{
    AddressRangeHighlightMatcher, CTokenHighlightMatcher, DecompilerHighlightService,
    HighlightServiceManager, HighlighterRecord, TextHighlightMatcher,
};
pub use location_memento::DecompilerLocationMemento;
pub use overlay_painter::OverlayMessagePainter;
pub use panel::{
    DecompiledFunction, DecompiledLine, DecompiledToken, DecompiledTokenType, DecompilerPanel,
};
pub use plugin::{
    DecompilePlugin, DelayedLocationUpdater, FiredPluginEvent, HoverServiceId, PluginEvent,
    SaveState, ServiceRegistration,
};
pub use primary_provider::PrimaryDecompilerProvider;
pub use provider::{
    ActionGroupInfo, ControllerSummary, CursorLocation, DecompilerPanelSummary, DecompilerProvider,
    DisplayLockState, GraphServiceState, NavigationTarget as ProviderNavigationTarget, ProviderState, ToggleButtonState,
    ViewerPosition,
};
pub use search::{
    DecompilerCursorPosition, DecompilerSearchLocation, DecompilerSearchResults,
    DecompilerSearcher,
};
pub use structure_actions::{
    CreateStructureVariableAction, DecompilerStructureVariableAction, ListingLocationKind,
    ListingStructureVariableAction, StructureCreationInfo, VariableKind,
};
pub use highlight_navigation_actions::{
    HighlightNavigationAction, NextHighlightedTokenAction, PreviousHighlightedTokenAction,
    TokenHighlight,
};
pub use secondary_highlight_actions::{
    RemoveAllSecondaryHighlightsAction, RemoveSecondaryHighlightAction,
    SecondaryHighlightColor, SecondaryHighlightStore, SetSecondaryHighlightAction,
    SetSecondaryHighlightColorChooserAction,
};
pub use convert_constant_action::{
    ConvertBinaryAction as ConvertBinaryConstAction, ConvertCharAction as ConvertCharConstAction,
    ConvertConstantAction as ConvertConstantActionTrait, ConvertConstantEquateTask,
    ConvertDecAction as ConvertDecConstAction, ConvertDoubleAction as ConvertDoubleConstAction,
    ConvertFloatAction as ConvertFloatConstAction, ConvertHexAction as ConvertHexConstAction,
    ConvertOctAction as ConvertOctConstAction, ConvertResult, ConvertTaskOutcome, EquateFormat,
    EquateInfo, EquateReference, NearMatchValues, ScalarInfo, ScalarMatch,
};
pub use decompiler_manager::{
    DecompileCallback, DecompileRequest, DecompilerManager, DecompilerStatus,
    RequestHistoryEntry, UpdateCoalescer,
};
pub use decompiler_utils::{
    ClangLine, HighVariableRef, PcodeOpcode, PcodeOpRef, TokenType, VarnodeRef,
    find_closest_addressed_token, get_backward_slice, get_backward_slice_to_pcode_ops,
    get_closest_address, get_data_type_trace_backward, get_data_type_trace_forward,
    get_forward_slice, get_forward_slice_to_pcode_ops, get_matching_brace, get_next_brace,
    get_tokens_by_addresses, get_tokens_in_range, is_brace, is_goto_statement, to_lines,
};

// -- Re-exports from convert_constant (equates/constant display) --
pub use convert_constant::{
    ConvertConstantAction as ConvertConstantAction2, ConvertConstantEquateTask as ConvertConstantEquateTask2,
    ConvertType, EquateEntry, EquateTable, NearMatchValues as NearMatchValues2, Scalar,
    ScalarMatch as ScalarMatch2, all_convert_actions,
};

// -- Re-exports from pcode_slice_actions (P-code operator slicing) --
pub use pcode_slice_actions::{
    BackwardsSliceToPCodeOpsAction, ForwardSliceToPCodeOpsAction, HighlightColor,
    PcodeOp, PcodeOpHighlight, PcodeOpcode as PcodeOpcodeSlice, SliceResult,
    VarnodeRef as VarnodeRefSlice,
};

// -- Re-exports from rename_tasks (background rename/retype operations) --
pub use rename_tasks::{
    DataTypeInfo, DialogSpec, FieldInfo, IsolateVariableTask, RenameStructBitFieldTask,
    RenameStructFieldTask, RenameTask, RenameUnionFieldTask, RenameVariableTask,
    RetypeFieldTask, RetypeStructFieldTask, RetypeUnionFieldTask, SourceType, SymbolInfo,
    TaskResult, is_symbol_in_function,
};

// -- Re-exports from decompiler_options (full decompile options model) --
pub use decompiler_options::{
    AliasBlockMode, BraceStyle, Color, CommentStyle, DecompileOptions, DecompilerLanguage,
    IntegerFormat, NanIgnoreMode, NamespaceStrategy, TokenColors,
};

// -- Re-exports from callback_handler (provider callback interface) --
pub use callback_handler::{
    AnnotationClick, AnnotationKind, DecompilerCallbackHandler, NavigationTarget,
    NullCallbackHandler, RecordedCallbackHandler,
};

// -- Re-exports from program_listener (domain-object change listener) --
pub use program_listener::{
    DecompilerProgramListener, DomainObjectChangeEvent, DomainObjectEventType, ListenerAction,
    UpdateCoalescer as ProgramUpdateCoalescer,
};

// -- Re-exports from decompiler_location (cursor location types) --
pub use decompiler_location::{
    DecompilerLocation, DecompilerLocationInfo, DefaultDecompilerLocation,
    FunctionNameDecompilerLocation, VariableDecompilerLocation,
};

// -- Re-exports from decomp_interface (decompiler process interface) --
pub use decomp_interface::{
    CompileAction, DecompInterface, DecompInterfaceStatus, EncodeDecodeSet,
};

// -- Re-exports from decompile_exception (decompiler error type) --
pub use decompile_exception::DecompileException;

// -- Re-exports from decompile_process (decompiler subprocess manager) --
pub use decompile_process::{DecompileProcess, DisposeState};

// -- Re-exports from pretty_printer (C code rendering) --
pub use pretty_printer::{
    ClangGroupType, ClangLine as PrettyClangLine, ClangNode, ClangSyntaxType, ClangToken as PrettyClangToken,
    ClangTokenGroup, IdentityNameTransformer, NameTransformer, PrettyPrinter,
};

// -- Re-exports from validator (post-analysis decompiler validators) --
pub use validator::{
    ConditionResult, ConditionStatus, DecompilerParameterIDValidator, DecompilerValidator,
    FunctionInfo, MIN_NUM_FUNCS_DEFAULT, PostAnalysisValidator, SourceType as ValidatorSourceType,
};

// -- Re-exports from flat_api (scripting-friendly decompiler interface) --
pub use flat_api::{
    DecompileError, DecompiledFunctionResult, FlatDecompileOptions, FlatDecompilerAPI,
    FunctionDescriptor as FlatFunctionDescriptor,
};

// -- Re-exports from parallel_decompiler (concurrent decompilation) --
pub use parallel_decompiler::{
    ChunkingParallelDecompiler, ClosureConfigurer, DecompileConfigurer, DecompileResultStub,
    DecompilerCallback as ParallelDecompilerCallback, DecompilerPool, ParallelDecompiler,
    ParallelFunctionInfo, DecompInterfaceStub,
};

// -- Re-exports from decompiler_margin_service (margin rendering) --
pub use decompiler_margin_service::{
    DecompilerMarginProvider, DecompilerMarginServiceImpl, HighlightMarginProvider,
    MarginInteraction, MarginInteractionKind, MarginLineInfo, MarginPaintResult,
    MarginProviderRegistration, MarkerMarginProvider,
};

// -- Re-exports from decompiler_options_listener (option change handling) --
// Note: IntegerFormat, BraceStyle, CommentStyle are renamed to avoid
// conflict with the ones from decompiler_options.
pub use decompiler_options_listener::{
    CommentStyle as OptionsCommentStyle, DecompilerOption, DecompilerOptionsListener,
    DecompilerOptionsState, IntegerFormat as OptionsIntegerFormat,
    OptionCategory, OptionChangeEvent, OptionsSyncResult, RefreshMode,
    BraceStyle as OptionsBraceStyle,
};

// -- Re-exports from decompiler_service_listener (service lifecycle) --
pub use decompiler_service_listener::{
    DecompilerServiceManager, GraphBrokerState, HoverServiceEntry, ServiceAction,
    ServiceChangeListener, ServiceEvent, ServiceKind,
};

// -- Re-exports from find_dialog (decompiler find dialog) --
pub use find_dialog::{
    DecompilerFindDialog, SearchDirection, SearchMatch, SearchOptions, SearchResult, SearchScope,
};

// -- Re-exports from hover_provider (decompiler hover provider) --
pub use hover_provider::{
    DecompilerHoverProvider, HighVariableInfo, HoverLocation, HoverServiceRegistration,
    HoverToken, TokenKind, VarnodeInfo,
};

// -- Re-exports from line_number_margin (line number margin provider) --
pub use line_number_margin::{
    FontMetrics, LayoutModel, LayoutPixelIndexMap, LineNumberMarginManager,
    LineNumberMarginProvider, LineNumberPaintInstruction, VisibleRange,
};

// -- Re-exports from slice_color_provider (slice highlight coloring) --
pub use slice_color_provider::{
    Color as SliceColor, ColorProvider, PcodeOp as SlicePcodeOp, SliceHighlightColorProvider,
    TokenInfo as SliceTokenInfo, Varnode as SliceVarnode,
};

// -- Re-exports from abstract_action (base action class + utilities) --
pub use abstract_action::{
    AbstractDecompilerAction as AbstractDecompilerActionTrait, ActionResult, ActionRegistry as AbstractActionRegistry,
    ActionEntry, CompositeDataType, CompositeKind, FieldInfo as AbstractFieldInfo, ParameterInfo,
    SymbolInfo as AbstractSymbolInfo, SymbolSource, VariableStorage, check_full_commit,
    get_composite_data_type, get_symbol_for_context,
};

// -- Re-exports from select_all_action (select all text in panel) --
pub use select_all_action::{
    EventTrigger, SelectAllAction as SelectAllPanelAction, SelectAllResult,
};
