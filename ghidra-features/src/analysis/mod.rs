//! Ghidra Rust - Auto-Analysis Plugin Layer.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.analysis` package.
//!
//! This module provides the plugin-level orchestration for automatic analysis.
//! Core analyzer types (traits, manager, scheduler, workers) live in
//! `base::analyzer` and are re-exported here for convenience.
//!
//! New types introduced by this module:
//! - [`AutoAnalysisPlugin`] -- the plugin that manages analysis lifecycle
//! - [`AnalysisOptionsDialog`] / [`AnalysisOptionsEditor`] -- options UI
//! - [`AnalysisPanel`] -- analysis status panel
//! - [`ConstantPropagationAnalyzer`] -- multi-instruction constant propagation
//! - [`ElfScalarOperandAnalyzer`] -- ELF-specific scalar reference cleanup
//! - [`MachoFunctionStartsAnalyzer`] -- Mach-O LC_FUNCTION_STARTS parser
//! - [`FindPossibleReferencesPlugin`] -- finds potential references
//! - [`FindReferencesTableModel`] -- table model for reference search results
//! - [`NonReturningFunctionNames`] -- non-returning function name patterns
//! - [`DefaultDataTypeManagerService`] -- headless data type manager service
//! - [`AnalysisEnablementTableModel`] -- analyzer enablement table model
//! - [`UpdateAlignmentAction`] -- alignment update action for memory blocks
//! - [`ProjectPathChooserEditor`] -- project path chooser for options
//! - [`validator`] -- post-analysis validators (offcut, percent, red flags)

pub mod plugin;
pub mod constant_propagation;
pub mod constant_propagation_context_evaluator;
pub mod elf_scalar;
pub mod find_no_return_analyzer;
pub mod macho_starts;
pub mod pef_debug;
pub mod find_references;
pub mod non_returning_names;
pub mod default_data_type_service;
pub mod enablement;
pub mod update_alignment;
pub mod analysis_options;
pub mod stored_times;
pub mod transient_properties;
pub mod options_updater;
pub mod project_path;
pub mod validator;

/// Auto-analysis manager, scheduler, task queue, and worker framework.
///
/// Ported from `ghidra.app.plugin.core.analysis.AutoAnalysisManager`,
/// `AnalysisScheduler`, `AnalysisTask`, `AnalysisTaskList`, `AnalysisWorker`,
/// `AnalysisBackgroundCommand`, and `OneShotAnalysisCommand`.
pub mod auto_analysis;

/// Analysis scheduler, task descriptors, and option management.
///
/// Ported from `AnalysisScheduler.java`, `AnalysisTask.java`,
/// `AnalysisTaskList.java`, `AnalysisOptionsUpdater.java`, and
/// `AnalysisBackgroundCommand.java`.
pub mod scheduler;

/// Demangler analyzer for C++/Rust/D/Java/Swift symbol demangling.
///
/// Ported from `AbstractDemanglerAnalyzer.java` and
/// `DemanglerAnalyzer.java`.
pub mod demangler_analyzer;

/// Reference analyzers: data operand, operand, scalar, and external symbol resolver.
///
/// Ported from `ghidra.app.plugin.core.analysis.DataOperandReferenceAnalyzer`,
/// `OperandReferenceAnalyzer`, `ScalarOperandAnalyzer`, and
/// `ExternalSymbolResolverAnalyzer`.
pub mod reference_analyzers;

/// Symbol and function analyzers: no-return detection, Go symbols,
/// ARM-specific analysis, DWARF debug info, and register context.
///
/// Ported from `ghidra.app.plugin.core.analysis.NoReturnFunctionAnalyzer`,
/// `GolangStringAnalyzer`, `GolangSymbolAnalyzer`, `ArmSymbolAnalyzer`,
/// `DWARFAnalyzer`, and `RegisterContextBuilder`.
pub mod symbol_analyzers;

/// Platform-specific analyzers: data archives, MinGW relocations, CLI
/// metadata tokens, embedded media, segmented calling conventions, and
/// source language detection.
///
/// Ported from `ghidra.app.plugin.core.analysis.ApplyDataArchiveAnalyzer`,
/// `MingwRelocationAnalyzer`, `CliMetadataTokenAnalyzer`,
/// `EmbeddedMediaAnalyzer`, `SegmentedCallingConventionAnalyzer`,
/// `SourceLanguageAnalyzer`, `AnalyzeAllOpenProgramsTask`, and
/// `AnalyzeProgramStrategy`.
pub mod platform_analyzers;

// Re-export module-level items (these are re-exports from base::analyzer
// plus new types unique to this module)
pub use plugin::AutoAnalysisPlugin;
pub use constant_propagation::{ConstantPropagationAnalyzer, AnalysisConstantPropagationEvaluator};
pub use constant_propagation_context_evaluator::ConstantPropagationContextEvaluator;
pub use find_no_return_analyzer::FindNoReturnFunctionsAnalyzer;
pub use elf_scalar::ElfScalarOperandAnalyzer;
pub use macho_starts::MachoFunctionStartsAnalyzer;
pub use pef_debug::PefDebugInfoAnalyzer;
pub use find_references::{FindPossibleReferencesPlugin, FindReferencesTableModel, ReferenceCandidate};
pub use non_returning_names::NonReturningFunctionNames;
pub use default_data_type_service::DefaultDataTypeManagerService;
pub use enablement::AnalysisEnablementTableModel;
pub use update_alignment::UpdateAlignmentAction;
pub use analysis_options::{AnalysisOptionsDialog, AnalysisOptionsEditor, AnalysisPanel, AnalysisOptionEntry};
pub use stored_times::StoredAnalyzerTimesPropertyEditor;
pub use project_path::ProjectPathChooserEditor;
pub use validator::{PostAnalysisValidator, OffcutReferencesValidator, PercentAnalyzedValidator, RedFlagsValidator, ConditionResult, ConditionStatus};

// -- New detailed analyzer implementations ported from Ghidra's Features/Base --

/// Detailed operand reference analyzer with full configuration model.
/// Ported from `ghidra.app.plugin.core.analysis.OperandReferenceAnalyzer`.
pub mod operand_reference_analyzer;

/// Detailed scalar operand analyzer with relocation checking.
/// Ported from `ghidra.app.plugin.core.analysis.ScalarOperandAnalyzer`.
pub mod scalar_operand_analyzer;

/// Golang symbol and string analyzers.
/// Ported from `ghidra.app.plugin.core.analysis.GolangSymbolAnalyzer` and
/// `ghidra.app.plugin.core.analysis.GolangStringAnalyzer`.
pub mod golang_analyzers;

/// MinGW relocation analyzer for PE binaries.
/// Ported from `ghidra.app.plugin.core.analysis.MingwRelocationAnalyzer`.
pub mod mingw_relocation_analyzer;

/// Analysis panel model for the analyzer configuration UI.
/// Ported from `ghidra.app.plugin.core.analysis.AnalysisPanel`.
pub mod analysis_panel;

/// No-return function analyzer with call graph propagation.
/// Ported from `ghidra.app.plugin.core.analysis.NoReturnFunctionAnalyzer`.
pub mod no_return_analyzer;

/// Analysis listener infrastructure for lifecycle events.
/// Ported from `ghidra.app.plugin.core.analysis.AutoAnalysisManagerListener`.
pub mod analysis_listener;

/// Analyzer adapter and wrapper types for scheduling.
/// Ported from `ghidra.app.plugin.core.analysis.AnalyzerAdapter`.
pub mod analysis_adapter;

/// Analysis priority levels for task ordering.
/// Ported from `ghidra.app.services.AnalysisPriority`.
pub mod analysis_priority;

/// Analysis worker command infrastructure.
/// Ported from `AutoAnalysisManager.AnalysisWorkerCommand` and `JointTaskMonitor`.
pub mod analysis_worker_command;

/// Analysis message log for warnings and errors.
/// Ported from `ghidra.app.util.importer.MessageLog`.
pub mod analysis_message_log;

/// Protected locations tracking during analysis.
/// Ported from `AutoAnalysisManager`'s protected locations mechanism.
pub mod protected_locations;

/// Analysis timing utilities for performance monitoring.
/// Ported from `AutoAnalysisManager` task timing and `StoredAnalyzerTimes`.
pub mod analysis_timing;

/// Analysis yield mechanism for task prioritization.
/// Ported from `AutoAnalysisManager.yield()` and `waitForAnalysis()`.
pub mod analysis_yield;

/// Analysis event handler for program change events.
/// Ported from `AutoAnalysisManager`'s `DomainObjectListener`.
pub mod analysis_event_handler;

/// Domain object listener for connecting program changes to analysis.
/// Ported from `AutoAnalysisManager.createDomainObjectListener()`.
pub mod analysis_domain_listener;

/// Analyze all open programs batch task.
/// Ported from `AnalyzeAllOpenProgramsTask` and `AnalyzeProgramStrategy`.
pub mod analyze_open_programs;

// Re-export types from base::analyzer that are commonly needed
pub use crate::base::analyzer::StoredAnalyzerTimes;
pub use crate::base::analyzer::TransientProgramProperties;
pub use crate::base::analyzer::AnalysisOptionsUpdater;

// ---------------------------------------------------------------------------
// PefAnalyzer / PefDebugAnalyzer
// ---------------------------------------------------------------------------

/// Analyzer for PEF (Preferred Executable Format) binaries.
///
/// Ported from `ghidra.app.plugin.core.analysis.PefAnalyzer`.
#[derive(Debug, Clone)]
pub struct PefAnalyzer {
    /// Analyzer name.
    pub name: String,
    /// Whether the analyzer is enabled.
    pub enabled: bool,
    /// Analysis priority.
    pub priority: i32,
}

impl PefAnalyzer {
    /// Create a new PEF analyzer.
    pub fn new() -> Self {
        Self {
            name: "PEF Analyzer".into(),
            enabled: true,
            priority: 0,
        }
    }
}

impl Default for PefAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

/// Analyzer for PEF debug information.
///
/// Ported from `ghidra.app.plugin.core.analysis.PefDebugAnalyzer`.
#[derive(Debug, Clone)]
pub struct PefDebugAnalyzer {
    /// Analyzer name.
    pub name: String,
    /// Whether the analyzer is enabled.
    pub enabled: bool,
    /// Whether to create labels from debug info.
    pub create_labels: bool,
    /// Whether to create functions from debug info.
    pub create_functions: bool,
}

impl PefDebugAnalyzer {
    /// Create a new PEF debug analyzer.
    pub fn new() -> Self {
        Self {
            name: "PEF Debug Analyzer".into(),
            enabled: true,
            create_labels: true,
            create_functions: true,
        }
    }
}

impl Default for PefDebugAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_analysis_module_exports() {
        let _ = std::any::type_name::<AutoAnalysisPlugin>();
        let _ = std::any::type_name::<ConstantPropagationAnalyzer>();
        let _ = std::any::type_name::<AnalysisConstantPropagationEvaluator>();
        let _ = std::any::type_name::<ElfScalarOperandAnalyzer>();
        let _ = std::any::type_name::<MachoFunctionStartsAnalyzer>();
        let _ = std::any::type_name::<PefDebugInfoAnalyzer>();
        let _ = std::any::type_name::<FindPossibleReferencesPlugin>();
        let _ = std::any::type_name::<FindReferencesTableModel>();
        let _ = std::any::type_name::<NonReturningFunctionNames>();
        let _ = std::any::type_name::<DefaultDataTypeManagerService>();
        let _ = std::any::type_name::<AnalysisEnablementTableModel>();
        let _ = std::any::type_name::<UpdateAlignmentAction>();
        let _ = std::any::type_name::<StoredAnalyzerTimes>();
        let _ = std::any::type_name::<TransientProgramProperties>();
        let _ = std::any::type_name::<AnalysisOptionsUpdater>();
        let _ = std::any::type_name::<ProjectPathChooserEditor>();
        // PostAnalysisValidator is a trait - verify concrete types exist
        let _ = std::any::type_name::<OffcutReferencesValidator>();
        let _ = std::any::type_name::<PercentAnalyzedValidator>();
        let _ = std::any::type_name::<RedFlagsValidator>();
    }
}
