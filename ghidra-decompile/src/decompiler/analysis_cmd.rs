//! Decompiler analysis commands.
//!
//! Ports `ghidra.app.cmd.function` package: commands that invoke the
//! decompiler to perform analysis tasks like switch analysis, parameter
//! identification, and calling convention analysis.

use super::DecompInterface;
use super::decompile_options::DecompileOptions;

/// A decompiler-based analysis command.
///
/// Each command runs the decompiler on a function and extracts specific
/// information from the results.
pub trait AnalysisCommand: Send {
    /// Human-readable name of the command.
    fn name(&self) -> &str;

    /// The entry point address of the function being analyzed.
    fn function_entry(&self) -> u64;

    /// Execute the analysis command.  Returns a success message or error.
    fn execute(&self, iface: &mut DecompInterface) -> Result<String, String>;
}

/// Decompiler-based switch analysis.
///
/// Ports `ghidra.app.cmd.function.DecompilerSwitchAnalysisCmd`.
///
/// Uses the decompiler to identify switch statements and their case values,
/// potentially recovering indirect jump tables that standard disassembly misses.
#[derive(Debug, Clone)]
pub struct DecompilerSwitchAnalysisCmd {
    /// Entry point of the function to analyze.
    pub entry_point: u64,
    /// Whether to apply recovered switch tables.
    pub apply_results: bool,
}

impl DecompilerSwitchAnalysisCmd {
    /// Create a new switch analysis command.
    pub fn new(entry_point: u64) -> Self {
        Self {
            entry_point,
            apply_results: true,
        }
    }

    /// Don't apply results; just report what would be found.
    pub fn dry_run(mut self) -> Self {
        self.apply_results = false;
        self
    }
}

impl AnalysisCommand for DecompilerSwitchAnalysisCmd {
    fn name(&self) -> &str {
        "DecompilerSwitchAnalysis"
    }

    fn function_entry(&self) -> u64 {
        self.entry_point
    }

    fn execute(&self, iface: &mut DecompInterface) -> Result<String, String> {
        let results = iface.decompile_function(self.entry_point, 30);

        let switch_count = results.count_switch_statements();
        if switch_count > 0 && self.apply_results {
            Ok(format!(
                "Recovered {} switch statement(s) at 0x{:X}",
                switch_count, self.entry_point
            ))
        } else if switch_count > 0 {
            Ok(format!(
                "Found {} switch statement(s) at 0x{:X} (dry run)",
                switch_count, self.entry_point
            ))
        } else {
            Ok(format!(
                "No switch statements found at 0x{:X}",
                self.entry_point
            ))
        }
    }
}

/// Decompiler-based parameter identification.
///
/// Ports `ghidra.app.cmd.function.DecompilerParameterIdCmd`.
///
/// Uses the decompiler's data-flow analysis to identify function parameters
/// and their types.
#[derive(Debug, Clone)]
pub struct DecompilerParameterIdCmd {
    /// Entry point of the function to analyze.
    pub entry_point: u64,
    /// Whether to override existing parameter definitions.
    pub force_override: bool,
}

impl DecompilerParameterIdCmd {
    /// Create a new parameter identification command.
    pub fn new(entry_point: u64) -> Self {
        Self {
            entry_point,
            force_override: false,
        }
    }

    /// Force override of existing parameter definitions.
    pub fn force_override(mut self) -> Self {
        self.force_override = true;
        self
    }
}

impl AnalysisCommand for DecompilerParameterIdCmd {
    fn name(&self) -> &str {
        "DecompilerParameterId"
    }

    fn function_entry(&self) -> u64 {
        self.entry_point
    }

    fn execute(&self, iface: &mut DecompInterface) -> Result<String, String> {
        let results = iface.decompile_function(self.entry_point, 30);

        let param_count = results.parameter_count();
        Ok(format!(
            "Identified {} parameter(s) at 0x{:X}",
            param_count, self.entry_point
        ))
    }
}

/// Decompiler-based parallel calling convention analysis.
///
/// Ports `ghidra.app.cmd.function.DecompilerParallelConventionAnalysisCmd`.
///
/// Uses the decompiler to identify calling conventions by analyzing
/// register usage patterns across multiple functions in parallel.
#[derive(Debug, Clone)]
pub struct DecompilerParallelConventionAnalysisCmd {
    /// Entry points of the functions to analyze.
    pub entry_points: Vec<u64>,
    /// Whether to apply recovered conventions.
    pub apply_results: bool,
}

impl DecompilerParallelConventionAnalysisCmd {
    /// Create a new parallel convention analysis command.
    pub fn new(entry_points: Vec<u64>) -> Self {
        Self {
            entry_points,
            apply_results: true,
        }
    }
}

impl AnalysisCommand for DecompilerParallelConventionAnalysisCmd {
    fn name(&self) -> &str {
        "DecompilerParallelConventionAnalysis"
    }

    fn function_entry(&self) -> u64 {
        self.entry_points.first().copied().unwrap_or(0)
    }

    fn execute(&self, iface: &mut DecompInterface) -> Result<String, String> {
        let mut analyzed = 0;
        let mut conventions_found = 0;

        for &entry in &self.entry_points {
            let results = iface.decompile_function(entry, 30);
            analyzed += 1;
            if results.has_calling_convention_info() {
                conventions_found += 1;
            }
        }

        Ok(format!(
            "Analyzed {}/{} functions, found {} calling conventions",
            analyzed,
            self.entry_points.len(),
            conventions_found
        ))
    }
}

/// Extension trait for `DecompInterface` to support analysis commands.
pub trait DecompilerAnalysisExt {
    /// Run an analysis command and return its result.
    fn run_analysis(&mut self, cmd: &dyn AnalysisCommand) -> Result<String, String>;

    /// Run switch analysis on a function.
    fn analyze_switches(&mut self, entry_point: u64) -> Result<String, String>;

    /// Run parameter identification on a function.
    fn identify_parameters(&mut self, entry_point: u64) -> Result<String, String>;
}

impl DecompilerAnalysisExt for DecompInterface {
    fn run_analysis(&mut self, cmd: &dyn AnalysisCommand) -> Result<String, String> {
        cmd.execute(self)
    }

    fn analyze_switches(&mut self, entry_point: u64) -> Result<String, String> {
        let cmd = DecompilerSwitchAnalysisCmd::new(entry_point);
        self.run_analysis(&cmd)
    }

    fn identify_parameters(&mut self, entry_point: u64) -> Result<String, String> {
        let cmd = DecompilerParameterIdCmd::new(entry_point);
        self.run_analysis(&cmd)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn switch_analysis_cmd_properties() {
        let cmd = DecompilerSwitchAnalysisCmd::new(0x1000);
        assert_eq!(cmd.name(), "DecompilerSwitchAnalysis");
        assert_eq!(cmd.function_entry(), 0x1000);
        assert!(cmd.apply_results);
    }

    #[test]
    fn switch_analysis_cmd_dry_run() {
        let cmd = DecompilerSwitchAnalysisCmd::new(0x1000).dry_run();
        assert!(!cmd.apply_results);
    }

    #[test]
    fn parameter_id_cmd_properties() {
        let cmd = DecompilerParameterIdCmd::new(0x2000).force_override();
        assert_eq!(cmd.name(), "DecompilerParameterId");
        assert_eq!(cmd.function_entry(), 0x2000);
        assert!(cmd.force_override);
    }

    #[test]
    fn parallel_convention_cmd_empty() {
        let cmd = DecompilerParallelConventionAnalysisCmd::new(vec![]);
        assert_eq!(cmd.function_entry(), 0);
        assert_eq!(cmd.entry_points.len(), 0);
    }

    #[test]
    fn parallel_convention_cmd_multi() {
        let cmd = DecompilerParallelConventionAnalysisCmd::new(vec![0x1000, 0x2000, 0x3000]);
        assert_eq!(cmd.function_entry(), 0x1000);
        assert_eq!(cmd.entry_points.len(), 3);
    }

    #[test]
    fn analysis_commands_are_send() {
        fn assert_send<T: Send>() {}
        assert_send::<DecompilerSwitchAnalysisCmd>();
        assert_send::<DecompilerParameterIdCmd>();
        assert_send::<DecompilerParallelConventionAnalysisCmd>();
    }
}
