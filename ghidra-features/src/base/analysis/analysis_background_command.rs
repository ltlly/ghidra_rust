//! Background command for triggering auto-analysis.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.analysis.AnalysisBackgroundCommand`.
//!
//! The [`AnalysisBackgroundCommand`] wraps an [`AutoAnalysisManager`] in a
//! mergeable background task so it can be queued through Ghidra's command
//! framework.  When executed it optionally marks the program as analyzed
//! and then delegates to [`AutoAnalysisManager::run_analysis`].

use super::analyzer::{BasicTaskMonitor, Program, TaskMonitor};
use super::auto_analysis_manager::AutoAnalysisManager;

/// Background command that kicks off auto-analysis on a program.
///
/// Multiple invocations can be merged: once a "mark as analyzed" flag is
/// set it stays on for the lifetime of the merged command.
pub struct AnalysisBackgroundCommand {
    mgr: AutoAnalysisManager,
    mark_as_analyzed: bool,
}

impl AnalysisBackgroundCommand {
    /// Create a new analysis background command.
    ///
    /// * `mgr` -- the program's [`AutoAnalysisManager`].
    /// * `mark_as_analyzed` -- if `true`, set the program's analyzed flag
    ///   before running analysis.
    pub fn new(mgr: AutoAnalysisManager, mark_as_analyzed: bool) -> Self {
        Self {
            mgr,
            mark_as_analyzed,
        }
    }

    /// Execute the command: optionally mark the program as analyzed, then
    /// run the analysis manager.
    pub fn apply_to(
        &mut self,
        program: &mut Program,
        monitor: &dyn TaskMonitor,
    ) -> bool {
        if self.mark_as_analyzed {
            program.mark_analyzed();
        }
        let _ = self.mgr.run_analysis(monitor);
        true
    }

    /// Merge another [`AnalysisBackgroundCommand`] into this one.
    ///
    /// The merged command keeps the "mark as analyzed" flag set if *either*
    /// command had it set.  Both commands must target the same program
    /// (enforced by assertion in debug builds).
    pub fn merge(&mut self, other: Self) {
        debug_assert_eq!(
            self.mgr.program().name,
            other.mgr.program().name,
            "AnalysisBackgroundCommand: both commands must target the same program"
        );
        // Once true, always true.
        self.mark_as_analyzed |= other.mark_as_analyzed;
    }

    /// Borrow the inner manager.
    pub fn manager(&self) -> &AutoAnalysisManager {
        &self.mgr
    }

    /// Whether the program will be marked as analyzed.
    pub fn mark_as_analyzed(&self) -> bool {
        self.mark_as_analyzed
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::super::analyzer::{Address, AddressRange, Language};
    use super::*;

    fn make_test_program() -> Program {
        let lang = Language {
            processor: "x86".into(),
            variant: "LE".into(),
            size: 64,
        };
        let mut prog = Program::new("test", lang);
        prog.image_base = 0x400000;
        prog.memory.add_range(AddressRange::new(
            Address::new(0x400000),
            Address::new(0x500000),
        ));
        prog
    }

    #[test]
    fn test_creation() {
        let prog = make_test_program();
        let mgr = AutoAnalysisManager::new(prog);
        let cmd = AnalysisBackgroundCommand::new(mgr, false);
        assert!(!cmd.mark_as_analyzed());
    }

    #[test]
    fn test_mark_as_analyzed() {
        let prog = make_test_program();
        let mgr = AutoAnalysisManager::new(prog);
        let cmd = AnalysisBackgroundCommand::new(mgr, true);
        assert!(cmd.mark_as_analyzed());
    }

    #[test]
    fn test_apply_to() {
        let mut prog = make_test_program();
        let mgr = AutoAnalysisManager::new(prog.clone());
        let mut cmd = AnalysisBackgroundCommand::new(mgr, true);
        let monitor = BasicTaskMonitor::new();
        assert!(cmd.apply_to(&mut prog, &monitor));
        assert!(prog.is_analyzed());
    }

    #[test]
    fn test_apply_without_marking() {
        let mut prog = make_test_program();
        let mgr = AutoAnalysisManager::new(prog.clone());
        let mut cmd = AnalysisBackgroundCommand::new(mgr, false);
        let monitor = BasicTaskMonitor::new();
        cmd.apply_to(&mut prog, &monitor);
        assert!(!prog.is_analyzed());
    }

    #[test]
    fn test_merge_stays_true() {
        let prog = make_test_program();
        let mgr1 = AutoAnalysisManager::new(prog.clone());
        let mgr2 = AutoAnalysisManager::new(prog);
        let mut cmd1 = AnalysisBackgroundCommand::new(mgr1, false);
        let cmd2 = AnalysisBackgroundCommand::new(mgr2, true);
        cmd1.merge(cmd2);
        assert!(cmd1.mark_as_analyzed());
    }

    #[test]
    fn test_merge_both_false() {
        let prog = make_test_program();
        let mgr1 = AutoAnalysisManager::new(prog.clone());
        let mgr2 = AutoAnalysisManager::new(prog);
        let mut cmd1 = AnalysisBackgroundCommand::new(mgr1, false);
        let cmd2 = AnalysisBackgroundCommand::new(mgr2, false);
        cmd1.merge(cmd2);
        assert!(!cmd1.mark_as_analyzed());
    }
}
