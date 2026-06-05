//! Trace experiment framework.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.debug.service.url.ProjectExperiments`
//! and the Framework-TraceModeling experiments package. Provides a container for
//! managing debug experiments -- collections of related traces and their
//! associations.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::model::Lifespan;
use crate::target::key_path::KeyPath;

/// A debug experiment: a named collection of traces and associated data.
///
/// Ported from Ghidra's `TraceExperiment`. Represents a single debug
/// session's data including snapshots, mappings, and analysis results.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceExperiment {
    /// The experiment name.
    pub name: String,
    /// The experiment key (unique within the project).
    pub key: String,
    /// The traces in this experiment, keyed by trace ID.
    pub traces: BTreeMap<String, ExperimentTraceEntry>,
    /// Static mapping proposals.
    pub mappings: Vec<ExperimentMapping>,
    /// User annotations.
    pub annotations: BTreeMap<String, String>,
    /// Whether this experiment is active.
    pub active: bool,
}

/// An entry for a trace within an experiment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExperimentTraceEntry {
    /// The trace ID.
    pub trace_id: String,
    /// The display name.
    pub display_name: String,
    /// The number of snapshots.
    pub snap_count: usize,
    /// The maximum snap value.
    pub max_snap: i64,
    /// Whether the trace is currently open.
    pub open: bool,
}

/// A mapping between a program and a trace within an experiment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExperimentMapping {
    /// The program URL.
    pub program_url: String,
    /// The trace ID.
    pub trace_id: String,
    /// The program address range start.
    pub program_min: u64,
    /// The program address range end.
    pub program_max: u64,
    /// The trace address range start.
    pub trace_min: u64,
    /// The trace address range end.
    pub trace_max: u64,
    /// The lifespan.
    pub lifespan: Lifespan,
    /// Whether this mapping is confirmed.
    pub confirmed: bool,
}

impl TraceExperiment {
    /// Create a new experiment.
    pub fn new(name: impl Into<String>) -> Self {
        let name = name.into();
        Self {
            key: name.clone(),
            name,
            traces: BTreeMap::new(),
            mappings: Vec::new(),
            annotations: BTreeMap::new(),
            active: false,
        }
    }

    /// Add a trace to the experiment.
    pub fn add_trace(
        &mut self,
        trace_id: impl Into<String>,
        display_name: impl Into<String>,
    ) {
        let trace_id = trace_id.into();
        self.traces.insert(
            trace_id.clone(),
            ExperimentTraceEntry {
                trace_id,
                display_name: display_name.into(),
                snap_count: 0,
                max_snap: 0,
                open: false,
            },
        );
    }

    /// Remove a trace from the experiment.
    pub fn remove_trace(&mut self, trace_id: &str) -> Option<ExperimentTraceEntry> {
        self.traces.remove(trace_id)
    }

    /// Get a trace entry.
    pub fn get_trace(&self, trace_id: &str) -> Option<&ExperimentTraceEntry> {
        self.traces.get(trace_id)
    }

    /// Add a mapping.
    pub fn add_mapping(&mut self, mapping: ExperimentMapping) {
        self.mappings.push(mapping);
    }

    /// Set an annotation.
    pub fn set_annotation(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.annotations.insert(key.into(), value.into());
    }

    /// Get an annotation.
    pub fn get_annotation(&self, key: &str) -> Option<&String> {
        self.annotations.get(key)
    }

    /// Activate this experiment.
    pub fn activate(&mut self) {
        self.active = true;
    }

    /// Deactivate this experiment.
    pub fn deactivate(&mut self) {
        self.active = false;
    }

    /// The number of traces in this experiment.
    pub fn trace_count(&self) -> usize {
        self.traces.len()
    }

    /// The number of mappings.
    pub fn mapping_count(&self) -> usize {
        self.mappings.len()
    }

    /// Get the confirmed mappings.
    pub fn confirmed_mappings(&self) -> Vec<&ExperimentMapping> {
        self.mappings.iter().filter(|m| m.confirmed).collect()
    }
}

/// A container for managing multiple experiments.
///
/// Ported from Ghidra's `ProjectExperiments`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ExperimentManager {
    experiments: BTreeMap<String, TraceExperiment>,
    active_experiment: Option<String>,
}

impl ExperimentManager {
    /// Create a new empty experiment manager.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a new experiment.
    pub fn create_experiment(&mut self, name: impl Into<String>) -> String {
        let exp = TraceExperiment::new(name);
        let key = exp.key.clone();
        self.experiments.insert(key.clone(), exp);
        key
    }

    /// Get an experiment by key.
    pub fn get_experiment(&self, key: &str) -> Option<&TraceExperiment> {
        self.experiments.get(key)
    }

    /// Get a mutable experiment by key.
    pub fn get_experiment_mut(&mut self, key: &str) -> Option<&mut TraceExperiment> {
        self.experiments.get_mut(key)
    }

    /// Remove an experiment.
    pub fn remove_experiment(&mut self, key: &str) -> Option<TraceExperiment> {
        if self.active_experiment.as_deref() == Some(key) {
            self.active_experiment = None;
        }
        self.experiments.remove(key)
    }

    /// Set the active experiment.
    pub fn set_active_experiment(&mut self, key: Option<String>) {
        // Deactivate the old one
        if let Some(old_key) = &self.active_experiment {
            if let Some(old) = self.experiments.get_mut(old_key) {
                old.deactivate();
            }
        }
        // Activate the new one
        if let Some(new_key) = &key {
            if let Some(new) = self.experiments.get_mut(new_key) {
                new.activate();
            }
        }
        self.active_experiment = key;
    }

    /// Get the active experiment key.
    pub fn active_experiment(&self) -> Option<&str> {
        self.active_experiment.as_deref()
    }

    /// Get all experiment keys.
    pub fn experiment_keys(&self) -> Vec<&str> {
        self.experiments.keys().map(|s| s.as_str()).collect()
    }

    /// The number of experiments.
    pub fn experiment_count(&self) -> usize {
        self.experiments.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trace_experiment() {
        let mut exp = TraceExperiment::new("debug-session-1");
        assert_eq!(exp.name, "debug-session-1");
        assert_eq!(exp.trace_count(), 0);
        assert!(!exp.active);

        exp.add_trace("trace1", "Main Trace");
        assert_eq!(exp.trace_count(), 1);
        assert!(exp.get_trace("trace1").is_some());
        assert!(exp.get_trace("missing").is_none());
    }

    #[test]
    fn test_trace_experiment_remove() {
        let mut exp = TraceExperiment::new("test");
        exp.add_trace("t1", "Trace 1");
        exp.add_trace("t2", "Trace 2");
        assert_eq!(exp.trace_count(), 2);

        exp.remove_trace("t1");
        assert_eq!(exp.trace_count(), 1);
        assert!(exp.get_trace("t1").is_none());
    }

    #[test]
    fn test_trace_experiment_mapping() {
        let mut exp = TraceExperiment::new("test");
        exp.add_mapping(ExperimentMapping {
            program_url: "file:///path/to/prog".into(),
            trace_id: "trace1".into(),
            program_min: 0,
            program_max: 0x1000,
            trace_min: 0x400000,
            trace_max: 0x401000,
            lifespan: Lifespan::now_on(0),
            confirmed: true,
        });
        assert_eq!(exp.mapping_count(), 1);
        assert_eq!(exp.confirmed_mappings().len(), 1);
    }

    #[test]
    fn test_trace_experiment_annotations() {
        let mut exp = TraceExperiment::new("test");
        exp.set_annotation("description", "Testing binary analysis");
        assert_eq!(
            exp.get_annotation("description"),
            Some(&"Testing binary analysis".to_string())
        );
        assert!(exp.get_annotation("missing").is_none());
    }

    #[test]
    fn test_trace_experiment_activate() {
        let mut exp = TraceExperiment::new("test");
        assert!(!exp.active);
        exp.activate();
        assert!(exp.active);
        exp.deactivate();
        assert!(!exp.active);
    }

    #[test]
    fn test_experiment_manager() {
        let mut mgr = ExperimentManager::new();
        assert_eq!(mgr.experiment_count(), 0);

        let key = mgr.create_experiment("exp1");
        assert_eq!(mgr.experiment_count(), 1);
        assert!(mgr.get_experiment(&key).is_some());
    }

    #[test]
    fn test_experiment_manager_active() {
        let mut mgr = ExperimentManager::new();
        let k1 = mgr.create_experiment("exp1");
        let k2 = mgr.create_experiment("exp2");

        mgr.set_active_experiment(Some(k1.clone()));
        assert_eq!(mgr.active_experiment(), Some(k1.as_str()));
        assert!(mgr.get_experiment(&k1).unwrap().active);
        assert!(!mgr.get_experiment(&k2).unwrap().active);

        mgr.set_active_experiment(Some(k2.clone()));
        assert_eq!(mgr.active_experiment(), Some(k2.as_str()));
        assert!(!mgr.get_experiment(&k1).unwrap().active);
        assert!(mgr.get_experiment(&k2).unwrap().active);
    }

    #[test]
    fn test_experiment_manager_remove() {
        let mut mgr = ExperimentManager::new();
        let key = mgr.create_experiment("exp1");
        mgr.set_active_experiment(Some(key.clone()));

        mgr.remove_experiment(&key);
        assert_eq!(mgr.experiment_count(), 0);
        assert!(mgr.active_experiment().is_none());
    }

    #[test]
    fn test_experiment_manager_keys() {
        let mut mgr = ExperimentManager::new();
        mgr.create_experiment("alpha");
        mgr.create_experiment("beta");
        let keys = mgr.experiment_keys();
        assert_eq!(keys.len(), 2);
        assert!(keys.contains(&"alpha"));
        assert!(keys.contains(&"beta"));
    }

    #[test]
    fn test_experiment_serde() {
        let exp = TraceExperiment::new("test");
        let json = serde_json::to_string(&exp).unwrap();
        let back: TraceExperiment = serde_json::from_str(&json).unwrap();
        assert_eq!(back.name, "test");
    }

    #[test]
    fn test_experiment_manager_serde() {
        let mut mgr = ExperimentManager::new();
        mgr.create_experiment("exp1");
        let json = serde_json::to_string(&mgr).unwrap();
        let back: ExperimentManager = serde_json::from_str(&json).unwrap();
        assert_eq!(back.experiment_count(), 1);
    }
}
