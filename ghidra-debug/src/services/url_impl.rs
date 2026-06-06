//! URL-based trace service implementation.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.debug.service.url` package.
//! Provides utilities for managing trace URLs within a project, including
//! experiment-based trace organization.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::plugin::experiments::ExperimentManager;

/// A URL for a trace within a project.
///
/// Ported from Ghidra's trace URL handling.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TraceUrl {
    /// The project name.
    pub project: String,
    /// The experiment name (optional).
    pub experiment: Option<String>,
    /// The trace file name.
    pub trace_name: String,
}

impl TraceUrl {
    /// Create a new trace URL.
    pub fn new(
        project: impl Into<String>,
        trace_name: impl Into<String>,
    ) -> Self {
        Self {
            project: project.into(),
            experiment: None,
            trace_name: trace_name.into(),
        }
    }

    /// Add an experiment path.
    pub fn with_experiment(mut self, experiment: impl Into<String>) -> Self {
        self.experiment = Some(experiment.into());
        self
    }

    /// Parse a trace URL string.
    ///
    /// Format: `project://project_name[/experiment]/trace_name`
    pub fn parse(url: &str) -> Result<Self, String> {
        let stripped = url
            .strip_prefix("project://")
            .ok_or_else(|| format!("Invalid trace URL scheme: {}", url))?;

        let parts: Vec<&str> = stripped.split('/').collect();
        if parts.len() < 2 {
            return Err(format!("Invalid trace URL format: {}", url));
        }

        let project = parts[0].to_string();
        let (experiment, trace_name) = if parts.len() == 3 {
            (Some(parts[1].to_string()), parts[2].to_string())
        } else {
            (None, parts[1].to_string())
        };

        Ok(Self {
            project,
            experiment,
            trace_name,
        })
    }

    /// Format as a URL string.
    pub fn to_url(&self) -> String {
        match &self.experiment {
            Some(exp) => format!("project://{}/{}/{}", self.project, exp, self.trace_name),
            None => format!("project://{}/{}", self.project, self.trace_name),
        }
    }
}

impl std::fmt::Display for TraceUrl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_url())
    }
}

/// A project-level service for managing trace URLs.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct TraceUrlService {
    /// Registered trace URLs.
    urls: BTreeMap<String, TraceUrl>,
    /// Experiment manager.
    experiments: ExperimentManager,
}

impl TraceUrlService {
    /// Create a new URL service.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a trace URL.
    pub fn register_trace(&mut self, url: TraceUrl) {
        self.urls.insert(url.to_url(), url);
    }

    /// Get a trace URL by its string representation.
    pub fn get_trace(&self, url_str: &str) -> Option<&TraceUrl> {
        self.urls.get(url_str)
    }

    /// Remove a trace URL.
    pub fn remove_trace(&mut self, url_str: &str) -> Option<TraceUrl> {
        self.urls.remove(url_str)
    }

    /// Get all registered trace URLs.
    pub fn all_traces(&self) -> Vec<&TraceUrl> {
        self.urls.values().collect()
    }

    /// Get the experiment manager.
    pub fn experiments(&self) -> &ExperimentManager {
        &self.experiments
    }

    /// Get the experiment manager mutably.
    pub fn experiments_mut(&mut self) -> &mut ExperimentManager {
        &mut self.experiments
    }

    /// Get traces for a specific experiment.
    pub fn traces_for_experiment(&self, experiment: &str) -> Vec<&TraceUrl> {
        self.urls
            .values()
            .filter(|u| u.experiment.as_deref() == Some(experiment))
            .collect()
    }

    /// Get traces without an experiment.
    pub fn unassigned_traces(&self) -> Vec<&TraceUrl> {
        self.urls
            .values()
            .filter(|u| u.experiment.is_none())
            .collect()
    }

    /// Move a trace to an experiment.
    pub fn move_to_experiment(
        &mut self,
        url_str: &str,
        experiment: impl Into<String>,
    ) -> Result<(), String> {
        if let Some(trace) = self.urls.remove(url_str) {
            let mut new_trace = trace;
            new_trace.experiment = Some(experiment.into());
            let new_url = new_trace.to_url();
            self.urls.insert(new_url, new_trace);
            Ok(())
        } else {
            Err(format!("Trace URL not found: {}", url_str))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trace_url_new() {
        let url = TraceUrl::new("MyProject", "trace1.bin");
        assert_eq!(url.project, "MyProject");
        assert_eq!(url.trace_name, "trace1.bin");
        assert!(url.experiment.is_none());
    }

    #[test]
    fn test_trace_url_with_experiment() {
        let url = TraceUrl::new("proj", "t1").with_experiment("exp1");
        assert_eq!(url.experiment, Some("exp1".to_string()));
    }

    #[test]
    fn test_trace_url_parse() {
        let url = TraceUrl::parse("project://MyProject/trace1.bin").unwrap();
        assert_eq!(url.project, "MyProject");
        assert_eq!(url.trace_name, "trace1.bin");
        assert!(url.experiment.is_none());
    }

    #[test]
    fn test_trace_url_parse_with_experiment() {
        let url = TraceUrl::parse("project://MyProject/exp1/trace1.bin").unwrap();
        assert_eq!(url.project, "MyProject");
        assert_eq!(url.experiment, Some("exp1".to_string()));
        assert_eq!(url.trace_name, "trace1.bin");
    }

    #[test]
    fn test_trace_url_parse_invalid() {
        assert!(TraceUrl::parse("http://bad").is_err());
        assert!(TraceUrl::parse("project://only-project").is_err());
    }

    #[test]
    fn test_trace_url_to_url() {
        let url = TraceUrl::new("proj", "t1");
        assert_eq!(url.to_url(), "project://proj/t1");

        let url = TraceUrl::new("proj", "t1").with_experiment("exp");
        assert_eq!(url.to_url(), "project://proj/exp/t1");
    }

    #[test]
    fn test_trace_url_display() {
        let url = TraceUrl::new("proj", "t1");
        assert_eq!(format!("{}", url), "project://proj/t1");
    }

    #[test]
    fn test_trace_url_roundtrip() {
        let original = TraceUrl::new("proj", "t1").with_experiment("exp1");
        let url_str = original.to_url();
        let parsed = TraceUrl::parse(&url_str).unwrap();
        assert_eq!(original, parsed);
    }

    #[test]
    fn test_trace_url_service() {
        let mut svc = TraceUrlService::new();
        let url = TraceUrl::new("proj", "t1");
        svc.register_trace(url);

        assert_eq!(svc.all_traces().len(), 1);
        assert!(svc.get_trace("project://proj/t1").is_some());
        assert!(svc.get_trace("project://proj/t2").is_none());
    }

    #[test]
    fn test_trace_url_service_remove() {
        let mut svc = TraceUrlService::new();
        svc.register_trace(TraceUrl::new("proj", "t1"));
        svc.remove_trace("project://proj/t1");
        assert!(svc.all_traces().is_empty());
    }

    #[test]
    fn test_trace_url_service_experiment_filter() {
        let mut svc = TraceUrlService::new();
        svc.register_trace(TraceUrl::new("proj", "t1").with_experiment("exp1"));
        svc.register_trace(TraceUrl::new("proj", "t2").with_experiment("exp1"));
        svc.register_trace(TraceUrl::new("proj", "t3"));

        assert_eq!(svc.traces_for_experiment("exp1").len(), 2);
        assert_eq!(svc.unassigned_traces().len(), 1);
    }

    #[test]
    fn test_trace_url_service_move_to_experiment() {
        let mut svc = TraceUrlService::new();
        svc.register_trace(TraceUrl::new("proj", "t1"));

        svc.move_to_experiment("project://proj/t1", "exp1").unwrap();
        assert_eq!(svc.unassigned_traces().len(), 0);
        assert_eq!(svc.traces_for_experiment("exp1").len(), 1);
    }

    #[test]
    fn test_trace_url_service_move_not_found() {
        let mut svc = TraceUrlService::new();
        assert!(svc.move_to_experiment("project://proj/missing", "exp1").is_err());
    }

    #[test]
    fn test_trace_url_serde() {
        let url = TraceUrl::new("proj", "t1").with_experiment("exp1");
        let json = serde_json::to_string(&url).unwrap();
        let back: TraceUrl = serde_json::from_str(&json).unwrap();
        assert_eq!(back, url);
    }
}
