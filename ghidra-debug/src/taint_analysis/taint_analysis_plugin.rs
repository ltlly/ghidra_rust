//! Taint analysis plugin.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.debug.gui.taint.TaintAnalysisPlugin`.
//!
//! Provides the plugin lifecycle, registration, and coordination for taint
//! analysis within the debugger.  The plugin manages one or more providers
//! and delegates to engine-specific backends (Angr, Emulator).

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};

use super::taint_engines::{TaintEngine, TaintQuery};
use super::taint_states::{TaintEntry, TaintError};

// ---------------------------------------------------------------------------
// TaintAnalysisPluginConfig -- configuration for the plugin
// ---------------------------------------------------------------------------

/// Configuration for the taint analysis plugin.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintAnalysisPluginConfig {
    /// Whether the plugin is enabled.
    pub enabled: bool,
    /// The default engine to use.
    pub default_engine: TaintEngine,
    /// Maximum number of concurrent analyses.
    pub max_concurrent_analyses: usize,
    /// Default maximum emulation steps.
    pub default_max_steps: u64,
    /// Path to the default Angr script.
    pub angr_script_path: Option<String>,
    /// Path to the default index database.
    pub default_index_db_path: Option<String>,
    /// Whether to auto-save SARIF results.
    pub auto_save_sarif: bool,
    /// Additional engine options.
    pub engine_options: BTreeMap<String, String>,
}

impl Default for TaintAnalysisPluginConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            default_engine: TaintEngine::Emulator,
            max_concurrent_analyses: 4,
            default_max_steps: 10_000,
            angr_script_path: None,
            default_index_db_path: None,
            auto_save_sarif: false,
            engine_options: BTreeMap::new(),
        }
    }
}

impl TaintAnalysisPluginConfig {
    /// Create a new config with defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the default engine.
    pub fn with_engine(mut self, engine: TaintEngine) -> Self {
        self.default_engine = engine;
        self
    }

    /// Set the max concurrent analyses.
    pub fn with_max_concurrent(mut self, max: usize) -> Self {
        self.max_concurrent_analyses = max;
        self
    }

    /// Set the default max steps.
    pub fn with_max_steps(mut self, steps: u64) -> Self {
        self.default_max_steps = steps;
        self
    }

    /// Set the Angr script path.
    pub fn with_angr_script(mut self, path: impl Into<String>) -> Self {
        self.angr_script_path = Some(path.into());
        self
    }

    /// Set the index database path.
    pub fn with_index_db(mut self, path: impl Into<String>) -> Self {
        self.default_index_db_path = Some(path.into());
        self
    }

    /// Enable auto-save of SARIF results.
    pub fn with_auto_save_sarif(mut self, auto_save: bool) -> Self {
        self.auto_save_sarif = auto_save;
        self
    }

    /// Add an engine option.
    pub fn with_engine_option(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.engine_options.insert(key.into(), value.into());
        self
    }

    /// Create a `TaintQuery` from this config.
    pub fn build_query(&self) -> TaintQuery {
        let mut query = TaintQuery::new(self.default_engine);
        if let Some(ref path) = self.angr_script_path {
            query = query.with_engine_path(path.clone());
        }
        for (k, v) in &self.engine_options {
            query.options.insert(k.clone(), v.clone());
        }
        query
    }
}

// ---------------------------------------------------------------------------
// TaintAnalysisJob -- an in-flight analysis request
// ---------------------------------------------------------------------------

/// The status of a taint analysis job.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TaintJobStatus {
    /// The job is queued and waiting to run.
    Queued,
    /// The job is running.
    Running,
    /// The job completed successfully.
    Completed,
    /// The job failed.
    Failed,
    /// The job was cancelled.
    Cancelled,
}

/// A taint analysis job representing an in-flight or completed analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintAnalysisJob {
    /// Unique identifier for this job.
    pub id: u64,
    /// The query being executed.
    pub query: TaintQuery,
    /// The current status.
    pub status: TaintJobStatus,
    /// Error message if the job failed.
    pub error: Option<String>,
    /// Result taint entries.
    pub results: Vec<TaintEntry>,
}

impl TaintAnalysisJob {
    /// Create a new job in queued status.
    pub fn new(id: u64, query: TaintQuery) -> Self {
        Self {
            id,
            query,
            status: TaintJobStatus::Queued,
            error: None,
            results: Vec::new(),
        }
    }

    /// Mark the job as running.
    pub fn start(&mut self) {
        self.status = TaintJobStatus::Running;
    }

    /// Mark the job as completed with results.
    pub fn complete(&mut self, results: Vec<TaintEntry>) {
        self.status = TaintJobStatus::Completed;
        self.results = results;
    }

    /// Mark the job as failed with an error message.
    pub fn fail(&mut self, error: impl Into<String>) {
        self.status = TaintJobStatus::Failed;
        self.error = Some(error.into());
    }

    /// Mark the job as cancelled.
    pub fn cancel(&mut self) {
        self.status = TaintJobStatus::Cancelled;
    }

    /// Whether the job has reached a terminal state.
    pub fn is_terminal(&self) -> bool {
        matches!(
            self.status,
            TaintJobStatus::Completed | TaintJobStatus::Failed | TaintJobStatus::Cancelled
        )
    }

    /// Number of tainted entries in the results.
    pub fn tainted_count(&self) -> usize {
        self.results
            .iter()
            .filter(|e| e.level.is_tainted())
            .count()
    }
}

// ---------------------------------------------------------------------------
// TaintAnalysisPluginState -- shared mutable state for the plugin
// ---------------------------------------------------------------------------

/// The internal state of the taint analysis plugin.
///
/// Manages job lifecycle: creation, execution dispatch, result collection,
/// and cancellation.  Thread-safe via `Arc<Mutex<_>>`.
#[derive(Debug)]
pub struct TaintAnalysisPluginState {
    /// Plugin configuration.
    pub config: TaintAnalysisPluginConfig,
    /// Next job ID.
    next_job_id: u64,
    /// All jobs by ID.
    jobs: BTreeMap<u64, TaintAnalysisJob>,
    /// Number of currently running analyses.
    running_count: usize,
    /// Provider IDs registered with this plugin.
    provider_ids: Vec<String>,
}

impl TaintAnalysisPluginState {
    /// Create a new plugin state with the given configuration.
    pub fn new(config: TaintAnalysisPluginConfig) -> Self {
        Self {
            config,
            next_job_id: 1,
            jobs: BTreeMap::new(),
            running_count: 0,
            provider_ids: Vec::new(),
        }
    }

    /// Create a new state with default configuration.
    pub fn with_defaults() -> Self {
        Self::new(TaintAnalysisPluginConfig::default())
    }

    /// Register a provider ID with this plugin.
    pub fn register_provider(&mut self, provider_id: impl Into<String>) {
        self.provider_ids.push(provider_id.into());
    }

    /// Get the registered provider IDs.
    pub fn provider_ids(&self) -> &[String] {
        &self.provider_ids
    }

    /// Submit a new analysis job.  Returns the job ID.
    ///
    /// Fails if the maximum concurrent analysis limit has been reached.
    pub fn submit_job(&mut self, query: TaintQuery) -> Result<u64, TaintError> {
        if self.running_count >= self.config.max_concurrent_analyses {
            return Err(TaintError::State(
                "Maximum concurrent analyses reached".to_string(),
            ));
        }
        let id = self.next_job_id;
        self.next_job_id += 1;
        let job = TaintAnalysisJob::new(id, query);
        self.jobs.insert(id, job);
        Ok(id)
    }

    /// Start a queued job.
    pub fn start_job(&mut self, job_id: u64) -> Result<(), TaintError> {
        let job = self
            .jobs
            .get_mut(&job_id)
            .ok_or_else(|| TaintError::State(format!("Job {} not found", job_id)))?;
        if job.status != TaintJobStatus::Queued {
            return Err(TaintError::State(format!(
                "Job {} is not in Queued state",
                job_id
            )));
        }
        job.start();
        self.running_count += 1;
        Ok(())
    }

    /// Complete a running job with results.
    pub fn complete_job(
        &mut self,
        job_id: u64,
        results: Vec<TaintEntry>,
    ) -> Result<(), TaintError> {
        let job = self
            .jobs
            .get_mut(&job_id)
            .ok_or_else(|| TaintError::State(format!("Job {} not found", job_id)))?;
        if job.status != TaintJobStatus::Running {
            return Err(TaintError::State(format!(
                "Job {} is not in Running state",
                job_id
            )));
        }
        job.complete(results);
        self.running_count -= 1;
        Ok(())
    }

    /// Fail a running job with an error.
    pub fn fail_job(&mut self, job_id: u64, error: impl Into<String>) -> Result<(), TaintError> {
        let job = self
            .jobs
            .get_mut(&job_id)
            .ok_or_else(|| TaintError::State(format!("Job {} not found", job_id)))?;
        if job.status != TaintJobStatus::Running {
            return Err(TaintError::State(format!(
                "Job {} is not in Running state",
                job_id
            )));
        }
        job.fail(error);
        self.running_count -= 1;
        Ok(())
    }

    /// Cancel a queued or running job.
    pub fn cancel_job(&mut self, job_id: u64) -> Result<(), TaintError> {
        let job = self
            .jobs
            .get_mut(&job_id)
            .ok_or_else(|| TaintError::State(format!("Job {} not found", job_id)))?;
        if job.is_terminal() {
            return Err(TaintError::State(format!(
                "Job {} is already in terminal state",
                job_id
            )));
        }
        let was_running = job.status == TaintJobStatus::Running;
        job.cancel();
        if was_running {
            self.running_count -= 1;
        }
        Ok(())
    }

    /// Get a reference to a job by ID.
    pub fn get_job(&self, job_id: u64) -> Option<&TaintAnalysisJob> {
        self.jobs.get(&job_id)
    }

    /// Get a mutable reference to a job by ID.
    pub fn get_job_mut(&mut self, job_id: u64) -> Option<&mut TaintAnalysisJob> {
        self.jobs.get_mut(&job_id)
    }

    /// Get all jobs.
    pub fn jobs(&self) -> &BTreeMap<u64, TaintAnalysisJob> {
        &self.jobs
    }

    /// Get the number of currently running jobs.
    pub fn running_count(&self) -> usize {
        self.running_count
    }

    /// Get the number of queued jobs.
    pub fn queued_count(&self) -> usize {
        self.jobs
            .values()
            .filter(|j| j.status == TaintJobStatus::Queued)
            .count()
    }

    /// Get all completed jobs.
    pub fn completed_jobs(&self) -> Vec<&TaintAnalysisJob> {
        self.jobs
            .values()
            .filter(|j| j.status == TaintJobStatus::Completed)
            .collect()
    }

    /// Get all failed jobs.
    pub fn failed_jobs(&self) -> Vec<&TaintAnalysisJob> {
        self.jobs
            .values()
            .filter(|j| j.status == TaintJobStatus::Failed)
            .collect()
    }

    /// Remove all terminal (completed/failed/cancelled) jobs.
    pub fn cleanup_terminal_jobs(&mut self) {
        self.jobs.retain(|_, j| !j.is_terminal());
    }

    /// Clear all jobs.
    pub fn clear_jobs(&mut self) {
        self.jobs.clear();
        self.running_count = 0;
    }
}

// ---------------------------------------------------------------------------
// TaintAnalysisPlugin -- the main plugin type
// ---------------------------------------------------------------------------

/// The taint analysis plugin.
///
/// Ported from Ghidra's `TaintAnalysisPlugin`.  Manages the lifecycle of
/// taint analysis jobs and coordinates providers.  Thread-safe via
/// `Arc<Mutex<TaintAnalysisPluginState>>`.
#[derive(Debug, Clone)]
pub struct TaintAnalysisPlugin {
    /// The shared plugin state.
    state: Arc<Mutex<TaintAnalysisPluginState>>,
}

impl TaintAnalysisPlugin {
    /// Create a new plugin with the given configuration.
    pub fn new(config: TaintAnalysisPluginConfig) -> Self {
        Self {
            state: Arc::new(Mutex::new(TaintAnalysisPluginState::new(config))),
        }
    }

    /// Create a plugin with default configuration.
    pub fn with_defaults() -> Self {
        Self::new(TaintAnalysisPluginConfig::default())
    }

    /// Get a clone of the shared state handle.
    pub fn state_handle(&self) -> Arc<Mutex<TaintAnalysisPluginState>> {
        Arc::clone(&self.state)
    }

    /// Get the current configuration.
    pub fn config(&self) -> TaintAnalysisPluginConfig {
        self.state.lock().unwrap().config.clone()
    }

    /// Update the plugin configuration.
    pub fn set_config(&self, config: TaintAnalysisPluginConfig) {
        self.state.lock().unwrap().config = config;
    }

    /// Submit a taint analysis query.  Returns the job ID.
    pub fn submit_query(&self, query: TaintQuery) -> Result<u64, TaintError> {
        self.state.lock().unwrap().submit_job(query)
    }

    /// Get a snapshot of a job's current state.
    pub fn job_status(&self, job_id: u64) -> Option<TaintJobStatus> {
        self.state
            .lock()
            .unwrap()
            .get_job(job_id)
            .map(|j| j.status)
    }

    /// Cancel a job.
    pub fn cancel(&self, job_id: u64) -> Result<(), TaintError> {
        self.state.lock().unwrap().cancel_job(job_id)
    }

    /// Get the number of running analyses.
    pub fn running_count(&self) -> usize {
        self.state.lock().unwrap().running_count()
    }

    /// Whether the plugin is accepting new analyses.
    pub fn can_accept(&self) -> bool {
        let s = self.state.lock().unwrap();
        s.config.enabled && s.running_count() < s.config.max_concurrent_analyses
    }

    /// Register a provider with the plugin.
    pub fn register_provider(&self, provider_id: impl Into<String>) {
        self.state.lock().unwrap().register_provider(provider_id);
    }

    /// Get registered provider IDs.
    pub fn provider_ids(&self) -> Vec<String> {
        self.state.lock().unwrap().provider_ids().to_vec()
    }

    /// Cleanup completed/failed/cancelled jobs.
    pub fn cleanup(&self) {
        self.state.lock().unwrap().cleanup_terminal_jobs();
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::taint_analysis::TaintLevel;

    // -- Config tests --

    #[test]
    fn test_plugin_config_default() {
        let cfg = TaintAnalysisPluginConfig::default();
        assert!(cfg.enabled);
        assert_eq!(cfg.default_engine, TaintEngine::Emulator);
        assert_eq!(cfg.max_concurrent_analyses, 4);
        assert_eq!(cfg.default_max_steps, 10_000);
        assert!(!cfg.auto_save_sarif);
    }

    #[test]
    fn test_plugin_config_builder() {
        let cfg = TaintAnalysisPluginConfig::new()
            .with_engine(TaintEngine::Angr)
            .with_max_concurrent(8)
            .with_max_steps(50_000)
            .with_angr_script("/usr/bin/angr")
            .with_auto_save_sarif(true)
            .with_engine_option("timeout", "300");

        assert_eq!(cfg.default_engine, TaintEngine::Angr);
        assert_eq!(cfg.max_concurrent_analyses, 8);
        assert_eq!(cfg.default_max_steps, 50_000);
        assert!(cfg.auto_save_sarif);
        assert_eq!(cfg.engine_options.get("timeout").unwrap(), "300");
    }

    #[test]
    fn test_plugin_config_build_query() {
        let cfg = TaintAnalysisPluginConfig::new()
            .with_engine(TaintEngine::Angr)
            .with_angr_script("/usr/bin/angr")
            .with_engine_option("mode", "symbolic");

        let query = cfg.build_query();
        assert_eq!(query.engine, TaintEngine::Angr);
        assert_eq!(query.engine_path.as_deref(), Some("/usr/bin/angr"));
        assert_eq!(query.options.get("mode").unwrap(), "symbolic");
    }

    // -- Job tests --

    #[test]
    fn test_job_lifecycle() {
        let query = TaintQuery::new(TaintEngine::Emulator);
        let mut job = TaintAnalysisJob::new(1, query);
        assert_eq!(job.status, TaintJobStatus::Queued);
        assert!(!job.is_terminal());

        job.start();
        assert_eq!(job.status, TaintJobStatus::Running);
        assert!(!job.is_terminal());

        let results = vec![TaintEntry {
            address: 0x1000,
            level: TaintLevel::UserInput,
            size: 4,
            source: Some("stdin".to_string()),
        }];
        job.complete(results);
        assert_eq!(job.status, TaintJobStatus::Completed);
        assert!(job.is_terminal());
        assert_eq!(job.tainted_count(), 1);
    }

    #[test]
    fn test_job_fail() {
        let query = TaintQuery::new(TaintEngine::Angr);
        let mut job = TaintAnalysisJob::new(2, query);
        job.start();
        job.fail("connection error");
        assert_eq!(job.status, TaintJobStatus::Failed);
        assert_eq!(job.error.as_deref(), Some("connection error"));
        assert!(job.is_terminal());
    }

    #[test]
    fn test_job_cancel() {
        let query = TaintQuery::new(TaintEngine::Emulator);
        let mut job = TaintAnalysisJob::new(3, query);
        job.start();
        job.cancel();
        assert_eq!(job.status, TaintJobStatus::Cancelled);
        assert!(job.is_terminal());
    }

    // -- State tests --

    #[test]
    fn test_plugin_state_submit_and_start() {
        let mut state = TaintAnalysisPluginState::with_defaults();
        let query = TaintQuery::new(TaintEngine::Emulator);
        let job_id = state.submit_job(query).unwrap();
        assert_eq!(job_id, 1);
        assert_eq!(state.queued_count(), 1);

        state.start_job(job_id).unwrap();
        assert_eq!(state.running_count(), 1);
        assert_eq!(state.queued_count(), 0);
    }

    #[test]
    fn test_plugin_state_max_concurrent() {
        let mut state = TaintAnalysisPluginState::with_defaults();
        // Default max is 4
        for _ in 0..4 {
            let query = TaintQuery::new(TaintEngine::Emulator);
            let id = state.submit_job(query).unwrap();
            state.start_job(id).unwrap();
        }
        // 5th should fail
        let query = TaintQuery::new(TaintEngine::Emulator);
        let result = state.submit_job(query);
        assert!(result.is_err());
    }

    #[test]
    fn test_plugin_state_complete_and_fail() {
        let mut state = TaintAnalysisPluginState::with_defaults();
        let query = TaintQuery::new(TaintEngine::Angr);
        let id = state.submit_job(query).unwrap();
        state.start_job(id).unwrap();

        state
            .fail_job(id, "timeout")
            .unwrap();
        assert_eq!(state.running_count(), 0);
        assert_eq!(state.failed_jobs().len(), 1);
    }

    #[test]
    fn test_plugin_state_cancel() {
        let mut state = TaintAnalysisPluginState::with_defaults();
        let query = TaintQuery::new(TaintEngine::Emulator);
        let id = state.submit_job(query).unwrap();
        state.start_job(id).unwrap();
        assert_eq!(state.running_count(), 1);

        state.cancel_job(id).unwrap();
        assert_eq!(state.running_count(), 0);
    }

    #[test]
    fn test_plugin_state_cleanup() {
        let mut state = TaintAnalysisPluginState::with_defaults();
        let q1 = TaintQuery::new(TaintEngine::Emulator);
        let id1 = state.submit_job(q1).unwrap();
        state.start_job(id1).unwrap();
        state
            .complete_job(id1, vec![])
            .unwrap();

        let q2 = TaintQuery::new(TaintEngine::Angr);
        let id2 = state.submit_job(q2).unwrap();

        state.cleanup_terminal_jobs();
        assert!(state.get_job(id1).is_none());
        assert!(state.get_job(id2).is_some());
    }

    #[test]
    fn test_plugin_state_register_provider() {
        let mut state = TaintAnalysisPluginState::with_defaults();
        state.register_provider("provider-1");
        state.register_provider("provider-2");
        assert_eq!(state.provider_ids().len(), 2);
    }

    // -- Plugin tests --

    #[test]
    fn test_plugin_creation() {
        let plugin = TaintAnalysisPlugin::with_defaults();
        assert_eq!(plugin.running_count(), 0);
        assert!(plugin.can_accept());
    }

    #[test]
    fn test_plugin_submit_and_cancel() {
        let plugin = TaintAnalysisPlugin::with_defaults();
        let query = TaintQuery::new(TaintEngine::Emulator);
        let id = plugin.submit_query(query).unwrap();
        assert!(plugin.can_accept());

        plugin.cancel(id).unwrap();
        assert_eq!(plugin.running_count(), 0);
    }

    #[test]
    fn test_plugin_register_provider() {
        let plugin = TaintAnalysisPlugin::with_defaults();
        plugin.register_provider("taint-view");
        assert_eq!(plugin.provider_ids(), vec!["taint-view"]);
    }

    #[test]
    fn test_plugin_config_update() {
        let plugin = TaintAnalysisPlugin::with_defaults();
        let new_cfg = TaintAnalysisPluginConfig::new()
            .with_engine(TaintEngine::Angr)
            .with_max_concurrent(16);
        plugin.set_config(new_cfg);

        let cfg = plugin.config();
        assert_eq!(cfg.default_engine, TaintEngine::Angr);
        assert_eq!(cfg.max_concurrent_analyses, 16);
    }

    #[test]
    fn test_plugin_cleanup() {
        let plugin = TaintAnalysisPlugin::with_defaults();
        let query = TaintQuery::new(TaintEngine::Emulator);
        let id = plugin.submit_query(query).unwrap();
        plugin.cancel(id).unwrap();

        plugin.cleanup();
        // The cancelled job should be removed; state is still healthy.
        assert_eq!(plugin.running_count(), 0);
    }

    #[test]
    fn test_plugin_state_serialization() {
        let cfg = TaintAnalysisPluginConfig::new()
            .with_engine(TaintEngine::Angr)
            .with_max_steps(20_000);
        let json = serde_json::to_string(&cfg).unwrap();
        let back: TaintAnalysisPluginConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back.default_engine, TaintEngine::Angr);
        assert_eq!(back.default_max_steps, 20_000);
    }
}
