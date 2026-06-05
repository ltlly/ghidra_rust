//! BSim function decompilation task.
//!
//! Ports `ghidra.features.bsim.query.DecompileFunctionTask` and
//! `ghidra.features.bsim.query.ParallelDecompileTask` from Ghidra's Java source.
//!
//! Provides utilities for decompiling functions in parallel and generating
//! BSim signatures from the decompiled output.

use std::collections::HashMap;

use super::description::{BSimFunctionDescription, FunctionSignatureInfo};
use super::gen_signatures::SignatureGenerator;
use super::{BSimError, BSimResult};

/// A single function to be decompiled for BSim signature generation.
#[derive(Debug, Clone)]
pub struct DecompileFunctionRequest {
    /// Entry point address.
    pub entry_point: u64,
    /// Function name.
    pub name: String,
    /// Raw function bytes.
    pub bytes: Vec<u8>,
    /// Mnemonic sequence (pre-computed, if available).
    pub mnemonics: Option<Vec<String>>,
}

impl DecompileFunctionRequest {
    /// Create a new request.
    pub fn new(entry_point: u64, name: impl Into<String>, bytes: Vec<u8>) -> Self {
        Self {
            entry_point,
            name: name.into(),
            bytes,
            mnemonics: None,
        }
    }

    /// Create a request with pre-computed mnemonics.
    pub fn with_mnemonics(mut self, mnemonics: Vec<String>) -> Self {
        self.mnemonics = Some(mnemonics);
        self
    }
}

/// Result of decompiling a function for BSim.
#[derive(Debug, Clone)]
pub struct DecompileFunctionResult {
    /// The original request.
    pub request: DecompileFunctionRequest,
    /// The generated signature (if successful).
    pub signature: Option<BSimFunctionDescription>,
    /// Error message (if failed).
    pub error: Option<String>,
    /// Time taken in milliseconds.
    pub time_ms: u64,
}

impl DecompileFunctionResult {
    /// Create a successful result.
    pub fn success(
        request: DecompileFunctionRequest,
        signature: BSimFunctionDescription,
        time_ms: u64,
    ) -> Self {
        Self {
            request,
            signature: Some(signature),
            error: None,
            time_ms,
        }
    }

    /// Create a failure result.
    pub fn failure(request: DecompileFunctionRequest, error: String, time_ms: u64) -> Self {
        Self {
            request,
            signature: None,
            error: Some(error),
            time_ms,
        }
    }

    /// Whether this result is successful.
    pub fn is_success(&self) -> bool {
        self.signature.is_some()
    }
}

/// Configuration for parallel decompilation tasks.
#[derive(Debug, Clone)]
pub struct ParallelDecompileConfig {
    /// Number of worker threads.
    pub thread_count: usize,
    /// Maximum number of functions to decompile.
    pub max_functions: Option<usize>,
    /// Timeout per function in milliseconds.
    pub timeout_ms: u64,
    /// Signature generation configuration.
    pub sig_config: super::gen_signatures::GenSignaturesConfig,
}

impl Default for ParallelDecompileConfig {
    fn default() -> Self {
        Self {
            thread_count: 4,
            max_functions: None,
            timeout_ms: 30_000,
            sig_config: super::gen_signatures::GenSignaturesConfig::default(),
        }
    }
}

/// Task that decompiles functions in parallel and produces BSim signatures.
///
/// Ports Ghidra's `ParallelDecompileTask`.
pub struct ParallelDecompileTask {
    config: ParallelDecompileConfig,
    generator: SignatureGenerator,
}

impl ParallelDecompileTask {
    /// Create a new parallel decompile task.
    pub fn new(config: ParallelDecompileConfig) -> Self {
        let generator = SignatureGenerator::with_config(config.sig_config.clone());
        Self { config, generator }
    }

    /// Get the configuration.
    pub fn config(&self) -> &ParallelDecompileConfig {
        &self.config
    }

    /// Decompile a batch of functions and produce BSim signatures.
    ///
    /// In a production environment, this would use a thread pool.  Here we
    /// process sequentially for compatibility with the single-threaded model.
    pub fn execute(
        &self,
        requests: &[DecompileFunctionRequest],
    ) -> BSimResult<Vec<DecompileFunctionResult>> {
        let max = self
            .config
            .max_functions
            .unwrap_or(requests.len());
        let mut results = Vec::with_capacity(requests.len().min(max));

        for request in requests.iter().take(max) {
            let start = std::time::Instant::now();

            let mnemonics = match &request.mnemonics {
                Some(m) => m.clone(),
                None => {
                    // Simulate disassembly by interpreting bytes as opcodes.
                    disassemble_simple(&request.bytes)
                }
            };

            match self.generator.generate_function_signature(
                request.entry_point,
                &request.name,
                &mnemonics,
                &request.bytes,
            ) {
                Ok(desc) => {
                    let elapsed = start.elapsed().as_millis() as u64;
                    results.push(DecompileFunctionResult::success(
                        request.clone(),
                        desc,
                        elapsed,
                    ));
                }
                Err(e) => {
                    let elapsed = start.elapsed().as_millis() as u64;
                    results.push(DecompileFunctionResult::failure(
                        request.clone(),
                        e.to_string(),
                        elapsed,
                    ));
                }
            }
        }

        Ok(results)
    }
}

/// Simple byte-to-mnemonic disassembly for signature generation.
///
/// Maps common x86 opcode bytes to mnemonic names.  This is a simplified
/// fallback used when the decompiler is not available.
fn disassemble_simple(bytes: &[u8]) -> Vec<String> {
    bytes
        .iter()
        .map(|b| match *b {
            0x50..=0x57 => "push",
            0x58..=0x5F => "pop",
            0x89 | 0x8B => "mov",
            0x01 | 0x03 => "add",
            0x29 | 0x2B => "sub",
            0x31 | 0x33 => "xor",
            0x09 | 0x0B => "or",
            0x21 | 0x23 => "and",
            0x39 | 0x3B => "cmp",
            0xE8 => "call",
            0xE9 => "jmp",
            0xFF => "call_ind",
            0xC3 => "ret",
            0x90 => "nop",
            0xEB => "jmp_short",
            0x74 => "je",
            0x75 => "jne",
            0xF4 => "hlt",
            _ => "unknown",
        })
        .map(|s| s.to_string())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decompile_request_basic() {
        let req = DecompileFunctionRequest::new(0x1000, "main", vec![0x55, 0x89, 0xe5]);
        assert_eq!(req.entry_point, 0x1000);
        assert_eq!(req.name, "main");
        assert!(req.mnemonics.is_none());
    }

    #[test]
    fn decompile_request_with_mnemonics() {
        let req = DecompileFunctionRequest::new(0x1000, "main", vec![0x55])
            .with_mnemonics(vec!["push".into(), "mov".into()]);
        assert!(req.mnemonics.is_some());
        assert_eq!(req.mnemonics.unwrap().len(), 2);
    }

    #[test]
    fn decompile_result_success() {
        let req = DecompileFunctionRequest::new(0x1000, "f", vec![0x55, 0x89, 0xe5, 0xc3]);
        let desc = BSimFunctionDescription::new("", "f", 0x1000);
        let result = DecompileFunctionResult::success(req, desc, 10);
        assert!(result.is_success());
        assert!(result.error.is_none());
    }

    #[test]
    fn decompile_result_failure() {
        let req = DecompileFunctionRequest::new(0x2000, "g", vec![0x90]);
        let result = DecompileFunctionResult::failure(req, "too small".into(), 5);
        assert!(!result.is_success());
        assert_eq!(result.error.as_deref(), Some("too small"));
    }

    #[test]
    fn parallel_config_default() {
        let config = ParallelDecompileConfig::default();
        assert_eq!(config.thread_count, 4);
        assert_eq!(config.timeout_ms, 30_000);
        assert!(config.max_functions.is_none());
    }

    #[test]
    fn parallel_decompile_task_execute() {
        let config = ParallelDecompileConfig {
            sig_config: super::super::gen_signatures::GenSignaturesConfig {
                min_function_size: 4,
                ..Default::default()
            },
            ..Default::default()
        };
        let task = ParallelDecompileTask::new(config);
        let requests = vec![
            DecompileFunctionRequest::new(
                0x1000,
                "main",
                vec![0x55, 0x89, 0xe5, 0x83, 0xec, 0x10, 0xc9, 0xc3],
            ),
            DecompileFunctionRequest::new(0x2000, "short", vec![0x90]),
        ];
        let results = task.execute(&requests).unwrap();
        assert_eq!(results.len(), 2);
        // First should succeed.
        assert!(results[0].is_success());
        // Second should fail (too small).
        assert!(!results[1].is_success());
    }

    #[test]
    fn disassemble_simple_basic() {
        let mnemonics = disassemble_simple(&[0x55, 0x89, 0xe5, 0xc3]);
        assert_eq!(mnemonics[0], "push");
        assert_eq!(mnemonics[1], "mov");
        assert_eq!(mnemonics[3], "ret");
    }

    #[test]
    fn disassemble_simple_branches() {
        let mnemonics = disassemble_simple(&[0xE8, 0xE9, 0x74, 0x75]);
        assert_eq!(mnemonics[0], "call");
        assert_eq!(mnemonics[1], "jmp");
        assert_eq!(mnemonics[2], "je");
        assert_eq!(mnemonics[3], "jne");
    }

    #[test]
    fn disassemble_simple_unknown() {
        let mnemonics = disassemble_simple(&[0xAB, 0xCD, 0xEF]);
        assert!(mnemonics.iter().all(|m| m == "unknown"));
    }
}
