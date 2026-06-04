//! Random Forest parameters for function start detection.
//!
//! Ported from `FunctionStartRFParams.java` in the MachineLearning extension.
//!
//! Contains the configuration parameters that control what data is collected
//! for training random forests to recognize function starts.

use std::num::ParseIntError;

/// Container for the parameters that determine what data is collected for
/// training random forests to recognize function starts.
#[derive(Debug, Clone)]
pub struct FunctionStartRfParams {
    /// Number of bytes before a function start to include in features.
    pre_bytes: Vec<usize>,
    /// Number of bytes after (and including) the first byte of a function.
    initial_bytes: Vec<usize>,
    /// How many non-starts to gather for each start gathered.
    sampling_factors: Vec<usize>,
    /// Minimum size of a function (in bytes) to include in training.
    min_func_size: usize,
    /// Maximum number of function starts to gather for training.
    max_starts: usize,
    /// Instruction alignment for the target architecture.
    instruction_alignment: usize,
    /// Whether to include bytes from preceding and following code units.
    include_preceding_and_following: bool,
    /// Whether to include bit-level features in feature vectors.
    include_bit_features: bool,
    /// Names of context registers to check.
    context_register_names: Vec<String>,
    /// Values of context registers (parallel to `context_register_names`).
    context_register_values: Vec<u64>,
}

impl FunctionStartRfParams {
    /// Create new parameters with default values.
    ///
    /// `instruction_alignment` should match the target architecture's
    /// instruction alignment (typically 1 for x86, 4 for ARM/MIPS).
    pub fn new(instruction_alignment: usize) -> Self {
        Self {
            pre_bytes: Vec::new(),
            initial_bytes: Vec::new(),
            sampling_factors: Vec::new(),
            min_func_size: 0,
            max_starts: 0,
            instruction_alignment,
            include_preceding_and_following: false,
            include_bit_features: false,
            context_register_names: Vec::new(),
            context_register_values: Vec::new(),
        }
    }

    // -- Getters --

    /// Get the pre-bytes configuration.
    pub fn pre_bytes(&self) -> &[usize] {
        &self.pre_bytes
    }

    /// Get the initial-bytes configuration.
    pub fn initial_bytes(&self) -> &[usize] {
        &self.initial_bytes
    }

    /// Get the sampling factors.
    pub fn sampling_factors(&self) -> &[usize] {
        &self.sampling_factors
    }

    /// Get the minimum function size.
    pub fn min_func_size(&self) -> usize {
        self.min_func_size
    }

    /// Get the maximum number of function starts.
    pub fn max_starts(&self) -> usize {
        self.max_starts
    }

    /// Get the instruction alignment.
    pub fn instruction_alignment(&self) -> usize {
        self.instruction_alignment
    }

    /// Whether to include preceding and following code units.
    pub fn include_preceding_and_following(&self) -> bool {
        self.include_preceding_and_following
    }

    /// Whether to include bit-level features.
    pub fn include_bit_features(&self) -> bool {
        self.include_bit_features
    }

    /// Whether the params are restricted by context register values.
    pub fn is_restricted_by_context(&self) -> bool {
        !self.context_register_names.is_empty()
    }

    /// Get the context register names.
    pub fn context_register_names(&self) -> &[String] {
        &self.context_register_names
    }

    /// Get the context register values.
    pub fn context_register_values(&self) -> &[u64] {
        &self.context_register_values
    }

    // -- Setters --

    /// Set the pre-bytes configuration.
    pub fn set_pre_bytes(&mut self, pre_bytes: Vec<usize>) {
        self.pre_bytes = pre_bytes;
    }

    /// Set the initial-bytes configuration.
    pub fn set_initial_bytes(&mut self, initial_bytes: Vec<usize>) {
        self.initial_bytes = initial_bytes;
    }

    /// Set the sampling factors.
    pub fn set_sampling_factors(&mut self, factors: Vec<usize>) {
        self.sampling_factors = factors;
    }

    /// Set the minimum function size.
    pub fn set_min_func_size(&mut self, size: usize) {
        self.min_func_size = size;
    }

    /// Set the maximum number of function starts.
    pub fn set_max_starts(&mut self, max: usize) {
        self.max_starts = max;
    }

    /// Set whether to include preceding and following code units.
    pub fn set_include_preceding_and_following(&mut self, b: bool) {
        self.include_preceding_and_following = b;
    }

    /// Set whether to include bit-level features.
    pub fn set_include_bit_features(&mut self, b: bool) {
        self.include_bit_features = b;
    }

    /// Parse register=value pairs from a CSV string and store them.
    ///
    /// The format is `creg1=0x10,creg2=0x20`. Any existing pairs are
    /// discarded.
    ///
    /// # Errors
    ///
    /// Returns an error if parsing fails.
    pub fn set_registers_and_values(
        &mut self,
        csv: &str,
    ) -> Result<(), String> {
        let mut names = Vec::new();
        let mut values = Vec::new();

        for part in csv.split(',') {
            let part = part.trim();
            let pair: Vec<&str> = part.splitn(2, '=').collect();
            if pair.len() != 2 {
                names.clear();
                values.clear();
                return Err(format!("Error parsing register=value string: {part}"));
            }

            let reg_name = pair[0].trim().to_string();
            let val_str = pair[1].trim();
            let val: u64 = if val_str.starts_with("0x") || val_str.starts_with("0X") {
                u64::from_str_radix(&val_str[2..], 16)
                    .map_err(|e| format!("Invalid hex value for {reg_name}: {e}"))?
            } else {
                val_str
                    .parse()
                    .map_err(|e: ParseIntError| format!("Invalid value for {reg_name}: {e}"))?
            };

            names.push(reg_name);
            values.push(val);
        }

        self.context_register_names = names;
        self.context_register_values = values;
        Ok(())
    }

    /// Parse a CSV string into a sorted list of distinct non-negative
    /// integers.
    ///
    /// Duplicates are silently removed. The result is sorted ascending.
    ///
    /// # Errors
    ///
    /// Returns an error if the string is blank, has leading/trailing commas,
    /// or contains invalid or negative integers.
    pub fn parse_integer_csv(csv: &str) -> Result<Vec<usize>, String> {
        let trimmed = csv.trim();
        if trimmed.is_empty() {
            return Err("Entry cannot be blank".to_string());
        }
        if trimmed.starts_with(',') || trimmed.ends_with(',') {
            return Err("String must not begin or end with a comma".to_string());
        }

        let mut results = Vec::new();
        for part in trimmed.split(',') {
            let part = part.trim();
            let val: usize = part
                .parse()
                .map_err(|_| format!("Invalid element {part} - must be non-negative"))?;
            if !results.contains(&val) {
                results.push(val);
            }
        }
        results.sort();
        Ok(results)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_params() {
        let params = FunctionStartRfParams::new(1);
        assert_eq!(params.instruction_alignment(), 1);
        assert!(params.pre_bytes().is_empty());
        assert!(params.initial_bytes().is_empty());
        assert!(params.sampling_factors().is_empty());
        assert_eq!(params.min_func_size(), 0);
        assert_eq!(params.max_starts(), 0);
        assert!(!params.include_preceding_and_following());
        assert!(!params.include_bit_features());
        assert!(!params.is_restricted_by_context());
    }

    #[test]
    fn test_setters() {
        let mut params = FunctionStartRfParams::new(4);
        params.set_pre_bytes(vec![16, 32]);
        params.set_initial_bytes(vec![8, 16]);
        params.set_sampling_factors(vec![2, 5]);
        params.set_min_func_size(64);
        params.set_max_starts(1000);
        params.set_include_preceding_and_following(true);
        params.set_include_bit_features(true);

        assert_eq!(params.pre_bytes(), &[16, 32]);
        assert_eq!(params.initial_bytes(), &[8, 16]);
        assert_eq!(params.sampling_factors(), &[2, 5]);
        assert_eq!(params.min_func_size(), 64);
        assert_eq!(params.max_starts(), 1000);
        assert!(params.include_preceding_and_following());
        assert!(params.include_bit_features());
    }

    #[test]
    fn test_set_registers_and_values() {
        let mut params = FunctionStartRfParams::new(1);
        params
            .set_registers_and_values("TMode=1,ISA=0")
            .unwrap();
        assert!(params.is_restricted_by_context());
        assert_eq!(params.context_register_names(), &["TMode", "ISA"]);
        assert_eq!(params.context_register_values(), &[1, 0]);
    }

    #[test]
    fn test_set_registers_and_values_hex() {
        let mut params = FunctionStartRfParams::new(1);
        params
            .set_registers_and_values("reg=0xFF")
            .unwrap();
        assert_eq!(params.context_register_values(), &[255]);
    }

    #[test]
    fn test_set_registers_and_values_error() {
        let mut params = FunctionStartRfParams::new(1);
        let result = params.set_registers_and_values("bad_format");
        assert!(result.is_err());
        // On error, the existing pairs should be cleared
        assert!(!params.is_restricted_by_context());
    }

    #[test]
    fn test_parse_integer_csv() {
        let result = FunctionStartRfParams::parse_integer_csv("3,1,2,1,3").unwrap();
        assert_eq!(result, vec![1, 2, 3]);
    }

    #[test]
    fn test_parse_integer_csv_single() {
        let result = FunctionStartRfParams::parse_integer_csv("42").unwrap();
        assert_eq!(result, vec![42]);
    }

    #[test]
    fn test_parse_integer_csv_blank() {
        assert!(FunctionStartRfParams::parse_integer_csv("").is_err());
        assert!(FunctionStartRfParams::parse_integer_csv("   ").is_err());
    }

    #[test]
    fn test_parse_integer_csv_leading_comma() {
        assert!(FunctionStartRfParams::parse_integer_csv(",1,2").is_err());
    }

    #[test]
    fn test_parse_integer_csv_trailing_comma() {
        assert!(FunctionStartRfParams::parse_integer_csv("1,2,").is_err());
    }

    #[test]
    fn test_parse_integer_csv_negative() {
        assert!(FunctionStartRfParams::parse_integer_csv("-1,2").is_err());
    }
}
