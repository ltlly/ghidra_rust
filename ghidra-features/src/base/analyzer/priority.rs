//! Analysis priority, analyzer type, and option types.

use std::fmt;

#[derive(Debug, Clone)]
pub struct AnalysisOption { pub name: String, pub description: String, pub default_value: AnalysisOptionValue, pub current_value: AnalysisOptionValue }
#[derive(Debug, Clone, PartialEq)]
pub enum AnalysisOptionValue { Bool(bool), Integer(i64), String(String), Choice(String, Vec<String>) }

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AnalyzerPriority { VeryHigh = 0, High = 1, Normal = 2, Low = 3, VeryLow = 4 }
impl fmt::Display for AnalyzerPriority { fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { match self { AnalyzerPriority::VeryHigh => write!(f, "VeryHigh"), AnalyzerPriority::High => write!(f, "High"), AnalyzerPriority::Normal => write!(f, "Normal"), AnalyzerPriority::Low => write!(f, "Low"), AnalyzerPriority::VeryLow => write!(f, "VeryLow"), } } }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AnalysisPriority { pub name: &'static str, pub priority: i32 }
impl PartialOrd for AnalysisPriority { fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> { Some(self.cmp(other)) } }
impl Ord for AnalysisPriority { fn cmp(&self, other: &Self) -> std::cmp::Ordering { self.priority.cmp(&other.priority) } }
impl AnalysisPriority {
    pub const HIGHEST: Self = Self::new("HIGH", 1);
    pub const FORMAT_ANALYSIS: Self = Self::new("FORMAT", 100);
    pub const BLOCK_ANALYSIS: Self = Self::new("BLOCK", 200);
    pub const DISASSEMBLY: Self = Self::new("DISASSEMBLY", 300);
    pub const CODE_ANALYSIS: Self = Self::new("CODE", 400);
    pub const FUNCTION_ANALYSIS: Self = Self::new("FUNCTION", 500);
    pub const REFERENCE_ANALYSIS: Self = Self::new("REFERENCE", 600);
    pub const DATA_ANALYSIS: Self = Self::new("DATA", 700);
    pub const FUNCTION_ID_ANALYSIS: Self = Self::new("FUNCTION ID", 800);
    pub const DATA_TYPE_PROPAGATION: Self = Self::new("DATA TYPE PROPAGATION", 900);
    pub const LOW_PRIORITY: Self = Self::new("LOW", 10000);
    pub const fn new(name: &'static str, priority: i32) -> Self { Self { name, priority } }
    pub const fn before(&self) -> Self { Self::new(self.name, self.priority - 1) }
    pub const fn after(&self) -> Self { Self::new(self.name, self.priority + 1) }
    pub const fn priority(&self) -> i32 { self.priority }
}
impl fmt::Display for AnalysisPriority { fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "[{}] {}", self.name, self.priority) } }

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AnalyzerType { Byte, Instruction, Function, FunctionModifiers, FunctionSignatures, Data }
impl AnalyzerType {
    pub fn name(&self) -> &'static str { match self { AnalyzerType::Byte => "Byte Analyzer", AnalyzerType::Instruction => "Instructions Analyzer", AnalyzerType::Function => "Function Analyzer", AnalyzerType::FunctionModifiers => "Function-modifiers Analyzer", AnalyzerType::FunctionSignatures => "Function-Signatures Analyzer", AnalyzerType::Data => "Data Analyzer", } }
    pub fn description(&self) -> &'static str { match self { AnalyzerType::Byte => "Triggered when bytes are added (memory block added).", AnalyzerType::Instruction => "Triggered when instructions are created.", AnalyzerType::Function => "Triggered when functions are created.", AnalyzerType::FunctionModifiers => "Triggered when a function's modifier changes.", AnalyzerType::FunctionSignatures => "Triggered when a function's signature changes.", AnalyzerType::Data => "Triggered when data is created.", } }
}
impl fmt::Display for AnalyzerType { fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "{}", self.name()) } }
