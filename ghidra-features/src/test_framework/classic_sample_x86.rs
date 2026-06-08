//! Classic sample x86 program builder for testing.
//!
//! Ported from `ghidra.test.ClassicSampleX86ProgramBuilder`.
//!
//! Builds a predefined x86 sample program with a set of memory blocks,
//! functions, labels, external references, data types, and comments that
//! are used across many Ghidra integration tests.

use std::collections::HashMap;

use crate::base::analyzer::core::{
    Address, AddressRange, AddressSet, Data, DataType, Function, FunctionManager, Instruction,
    Language, Listing, MemoryBlock, Program, RefType, SourceType,
};
use super::ToyProgramBuilder;
use super::test_processor_constants;

// ---------------------------------------------------------------------------
// Sample function specifications
// ---------------------------------------------------------------------------

/// Describes a sample function to be placed into the classic program.
#[derive(Debug, Clone)]
pub struct SampleFunctionSpec {
    /// Entry point address (hex string, e.g. "0x01006420").
    pub entry: u64,
    /// Function name.
    pub name: String,
    /// Body start address.
    pub body_start: u64,
    /// Body end address.
    pub body_end: u64,
    /// Optional label at the entry point.
    pub label: Option<String>,
    /// Whether this is an entry point function.
    pub is_entry: bool,
}

/// Describes a sample external reference to be placed into the classic program.
#[derive(Debug, Clone)]
pub struct ExternalRefSpec {
    /// Address of the external reference pointer.
    pub address: u64,
    /// Library name (e.g. "ADVAPI32.dll").
    pub library: String,
    /// External function name (e.g. "IsTextUnicode").
    pub external_name: String,
    /// Byte offset into the import.
    pub offset: u64,
    /// Label at the address.
    pub label: String,
}

/// Describes a memory reference (cross-reference) in the sample program.
#[derive(Debug, Clone)]
pub struct MemRefSpec {
    /// From address.
    pub from: u64,
    /// To address.
    pub to: u64,
    /// Reference type.
    pub ref_type: RefType,
    /// Source of the reference.
    pub source: SourceType,
}

/// Describes a label in the sample program.
#[derive(Debug, Clone)]
pub struct LabelSpec {
    /// Address.
    pub address: u64,
    /// Label name.
    pub name: String,
}

/// Describes a comment in the sample program.
#[derive(Debug, Clone)]
pub struct CommentSpec {
    /// Address.
    pub address: u64,
    /// Comment text.
    pub text: String,
    /// Comment type (repeatable, pre, post, end-of-line).
    pub comment_type: CommentType,
}

/// Comment types for the sample program.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommentType {
    /// End-of-line comment.
    EndOfLine,
    /// Pre-comment (above).
    Pre,
    /// Post-comment (below).
    Post,
    /// Repeatable comment.
    Repeatable,
}

/// Describes a data type application in the sample program.
#[derive(Debug, Clone)]
pub struct DataTypeSpec {
    /// Address to apply the data type.
    pub address: u64,
    /// Data type name.
    pub type_name: String,
    /// Size in bytes.
    pub size: usize,
}

// ---------------------------------------------------------------------------
// ClassicSampleX86ProgramBuilder
// ---------------------------------------------------------------------------

/// Builds a predefined x86 sample program used across many Ghidra tests.
///
/// Ported from `ghidra.test.ClassicSampleX86ProgramBuilder`.
///
/// The program contains:
/// - Multiple `.text` memory regions at well-known addresses
/// - External references to Windows DLLs (ADVAPI32, comdlg32, MSVCRT)
/// - Several functions with disassembled bytes
/// - Labels, equates, comments, and data type applications
/// - Memory references (xrefs)
///
/// # Example
///
/// ```rust
/// use ghidra_features::test_framework::classic_sample_x86::ClassicSampleX86ProgramBuilder;
///
/// let program = ClassicSampleX86ProgramBuilder::new("sample", false).build();
/// assert!(!program.memory_blocks.is_empty());
/// assert!(!program.function_manager.functions.is_empty());
/// ```
#[derive(Debug)]
pub struct ClassicSampleX86ProgramBuilder {
    /// The program name.
    name: String,
    /// Whether analysis is disabled.
    disable_analysis: bool,
    /// Memory blocks to create: (name, start_hex, size).
    memory_blocks: Vec<(String, u64, u64)>,
    /// External references.
    external_refs: Vec<ExternalRefSpec>,
    /// Functions.
    functions: Vec<SampleFunctionSpec>,
    /// Labels (non-function).
    labels: Vec<LabelSpec>,
    /// Memory references (xrefs).
    mem_refs: Vec<MemRefSpec>,
    /// Comments.
    comments: Vec<CommentSpec>,
    /// Data type applications.
    data_types: Vec<DataTypeSpec>,
    /// Raw bytes set in the program: (address, bytes).
    bytes: Vec<(u64, Vec<u8>)>,
}

impl ClassicSampleX86ProgramBuilder {
    /// Create a new classic sample x86 program builder.
    ///
    /// When `disable_analysis` is true, the analysis manager will not be
    /// attached to the resulting program.
    pub fn new(name: &str, disable_analysis: bool) -> Self {
        let mut builder = Self {
            name: name.to_string(),
            disable_analysis,
            memory_blocks: Vec::new(),
            external_refs: Vec::new(),
            functions: Vec::new(),
            labels: Vec::new(),
            mem_refs: Vec::new(),
            comments: Vec::new(),
            data_types: Vec::new(),
            bytes: Vec::new(),
        };
        builder.setup_sample_program();
        builder
    }

    /// Create with default name "sample" and analysis enabled.
    pub fn default_sample() -> Self {
        Self::new("sample", false)
    }

    /// Create with default name "sample" and analysis disabled.
    pub fn default_sample_no_analysis() -> Self {
        Self::new("sample", true)
    }

    /// Set up the predefined sample program content.
    fn setup_sample_program(&mut self) {
        // -- Memory blocks (.text regions) --
        self.memory_blocks
            .push((".text".to_string(), 0x01001000, 0x6600));
        self.memory_blocks
            .push((".text".to_string(), 0x01008000, 0x600));
        self.memory_blocks
            .push((".text".to_string(), 0x0100a000, 0x5400));
        self.memory_blocks
            .push((".text".to_string(), 0xf0000248, 0xa8));
        self.memory_blocks
            .push((".text".to_string(), 0xf0001300, 0x1c));

        // -- External references --
        self.external_refs.push(ExternalRefSpec {
            address: 0x01001000,
            library: "ADVAPI32.dll".to_string(),
            external_name: "IsTextUnicode".to_string(),
            offset: 0,
            label: "ADVAPI32.dll_IsTextUnicode".to_string(),
        });
        self.external_refs.push(ExternalRefSpec {
            address: 0x01001004,
            library: "ADVAPI32.dll".to_string(),
            external_name: "RegCreateKeyW".to_string(),
            offset: 0,
            label: "ADVAPI32.dll_RegCreateKeyW".to_string(),
        });
        self.external_refs.push(ExternalRefSpec {
            address: 0x01001008,
            library: "ADVAPI32.dll".to_string(),
            external_name: "RegQueryValueExW".to_string(),
            offset: 0,
            label: "ADVAPI32.dll_RegQueryValueExW".to_string(),
        });
        self.external_refs.push(ExternalRefSpec {
            address: 0x010012f4,
            library: "comdlg32.dll".to_string(),
            external_name: "CommDlgExtendedError".to_string(),
            offset: 0,
            label: "comdlg32.dll_CommDlgExtendedError".to_string(),
        });

        // -- Memory references (xrefs) --
        self.mem_refs.push(MemRefSpec {
            from: 0x010063cc,
            to: 0x01001000,
            ref_type: RefType::Indirection,
            source: SourceType::Default,
        });
        self.mem_refs.push(MemRefSpec {
            from: 0x010030d2,
            to: 0x010012f4,
            ref_type: RefType::Indirection,
            source: SourceType::Default,
        });
        self.mem_refs.push(MemRefSpec {
            from: 0x01004930,
            to: 0x010049f9,
            ref_type: RefType::ConditionalJump,
            source: SourceType::Analysis,
        });

        // -- Functions --
        self.functions.push(SampleFunctionSpec {
            entry: 0x01006420,
            name: "entry".to_string(),
            body_start: 0x01006420,
            body_end: 0x010065aa,
            label: Some("entry".to_string()),
            is_entry: true,
        });
        self.functions.push(SampleFunctionSpec {
            entry: 0x0100415a,
            name: "sscanf".to_string(),
            body_start: 0x0100415a,
            body_end: 0x010041a7,
            label: Some("sscanf".to_string()),
            is_entry: false,
        });
        self.functions.push(SampleFunctionSpec {
            entry: 0x0100248f,
            name: "func_248f".to_string(),
            body_start: 0x0100248f,
            body_end: 0x0100294d,
            label: None,
            is_entry: false,
        });
        self.functions.push(SampleFunctionSpec {
            entry: 0x01002cf5,
            name: "ghidra".to_string(),
            body_start: 0x01002cf5,
            body_end: 0x01002d6e,
            label: Some("ghidra".to_string()),
            is_entry: false,
        });
        self.functions.push(SampleFunctionSpec {
            entry: 0x010048a3,
            name: "doStuff".to_string(),
            body_start: 0x010048a3,
            body_end: 0x010048bd,
            label: Some("doStuff".to_string()),
            is_entry: false,
        });
        self.functions.push(SampleFunctionSpec {
            entry: 0x010059a3,
            name: "func_59a3".to_string(),
            body_start: 0x010059a3,
            body_end: 0x01005c6d,
            label: None,
            is_entry: false,
        });
        self.functions.push(SampleFunctionSpec {
            entry: 0x010030d2,
            name: "func_30d2".to_string(),
            body_start: 0x010030d2,
            body_end: 0x010030d7,
            label: None,
            is_entry: false,
        });
        self.functions.push(SampleFunctionSpec {
            entry: 0x01002239,
            name: "func_2239".to_string(),
            body_start: 0x01002239,
            body_end: 0x0100248c,
            label: None,
            is_entry: false,
        });

        // -- Labels (non-function) --
        self.labels.push(LabelSpec {
            address: 0x01001160,
            name: "MSVCRT.dll___set_app_type".to_string(),
        });
        self.labels.push(LabelSpec {
            address: 0x01002d1f,
            name: "MyLocal".to_string(),
        });
        self.labels.push(LabelSpec {
            address: 0x01002d2b,
            name: "AnotherLocal".to_string(),
        });
        self.labels.push(LabelSpec {
            address: 0x0100eb90,
            name: "rsrc_String_4_5c8".to_string(),
        });
        self.labels.push(LabelSpec {
            address: 0x0100f1d0,
            name: "rsrc_String_6_64".to_string(),
        });

        // -- Comments --
        self.comments.push(CommentSpec {
            address: 0x0100415a,
            text: "Repeatable Comment".to_string(),
            comment_type: CommentType::Repeatable,
        });

        // -- Raw bytes (selective samples) --
        // External pointer bytes
        self.bytes.push((0x01001000, vec![0x85, 0x4f, 0xdc, 0x77]));
        self.bytes.push((0x01001004, vec![0xb0, 0x90, 0xdb, 0x77]));
        self.bytes.push((0x01001008, vec![0x9c, 0x1d, 0xb4, 0x76]));
        self.bytes.push((0x010012f4, vec![0x9c, 0x1d, 0xb4, 0x76]));

        // String data
        self.bytes.push((
            0x0100750e,
            b"RegisterClassExW\0".to_vec(),
        ));
        self.bytes.push((
            0x01006a02,
            b"ChooseFontW\0".to_vec(),
        ));
        self.bytes.push((
            0x01006a10,
            b"ReplaceTextW\0".to_vec(),
        ));

        // Float/double test data
        self.bytes.push((0x010085a7, vec![0x00, 0xef, 0xbb, 0xbf]));
        self.bytes.push((0x010085a9, vec![0xbb, 0xbf, 0x00, 0xff, 0xfe, 0x00, 0x00, 0xfe]));
    }

    /// Build the program.
    ///
    /// Constructs a [`Program`] with all the predefined memory blocks,
    /// functions, labels, comments, bytes, and cross-references.
    pub fn build(self) -> Program {
        let lang = test_processor_constants::x86_language();
        let mut program = Program::new(&self.name, lang);
        program.executable_format = Some("PE".to_string());

        // Create memory blocks
        let mut block_id = 0u32;
        for (block_name, start, size) in &self.memory_blocks {
            let block = MemoryBlock {
                name: format!("{}_{}", block_name, block_id),
                start: Address::new(*start),
                size: *size,
                is_initialized: true,
                is_read: true,
                is_write: true,
                is_execute: true,
            };
            program.memory_blocks.push(block);
            block_id += 1;
        }

        // Set raw bytes into the program
        for (addr, ref data) in &self.bytes {
            program.set_bytes(Address::new(*addr), data);
        }

        // Create external references (labels + symbols for external stubs)
        for ext in &self.external_refs {
            program
                .symbols
                .insert(Address::new(ext.address), ext.label.clone());
        }

        // Create functions
        for func_spec in &self.functions {
            let mut body = AddressSet::new();
            body.add_range(AddressRange::new(
                Address::new(func_spec.body_start),
                Address::new(func_spec.body_end),
            ));
            let func = Function {
                entry_point: Address::new(func_spec.entry),
                name: Some(func_spec.name.clone()),
                body,
                is_external: false,
                is_thunk: false,
                is_inline: false,
                has_noreturn: false,
                call_fixup: None,
            };
            program
                .function_manager
                .functions
                .insert(Address::new(func_spec.entry), func);

            // Add label at function entry if specified
            if let Some(ref label) = func_spec.label {
                program
                    .symbols
                    .insert(Address::new(func_spec.entry), label.clone());
            }
        }

        // Create non-function labels
        for label_spec in &self.labels {
            program
                .symbols
                .insert(Address::new(label_spec.address), label_spec.name.clone());
        }

        // Record comments
        for comment_spec in &self.comments {
            program.comments.insert(
                Address::new(comment_spec.address),
                comment_spec.text.clone(),
            );
        }

        // Record cross-references
        for mem_ref in &self.mem_refs {
            program.references.push(crate::base::analyzer::core::Reference {
                from: Address::new(mem_ref.from),
                to: Address::new(mem_ref.to),
                ref_type: mem_ref.ref_type.clone(),
                source: mem_ref.source,
            });
        }

        program
    }

    /// Get the list of function entry addresses that will be created.
    pub fn function_entries(&self) -> Vec<u64> {
        self.functions.iter().map(|f| f.entry).collect()
    }

    /// Get the list of external reference addresses.
    pub fn external_ref_addresses(&self) -> Vec<u64> {
        self.external_refs.iter().map(|e| e.address).collect()
    }

    /// Get the total number of memory blocks that will be created.
    pub fn memory_block_count(&self) -> usize {
        self.memory_blocks.len()
    }

    /// Get the total number of functions that will be created.
    pub fn function_count(&self) -> usize {
        self.functions.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_builder_creates_program() {
        let program = ClassicSampleX86ProgramBuilder::new("test_sample", false).build();
        assert_eq!(program.name, "test_sample");
        assert!(!program.memory_blocks.is_empty());
        assert!(!program.function_manager.functions.is_empty());
    }

    #[test]
    fn test_builder_default_sample() {
        let program = ClassicSampleX86ProgramBuilder::default_sample().build();
        assert_eq!(program.name, "sample");
    }

    #[test]
    fn test_builder_memory_blocks() {
        let builder = ClassicSampleX86ProgramBuilder::new("test", false);
        assert_eq!(builder.memory_block_count(), 5);

        let program = builder.build();
        assert_eq!(program.memory_blocks.len(), 5);
    }

    #[test]
    fn test_builder_functions() {
        let builder = ClassicSampleX86ProgramBuilder::new("test", false);
        assert_eq!(builder.function_count(), 8);

        let program = builder.build();
        assert_eq!(program.function_manager.functions.len(), 8);
    }

    #[test]
    fn test_builder_entry_function() {
        let program = ClassicSampleX86ProgramBuilder::new("test", false).build();
        let entry = program
            .function_manager
            .functions
            .get(&Address::new(0x01006420));
        assert!(entry.is_some());
        let entry = entry.unwrap();
        assert_eq!(entry.name, Some("entry".to_string()));
        assert!(entry.is_entry());
    }

    #[test]
    fn test_builder_symbols() {
        let program = ClassicSampleX86ProgramBuilder::new("test", false).build();
        // External ref labels
        assert!(program.symbols.get(&Address::new(0x01001000)).is_some());
        assert!(program.symbols.get(&Address::new(0x01001004)).is_some());
        // Non-function labels
        assert!(program.symbols.get(&Address::new(0x01002d1f)).is_some());
        assert_eq!(
            program.symbols.get(&Address::new(0x01002d1f)).unwrap(),
            "MyLocal"
        );
    }

    #[test]
    fn test_builder_external_refs() {
        let builder = ClassicSampleX86ProgramBuilder::new("test", false);
        let addrs = builder.external_ref_addresses();
        assert_eq!(addrs.len(), 4);
        assert!(addrs.contains(&0x01001000));
        assert!(addrs.contains(&0x010012f4));
    }

    #[test]
    fn test_builder_comments() {
        let program = ClassicSampleX86ProgramBuilder::new("test", false).build();
        let comment = program.comments.get(&Address::new(0x0100415a));
        assert!(comment.is_some());
        assert_eq!(comment.unwrap(), "Repeatable Comment");
    }

    #[test]
    fn test_builder_executable_format() {
        let program = ClassicSampleX86ProgramBuilder::new("test", false).build();
        assert_eq!(program.executable_format, Some("PE".to_string()));
    }

    #[test]
    fn test_builder_function_entries() {
        let builder = ClassicSampleX86ProgramBuilder::new("test", false);
        let entries = builder.function_entries();
        assert!(entries.contains(&0x01006420)); // entry
        assert!(entries.contains(&0x0100415a)); // sscanf
        assert!(entries.contains(&0x01002cf5)); // ghidra
        assert!(entries.contains(&0x010048a3)); // doStuff
    }

    #[test]
    fn test_builder_disable_analysis_flag() {
        let builder_no_analysis = ClassicSampleX86ProgramBuilder::new("test", true);
        assert!(builder_no_analysis.disable_analysis);

        let builder_with_analysis = ClassicSampleX86ProgramBuilder::new("test", false);
        assert!(!builder_with_analysis.disable_analysis);
    }
}
