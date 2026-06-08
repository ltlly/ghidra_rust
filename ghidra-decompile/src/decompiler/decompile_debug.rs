#![allow(dead_code)]
//! DecompileDebug: debug container for decompiler/database communication.
//!
//! Port of Ghidra's `ghidra.app.decompiler.DecompileDebug`.

use std::collections::BTreeMap;

use ghidra_core::addr::Address;

/// A container for debugging the communication between the decompiler
/// and the Ghidra database, as serviced through DecompileCallback during
/// decompilation of a function.
///
/// The query results can be dumped as an XML document for analysis.
/// The container is populated through methods that mirror the various
/// methods in DecompileCallback.
#[derive(Debug, Clone)]
pub struct DecompileDebug {
    /// Entry point address of the function being decompiled.
    function_entry: Option<Address>,
    /// Name of the function being decompiled.
    function_name: Option<String>,
    /// Name of the program.
    program_name: Option<String>,
    /// Debug file path.
    _debug_file: Option<String>,
    /// Local extensions to the compiler spec.
    _spec_extensions: BTreeMap<String, String>,
    /// Database scope entries.
    database_scope: Vec<DatabaseScopeEntry>,
    /// Data type entries.
    data_types: Vec<DataTypeEntry>,
    /// Context register entries.
    context_registers: Vec<ContextRegisterEntry>,
    /// Memory bytes.
    memory_bytes: BTreeMap<u64, Vec<u8>>,
    /// Symbol table entries.
    symbol_table: Vec<SymbolEntry>,
    /// Warning/error messages.
    messages: Vec<String>,
}

/// A database scope entry.
#[derive(Debug, Clone)]
pub struct DatabaseScopeEntry {
    /// Address range start.
    pub address: Address,
    /// Size in bytes.
    pub size: u32,
    /// Scope name.
    pub name: String,
}

/// A data type entry.
#[derive(Debug, Clone)]
pub struct DataTypeEntry {
    /// Data type name.
    pub name: String,
    /// Data type id.
    pub id: u64,
    /// Size in bytes.
    pub size: u32,
}

/// A context register entry.
#[derive(Debug, Clone)]
pub struct ContextRegisterEntry {
    /// Register name.
    pub name: String,
    /// Register value.
    pub value: u64,
    /// Address where the context is valid.
    pub address: Address,
}

/// A symbol table entry.
#[derive(Debug, Clone)]
pub struct SymbolEntry {
    /// Symbol name.
    pub name: String,
    /// Symbol address.
    pub address: Address,
    /// Symbol namespace.
    pub namespace: Option<String>,
}

impl DecompileDebug {
    /// Create a new DecompileDebug.
    pub fn new() -> Self {
        Self {
            function_entry: None,
            function_name: None,
            program_name: None,
            _debug_file: None,
            _spec_extensions: BTreeMap::new(),
            database_scope: Vec::new(),
            data_types: Vec::new(),
            context_registers: Vec::new(),
            memory_bytes: BTreeMap::new(),
            symbol_table: Vec::new(),
            messages: Vec::new(),
        }
    }

    /// Set the function being decompiled.
    pub fn set_function(&mut self, entry: Address, name: &str) {
        self.function_entry = Some(entry);
        self.function_name = Some(name.to_string());
    }

    /// Set the program name.
    pub fn set_program(&mut self, name: &str) {
        self.program_name = Some(name.to_string());
    }

    /// Add a database scope entry.
    pub fn add_database_scope(&mut self, entry: DatabaseScopeEntry) {
        self.database_scope.push(entry);
    }

    /// Add a data type entry.
    pub fn add_data_type(&mut self, entry: DataTypeEntry) {
        self.data_types.push(entry);
    }

    /// Add a context register entry.
    pub fn add_context_register(&mut self, entry: ContextRegisterEntry) {
        self.context_registers.push(entry);
    }

    /// Store memory bytes at the given address.
    pub fn store_memory_bytes(&mut self, address: u64, bytes: Vec<u8>) {
        self.memory_bytes.insert(address, bytes);
    }

    /// Add a symbol entry.
    pub fn add_symbol(&mut self, entry: SymbolEntry) {
        self.symbol_table.push(entry);
    }

    /// Add a warning message.
    pub fn add_message(&mut self, msg: &str) {
        self.messages.push(msg.to_string());
    }

    /// Get the function entry point.
    pub fn function_entry(&self) -> Option<Address> {
        self.function_entry
    }

    /// Get the function name.
    pub fn function_name(&self) -> Option<&str> {
        self.function_name.as_deref()
    }

    /// Get all messages.
    pub fn messages(&self) -> &[String] {
        &self.messages
    }

    /// Dump the debug data as XML.
    pub fn to_xml(&self) -> String {
        let mut xml = String::from("<?xml version=\"1.0\"?>\n<decompile_debug>\n");

        if let Some(ref name) = self.function_name {
            xml.push_str(&format!("  <function name=\"{}\"", name));
            if let Some(entry) = self.function_entry {
                xml.push_str(&format!(" entry=\"0x{:x}\"", entry.offset));
            }
            xml.push_str("/>\n");
        }

        if !self.data_types.is_empty() {
            xml.push_str("  <datatypes>\n");
            for dt in &self.data_types {
                xml.push_str(&format!(
                    "    <datatype name=\"{}\" id=\"{}\" size=\"{}\"/>\n",
                    dt.name, dt.id, dt.size
                ));
            }
            xml.push_str("  </datatypes>\n");
        }

        if !self.messages.is_empty() {
            xml.push_str("  <messages>\n");
            for msg in &self.messages {
                xml.push_str(&format!("    <message>{}</message>\n", msg));
            }
            xml.push_str("  </messages>\n");
        }

        xml.push_str("</decompile_debug>\n");
        xml
    }
}

impl Default for DecompileDebug {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decompile_debug_new() {
        let debug = DecompileDebug::new();
        assert!(debug.function_entry().is_none());
        assert!(debug.function_name().is_none());
        assert!(debug.messages().is_empty());
    }

    #[test]
    fn test_set_function() {
        let mut debug = DecompileDebug::new();
        debug.set_function(Address::new(0x1000), "main");
        assert_eq!(debug.function_entry(), Some(Address::new(0x1000)));
        assert_eq!(debug.function_name(), Some("main"));
    }

    #[test]
    fn test_add_messages() {
        let mut debug = DecompileDebug::new();
        debug.add_message("warning 1");
        debug.add_message("warning 2");
        assert_eq!(debug.messages().len(), 2);
    }

    #[test]
    fn test_to_xml() {
        let mut debug = DecompileDebug::new();
        debug.set_function(Address::new(0x1000), "main");
        debug.add_data_type(DataTypeEntry {
            name: "int".to_string(),
            id: 1,
            size: 4,
        });
        let xml = debug.to_xml();
        assert!(xml.contains("<function"));
        assert!(xml.contains("main"));
        assert!(xml.contains("<datatype"));
    }

    #[test]
    fn test_memory_bytes() {
        let mut debug = DecompileDebug::new();
        debug.store_memory_bytes(0x1000, vec![0x55, 0x89, 0xe5]);
        assert_eq!(debug.memory_bytes.get(&0x1000), Some(&vec![0x55, 0x89, 0xe5]));
    }

    #[test]
    fn test_symbol_table() {
        let mut debug = DecompileDebug::new();
        debug.add_symbol(SymbolEntry {
            name: "main".to_string(),
            address: Address::new(0x1000),
            namespace: Some("Global".to_string()),
        });
        assert_eq!(debug.symbol_table.len(), 1);
    }
}
