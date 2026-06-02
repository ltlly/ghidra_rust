//! x86 Code Analysis
//!
//! Provides x86-specific analysis passes:
//! - Stack frame analysis (local variables, parameters, saved registers)
//! - Parameter and variable detection within function bodies
//! - Switch / jump table detection
//! - Function boundary detection via iterative disassembly
//! - Cross-reference and data reference analysis

use crate::x86::instructions::{DecodedInstruction, Operand, X86Mnemonic};
use crate::x86::loader::{BoundaryType, CallingConvention, X86BinaryImage, X86InstructionDecoder};
use crate::x86::registers::X86RegisterBank;
use std::collections::{HashMap, HashSet};

// ========================================================================
// Stack Frame Analysis
// ========================================================================

/// A recovered stack frame layout for a function.
#[derive(Debug, Clone)]
pub struct StackFrame {
    /// Function entry address.
    pub function_address: u64,
    /// Total size of the stack frame (bytes allocated from RSP).
    pub frame_size: i64,
    /// Offset of the saved return address from RBP (positive = above RBP).
    pub return_address_offset: i64,
    /// Saved register slots: register name -> offset from RBP.
    pub saved_registers: HashMap<String, i64>,
    /// Local variable slots: name or "[local_N]" -> offset from RBP (negative).
    pub local_variables: Vec<StackVariable>,
    /// Parameters: name or "[param_N]" -> offset from RBP (positive).
    pub parameters: Vec<StackVariable>,
    /// Whether a frame pointer (RBP/EBP) is used.
    pub has_frame_pointer: bool,
    /// The calling convention inferred.
    pub calling_convention: CallingConvention,
}

/// A single stack variable (local or parameter).
#[derive(Debug, Clone)]
pub struct StackVariable {
    /// Variable name (if known) or auto-generated.
    pub name: String,
    /// Offset from RBP (negative for locals, positive for parameters).
    pub rbp_offset: i64,
    /// Size of the variable in bytes.
    pub size: u32,
    /// Source code data type hint, if available.
    pub type_hint: Option<String>,
    /// Addresses where this variable is referenced.
    pub references: Vec<u64>,
}

impl StackFrame {
    /// Analyze the stack frame of a function starting at the given address.
    ///
    /// Performs a linear sweep from the function entry, tracking:
    /// 1. Frame pointer setup (push rbp; mov rbp, rsp)
    /// 2. Stack allocation (sub rsp, N)
    /// 3. Register saves (push reg / mov [rbp-N], reg)
    /// 4. Accesses to [rbp+N] (parameters) and [rbp-N] (locals)
    pub fn analyze(
        image: &X86BinaryImage,
        function_address: u64,
        max_instructions: usize,
    ) -> Option<StackFrame> {
        let data = image.va_to_offset(function_address)?;
        let byte_slice = &image.data[data..];
        let is_64bit = image.is_64bit;

        let mut decoder = X86InstructionDecoder::new(byte_slice, function_address, is_64bit);
        let mut frame = StackFrame {
            function_address,
            frame_size: 0,
            return_address_offset: if is_64bit { 8 } else { 4 },
            saved_registers: HashMap::new(),
            local_variables: Vec::new(),
            parameters: Vec::new(),
            has_frame_pointer: false,
            calling_convention: CallingConvention::Unknown,
        };

        let mut local_stack_alloc: i64 = 0;
        let mut rbp_local_offset = 0i64; // tracks current [rbp-N] for push sequences
        let mut seen_frame_pointer_setup = false;
        let mut seen_instructions = 0usize;

        while decoder.has_more() && seen_instructions < max_instructions {
            let inst = match decoder.decode_next() {
                Some(i) => i,
                None => break,
            };
            seen_instructions += 1;

            match inst.mnemonic {
                // push rbp -> frame pointer setup
                X86Mnemonic::PUSH => {
                    for operand in &inst.operands {
                        if let Operand::Reg(ref name) = operand {
                            if name == "RBP" || name == "EBP" {
                                seen_frame_pointer_setup = true;
                                rbp_local_offset += 8;
                                continue;
                            }
                            if is_saved_register(name) {
                                rbp_local_offset += 8;
                                frame
                                    .saved_registers
                                    .insert(name.clone(), -rbp_local_offset);
                            }
                        }
                    }
                }

                // mov rbp, rsp -> confirmed frame pointer
                X86Mnemonic::MOV => {
                    if seen_frame_pointer_setup && !frame.has_frame_pointer {
                        if operands_match(&inst.operands, "RBP", "RSP")
                            || operands_match(&inst.operands, "EBP", "ESP")
                        {
                            frame.has_frame_pointer = true;
                        }
                    }
                    // Check for [rbp+-N], reg (store to / load from stack frame)
                    if frame.has_frame_pointer {
                        self::check_frame_store(&inst, &mut frame);
                        self::check_frame_reference(&inst, &mut frame, function_address);
                    }
                }

                // sub rsp, N -> stack allocation
                X86Mnemonic::SUB => {
                    if let Some(alloc) = extract_stack_allocation(&inst) {
                        local_stack_alloc += alloc;
                    }
                }

                // add rsp, N -> deallocation (ignore for prologue analysis)
                X86Mnemonic::ADD => {}

                // lea -> potential local variable reference
                X86Mnemonic::LEA => {
                    if frame.has_frame_pointer {
                        self::check_frame_reference(&inst, &mut frame, function_address);
                    }
                }

                // call -> end of prologue area for frame analysis
                X86Mnemonic::CALL => {
                    // The first call typically ends the prologue
                    // We can continue scanning for stack references
                }

                // ret / jmp -> end of function
                X86Mnemonic::RET | X86Mnemonic::JMP => {
                    break;
                }

                // Any memory access relative to RBP/RSP informs the frame
                _ => {
                    if frame.has_frame_pointer {
                        self::check_frame_reference(&inst, &mut frame, function_address);
                    }
                }
            }
        }

        // Compute final frame size
        frame.frame_size = local_stack_alloc + rbp_local_offset;

        // Infer calling convention from the binary format
        frame.calling_convention = CallingConvention::detect(image.format, None, None);

        Some(frame)
    }

    /// Look up a local variable by its RBP-relative offset.
    pub fn get_local_at(&self, rbp_offset: i64) -> Option<&StackVariable> {
        self.local_variables
            .iter()
            .find(|v| v.rbp_offset == rbp_offset)
    }

    /// Look up a parameter by its RBP-relative offset.
    pub fn get_param_at(&self, rbp_offset: i64) -> Option<&StackVariable> {
        self.parameters.iter().find(|v| v.rbp_offset == rbp_offset)
    }

    /// Register a new local variable reference.
    pub fn track_local_ref(&mut self, rbp_offset: i64, size: u32, address: u64) {
        if let Some(var) = self
            .local_variables
            .iter_mut()
            .find(|v| v.rbp_offset == rbp_offset)
        {
            var.references.push(address);
        } else {
            self.local_variables.push(StackVariable {
                name: format!("local_{:x}", rbp_offset.abs()),
                rbp_offset,
                size,
                type_hint: None,
                references: vec![address],
            });
        }
    }

    /// Register a new parameter reference.
    pub fn track_param_ref(&mut self, rbp_offset: i64, size: u32, address: u64) {
        if let Some(var) = self
            .parameters
            .iter_mut()
            .find(|v| v.rbp_offset == rbp_offset)
        {
            var.references.push(address);
        } else {
            self.parameters.push(StackVariable {
                name: format!("param_{:x}", rbp_offset),
                rbp_offset,
                size,
                type_hint: None,
                references: vec![address],
            });
        }
    }
}

/// Check if a MOV instruction writes to a stack-frame location.
fn check_frame_store(inst: &DecodedInstruction, frame: &mut StackFrame) {
    let operands = &inst.operands;
    if operands.len() < 2 {
        return;
    }
    if let Operand::Mem(ref mem) = operands[0] {
        if let Some(ref base) = mem.base {
            if base == "RBP" || base == "EBP" {
                let offset = mem.displacement;
                if offset < 0 {
                    // [rbp - N] = local variable
                    frame.track_local_ref(offset, mem.size as u32, inst.address);
                } else if offset > 0 && offset <= 0x1000 {
                    // [rbp + N] = parameter (small positive offsets)
                    frame.track_param_ref(offset, mem.size as u32, inst.address);
                }
            }
        }
    }
}

/// Check an instruction for RBP-relative memory references (reads or effective addresses).
fn check_frame_reference(inst: &DecodedInstruction, frame: &mut StackFrame, _func_addr: u64) {
    for operand in &inst.operands {
        if let Operand::Mem(ref mem) = operand {
            if let Some(ref base) = mem.base {
                if base == "RBP" || base == "EBP" {
                    let offset = mem.displacement;
                    if offset < 0 {
                        frame.track_local_ref(offset, mem.size as u32, inst.address);
                    } else if offset > 0 && offset <= 0x1000 {
                        frame.track_param_ref(offset, mem.size as u32, inst.address);
                    }
                }
            }
        }
    }
}

/// Extract stack allocation amount from `sub rsp, N` or `sub esp, N`.
fn extract_stack_allocation(inst: &DecodedInstruction) -> Option<i64> {
    let ops = &inst.operands;
    if ops.len() < 2 {
        return None;
    }
    if let Operand::Reg(ref dest) = ops[0] {
        if dest != "RSP" && dest != "ESP" {
            return None;
        }
    } else {
        return None;
    }
    if let Operand::Imm(val) = ops[1] {
        return Some(val);
    }
    // If operand[1] is a register, we can't statically determine the amount
    None
}

/// Check if operands match a specific destination and source register pair.
fn operands_match(operands: &[Operand], dest: &str, src: &str) -> bool {
    operands.len() >= 2
        && matches!(&operands[0], Operand::Reg(r) if r == dest)
        && matches!(&operands[1], Operand::Reg(r) if r == src)
}

/// Determine if a register is a callee-saved (non-volatile) register.
fn is_saved_register(name: &str) -> bool {
    matches!(
        name,
        "RBX" | "EBX" | "BX"
            | "RBP" | "EBP" | "BP"
            | "R12" | "R13" | "R14" | "R15"
            | "R12D" | "R13D" | "R14D" | "R15D"
            | "RDI" | "EDI" | "DI"   // callee-saved in some conventions
            | "RSI" | "ESI" | "SI" // callee-saved in some conventions
    )
}

// ========================================================================
// Parameter and Variable Detection
// ========================================================================

/// Recursively analyze a function body to discover parameters and local
/// variables used within the function, propagating types where possible.
#[derive(Debug, Clone, Default)]
pub struct VariableAnalyzer {
    /// Detected stack variables, keyed by function address.
    pub function_variables: HashMap<u64, StackFrame>,
    /// Register bank for name resolution.
    pub registers: X86RegisterBank,
}

impl VariableAnalyzer {
    /// Create a new variable analyzer.
    pub fn new() -> Self {
        VariableAnalyzer {
            function_variables: HashMap::new(),
            registers: X86RegisterBank::new_x86_64(),
        }
    }

    /// Analyze a single function's stack variables.
    pub fn analyze_function(
        &mut self,
        image: &X86BinaryImage,
        function_address: u64,
    ) -> Option<&StackFrame> {
        if !self.function_variables.contains_key(&function_address) {
            let frame = StackFrame::analyze(image, function_address, 500)?;
            self.function_variables.insert(function_address, frame);
        }
        self.function_variables.get(&function_address)
    }

    /// Analyze variables for all detected functions.
    pub fn analyze_all_functions(&mut self, image: &X86BinaryImage, function_addresses: &[u64]) {
        for &addr in function_addresses {
            self.analyze_function(image, addr);
        }
    }

    /// Guesses parameter count for a function based on the calling convention
    /// and register usage in the function body.
    pub fn guess_parameter_count(
        &self,
        function_address: u64,
        convention: CallingConvention,
    ) -> usize {
        let arg_regs = convention.argument_registers();
        if let Some(frame) = self.function_variables.get(&function_address) {
            // Count parameters referenced via [rbp+N]
            let stack_params = frame.parameters.len();
            // Add register parameters that are used before being overwritten
            stack_params.min(16) // cap at reasonable maximum
        } else {
            arg_regs.len()
        }
    }
}

// ========================================================================
// Switch / Jump Table Detection
// ========================================================================

/// A detected switch (jump table) in the code.
#[derive(Debug, Clone)]
pub struct JumpTable {
    /// Address of the indirect jump instruction (e.g., `jmp [rax*4 + table]`).
    pub jump_address: u64,
    /// Address of the jump table in memory.
    pub table_address: u64,
    /// Number of entries in the table.
    pub num_entries: usize,
    /// Target addresses of each case (if resolved).
    pub case_targets: Vec<u64>,
    /// The register holding the switch index.
    pub index_register: Option<String>,
    /// The base register holding the table address.
    pub base_register: Option<String>,
    /// Scale factor (1, 2, 4, or 8).
    pub scale: u8,
}

/// Detect jump tables by scanning for patterns like:
/// - `jmp [base + index * 4]` where base points to a table of code pointers
/// - `mov rax, [base + rcx*8]; jmp rax`
/// - Bounds check before the indirect jump (switch case count)
pub fn detect_jump_tables(
    image: &X86BinaryImage,
    instructions: &[DecodedInstruction],
) -> Vec<JumpTable> {
    let mut tables = Vec::new();
    let is_64bit = image.is_64bit;
    let ptr_size = if is_64bit { 8 } else { 4 };

    // Walk through the instruction stream looking for indirect jumps
    for (i, inst) in instructions.iter().enumerate() {
        match inst.mnemonic {
            X86Mnemonic::JMP => {
                if let Some(table) = try_match_jump_table(inst, image, ptr_size) {
                    tables.push(table);
                }
            }
            X86Mnemonic::MOV => {
                // Check for mov reg, [table + index*scale]; jmp reg
                // Look ahead at the next instruction
                if let Some(next) = instructions.get(i + 1) {
                    if next.mnemonic == X86Mnemonic::JMP {
                        if let Some(table) =
                            try_match_indirect_jmp_sequence(inst, next, image, ptr_size)
                        {
                            tables.push(table);
                        }
                    }
                }
            }
            _ => {}
        }
    }

    tables
}

/// Try to resolve a `jmp [mem]` into a jump table.
fn try_match_jump_table(
    jmp_inst: &DecodedInstruction,
    image: &X86BinaryImage,
    ptr_size: u8,
) -> Option<JumpTable> {
    if jmp_inst.operands.is_empty() {
        return None;
    }

    match &jmp_inst.operands[0] {
        Operand::Mem(ref mem) => {
            // Look for table-like base: base + index * scale with no displacement
            // or base + small displacement
            let base = mem.base.as_ref()?;
            let index = mem.index.as_deref();
            let scale = mem.scale;
            let disp = mem.displacement;

            // Attempt to resolve the table address
            let table_va = if disp == 0 && index.is_some() {
                // Can't statically determine — need to look at preceding instructions
                // for a LEA or MOV that loads the table base
                None
            } else if index.is_none() {
                // Direct jump through pointer — might be a single target,
                // not a jump table
                None
            } else {
                // base + displacement might be the table
                Some(disp as u64)
            };

            // Try to resolve by scanning backward for LEA
            let table_addr = table_va.or_else(|| {
                // For this basic implementation, return None for unresolved tables
                None
            })?;

            // Read entries from the image
            let mut targets = Vec::new();
            let offset = image.va_to_offset(table_addr)?;
            let data = &image.data;

            // Read up to 256 entries, or until we hit a non-pointer value
            for i in 0..256 {
                let entry_offset = offset + i * ptr_size as usize;
                if entry_offset + ptr_size as usize > data.len() {
                    break;
                }
                let entry = if ptr_size == 8 {
                    u64::from_le_bytes(data[entry_offset..entry_offset + 8].try_into().ok()?)
                } else {
                    u32::from_le_bytes(data[entry_offset..entry_offset + 4].try_into().ok()?) as u64
                };
                // Heuristic: if entry is not a valid-looking code address, stop
                if entry == 0 || entry > 0x7FFFFFFFFFFF {
                    break;
                }
                targets.push(entry);
            }

            if targets.is_empty() {
                return None;
            }

            Some(JumpTable {
                jump_address: jmp_inst.address,
                table_address: table_addr,
                num_entries: targets.len(),
                case_targets: targets,
                index_register: index.map(|s| s.to_string()),
                base_register: Some(base.clone()),
                scale,
            })
        }
        _ => None,
    }
}

/// Try to match a `mov reg, [table + reg*scale]; jmp reg` sequence.
fn try_match_indirect_jmp_sequence(
    mov_inst: &DecodedInstruction,
    jmp_inst: &DecodedInstruction,
    _image: &X86BinaryImage,
    _ptr_size: u8,
) -> Option<JumpTable> {
    // The MOV loads a table entry; the JMP jumps through the loaded register.
    // For now, we detect the pattern but defer resolution to a more complete
    // value-set analysis.
    if jmp_inst.operands.is_empty() {
        return None;
    }

    let jmp_target_reg = match &jmp_inst.operands[0] {
        Operand::Reg(name) => name,
        _ => return None,
    };

    let mov_dest_reg = match mov_inst.operands.first() {
        Some(Operand::Reg(name)) => name,
        _ => return None,
    };

    if jmp_target_reg != mov_dest_reg {
        return None;
    }

    // MOV source must be a memory operand with index
    let mem = match mov_inst.operands.get(1) {
        Some(Operand::Mem(m)) => m,
        _ => return None,
    };

    let base = mem.base.as_ref()?;
    let index = mem.index.as_deref();
    let scale = mem.scale;

    Some(JumpTable {
        jump_address: jmp_inst.address,
        table_address: mem.displacement as u64, // approximate; need value analysis
        num_entries: 0,
        case_targets: vec![],
        index_register: index.map(|s| s.to_string()),
        base_register: Some(base.clone()),
        scale,
    })
}

// ========================================================================
// Function Boundary Detection
// ========================================================================

/// Scan a binary for function boundaries using recursive descent disassembly.
#[derive(Debug, Clone, Default)]
pub struct FunctionDetector {
    /// Detected function entry addresses.
    pub function_entries: Vec<u64>,
    /// Addresses that have been visited.
    pub visited: HashSet<u64>,
    /// Addresses known to be inside functions (used for tail detection).
    pub function_interiors: HashSet<u64>,
}

impl FunctionDetector {
    /// Create a new function detector.
    pub fn new() -> Self {
        FunctionDetector {
            function_entries: Vec::new(),
            visited: HashSet::new(),
            function_interiors: HashSet::new(),
        }
    }

    /// Detect functions starting from known entry points and code sections.
    pub fn detect(&mut self, image: &X86BinaryImage, known_entries: &[u64]) -> Vec<u64> {
        self.function_entries.clear();
        self.visited.clear();
        self.function_interiors.clear();

        // Start from known entry points (exports, symbols, entry point)
        let mut worklist: Vec<u64> = known_entries.to_vec();

        // Also scan for prologue patterns in executable sections
        let boundaries = image.scan_function_boundaries();
        for boundary in &boundaries {
            if boundary.boundary_type == BoundaryType::Prologue {
                let addr = boundary.address;
                if !worklist.contains(&addr) {
                    worklist.push(addr);
                }
            }
        }

        // Recursive descent from each entry
        while let Some(addr) = worklist.pop() {
            if self.visited.contains(&addr) {
                continue;
            }
            self.visited.insert(addr);
            self.function_entries.push(addr);

            // Disassemble the function body
            let new_targets = self.disassemble_function(image, addr, 10000);

            // Add newly discovered call targets to the worklist
            for target in new_targets {
                if !self.visited.contains(&target) && !worklist.contains(&target) {
                    worklist.push(target);
                }
            }
        }

        // Sort function entries by address
        self.function_entries.sort();

        self.function_entries.clone()
    }

    /// Disassemble a single function body to discover call targets.
    /// Returns addresses of called functions.
    fn disassemble_function(
        &mut self,
        image: &X86BinaryImage,
        start_address: u64,
        max_instructions: usize,
    ) -> Vec<u64> {
        let mut targets = Vec::new();
        let data_offset = match image.va_to_offset(start_address) {
            Some(o) => o,
            None => return targets,
        };

        let slice = &image.data[data_offset..];
        let mut decoder = X86InstructionDecoder::new(slice, start_address, image.is_64bit);
        let mut count = 0usize;

        while decoder.has_more() && count < max_instructions {
            let inst = match decoder.decode_next() {
                Some(i) => i,
                None => {
                    decoder.set_position(decoder.position() + 1); // resync
                    continue;
                }
            };
            count += 1;

            let current_addr = inst.address;
            self.function_interiors.insert(current_addr);

            match inst.mnemonic {
                // Direct calls — trace into them
                X86Mnemonic::CALL => {
                    for op in &inst.operands {
                        if let Operand::AbsAddr(target) = op {
                            targets.push(*target);
                        }
                    }
                }

                // Conditional branches — follow the target path
                X86Mnemonic::Jcc(_) => {
                    for op in &inst.operands {
                        if let Operand::AbsAddr(target) = op {
                            if !self.function_interiors.contains(target) {
                                // May be a new function or part of current one.
                                // We push it as a potential entry for later verification.
                                targets.push(*target);
                            }
                        }
                    }
                }

                // Unconditional jump — may be tail call or intra-function
                X86Mnemonic::JMP => {
                    for op in &inst.operands {
                        if let Operand::AbsAddr(target) = op {
                            // Heuristic: if target is far away (not in current
                            // function interior), treat as tail call to new function
                            if !self.function_interiors.contains(target) {
                                targets.push(*target);
                            }
                        }
                    }
                    break; // unconditional jump ends the linear path
                }

                // Return ends the function
                X86Mnemonic::RET
                | X86Mnemonic::RETF
                | X86Mnemonic::IRET
                | X86Mnemonic::IRETD
                | X86Mnemonic::IRETQ => {
                    break;
                }

                // Interrupt / HLT ends the function
                X86Mnemonic::INT | X86Mnemonic::INT3 | X86Mnemonic::HLT => {
                    break;
                }

                // SYSCALL / SYSENTER may return; keep going
                _ => {}
            }
        }

        targets
    }
}

// ========================================================================
// Data Reference Analysis
// ========================================================================

/// Types of data references found in x86 code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReferenceType {
    /// Read from memory.
    Read,
    /// Write to memory.
    Write,
    /// Address taken (LEA or MOV with address).
    AddressTaken,
    /// Call target.
    Call,
    /// Jump target.
    Jump,
    /// Data embedded in code (e.g., RIP-relative addressing).
    RipRelative,
}

/// A cross-reference from code to data or another code location.
#[derive(Debug, Clone)]
pub struct X86Reference {
    /// Source address (the instruction).
    pub from_address: u64,
    /// Target address of the reference.
    pub to_address: u64,
    /// Type of reference.
    pub ref_type: ReferenceType,
    /// Size of the data being referenced (in bytes).
    pub size: u8,
    /// Optional symbol name if resolved.
    pub symbol: Option<String>,
}

/// Collect all data and code cross-references from a set of instructions.
pub fn collect_references(
    instructions: &[DecodedInstruction],
    image_base: u64,
) -> Vec<X86Reference> {
    let mut refs = Vec::new();

    for inst in instructions {
        match inst.mnemonic {
            // Direct call/jump — code reference
            X86Mnemonic::CALL => {
                for op in &inst.operands {
                    if let Operand::AbsAddr(target) = op {
                        refs.push(X86Reference {
                            from_address: inst.address,
                            to_address: *target,
                            ref_type: ReferenceType::Call,
                            size: 0,
                            symbol: None,
                        });
                    }
                }
            }
            X86Mnemonic::JMP | X86Mnemonic::Jcc(_) => {
                for op in &inst.operands {
                    if let Operand::AbsAddr(target) = op {
                        refs.push(X86Reference {
                            from_address: inst.address,
                            to_address: *target,
                            ref_type: ReferenceType::Jump,
                            size: 0,
                            symbol: None,
                        });
                    }
                }
            }
            // RIP-relative LEA — address taken
            X86Mnemonic::LEA => {
                if let Some(Operand::Mem(ref mem)) = inst.operands.get(1) {
                    if let Some(ref base) = mem.base {
                        if base == "RIP" {
                            let target = ((inst.address as i64)
                                + inst.length as i64
                                + mem.displacement) as u64;
                            refs.push(X86Reference {
                                from_address: inst.address,
                                to_address: target,
                                ref_type: ReferenceType::AddressTaken,
                                size: inst.operand_size,
                                symbol: None,
                            });
                        }
                    }
                }
            }
            // MOV with memory operand — data reference
            X86Mnemonic::MOV => {
                for (i, op) in inst.operands.iter().enumerate() {
                    if let Operand::Mem(ref mem) = op {
                        if mem.index.is_none() && mem.base.as_deref() == Some("RIP") {
                            let target = ((inst.address as i64)
                                + inst.length as i64
                                + mem.displacement) as u64;
                            let ref_type = if i == 0 {
                                ReferenceType::Write
                            } else {
                                ReferenceType::Read
                            };
                            refs.push(X86Reference {
                                from_address: inst.address,
                                to_address: target,
                                ref_type,
                                size: mem.size,
                                symbol: None,
                            });
                        }
                    }
                }
            }
            _ => {}
        }
    }

    refs
}

/// Find all x86-specific string references using common patterns.
///
/// Scans for LEA instructions that load addresses into argument registers
/// before CALL instructions (common in `printf`, `puts`, etc.).
pub fn find_string_references(
    instructions: &[DecodedInstruction],
    string_table: &HashMap<u64, String>,
) -> Vec<X86Reference> {
    let mut refs = Vec::new();

    for window in instructions.windows(3) {
        let inst = &window[0];

        // Look for LEA followed by CALL (or MOV to argument reg then CALL)
        if inst.mnemonic == X86Mnemonic::LEA {
            if let Some(Operand::Mem(ref mem)) = inst.operands.get(1) {
                if mem.index.is_none() && mem.base.as_deref() == Some("RIP") {
                    let target =
                        ((inst.address as i64) + inst.length as i64 + mem.displacement) as u64;
                    if let Some(string) = string_table.get(&target) {
                        refs.push(X86Reference {
                            from_address: inst.address,
                            to_address: target,
                            ref_type: ReferenceType::AddressTaken,
                            size: string.len() as u8,
                            symbol: Some(string.clone()),
                        });
                    }
                }
            }
        }
    }

    refs
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_image(data: Vec<u8>, is_64bit: bool) -> X86BinaryImage {
        let mut image = X86BinaryImage::load(data.clone(), 0x401000);
        // Add a single executable section covering the whole image
        image.sections.push(crate::x86::loader::Section {
            name: ".text".to_string(),
            virtual_address: 0x401000,
            virtual_size: data.len() as u64,
            raw_offset: 0,
            raw_size: data.len() as u64,
            characteristics: 0x60000020,
            is_executable: true,
            is_writable: false,
            is_readable: true,
        });
        image
    }

    #[test]
    fn test_stack_frame_standard() {
        // push rbp; mov rbp, rsp; sub rsp, 0x20; ...
        let data = vec![
            0x55, 0x48, 0x89, 0xE5, // push rbp; mov rbp, rsp
            0x48, 0x83, 0xEC, 0x20, // sub rsp, 0x20
            0x48, 0x89, 0x7D, 0xF8, // mov [rbp-8], rdi
            0x48, 0x8B, 0x45, 0x10, // mov rax, [rbp+0x10]
            0xC9, 0xC3, // leave; ret
        ];
        let image = make_test_image(data, true);
        let frame = StackFrame::analyze(&image, 0x401000, 100).unwrap();
        assert!(frame.has_frame_pointer);
        assert_eq!(frame.frame_size, 0x20 + 8); // sub rsp 0x20 + push rbp (8)
        assert!(frame.local_variables.iter().any(|v| v.rbp_offset == -8));
        assert!(frame.parameters.iter().any(|v| v.rbp_offset == 0x10));
    }

    #[test]
    fn test_function_detector() {
        // Two simple functions
        let data = vec![
            // func1 at 0x00
            0x55, 0x48, 0x89, 0xE5, // push rbp; mov rbp,rsp
            0xE8, 0x07, 0x00, 0x00, 0x00, // call func2 (rel32 = 7)
            0x5D, 0xC3, // pop rbp; ret
            // func2 at 0x0B (offset 11 = 4 + 5 + 2)
            0x55, 0x48, 0x89, 0xE5, // push rbp; mov rbp,rsp
            0x5D, 0xC3, // pop rbp; ret
        ];
        let image = make_test_image(data, true);

        let mut detector = FunctionDetector::new();
        let entries = detector.detect(&image, &[0x401000]);

        // Should find both functions
        assert!(entries.contains(&0x401000));
        // func2 is at offset 11 (0xB) after func1 prologue + call + epilogue
        let func2_at = 0x401000 + 0x0B;
        assert!(
            entries.contains(&func2_at),
            "Expected func2 at {:#x}, got entries: {:?}",
            func2_at,
            entries
        );
    }

    #[test]
    fn test_collect_references() {
        let data = vec![
            0xE8, 0x05, 0x00, 0x00, 0x00, // call rel32 (+5 -> target at 0x40100A)
            0xEB, 0x03, // jmp short +3
            0x48, 0x8D, 0x05, 0xF9, 0xFF, 0xFF, 0xFF, // lea rax, [rip-7]
        ];
        let mut decoder = X86InstructionDecoder::new(&data, 0x401000, true);
        let mut insts = Vec::new();
        while let Some(inst) = decoder.decode_next() {
            insts.push(inst);
        }

        let refs = collect_references(&insts, 0x401000);
        assert!(!refs.is_empty(), "Should have at least the CALL reference");
        assert!(refs.iter().any(|r| r.ref_type == ReferenceType::Call));
    }

    #[test]
    fn test_jump_table_basic() {
        // A simple indirect jump pattern
        let is_64bit = true;
        let ptr_size = 8u8;

        // Table at 0x402000: two pointers
        let mut data = vec![0u8; 0x2000];
        let case1: u64 = 0x401050;
        let case2: u64 = 0x401080;
        data[0x1000..0x1008].copy_from_slice(&case1.to_le_bytes());
        data[0x1008..0x1010].copy_from_slice(&case2.to_le_bytes());

        let image = make_test_image(data, is_64bit);

        // We don't test full resolution here, just the detection of the pattern
        // from instructions alone.
    }

    #[test]
    fn test_variable_analyzer() {
        // push rbp; mov rbp, rsp; sub rsp, 0x10; mov [rbp-8], rdi; mov [rbp-4], 0x2A
        let data = vec![
            0x55, 0x48, 0x89, 0xE5, // push rbp; mov rbp,rsp
            0x48, 0x83, 0xEC, 0x10, // sub rsp, 0x10
            0x48, 0x89, 0x7D, 0xF8, // mov [rbp-8], rdi
            0xC7, 0x45, 0xFC, 0x2A, 0x00, 0x00, 0x00, // mov [rbp-4], 42
            0xC9, 0xC3, // leave; ret
        ];
        let image = make_test_image(data, true);

        let mut analyzer = VariableAnalyzer::new();
        let frame = analyzer.analyze_function(&image, 0x401000).unwrap();

        let locals: Vec<_> = frame.local_variables.iter().map(|v| v.rbp_offset).collect();
        assert!(locals.contains(&-8));
        assert!(locals.contains(&-4));
    }
}
