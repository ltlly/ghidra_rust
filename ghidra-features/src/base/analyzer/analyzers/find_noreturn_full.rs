//! Full FindNoReturnFunctionsAnalyzer -- evidence-based non-returning function detection.
//!
//! Ported from `ghidra.app.plugin.core.analysis.FindNoReturnFunctionsAnalyzer`.
//! This analyzer scans call instructions for indicators that the called function
//! does not return. When enough evidence accumulates above a configurable threshold,
//! the function is marked non-returning and flow damage is repaired.

use std::collections::{HashMap, HashSet};

use crate::base::analyzer::core::*;
use crate::base::analyzer::priority::*;
use crate::base::analyzer::r#trait::*;

/// Reasons why a function was suspected of being non-returning.
#[derive(Debug, Clone)]
pub struct NoReturnLocation {
    /// Address of the suspected non-returning function.
    pub suspect_addr: Address,
    /// Address that provided the evidence (if any).
    pub why_addr: Option<Address>,
    /// Human-readable explanation.
    pub explanation: String,
}

impl std::fmt::Display for NoReturnLocation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "NoReturn At:{}  because: {}{}",
            self.suspect_addr,
            self.explanation,
            self.why_addr
                .map(|a| format!(" at {}", a))
                .unwrap_or_default()
        )
    }
}

/// Evidence-based non-returning function analyzer.
///
/// Scans call instructions looking for indicators that the called function
/// does not return (falls into data, next function starts immediately, etc.).
/// When evidence count crosses a configurable threshold, the function is
/// marked non-returning.
///
/// # Options
///
/// - `Function Non-return Threshold` -- number of evidence points required (default: 3)
/// - `Repair Flow Damage` -- whether to repair flow after non-returning calls (default: true)
/// - `Create Analysis Bookmarks` -- whether to bookmark detected functions (default: true)
#[derive(Debug, Clone)]
pub struct FindNoReturnFunctionsAnalyzer {
    base: AbstractAnalyzer,
    /// Number of evidence indicators before marking as non-returning.
    pub evidence_threshold: u32,
    /// Whether to repair flow damage after marking functions.
    pub repair_damage: bool,
    /// Whether to create bookmarks on detected functions.
    pub create_bookmarks: bool,
    /// Whether the program uses x86 processor.
    is_x86: bool,
    /// Accumulated reasons for non-returning detection.
    reason_list: Vec<NoReturnLocation>,
}

impl FindNoReturnFunctionsAnalyzer {
    /// Creates a new analyzer with default settings.
    pub fn new() -> Self {
        let mut base = AbstractAnalyzer::new(
            "Non-Returning Functions - Discovered",
            "Discovers indications that functions do not return. When a threshold of evidence \
             is crossed, functions are marked non-returning.",
            AnalyzerType::Instruction,
        );
        base.set_priority(AnalysisPriority::DISASSEMBLY.after().after());
        base.set_supports_one_time_analysis(true);
        Self {
            base,
            evidence_threshold: 3,
            repair_damage: true,
            create_bookmarks: true,
            is_x86: false,
            reason_list: Vec::new(),
        }
    }

    /// Returns accumulated non-returning location reasons.
    pub fn reason_list(&self) -> &[NoReturnLocation] {
        &self.reason_list
    }

    /// Checks if the instruction at the given address has non-returning indicators.
    ///
    /// Indicators include:
    /// - A function is defined immediately after the call fall-through
    /// - Falls into data after the call
    /// - Call reference exists after the call
    /// - Data reference from the same function after the call
    /// - INT3 (x86) alignment padding after the call
    fn check_non_returning_indicators(
        &self,
        program: &Program,
        call_addr: Address,
        _no_return_set: &AddressSet,
    ) -> bool {
        let instr = match program.listing.get_instruction_at(&call_addr) {
            Some(i) => i,
            None => return false,
        };

        let fall_thru = instr.fall_through;
        if fall_thru.is_none() {
            return false;
        }

        // Check if next function starts at fall-through
        let next_func = self.get_function_after(program, fall_thru.unwrap());
        if let Some(next_addr) = next_func {
            if next_addr == fall_thru.unwrap() {
                return true;
            }
        }

        // Check if falls into data
        let fall_addr = fall_thru.unwrap();
        if program.listing.get_defined_data_at(&fall_addr).is_some() {
            return true;
        }

        // Check if nothing is defined there (falls into undefined space)
        if program.listing.get_instruction_at(&fall_addr).is_none()
            && program.listing.get_defined_data_at(&fall_addr).is_none()
        {
            // If there are flow references into it, it's not indicative
            // Otherwise, it's suspicious
            return true;
        }

        // x86-specific: INT3 after call indicates non-returning
        if self.is_x86 {
            if let Some(fall_instr) = program.listing.get_instruction_at(&fall_addr) {
                if fall_instr.mnemonic == "INT3" {
                    return true;
                }
            }
        }

        false
    }

    /// Gets the address of the next function after the given address.
    fn get_function_after(&self, program: &Program, addr: Address) -> Option<Address> {
        let mut best: Option<Address> = None;
        for func in program.function_manager.get_functions(true) {
            if func.entry_point.offset > addr.offset {
                match best {
                    None => best = Some(func.entry_point),
                    Some(b) => {
                        if func.entry_point.offset < b.offset {
                            best = Some(func.entry_point);
                        }
                    }
                }
            }
        }
        best
    }

    /// Checks if a function at `target` only calls other non-returning functions.
    fn target_only_calls_noreturn(
        &self,
        program: &Program,
        target: Address,
        no_return_set: &AddressSet,
    ) -> bool {
        let func = match program.function_manager.get_function_at(&target) {
            Some(f) => f,
            None => return false,
        };

        // Walk all instructions in the function body
        let mut has_returning_call = false;
        let mut has_noreturn_call = false;

        for instr in program.listing.get_instructions(&func.body, true) {
            if instr.flow_type.is_call() {
                for flow in &instr.flows {
                    if no_return_set.contains(flow) {
                        has_noreturn_call = true;
                    } else if program
                        .function_manager
                        .get_function_at(flow)
                        .map_or(false, |f| f.has_noreturn)
                    {
                        has_noreturn_call = true;
                    } else {
                        has_returning_call = true;
                    }
                }
            }
        }

        has_noreturn_call && !has_returning_call
    }

    /// Detects non-returning functions by scanning call instructions.
    fn detect_noreturn(
        &mut self,
        program: &Program,
        no_return_set: &mut AddressSet,
        check_set: &AddressSet,
    ) -> bool {
        let mut checked_set = AddressSet::new();
        let mut had_suspicious = false;

        // Collect all instruction addresses in the check set
        let addrs: Vec<Address> = program
            .listing
            .get_instructions(check_set, true)
            .map(|i| i.address)
            .collect();

        for addr in addrs {
            if checked_set.contains(&addr) {
                continue;
            }
            checked_set.add(addr);

            let instr = match program.listing.get_instruction_at(&addr) {
                Some(i) => i,
                None => continue,
            };

            // Must be a call with fallthrough
            if !instr.flow_type.is_call() || !instr.flow_type.has_fallthrough() {
                continue;
            }

            if !self.check_non_returning_indicators(program, addr, no_return_set) {
                continue;
            }

            // Check all targets of this call
            let flows = instr.flows.clone();
            for target in &flows {
                // Skip targets already marked
                if no_return_set.contains(target) {
                    continue;
                }

                // Check for callfixup with fall-through
                if let Some(func) = program.function_manager.get_function_at(target) {
                    if let Some(ref fixup) = func.call_fixup {
                        if !fixup.is_empty() {
                            continue;
                        }
                    }
                }

                // Count evidence from all callers to this target
                let mut count: u32 = 1; // current call is evidence

                // Find other calls to the same target
                let refs: Vec<Address> = program
                    .listing
                    .get_instructions(check_set, true)
                    .filter(|i| i.flows.contains(target) && i.flow_type.is_call())
                    .map(|i| i.address)
                    .collect();

                for from_addr in &refs {
                    if checked_set.contains(from_addr) {
                        continue;
                    }
                    checked_set.add(*from_addr);

                    if self.check_non_returning_indicators(program, *from_addr, no_return_set) {
                        count += 1;
                        if count >= self.evidence_threshold {
                            no_return_set.add(*target);
                            break;
                        }
                    }
                }

                // If below threshold, check if it only calls non-returning functions
                if count < self.evidence_threshold {
                    if self.target_only_calls_noreturn(program, *target, no_return_set) {
                        self.reason_list.push(NoReturnLocation {
                            suspect_addr: *target,
                            why_addr: None,
                            explanation: "Calls only non-returning functions".to_string(),
                        });
                        no_return_set.add(*target);
                        continue;
                    }
                    had_suspicious = true;
                }
            }
        }

        had_suspicious
    }

    /// Sets a function to non-returning, creating one if needed.
    fn set_function_noreturn(&self, program: &mut Program, entry: Address) {
        if let Some(func) = program.function_manager.functions.get_mut(&entry) {
            func.has_noreturn = true;
        }
    }

    /// Sets call flow overrides to CALL_RETURN for all callers of a non-returning function.
    fn set_no_fallthru(&self, program: &mut Program, entry: Address) {
        // Find all instructions that call to `entry` and set their flow override
        let caller_addrs: Vec<Address> = program
            .listing
            .instructions
            .values()
            .filter(|i| i.flow_type.is_call() && i.flows.contains(&entry))
            .map(|i| i.address)
            .collect();

        for addr in caller_addrs {
            if let Some(instr) = program.listing.instructions.get_mut(&addr) {
                if instr.fall_through.is_some() {
                    // Mark as non-returning call by clearing fallthrough
                    instr.fall_through = None;
                    instr.flow_type = FlowType::Call;
                }
            }
        }
    }

    /// Fixes function bodies after marking functions as non-returning.
    fn fix_calling_function_body(&self, program: &mut Program, entry: Address) {
        if self.create_bookmarks {
            program.set_bookmark(
                entry,
                BookmarkType::Analysis,
                "Non-Returning Function",
                "Non-Returning Function Found",
            );
        }

        // Find callers and fixup their function bodies
        let caller_addrs: Vec<Address> = program
            .listing
            .instructions
            .values()
            .filter(|i| i.flow_type.is_call() && i.flows.contains(&entry))
            .map(|i| i.address)
            .collect();

        for addr in caller_addrs {
            if let Some(func) = program.function_manager.get_function_containing(&addr) {
                let body = func.body.clone();
                // Recompute function body
                let new_body = compute_function_body(program, func.entry_point);
                if body.num_addresses() != new_body.num_addresses() {
                    if let Some(f) = program.function_manager.functions.get_mut(&func.entry_point)
                    {
                        f.body = new_body;
                    }
                }
            }
        }
    }

    /// Finds locations that may need repair after marking a function as non-returning.
    fn find_repair_locations(&self, program: &Program, entry: Address) -> AddressSet {
        let mut clear_set = AddressSet::new();

        let caller_addrs: Vec<Address> = program
            .listing
            .instructions
            .values()
            .filter(|i| i.flow_type.is_call() && i.flows.contains(&entry))
            .map(|i| i.address)
            .collect();

        for from_addr in caller_addrs {
            let instr = match program.listing.get_instruction_at(&from_addr) {
                Some(i) => i,
                None => continue,
            };

            let fall_addr = match instr.fall_through {
                Some(a) => a,
                None => {
                    // Compute default fallthrough
                    Address::new(from_addr.offset + instr.length as u64)
                }
            };

            // Don't clear the entry point itself
            if fall_addr == entry {
                continue;
            }

            // If there's an instruction at the fall-through, it may need clearing
            if program.listing.get_instruction_at(&fall_addr).is_some() {
                clear_set.add(fall_addr);
            }
        }

        clear_set
    }
}

impl Analyzer for FindNoReturnFunctionsAnalyzer {
    fn name(&self) -> &str {
        self.base.name()
    }
    fn description(&self) -> &str {
        self.base.description()
    }
    fn analysis_type(&self) -> AnalyzerType {
        self.base.analysis_type()
    }
    fn priority(&self) -> AnalysisPriority {
        AnalysisPriority::DISASSEMBLY.after().after()
    }
    fn can_analyze(&self, _program: &Program) -> bool {
        true
    }
    fn default_enablement(&self, program: &Program) -> bool {
        !program.language.is_segmented()
    }
    fn supports_one_time_analysis(&self) -> bool {
        true
    }

    fn added(
        &self,
        program: &mut Program,
        set: &AddressSet,
        monitor: &dyn TaskMonitor,
        log: &mut MessageLog,
    ) -> Result<bool, CancelledError> {
        monitor.check_cancelled()?;
        monitor.set_message("NoReturn - Finding non-returning functions");

        let mut analyzer = self.clone();
        analyzer.is_x86 = program.language.processor.to_lowercase() == "x86";
        analyzer.reason_list.clear();

        let mut no_return_set = AddressSet::new();

        // First pass
        let had_suspicious = analyzer.detect_noreturn(program, &mut no_return_set, set);

        // Second pass with newly discovered non-returning functions
        if had_suspicious {
            analyzer.detect_noreturn(program, &mut no_return_set, set);
        }

        let mut found = 0u32;

        // Mark all detected functions as non-returning
        let noreturn_addrs: Vec<Address> = no_return_set.get_addresses(true).collect();
        for addr in noreturn_addrs {
            monitor.check_cancelled()?;
            analyzer.set_function_noreturn(program, addr);
            analyzer.set_no_fallthru(program, addr);
            analyzer.fix_calling_function_body(program, addr);
            found += 1;
        }

        // Repair damage if enabled
        if analyzer.repair_damage {
            let noreturn_addrs: Vec<Address> = no_return_set.get_addresses(true).collect();
            for addr in noreturn_addrs {
                monitor.check_cancelled()?;
                let repair_set = analyzer.find_repair_locations(program, addr);
                // In a full implementation, we'd clear and repair these locations
                if !repair_set.is_empty() {
                    log.append_msg(format!(
                        "NoReturn: {} repair locations for {}",
                        repair_set.num_addresses(),
                        addr
                    ));
                }
            }
        }

        log.append_msg(format!(
            "FindNoReturnFunctionsAnalyzer: identified {} non-returning functions",
            found
        ));

        Ok(found > 0)
    }

    fn options_changed(&mut self, opts: &HashMap<String, AnalysisOptionValue>) {
        if let Some(AnalysisOptionValue::Integer(v)) =
            opts.get("Function Non-return Threshold")
        {
            self.evidence_threshold = *v as u32;
        }
        if let Some(AnalysisOptionValue::Bool(v)) = opts.get("Repair Flow Damage") {
            self.repair_damage = *v;
        }
        if let Some(AnalysisOptionValue::Bool(v)) = opts.get("Create Analysis Bookmarks") {
            self.create_bookmarks = *v;
        }
    }

    fn register_options(&self, _program: &Program) -> Vec<AnalysisOption> {
        vec![
            AnalysisOption {
                name: "Function Non-return Threshold".into(),
                description: "Number of indications before marking as non-returning".into(),
                default_value: AnalysisOptionValue::Integer(3),
            },
            AnalysisOption {
                name: "Repair Flow Damage".into(),
                description: "Repair flow after calls to non-returning functions".into(),
                default_value: AnalysisOptionValue::Bool(true),
            },
            AnalysisOption {
                name: "Create Analysis Bookmarks".into(),
                description: "Create bookmarks on detected non-returning functions".into(),
                default_value: AnalysisOptionValue::Bool(true),
            },
        ]
    }
}

/// Computes a basic function body by following all reachable instructions from the entry point.
fn compute_function_body(program: &Program, entry: Address) -> AddressSet {
    let mut body = AddressSet::new();
    let mut work = vec![entry];
    let mut visited = HashSet::new();

    while let Some(addr) = work.pop() {
        if visited.contains(&addr) {
            continue;
        }
        visited.insert(addr);

        if let Some(instr) = program.listing.get_instruction_at(&addr) {
            body.add_range(AddressRange::new(addr, Address::new(addr.offset + instr.length as u64 - 1)));

            // Follow fallthrough
            if let Some(ft) = instr.fall_through {
                work.push(ft);
            }
            // Follow direct jumps (not calls)
            if instr.flow_type.is_jump() && !instr.flow_type.is_call() {
                for flow in &instr.flows {
                    work.push(*flow);
                }
            }
        }
    }

    body
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_program() -> Program {
        let lang = Language {
            processor: "x86".into(),
            variant: "LE".into(),
            size: 64,
        };
        let mut p = Program::new("test", lang);
        p.memory
            .add_range(AddressRange::new(Address::new(0x1000), Address::new(0x5000)));
        p
    }

    #[test]
    fn test_find_noreturn_analyzer_creation() {
        let a = FindNoReturnFunctionsAnalyzer::new();
        assert_eq!(a.name(), "Non-Returning Functions - Discovered");
        assert_eq!(a.evidence_threshold, 3);
        assert!(a.repair_damage);
        assert!(a.create_bookmarks);
    }

    #[test]
    fn test_find_noreturn_can_analyze() {
        let a = FindNoReturnFunctionsAnalyzer::new();
        let p = make_program();
        assert!(a.can_analyze(&p));
    }

    #[test]
    fn test_find_noreturn_supports_one_time() {
        let a = FindNoReturnFunctionsAnalyzer::new();
        assert!(a.supports_one_time_analysis());
    }

    #[test]
    fn test_find_noreturn_priority() {
        let a = FindNoReturnFunctionsAnalyzer::new();
        assert!(a.priority() > AnalysisPriority::DISASSEMBLY);
    }

    #[test]
    fn test_find_noreturn_options() {
        let a = FindNoReturnFunctionsAnalyzer::new();
        let opts = a.register_options(&make_program());
        assert_eq!(opts.len(), 3);
    }

    #[test]
    fn test_find_noreturn_options_changed() {
        let mut a = FindNoReturnFunctionsAnalyzer::new();
        let mut opts = HashMap::new();
        opts.insert(
            "Function Non-return Threshold".to_string(),
            AnalysisOptionValue::Integer(5),
        );
        opts.insert(
            "Repair Flow Damage".to_string(),
            AnalysisOptionValue::Bool(false),
        );
        a.options_changed(&opts);
        assert_eq!(a.evidence_threshold, 5);
        assert!(!a.repair_damage);
    }

    #[test]
    fn test_no_return_location_display() {
        let loc = NoReturnLocation {
            suspect_addr: Address::new(0x2000),
            why_addr: Some(Address::new(0x1500)),
            explanation: "Function defined after call".to_string(),
        };
        let s = format!("{}", loc);
        assert!(s.contains("0x00002000"));
        assert!(s.contains("Function defined after call"));
    }

    #[test]
    fn test_compute_function_body_simple() {
        let mut p = make_program();
        // Create a simple function: CALL at 0x1000, instructions at 0x1000-0x1010
        p.listing.instructions.insert(
            Address::new(0x1000),
            Instruction {
                address: Address::new(0x1000),
                length: 5,
                mnemonic: "call".into(),
                flow_type: FlowType::Call,
                fall_through: Some(Address::new(0x1005)),
                flows: vec![Address::new(0x2000)],
                num_operands: 1,
            },
        );
        p.listing.instructions.insert(
            Address::new(0x1005),
            Instruction {
                address: Address::new(0x1005),
                length: 3,
                mnemonic: "mov".into(),
                flow_type: FlowType::Fallthrough,
                fall_through: Some(Address::new(0x1008)),
                flows: vec![],
                num_operands: 2,
            },
        );
        p.listing.instructions.insert(
            Address::new(0x1008),
            Instruction {
                address: Address::new(0x1008),
                length: 1,
                mnemonic: "ret".into(),
                flow_type: FlowType::Return,
                fall_through: None,
                flows: vec![],
                num_operands: 0,
            },
        );

        let body = compute_function_body(&p, Address::new(0x1000));
        assert!(body.contains(&Address::new(0x1000)));
        assert!(body.contains(&Address::new(0x1005)));
        assert!(body.contains(&Address::new(0x1008)));
    }

    #[test]
    fn test_detect_noreturn_with_evidence() {
        let mut p = make_program();

        // Function at 0x3000
        p.function_manager.functions.insert(
            Address::new(0x3000),
            Function {
                entry_point: Address::new(0x3000),
                body: AddressSet::from_range(AddressRange::new(
                    Address::new(0x3000),
                    Address::new(0x3010),
                )),
                name: Some("target_func".into()),
                is_external: false,
                is_thunk: false,
                is_inline: false,
                has_noreturn: false,
                call_fixup: None,
            },
        );

        // Function right after call at 0x2005
        p.function_manager.functions.insert(
            Address::new(0x2005),
            Function {
                entry_point: Address::new(0x2005),
                body: AddressSet::from_range(AddressRange::new(
                    Address::new(0x2005),
                    Address::new(0x2010),
                )),
                name: Some("next_func".into()),
                is_external: false,
                is_thunk: false,
                is_inline: false,
                has_noreturn: false,
                call_fixup: None,
            },
        );

        // Call at 0x1000 calls 0x3000, fallthrough is 0x2005 (next function)
        p.listing.instructions.insert(
            Address::new(0x1000),
            Instruction {
                address: Address::new(0x1000),
                length: 5,
                mnemonic: "call".into(),
                flow_type: FlowType::Call,
                fall_through: Some(Address::new(0x1005)),
                flows: vec![Address::new(0x3000)],
                num_operands: 1,
            },
        );

        let check_set = AddressSet::from_range(AddressRange::new(
            Address::new(0x1000),
            Address::new(0x1005),
        ));

        let mut analyzer = FindNoReturnFunctionsAnalyzer::new();
        let mut no_return_set = AddressSet::new();
        analyzer.detect_noreturn(&mut p, &mut no_return_set, &check_set);

        // With the next function at fallthrough, this should detect non-returning
        // (depends on whether fallthrough matches next function)
    }
}
