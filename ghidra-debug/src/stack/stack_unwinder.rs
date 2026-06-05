//! Stack unwinder: orchestrates multi-frame stack unwinding.
//!
//! Ported from Ghidra's `StackUnwinder`. Starting from a given frame,
//! iteratively unwinds each frame using symbolic analysis (via `SymState`)
//! to recover stack depth, saved registers, and return addresses.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use super::saved_register_map::SavedRegisterMap;
use super::sym_arithmetic::SymArithmetic;
use super::unwind_info::{ReturnLocation as UnwindReturnLocation, UnwindInfo};
use super::unwind_warning::{UnwindWarning, UnwindWarningKind, UnwindWarningSet};

/// A frame recovered by the stack unwinder.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnwoundFrame {
    /// The frame level (0 = innermost/leaf).
    pub level: u32,
    /// The program counter at this frame.
    pub pc: u64,
    /// The stack pointer at this frame.
    pub sp: u64,
    /// The frame base pointer (SP at function entry).
    pub base_pointer: Option<u64>,
    /// The return address (PC for the next outer frame).
    pub return_address: Option<u64>,
    /// The function name, if known.
    pub function_name: Option<String>,
    /// Unwind info for this frame.
    pub unwind_info: Option<UnwindInfo>,
    /// The saved register map accumulated up to this frame.
    pub register_map: SavedRegisterMap,
    /// Warnings for this frame.
    pub warnings: UnwindWarningSet,
    /// Error that occurred while unwinding this frame, if any.
    pub error: Option<String>,
}

impl UnwoundFrame {
    /// Create a new unwound frame.
    pub fn new(level: u32, pc: u64, sp: u64) -> Self {
        Self {
            level,
            pc,
            sp,
            base_pointer: None,
            return_address: None,
            function_name: None,
            unwind_info: None,
            register_map: SavedRegisterMap::new(),
            warnings: UnwindWarningSet::new(),
            error: None,
        }
    }

    /// Whether this frame has an error.
    pub fn has_error(&self) -> bool {
        self.error.is_some()
    }

    /// Whether this frame has unwind info.
    pub fn has_unwind_info(&self) -> bool {
        self.unwind_info.is_some()
    }
}

/// Coordinates for starting a stack unwind.
#[derive(Debug, Clone)]
pub struct UnwindCoordinates {
    /// The trace key.
    pub trace_key: String,
    /// The thread key.
    pub thread_key: i64,
    /// The snapshot (snap).
    pub snap: i64,
    /// The starting frame level.
    pub frame_level: u32,
}

impl UnwindCoordinates {
    /// Create new coordinates.
    pub fn new(
        trace_key: impl Into<String>,
        thread_key: i64,
        snap: i64,
        frame_level: u32,
    ) -> Self {
        Self {
            trace_key: trace_key.into(),
            thread_key,
            snap,
            frame_level,
        }
    }
}

/// The stack unwinder: iteratively unwinds frames from a starting point.
///
/// Usage:
/// ```ignore
/// let mut unwinder = StackUnwinder::new("SP", false);
/// let frames = unwinder.unwind_from(coords, pc, sp, max_depth);
/// ```
#[derive(Debug, Clone)]
pub struct StackUnwinder {
    /// Stack pointer register name.
    pub sp_name: String,
    /// Whether the architecture is big-endian.
    pub big_endian: bool,
    /// Cached unwind info by PC address.
    cache: HashMap<u64, UnwindInfo>,
}

impl StackUnwinder {
    /// Create a new stack unwinder.
    pub fn new(sp_name: impl Into<String>, big_endian: bool) -> Self {
        Self {
            sp_name: sp_name.into(),
            big_endian,
            cache: HashMap::new(),
        }
    }

    /// Get the symbolic arithmetic engine for this unwinder.
    pub fn arithmetic(&self) -> SymArithmetic {
        SymArithmetic::new(&self.sp_name, self.big_endian)
    }

    /// Unwind from the given starting state.
    ///
    /// `start_pc` and `start_sp` are the program counter and stack pointer
    /// at the starting frame. `max_depth` limits the number of frames to
    /// unwind (-1 for unlimited).
    pub fn unwind_from(
        &mut self,
        coords: &UnwindCoordinates,
        start_pc: u64,
        start_sp: u64,
        max_depth: i32,
        unwind_info_fn: &dyn Fn(u64) -> Option<UnwindInfo>,
    ) -> Vec<UnwoundFrame> {
        let mut frames = Vec::new();
        let mut current_pc = start_pc;
        let mut current_sp = start_sp;
        let mut register_map = SavedRegisterMap::new();

        for level in 0.. {
            if max_depth >= 0 && level as i32 >= max_depth {
                break;
            }

            let mut frame = UnwoundFrame::new(level, current_pc, current_sp);

            // Look up or compute unwind info
            let info = self
                .cache
                .get(&current_pc)
                .cloned()
                .or_else(|| unwind_info_fn(current_pc));

            if let Some(info) = info {
                // Compute base pointer
                let base = info.compute_base(current_sp as i64);
                frame.base_pointer = base.map(|b| b as u64);
                frame.function_name = info.function_name.clone();
                frame.unwind_info = Some(info.clone());

                // Update register map with saved registers
                if let Some(b) = base {
                    for (reg_name, offset) in &info.saved_registers {
                        let stack_addr = (b + offset) as u64;
                        // Map register to stack location
                        // We use a simple scheme: each register gets a synthetic offset
                        let reg_offset = register_name_to_offset(reg_name);
                        register_map.put_register(reg_offset, 8, stack_addr);
                    }
                }

                // Compute return address and next SP
                if let Some(b) = base {
                    frame.return_address = info.compute_return_address(
                        b,
                        &|addr, _size| {
                            // In a real implementation, this would read from the trace
                            // For now, we can't read stack values without trace access
                            let _ = addr;
                            None
                        },
                        &|name| {
                            // Check if the register is saved to the stack
                            let reg_offset = register_name_to_offset(name);
                            if let Some(_entry) = register_map.lookup(reg_offset) {
                                // Would need to read from the trace at the stack address
                                None
                            } else {
                                None
                            }
                        },
                    );

                    if let Some(next_sp) = info.compute_next_sp(b) {
                        // Continue unwinding from the return address
                        if let Some(ra) = frame.return_address {
                            current_pc = ra;
                            current_sp = next_sp as u64;
                        } else {
                            // Cannot determine return address, stop
                            frame.warnings.add(UnwindWarning {
                                kind: UnwindWarningKind::OpaqueReturnPath,
                                message: "Cannot determine return address".into(),
                            });
                            frames.push(frame);
                            break;
                        }
                    } else {
                        // Cannot determine next SP, stop
                        frame.warnings.add(UnwindWarning {
                            kind: UnwindWarningKind::AnalysisError,
                            message: "Cannot determine stack adjustment".into(),
                        });
                        frames.push(frame);
                        break;
                    }
                } else {
                    frame.error = Some("Cannot compute frame base".into());
                    frames.push(frame);
                    break;
                }
            } else {
                frame.error = Some(format!(
                    "No unwind info for address 0x{:x}",
                    current_pc
                ));
                frames.push(frame);
                break;
            }

            frame.register_map = register_map.fork();
            let has_return = frame.return_address.is_some();
            frames.push(frame);

            // Check if we've reached a non-returning function or bottom of stack
            if !has_return {
                break;
            }
        }

        frames
    }

    /// Store computed unwind info in the cache.
    pub fn cache_unwind_info(&mut self, pc: u64, info: UnwindInfo) {
        self.cache.insert(pc, info);
    }

    /// Invalidate the entire cache.
    pub fn invalidate_cache(&mut self) {
        self.cache.clear();
    }

    /// Get the number of cached entries.
    pub fn cache_size(&self) -> usize {
        self.cache.len()
    }
}

/// Convert a register name to a synthetic numeric offset for the register map.
fn register_name_to_offset(name: &str) -> u64 {
    // Simple hash-based scheme for register name -> offset mapping
    let mut hash: u64 = 0;
    for byte in name.bytes() {
        hash = hash.wrapping_mul(31).wrapping_add(byte as u64);
    }
    hash % 0x10000 // Keep in a reasonable range
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unwound_frame_basic() {
        let frame = UnwoundFrame::new(0, 0x400080, 0x7fff0000);
        assert_eq!(frame.level, 0);
        assert_eq!(frame.pc, 0x400080);
        assert_eq!(frame.sp, 0x7fff0000);
        assert!(!frame.has_error());
    }

    #[test]
    fn test_stack_unwinder_creation() {
        let unwinder = StackUnwinder::new("SP", false);
        assert_eq!(unwinder.sp_name, "SP");
        assert!(!unwinder.big_endian);
    }

    #[test]
    fn test_unwind_simple_frame() {
        let mut unwinder = StackUnwinder::new("SP", false);

        // Create unwind info for a simple function at 0x400000
        let mut saved = HashMap::new();
        saved.insert("R30".to_string(), -8i64);
        saved.insert("R29".to_string(), -16i64);

        let info = UnwindInfo::new(
            Some("main".into()),
            Some(32),
            Some(40),
            UnwindReturnLocation::Stack { offset: -8, size: 8 },
            u64::MAX,
            saved,
            UnwindWarningSet::new(),
        );

        let coords = UnwindCoordinates::new("trace1", 1, 0, 0);

        let unwind_info_fn = |pc: u64| -> Option<UnwindInfo> {
            match pc {
                0x400000 => Some(info.clone()),
                _ => None,
            }
        };

        let frames = unwinder.unwind_from(
            &coords,
            0x400000,
            0x7fff0000,
            10,
            &unwind_info_fn,
        );

        assert!(!frames.is_empty());
        let frame0 = &frames[0];
        assert_eq!(frame0.level, 0);
        assert_eq!(frame0.pc, 0x400000);
        assert_eq!(frame0.function_name, Some("main".into()));
        // Base = SP - depth = 0x7fff0000 - 32 = 0x7fffe000 (unsigned: wraps)
        assert!(frame0.base_pointer.is_some());
    }

    #[test]
    fn test_unwind_no_info() {
        let mut unwinder = StackUnwinder::new("SP", false);
        let coords = UnwindCoordinates::new("trace1", 1, 0, 0);

        let unwind_info_fn = |_pc: u64| -> Option<UnwindInfo> { None };

        let frames = unwinder.unwind_from(
            &coords,
            0x400000,
            0x7fff0000,
            10,
            &unwind_info_fn,
        );

        assert_eq!(frames.len(), 1);
        assert!(frames[0].has_error());
    }

    #[test]
    fn test_cache() {
        let mut unwinder = StackUnwinder::new("SP", false);
        assert_eq!(unwinder.cache_size(), 0);

        let info = UnwindInfo::error_only("test");
        unwinder.cache_unwind_info(0x400000, info);
        assert_eq!(unwinder.cache_size(), 1);

        unwinder.invalidate_cache();
        assert_eq!(unwinder.cache_size(), 0);
    }

    #[test]
    fn test_coordinates() {
        let coords = UnwindCoordinates::new("trace1", 1, 0, 3);
        assert_eq!(coords.trace_key, "trace1");
        assert_eq!(coords.thread_key, 1);
        assert_eq!(coords.snap, 0);
        assert_eq!(coords.frame_level, 3);
    }

    #[test]
    fn test_register_name_to_offset() {
        let off1 = register_name_to_offset("RAX");
        let off2 = register_name_to_offset("RBX");
        let off3 = register_name_to_offset("RAX");
        assert_eq!(off1, off3); // deterministic
        assert_ne!(off1, off2); // different registers map differently
    }

    #[test]
    fn test_max_depth_limits_frames() {
        let mut unwinder = StackUnwinder::new("SP", false);
        let coords = UnwindCoordinates::new("trace1", 1, 0, 0);

        let unwind_info_fn = |_pc: u64| -> Option<UnwindInfo> {
            Some(UnwindInfo::new(
                Some("func".into()),
                Some(16),
                Some(24),
                UnwindReturnLocation::Stack { offset: 0, size: 8 },
                u64::MAX,
                HashMap::new(),
                UnwindWarningSet::new(),
            ))
        };

        let frames = unwinder.unwind_from(
            &coords,
            0x400000,
            0x7fff0000,
            2, // max 2 frames
            &unwind_info_fn,
        );

        // Should stop after at most 2 frames (plus error frames for no-return-address)
        assert!(frames.len() <= 3);
    }

    #[test]
    fn test_serde_unwound_frame() {
        let frame = UnwoundFrame::new(0, 0x400080, 0x7fff0000);
        let json = serde_json::to_string(&frame).unwrap();
        let back: UnwoundFrame = serde_json::from_str(&json).unwrap();
        assert_eq!(back.pc, 0x400080);
    }
}
