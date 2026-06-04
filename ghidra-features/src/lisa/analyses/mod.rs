//! Abstract interpretation domains for p-code analysis.
//!
//! Each domain implements a lattice over some abstract property
//! (taint, sign, interval, parity, etc.) and can be used for
//! fixpoint dataflow analysis on p-code control flow graphs.

mod taint;
mod sign;
mod parity;
mod interval;
mod constant_propagation;

pub use taint::{PcodeTaint, PcodeThreeLevelTaint};
pub use sign::PcodeSign;
pub use parity::PcodeParity;
pub use interval::{LongInterval, PcodeInterval};
pub use constant_propagation::PcodeDataflowConstantPropagation;
