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
mod stability;
mod upper_bounds;
mod pentagon;
mod byte_constant_propagation;
mod non_relational_value;
mod powerset_interval;

pub use taint::{PcodeTaint, PcodeThreeLevelTaint};
pub use sign::PcodeSign;
pub use parity::PcodeParity;
pub use interval::{LongInterval, PcodeInterval};
pub use constant_propagation::PcodeDataflowConstantPropagation;
pub use stability::PcodeStability;
pub use upper_bounds::PcodeUpperBounds;
pub use pentagon::{Pentagon, PointRelation, LinearRelation};
pub use byte_constant_propagation::PcodeByteBasedConstantPropagation;
pub use non_relational_value::PcodeNonRelationalValue;
pub use powerset_interval::PcodePowersetInterval;
