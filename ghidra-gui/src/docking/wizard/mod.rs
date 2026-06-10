//! Wizard dialog support for the docking framework.
//!
//! Port of Ghidra's `WizardManager` and related wizard infrastructure.
//! Provides a multi-step dialog flow where each step is a
//! [`WizardStep`] that can validate user input and determine which
//! step to show next.

pub mod wizard_step;

pub use wizard_step::{StepDirection, WizardState, WizardStep, WizardStepId};
