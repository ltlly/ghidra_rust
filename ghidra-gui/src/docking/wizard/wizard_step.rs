//! Abstract step for a wizard dialog.
//!
//! Port of Ghidra's `WizardStep`.  Each step in a wizard dialog implements
//! the [`WizardStep`] trait, which provides methods for entering / leaving
//! the step, validating user input, and determining the next or previous step.

use std::any::Any;
use std::collections::HashMap;

// ---------------------------------------------------------------------------
// WizardStepId — unique identifier for a wizard step
// ---------------------------------------------------------------------------

/// A unique identifier for a wizard step.
///
/// Steps are identified by a string name so that transitions can be
/// expressed as data (e.g. "if the user picks option A, go to step X").
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct WizardStepId(pub String);

impl WizardStepId {
    /// Create a new step identifier.
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    /// Returns the step identifier as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<&str> for WizardStepId {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

impl From<String> for WizardStepId {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl std::fmt::Display for WizardStepId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

// ---------------------------------------------------------------------------
// StepDirection — which direction the wizard is moving
// ---------------------------------------------------------------------------

/// Direction of wizard navigation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StepDirection {
    /// Moving forward (Next).
    Forward,
    /// Moving backward (Back / Previous).
    Backward,
}

// ---------------------------------------------------------------------------
// WizardState — shared mutable state across all wizard steps
// ---------------------------------------------------------------------------

/// Shared state passed to every wizard step.
///
/// Steps can read from and write to this state to communicate with each
/// other.  The state is a simple key-value store of `Box<dyn Any>` values.
#[derive(Debug, Default)]
pub struct WizardState {
    values: HashMap<String, Box<dyn Any>>,
}

impl WizardState {
    /// Create an empty wizard state.
    pub fn new() -> Self {
        Self {
            values: HashMap::new(),
        }
    }

    /// Store a value under the given key.
    pub fn set<T: Any>(&mut self, key: impl Into<String>, value: T) {
        self.values.insert(key.into(), Box::new(value));
    }

    /// Retrieve a value by key, downcast to the given type.
    pub fn get<T: Any>(&self, key: &str) -> Option<&T> {
        self.values.get(key).and_then(|v| v.downcast_ref::<T>())
    }

    /// Retrieve a mutable reference to a value by key.
    pub fn get_mut<T: Any>(&mut self, key: &str) -> Option<&mut T> {
        self.values.get_mut(key).and_then(|v| v.downcast_mut::<T>())
    }

    /// Remove a value by key, returning it if present.
    pub fn remove(&mut self, key: &str) -> Option<Box<dyn Any>> {
        self.values.remove(key)
    }

    /// Returns whether the state contains a value for the given key.
    pub fn contains(&self, key: &str) -> bool {
        self.values.contains_key(key)
    }

    /// Clear all values.
    pub fn clear(&mut self) {
        self.values.clear();
    }

    /// Returns the number of entries in the state.
    pub fn len(&self) -> usize {
        self.values.len()
    }

    /// Returns whether the state is empty.
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }
}

// ---------------------------------------------------------------------------
// StepResult — the result of entering or validating a step
// ---------------------------------------------------------------------------

/// The result of a step operation.
#[derive(Debug, Clone)]
pub enum StepResult {
    /// The step completed successfully; advance to the given step.
    Next(WizardStepId),
    /// Go back to the given step.
    Back(WizardStepId),
    /// The wizard is finished.
    Finish,
    /// Stay on the current step (validation failed, etc.).
    Stay,
}

// ---------------------------------------------------------------------------
// WizardStep — the trait every wizard step must implement
// ---------------------------------------------------------------------------

/// A single step in a wizard dialog.
///
/// Implementors provide the UI rendering, entry / exit logic, and
/// validation for a wizard step.  The step communicates with the wizard
/// manager through the [`WizardState`] and [`StepResult`] types.
///
/// # Lifecycle
///
/// 1. [`WizardStep::enter`] — called when the step becomes active.
/// 2. [`WizardStep::render`] — called each frame to draw the step's UI.
/// 3. [`WizardStep::validate`] — called when the user clicks "Next".
/// 4. [`WizardStep::leave`] — called when the step is deactivated.
pub trait WizardStep {
    /// Returns the unique identifier for this step.
    fn id(&self) -> WizardStepId;

    /// Returns a human-readable title for this step (shown in the header).
    fn title(&self) -> &str;

    /// Returns an optional description shown below the title.
    fn description(&self) -> Option<&str> {
        None
    }

    /// Called when this step becomes the active step.
    ///
    /// The `direction` indicates whether the user arrived by pressing
    /// Next or Back.
    fn enter(&mut self, direction: StepDirection, state: &mut WizardState) {
        let _ = (direction, state);
    }

    /// Called when this step is about to be deactivated.
    ///
    /// The `direction` indicates whether the user is leaving by pressing
    /// Next or Back.
    fn leave(&mut self, direction: StepDirection, state: &mut WizardState) {
        let _ = (direction, state);
    }

    /// Render the step's UI content.
    ///
    /// This is called once per frame while the step is active.
    fn render(&mut self, ui: &mut egui::Ui, state: &mut WizardState);

    /// Validate the step's input.
    ///
    /// Called when the user clicks "Next".  Returns a [`StepResult`]
    /// indicating whether to advance, stay, or finish.
    fn validate(&self, state: &WizardState) -> StepResult {
        let _ = state;
        // Default: always allow advancing.
        StepResult::Next(WizardStepId::new("__next__"))
    }

    /// Returns whether the "Back" button should be shown.
    fn show_back_button(&self) -> bool {
        true
    }

    /// Returns whether the "Next" button should be shown.
    fn show_next_button(&self) -> bool {
        true
    }

    /// Returns whether the "Cancel" button should be shown.
    fn show_cancel_button(&self) -> bool {
        true
    }

    /// Returns whether the "Finish" button should be shown (instead of "Next").
    ///
    /// Override this to return `true` on the last step.
    fn show_finish_button(&self) -> bool {
        false
    }

    /// Returns the label for the "Next" button.
    fn next_button_label(&self) -> &str {
        "Next"
    }

    /// Returns whether the "Next" button is currently enabled.
    fn next_button_enabled(&self, state: &WizardState) -> bool {
        let _ = state;
        true
    }
}

// ---------------------------------------------------------------------------
// SimpleWizardStep — a convenience implementation
// ---------------------------------------------------------------------------

/// A simple wizard step that stores its configuration as data rather
/// than requiring a custom struct for each step.
pub struct SimpleWizardStep {
    id: WizardStepId,
    title: String,
    description: Option<String>,
    show_back: bool,
    show_next: bool,
    show_cancel: bool,
    show_finish: bool,
    next_label: String,
    render_fn: Option<Box<dyn FnMut(&mut egui::Ui, &mut WizardState)>>,
    validate_fn: Option<Box<dyn Fn(&WizardState) -> StepResult>>,
}

impl SimpleWizardStep {
    /// Create a new simple wizard step.
    pub fn new(id: impl Into<WizardStepId>, title: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            title: title.into(),
            description: None,
            show_back: true,
            show_next: true,
            show_cancel: true,
            show_finish: false,
            next_label: "Next".to_string(),
            render_fn: None,
            validate_fn: None,
        }
    }

    /// Set the description.
    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = Some(desc.into());
        self
    }

    /// Set whether to show the back button.
    pub fn with_show_back(mut self, show: bool) -> Self {
        self.show_back = show;
        self
    }

    /// Set whether to show the next button.
    pub fn with_show_next(mut self, show: bool) -> Self {
        self.show_next = show;
        self
    }

    /// Set whether to show the cancel button.
    pub fn with_show_cancel(mut self, show: bool) -> Self {
        self.show_cancel = show;
        self
    }

    /// Set whether to show the finish button.
    pub fn with_show_finish(mut self, show: bool) -> Self {
        self.show_finish = show;
        self
    }

    /// Set the next button label.
    pub fn with_next_label(mut self, label: impl Into<String>) -> Self {
        self.next_label = label.into();
        self
    }

    /// Set the render function.
    pub fn with_render(
        mut self,
        f: impl FnMut(&mut egui::Ui, &mut WizardState) + 'static,
    ) -> Self {
        self.render_fn = Some(Box::new(f));
        self
    }

    /// Set the validation function.
    pub fn with_validate(
        mut self,
        f: impl Fn(&WizardState) -> StepResult + 'static,
    ) -> Self {
        self.validate_fn = Some(Box::new(f));
        self
    }
}

impl WizardStep for SimpleWizardStep {
    fn id(&self) -> WizardStepId {
        self.id.clone()
    }

    fn title(&self) -> &str {
        &self.title
    }

    fn description(&self) -> Option<&str> {
        self.description.as_deref()
    }

    fn render(&mut self, ui: &mut egui::Ui, state: &mut WizardState) {
        if let Some(ref mut f) = self.render_fn {
            f(ui, state);
        }
    }

    fn validate(&self, state: &WizardState) -> StepResult {
        if let Some(ref f) = self.validate_fn {
            f(state)
        } else {
            StepResult::Next(WizardStepId::new("__next__"))
        }
    }

    fn show_back_button(&self) -> bool {
        self.show_back
    }

    fn show_next_button(&self) -> bool {
        self.show_next
    }

    fn show_cancel_button(&self) -> bool {
        self.show_cancel
    }

    fn show_finish_button(&self) -> bool {
        self.show_finish
    }

    fn next_button_label(&self) -> &str {
        &self.next_label
    }
}
