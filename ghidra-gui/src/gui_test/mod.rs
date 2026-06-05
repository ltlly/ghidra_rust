//! GUI test utilities.
//!
//! Port of Ghidra's `generic.test.AbstractGuiTest` and `ghidra.test.GhidraTestCase`.

pub mod abstract_gui_test;

use std::time::{Duration, Instant};

/// Maximum time to wait for a GUI condition before timing out.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);

/// Polling interval for GUI condition checks.
const POLL_INTERVAL: Duration = Duration::from_millis(50);

/// Wait for a condition to become true, polling at regular intervals.
///
/// Returns `Ok(())` when the condition is met, or `Err` if the timeout expires.
///
/// Ported from Ghidra's `AbstractGuiTest.waitForCondition`.
pub fn wait_for_condition<F: Fn() -> bool>(condition: F) -> Result<(), String> {
    wait_for_condition_with_timeout(condition, DEFAULT_TIMEOUT)
}

/// Wait for a condition with a custom timeout.
pub fn wait_for_condition_with_timeout<F: Fn() -> bool>(
    condition: F,
    timeout: Duration,
) -> Result<(), String> {
    let start = Instant::now();
    while !condition() {
        if start.elapsed() >= timeout {
            return Err(format!(
                "Timed out waiting for condition after {}ms",
                timeout.as_millis()
            ));
        }
        std::thread::sleep(POLL_INTERVAL);
    }
    Ok(())
}

/// Run a closure on the "GUI thread" (in tests, this just runs inline).
///
/// Ported from Ghidra's `AbstractGuiTest.runSwing`.
pub fn run_swing<F, R>(f: F) -> R
where
    F: FnOnce() -> R,
{
    f()
}

/// Assert that a value is within a tolerance of an expected value.
pub fn assert_approx_eq(actual: f64, expected: f64, tolerance: f64) {
    let diff = (actual - expected).abs();
    assert!(
        diff <= tolerance,
        "assertion failed: actual {} != expected {} (diff {} > tolerance {})",
        actual,
        expected,
        diff,
        tolerance
    );
}

/// A simple mock component for GUI testing.
#[derive(Debug, Clone)]
pub struct MockComponent {
    pub id: String,
    pub x: f64,
    pub y: f64,
    pub width: f64,
    pub height: f64,
    pub visible: bool,
    pub enabled: bool,
    pub focused: bool,
}

impl MockComponent {
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            x: 0.0,
            y: 0.0,
            width: 100.0,
            height: 30.0,
            visible: true,
            enabled: true,
            focused: false,
        }
    }

    pub fn with_position(mut self, x: f64, y: f64) -> Self {
        self.x = x;
        self.y = y;
        self
    }

    pub fn with_size(mut self, width: f64, height: f64) -> Self {
        self.width = width;
        self.height = height;
        self
    }

    pub fn bounds(&self) -> (f64, f64, f64, f64) {
        (self.x, self.y, self.width, self.height)
    }

    pub fn contains_point(&self, px: f64, py: f64) -> bool {
        px >= self.x && px <= self.x + self.width && py >= self.y && py <= self.y + self.height
    }
}

/// Simulate a mouse click on a mock component.
pub fn simulate_click(component: &mut MockComponent, x: f64, y: f64) -> bool {
    if component.visible && component.enabled && component.contains_point(x, y) {
        component.focused = true;
        true
    } else {
        false
    }
}

/// Simulate pressing a key (returns the key name as a string for logging).
pub fn simulate_key_press(key: &str) -> String {
    format!("KeyPress({})", key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wait_for_immediate_condition() {
        let result = wait_for_condition(|| true);
        assert!(result.is_ok());
    }

    #[test]
    fn wait_for_condition_timeout() {
        let result = wait_for_condition_with_timeout(|| false, Duration::from_millis(100));
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Timed out"));
    }

    #[test]
    fn wait_for_delayed_condition() {
        let start = Instant::now();
        let result = wait_for_condition_with_timeout(
            || start.elapsed() >= Duration::from_millis(50),
            Duration::from_secs(1),
        );
        assert!(result.is_ok());
    }

    #[test]
    fn run_swing_returns_value() {
        let result = run_swing(|| 42);
        assert_eq!(result, 42);
    }

    #[test]
    fn approx_eq_pass() {
        assert_approx_eq(1.0, 1.0001, 0.001);
    }

    #[test]
    #[should_panic]
    fn approx_eq_fail() {
        assert_approx_eq(1.0, 2.0, 0.001);
    }

    #[test]
    fn mock_component_basics() {
        let c = MockComponent::new("btn").with_position(10.0, 20.0).with_size(80.0, 40.0);
        assert_eq!(c.id, "btn");
        assert!(c.contains_point(50.0, 40.0));
        assert!(!c.contains_point(0.0, 0.0));
    }

    #[test]
    fn simulate_click_on_component() {
        let mut c = MockComponent::new("btn");
        assert!(simulate_click(&mut c, 50.0, 15.0));
        assert!(c.focused);
    }

    #[test]
    fn simulate_click_disabled() {
        let mut c = MockComponent::new("btn");
        c.enabled = false;
        assert!(!simulate_click(&mut c, 50.0, 15.0));
        assert!(!c.focused);
    }

    #[test]
    fn simulate_click_invisible() {
        let mut c = MockComponent::new("btn");
        c.visible = false;
        assert!(!simulate_click(&mut c, 50.0, 15.0));
    }

    #[test]
    fn simulate_key_press_format() {
        assert_eq!(simulate_key_press("Enter"), "KeyPress(Enter)");
    }
}
