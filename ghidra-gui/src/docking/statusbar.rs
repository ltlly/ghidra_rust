//! Status bar for the docking framework.
//!
//! Port of Ghidra's `StatusBar`. Provides a panel that displays status text
//! on the left and optional custom status items on the right. Supports
//! message queuing, fading, and flashing.

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::dialog::MessageType;

// ---------------------------------------------------------------------------
// StatusMessage — a single message in the queue
// ---------------------------------------------------------------------------

/// A queued status message with its severity and timestamp.
#[derive(Debug, Clone)]
pub struct StatusMessage {
    /// The message text.
    pub text: String,
    /// Severity level.
    pub message_type: MessageType,
    /// When the message was posted.
    pub timestamp: Instant,
}

impl StatusMessage {
    /// Create a new status message.
    pub fn new(text: impl Into<String>, message_type: MessageType) -> Self {
        Self {
            text: text.into(),
            message_type,
            timestamp: Instant::now(),
        }
    }

    /// Create an info message.
    pub fn info(text: impl Into<String>) -> Self {
        Self::new(text, MessageType::Info)
    }

    /// Create a warning message.
    pub fn warning(text: impl Into<String>) -> Self {
        Self::new(text, MessageType::Warning)
    }

    /// Create an error message.
    pub fn error(text: impl Into<String>) -> Self {
        Self::new(text, MessageType::Error)
    }

    /// Age of this message.
    pub fn age(&self) -> Duration {
        self.timestamp.elapsed()
    }
}

// ---------------------------------------------------------------------------
// StatusItem — a custom item on the right side of the status bar
// ---------------------------------------------------------------------------

/// A custom status item that can be added to the right side of the status bar.
#[derive(Debug, Clone)]
pub struct StatusItem {
    /// Unique identifier for this item.
    pub id: String,
    /// Display text.
    pub text: String,
    /// Optional tooltip.
    pub tooltip: Option<String>,
    /// Whether the item is currently visible.
    pub visible: bool,
    /// Width hint in pixels (None means auto).
    pub width_hint: Option<f32>,
}

impl StatusItem {
    /// Create a new status item.
    pub fn new(id: impl Into<String>, text: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            text: text.into(),
            tooltip: None,
            visible: true,
            width_hint: None,
        }
    }

    /// Set tooltip.
    pub fn with_tooltip(mut self, tooltip: impl Into<String>) -> Self {
        self.tooltip = Some(tooltip.into());
        self
    }

    /// Set visibility.
    pub fn with_visible(mut self, visible: bool) -> Self {
        self.visible = visible;
        self
    }

    /// Set width hint.
    pub fn with_width_hint(mut self, width: f32) -> Self {
        self.width_hint = Some(width);
        self
    }
}

// ---------------------------------------------------------------------------
// StatusBar
// ---------------------------------------------------------------------------

/// Maximum number of messages retained in the history.
const MAX_MESSAGE_HISTORY: usize = 20;

/// Default fade duration for messages.
const FADE_DURATION: Duration = Duration::from_secs(5);

/// The status bar widget.
///
/// Displays the most recent status message on the left, with optional
/// custom status items on the right. Maintains a message history and
/// supports message fading.
pub struct StatusBar {
    /// Current displayed status text.
    status_text: String,
    /// Current status severity.
    status_type: MessageType,
    /// Message history (newest at back).
    history: VecDeque<StatusMessage>,
    /// Custom status items on the right side.
    items: Vec<StatusItem>,
    /// Whether the status bar is visible.
    visible: bool,
    /// Callback when the status text changes.
    on_change: Option<Arc<dyn Fn(&str, MessageType) + Send + Sync>>,
    /// Whether to enable message fading.
    fading_enabled: bool,
    /// Duration before a message starts fading.
    fade_duration: Duration,
    /// Whether to enable message flashing.
    flash_enabled: bool,
    /// Callback when the "home" button is pressed.
    on_home: Option<Arc<dyn Fn() + Send + Sync>>,
}

impl StatusBar {
    /// Create a new, empty status bar.
    pub fn new() -> Self {
        Self {
            status_text: String::new(),
            status_type: MessageType::Info,
            history: VecDeque::new(),
            items: Vec::new(),
            visible: true,
            on_change: None,
            fading_enabled: true,
            fade_duration: FADE_DURATION,
            flash_enabled: true,
            on_home: None,
        }
    }

    // ---------------------------------------------------------------
    // Status text
    // ---------------------------------------------------------------

    /// Get the current status text.
    pub fn status_text(&self) -> &str {
        &self.status_text
    }

    /// Get the current status type.
    pub fn status_type(&self) -> MessageType {
        self.status_type
    }

    /// Set the status text with default (Info) severity.
    pub fn set_status_text(&mut self, text: impl Into<String>) {
        self.set_status_text_with_type(text, MessageType::Info);
    }

    /// Set the status text with a specific severity.
    pub fn set_status_text_with_type(
        &mut self,
        text: impl Into<String>,
        msg_type: MessageType,
    ) {
        let text = text.into();
        if text.is_empty() {
            return;
        }
        self.status_text = text.clone();
        self.status_type = msg_type;

        // Add to history.
        self.history
            .push_back(StatusMessage::new(&text, msg_type));
        if self.history.len() > MAX_MESSAGE_HISTORY {
            self.history.pop_front();
        }

        // Notify listeners.
        if let Some(cb) = &self.on_change {
            cb(&self.status_text, self.status_type);
        }
    }

    /// Add an informational message (alias for set_status_text).
    pub fn info(&mut self, text: impl Into<String>) {
        self.set_status_text_with_type(text, MessageType::Info);
    }

    /// Add a warning message.
    pub fn warning(&mut self, text: impl Into<String>) {
        self.set_status_text_with_type(text, MessageType::Warning);
    }

    /// Add an error message.
    pub fn error(&mut self, text: impl Into<String>) {
        self.set_status_text_with_type(text, MessageType::Error);
    }

    /// Clear the status text.
    pub fn clear(&mut self) {
        self.status_text.clear();
        self.status_type = MessageType::Info;
    }

    // ---------------------------------------------------------------
    // History
    // ---------------------------------------------------------------

    /// Get the message history (oldest first).
    pub fn history(&self) -> &VecDeque<StatusMessage> {
        &self.history
    }

    /// Get all history messages as plain text strings.
    pub fn history_text(&self) -> Vec<&str> {
        self.history.iter().map(|m| m.text.as_str()).collect()
    }

    /// Clear the message history.
    pub fn clear_history(&mut self) {
        self.history.clear();
    }

    /// Number of messages in history.
    pub fn history_len(&self) -> usize {
        self.history.len()
    }

    /// Get the most recent message of a specific type.
    pub fn last_message_of_type(&self, msg_type: MessageType) -> Option<&StatusMessage> {
        self.history
            .iter()
            .rev()
            .find(|m| m.message_type == msg_type)
    }

    // ---------------------------------------------------------------
    // Custom items
    // ---------------------------------------------------------------

    /// Add a custom status item to the right side.
    pub fn add_item(&mut self, item: StatusItem) {
        // Replace if same ID exists.
        if let Some(existing) = self.items.iter_mut().find(|i| i.id == item.id) {
            *existing = item;
        } else {
            self.items.push(item);
        }
    }

    /// Remove a custom status item by ID.
    pub fn remove_item(&mut self, id: &str) -> bool {
        if let Some(pos) = self.items.iter().position(|i| i.id == id) {
            self.items.remove(pos);
            true
        } else {
            false
        }
    }

    /// Get a status item by ID.
    pub fn get_item(&self, id: &str) -> Option<&StatusItem> {
        self.items.iter().find(|i| i.id == id)
    }

    /// Get a mutable reference to a status item by ID.
    pub fn get_item_mut(&mut self, id: &str) -> Option<&mut StatusItem> {
        self.items.iter_mut().find(|i| i.id == id)
    }

    /// Update the text of a status item.
    pub fn set_item_text(&mut self, id: &str, text: impl Into<String>) -> bool {
        if let Some(item) = self.items.iter_mut().find(|i| i.id == id) {
            item.text = text.into();
            true
        } else {
            false
        }
    }

    /// All status items.
    pub fn items(&self) -> &[StatusItem] {
        &self.items
    }

    /// Visible status items.
    pub fn visible_items(&self) -> Vec<&StatusItem> {
        self.items.iter().filter(|i| i.visible).collect()
    }

    // ---------------------------------------------------------------
    // Visibility
    // ---------------------------------------------------------------

    /// Whether the status bar is visible.
    pub fn is_visible(&self) -> bool {
        self.visible
    }

    /// Show or hide the status bar.
    pub fn set_visible(&mut self, visible: bool) {
        self.visible = visible;
    }

    // ---------------------------------------------------------------
    // Configuration
    // ---------------------------------------------------------------

    /// Enable or disable message fading.
    pub fn set_fading_enabled(&mut self, enabled: bool) {
        self.fading_enabled = enabled;
    }

    /// Whether fading is enabled.
    pub fn is_fading_enabled(&self) -> bool {
        self.fading_enabled
    }

    /// Set the fade duration.
    pub fn set_fade_duration(&mut self, duration: Duration) {
        self.fade_duration = duration;
    }

    /// Get the fade duration.
    pub fn fade_duration(&self) -> Duration {
        self.fade_duration
    }

    /// Enable or disable message flashing.
    pub fn set_flash_enabled(&mut self, enabled: bool) {
        self.flash_enabled = enabled;
    }

    /// Whether flashing is enabled.
    pub fn is_flash_enabled(&self) -> bool {
        self.flash_enabled
    }

    // ---------------------------------------------------------------
    // Callbacks
    // ---------------------------------------------------------------

    /// Set a callback invoked when the status text changes.
    pub fn set_on_change(&mut self, callback: Arc<dyn Fn(&str, MessageType) + Send + Sync>) {
        self.on_change = Some(callback);
    }

    /// Set a callback invoked when the home button is pressed.
    pub fn set_on_home(&mut self, callback: Arc<dyn Fn() + Send + Sync>) {
        self.on_home = Some(callback);
    }

    /// Invoke the home callback.
    pub fn invoke_home(&self) {
        if let Some(cb) = &self.on_home {
            cb();
        }
    }
}

impl Default for StatusBar {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for StatusBar {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StatusBar")
            .field("status_text", &self.status_text)
            .field("status_type", &self.status_type)
            .field("history_len", &self.history.len())
            .field("items_len", &self.items.len())
            .field("visible", &self.visible)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_status_bar_new() {
        let bar = StatusBar::new();
        assert!(bar.status_text().is_empty());
        assert_eq!(bar.status_type(), MessageType::Info);
        assert!(bar.is_visible());
        assert!(bar.history().is_empty());
        assert!(bar.items().is_empty());
    }

    #[test]
    fn test_status_bar_set_text() {
        let mut bar = StatusBar::new();
        bar.set_status_text("Ready");
        assert_eq!(bar.status_text(), "Ready");
        assert_eq!(bar.status_type(), MessageType::Info);
    }

    #[test]
    fn test_status_bar_with_type() {
        let mut bar = StatusBar::new();
        bar.set_status_text_with_type("Something wrong", MessageType::Warning);
        assert_eq!(bar.status_text(), "Something wrong");
        assert_eq!(bar.status_type(), MessageType::Warning);
    }

    #[test]
    fn test_status_bar_history() {
        let mut bar = StatusBar::new();
        bar.info("First");
        bar.warning("Second");
        bar.error("Third");

        assert_eq!(bar.history_len(), 3);
        let texts = bar.history_text();
        assert_eq!(texts, vec!["First", "Second", "Third"]);
    }

    #[test]
    fn test_status_bar_history_overflow() {
        let mut bar = StatusBar::new();
        for i in 0..MAX_MESSAGE_HISTORY + 5 {
            bar.info(format!("msg {}", i));
        }
        assert_eq!(bar.history_len(), MAX_MESSAGE_HISTORY);
        // Oldest messages should be dropped.
        assert!(bar.history_text()[0].starts_with("msg "));
    }

    #[test]
    fn test_status_bar_clear() {
        let mut bar = StatusBar::new();
        bar.info("Something");
        assert!(!bar.status_text().is_empty());
        bar.clear();
        assert!(bar.status_text().is_empty());
        assert_eq!(bar.status_type(), MessageType::Info);
    }

    #[test]
    fn test_status_bar_history_not_affected_by_clear() {
        let mut bar = StatusBar::new();
        bar.info("Message");
        bar.clear();
        assert_eq!(bar.history_len(), 1);
    }

    #[test]
    fn test_status_bar_empty_string_ignored() {
        let mut bar = StatusBar::new();
        bar.set_status_text("Hello");
        bar.set_status_text("");
        assert_eq!(bar.status_text(), "Hello");
    }

    #[test]
    fn test_status_bar_convenience_methods() {
        let mut bar = StatusBar::new();
        bar.info("info msg");
        assert_eq!(bar.status_type(), MessageType::Info);

        bar.warning("warn msg");
        assert_eq!(bar.status_type(), MessageType::Warning);

        bar.error("err msg");
        assert_eq!(bar.status_type(), MessageType::Error);
    }

    #[test]
    fn test_status_bar_last_message_of_type() {
        let mut bar = StatusBar::new();
        bar.info("info 1");
        bar.warning("warn 1");
        bar.info("info 2");
        bar.error("err 1");

        let last_info = bar.last_message_of_type(MessageType::Info).unwrap();
        assert_eq!(last_info.text, "info 2");

        let last_warn = bar.last_message_of_type(MessageType::Warning).unwrap();
        assert_eq!(last_warn.text, "warn 1");

        assert!(bar.last_message_of_type(MessageType::Error).is_some());
    }

    #[test]
    fn test_status_bar_items() {
        let mut bar = StatusBar::new();
        bar.add_item(StatusItem::new("mem", "128 MB").with_tooltip("Memory usage"));
        bar.add_item(StatusItem::new("addr", "0x1000"));

        assert_eq!(bar.items().len(), 2);
        assert!(bar.get_item("mem").is_some());
        assert!(bar.get_item("nonexistent").is_none());

        bar.set_item_text("mem", "256 MB");
        assert_eq!(bar.get_item("mem").unwrap().text, "256 MB");

        assert!(bar.remove_item("addr"));
        assert_eq!(bar.items().len(), 1);
    }

    #[test]
    fn test_status_bar_item_replacement() {
        let mut bar = StatusBar::new();
        bar.add_item(StatusItem::new("x", "old"));
        bar.add_item(StatusItem::new("x", "new"));
        assert_eq!(bar.items().len(), 1);
        assert_eq!(bar.get_item("x").unwrap().text, "new");
    }

    #[test]
    fn test_status_bar_visible_items() {
        let mut bar = StatusBar::new();
        bar.add_item(StatusItem::new("a", "A").with_visible(true));
        bar.add_item(StatusItem::new("b", "B").with_visible(false));
        bar.add_item(StatusItem::new("c", "C").with_visible(true));

        assert_eq!(bar.visible_items().len(), 2);
    }

    #[test]
    fn test_status_bar_visibility() {
        let mut bar = StatusBar::new();
        assert!(bar.is_visible());
        bar.set_visible(false);
        assert!(!bar.is_visible());
    }

    #[test]
    fn test_status_bar_fading() {
        let mut bar = StatusBar::new();
        assert!(bar.is_fading_enabled());
        bar.set_fading_enabled(false);
        assert!(!bar.is_fading_enabled());

        let d = Duration::from_secs(10);
        bar.set_fade_duration(d);
        assert_eq!(bar.fade_duration(), d);
    }

    #[test]
    fn test_status_bar_flash() {
        let mut bar = StatusBar::new();
        assert!(bar.is_flash_enabled());
        bar.set_flash_enabled(false);
        assert!(!bar.is_flash_enabled());
    }

    #[test]
    fn test_status_bar_on_change() {
        use std::sync::atomic::{AtomicBool, Ordering};
        let called = Arc::new(AtomicBool::new(false));
        let called2 = called.clone();

        let mut bar = StatusBar::new();
        bar.set_on_change(Arc::new(move |_, _| {
            called2.store(true, Ordering::SeqCst);
        }));

        bar.info("Test");
        assert!(called.load(Ordering::SeqCst));
    }

    #[test]
    fn test_status_message_age() {
        let msg = StatusMessage::info("Test");
        // Just verify the method works without panicking.
        let _age = msg.age();
    }

    #[test]
    fn test_status_message_builder() {
        let msg = StatusItem::new("test", "value")
            .with_tooltip("A tooltip")
            .with_width_hint(100.0);
        assert_eq!(msg.id, "test");
        assert_eq!(msg.text, "value");
        assert_eq!(msg.tooltip.as_deref(), Some("A tooltip"));
        assert_eq!(msg.width_hint, Some(100.0));
        assert!(msg.visible);
    }
}
