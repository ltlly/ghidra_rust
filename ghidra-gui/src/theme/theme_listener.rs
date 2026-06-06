//! Port of Ghidra's `generic.theme.ThemeListener`.

/// Listener for theme change events.
pub trait ThemeListener: Send + Sync {
    /// Called when the theme changes.
    fn theme_changed(&self, _theme_name: &str) {}
    /// Called when a color value changes.
    fn color_changed(&self, _color_id: &str, _new_value: &str) {}
    /// Called when a font value changes.
    fn font_changed(&self, _font_id: &str, _new_value: &str) {}
    /// Called when an icon value changes.
    fn icon_changed(&self, _icon_id: &str, _new_value: &str) {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[derive(Debug)]
    struct Mock { events: Arc<Mutex<Vec<String>>> }
    impl ThemeListener for Mock {
        fn theme_changed(&self, name: &str) { self.events.lock().unwrap().push(format!("theme:{}", name)); }
        fn color_changed(&self, id: &str, val: &str) { self.events.lock().unwrap().push(format!("color:{}={}", id, val)); }
    }

    #[test]
    fn test_theme_listener() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let listener = Mock { events: events.clone() };
        listener.theme_changed("dark");
        listener.color_changed("bg", "#000000");
        let evts = events.lock().unwrap();
        assert_eq!(evts[0], "theme:dark");
        assert_eq!(evts[1], "color:bg=#000000");
    }
}
