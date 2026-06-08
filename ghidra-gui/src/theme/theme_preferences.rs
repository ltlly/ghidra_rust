//! Theme preferences: load and persist the user's theme choice.
//!
//! Port of `generic.theme.ThemePreferences`. Reads and writes the
//! current theme identifier to/from the application preferences store.

/// Key used to store the theme preference.
const THEME_PREFERENCE_KEY: &str = "Theme";

/// Default theme id used when no preference has been stored.
const DEFAULT_THEME_ID: &str = "Default";

/// Prefix for file-based custom themes.
const FILE_PREFIX: &str = "file:";

/// Prefix for discoverable (class-based) themes.
const CLASS_PREFIX: &str = "class:";

/// Reads and writes the current theme identifier from/to application
/// preferences, analogous to Ghidra's `Preferences`-backed storage.
///
/// On startup, call [`ThemePreferences::load_theme`] to retrieve the
/// user's last-used theme.  When the user selects a new theme, call
/// [`ThemePreferences::save_theme`] to persist the choice.
#[derive(Debug, Clone, Default)]
pub struct ThemePreferences {
    /// In-memory store of key-value pairs (simulates `Preferences`).
    /// In a real application this would be backed by a file or registry.
    store: std::collections::HashMap<String, String>,
}

impl ThemePreferences {
    /// Create a new, empty preferences store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a preferences store pre-populated with the given entries.
    pub fn with_entries(entries: Vec<(String, String)>) -> Self {
        let mut store = std::collections::HashMap::new();
        for (k, v) in entries {
            store.insert(k, v);
        }
        Self { store }
    }

    /// Load the stored theme id, or return the default.
    ///
    /// The stored value may be:
    /// - `"Default"` (or absent) -- use the default built-in theme.
    /// - `"file:<path>"` -- a custom theme file.
    /// - `"class:<classname>"` -- a discoverable theme class name.
    pub fn get_stored_theme_id(&self) -> String {
        self.store
            .get(THEME_PREFERENCE_KEY)
            .cloned()
            .unwrap_or_else(|| DEFAULT_THEME_ID.to_string())
    }

    /// Determine whether the stored theme id refers to a file-based theme.
    pub fn is_file_theme(theme_id: &str) -> bool {
        theme_id.starts_with(FILE_PREFIX)
    }

    /// Determine whether the stored theme id refers to a discoverable class theme.
    pub fn is_class_theme(theme_id: &str) -> bool {
        theme_id.starts_with(CLASS_PREFIX)
    }

    /// Extract the file path from a file-based theme id.
    ///
    /// Returns `None` if `theme_id` does not start with the file prefix.
    pub fn file_path_from_id(theme_id: &str) -> Option<&str> {
        if Self::is_file_theme(theme_id) {
            Some(&theme_id[FILE_PREFIX.len()..])
        } else {
            None
        }
    }

    /// Extract the class name from a class-based theme id.
    ///
    /// Returns `None` if `theme_id` does not start with the class prefix.
    pub fn class_name_from_id(theme_id: &str) -> Option<&str> {
        if Self::is_class_theme(theme_id) {
            Some(&theme_id[CLASS_PREFIX.len()..])
        } else {
            None
        }
    }

    /// Create a file-based theme identifier from a file path.
    pub fn file_theme_id(path: &str) -> String {
        format!("{}{}", FILE_PREFIX, path)
    }

    /// Create a class-based theme identifier from a class name.
    pub fn class_theme_id(class_name: &str) -> String {
        format!("{}{}", CLASS_PREFIX, class_name)
    }

    /// Persist the active theme id into the preferences store.
    pub fn save_theme(&mut self, theme_id: &str) {
        self.store.insert(THEME_PREFERENCE_KEY.to_string(), theme_id.to_string());
    }

    /// Persist a file-based custom theme path.
    pub fn save_file_theme(&mut self, path: &str) {
        self.save_theme(&Self::file_theme_id(path));
    }

    /// Persist a discoverable theme class name.
    pub fn save_class_theme(&mut self, class_name: &str) {
        self.save_theme(&Self::class_theme_id(class_name));
    }

    /// Load the previously stored theme, or the default if none stored.
    ///
    /// This is a simplified version that returns a theme id string;
    /// the actual theme loading (reading `.theme` XML files, instantiating
    /// discoverable classes) is handled by the caller using
    /// [`ThemeReader`] and the class finder.
    pub fn load_theme(&self) -> String {
        self.get_stored_theme_id()
    }

    /// Clear the stored theme preference, reverting to the default.
    pub fn clear(&mut self) {
        self.store.remove(THEME_PREFERENCE_KEY);
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_theme_id_when_empty() {
        let prefs = ThemePreferences::new();
        assert_eq!(prefs.get_stored_theme_id(), "Default");
    }

    #[test]
    fn save_and_load_theme() {
        let mut prefs = ThemePreferences::new();
        prefs.save_theme("DarkTheme");
        assert_eq!(prefs.get_stored_theme_id(), "DarkTheme");
    }

    #[test]
    fn save_file_theme() {
        let mut prefs = ThemePreferences::new();
        prefs.save_file_theme("/home/user/custom.theme");
        let id = prefs.get_stored_theme_id();
        assert!(ThemePreferences::is_file_theme(&id));
        assert_eq!(
            ThemePreferences::file_path_from_id(&id),
            Some("/home/user/custom.theme")
        );
    }

    #[test]
    fn save_class_theme() {
        let mut prefs = ThemePreferences::new();
        prefs.save_class_theme("generic.theme.builtin.FlatDarkTheme");
        let id = prefs.get_stored_theme_id();
        assert!(ThemePreferences::is_class_theme(&id));
        assert_eq!(
            ThemePreferences::class_name_from_id(&id),
            Some("generic.theme.builtin.FlatDarkTheme")
        );
    }

    #[test]
    fn is_file_theme_negative() {
        assert!(!ThemePreferences::is_file_theme("Default"));
        assert!(!ThemePreferences::is_file_theme("class:some.Class"));
    }

    #[test]
    fn is_class_theme_negative() {
        assert!(!ThemePreferences::is_class_theme("Default"));
        assert!(!ThemePreferences::is_class_theme("file:/path/to/theme"));
    }

    #[test]
    fn clear_reverts_to_default() {
        let mut prefs = ThemePreferences::new();
        prefs.save_theme("SomeTheme");
        assert_eq!(prefs.get_stored_theme_id(), "SomeTheme");
        prefs.clear();
        assert_eq!(prefs.get_stored_theme_id(), "Default");
    }

    #[test]
    fn file_theme_id_round_trip() {
        let path = "/opt/themes/dark.theme";
        let id = ThemePreferences::file_theme_id(path);
        assert_eq!(ThemePreferences::file_path_from_id(&id), Some(path));
    }

    #[test]
    fn class_theme_id_round_trip() {
        let class = "generic.theme.builtin.MacTheme";
        let id = ThemePreferences::class_theme_id(class);
        assert_eq!(ThemePreferences::class_name_from_id(&id), Some(class));
    }

    #[test]
    fn with_entries_prepopulated() {
        let entries = vec![
            ("Theme".to_string(), "PresetDark".to_string()),
            ("other_key".to_string(), "other_val".to_string()),
        ];
        let prefs = ThemePreferences::with_entries(entries);
        assert_eq!(prefs.get_stored_theme_id(), "PresetDark");
    }

    #[test]
    fn load_theme_returns_stored_value() {
        let mut prefs = ThemePreferences::new();
        prefs.save_class_theme("MyTheme");
        assert_eq!(prefs.load_theme(), "class:MyTheme");
    }
}
