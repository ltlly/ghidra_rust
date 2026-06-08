//! GColor: dynamic color looked up from the active theme.
//!
//! Ported from `generic.theme.GColor`.  Instead of using hard-coded RGB
//! values, code declares a `GColor("color.mywidget.bg")` whose actual
//! value is resolved at runtime from the current theme's color table.

use std::sync::{Arc, Mutex, OnceLock, RwLock, Weak};
use crate::gui_util::web_colors::RgbaColor;

/// Default "missing color" sentinel (gray) used when a color id is not registered.
pub const MISSING_COLOR_RGB: RgbaColor = RgbaColor::new(128, 128, 128);

/// Registry of live GColor instances so the theme manager can refresh them.
static IN_USE_COLORS: OnceLock<Mutex<Vec<Weak<RwLock<GColorInner>>>>> = OnceLock::new();

fn register_gcolor(r: Weak<RwLock<GColorInner>>) {
    IN_USE_COLORS.get_or_init(|| Mutex::new(Vec::new())).lock().unwrap().push(r);
}

#[derive(Debug, Clone)]
struct GColorInner {
    id: String,
    delegate: RgbaColor,
    _alpha_override: Option<u8>,
}

/// A color whose value is dynamically resolved from the active theme.
#[derive(Debug, Clone)]
pub struct GColor {
    inner: Arc<RwLock<GColorInner>>,
}

impl GColor {
    /// Create a new GColor with the "missing color" sentinel as its initial value.
    pub fn new(id: impl Into<String>) -> Self {
        let inner = Arc::new(RwLock::new(GColorInner {
            id: id.into(),
            delegate: MISSING_COLOR_RGB,
            _alpha_override: None,
        }));
        let gc = Self { inner };
        register_gcolor(Arc::downgrade(&gc.inner));
        gc
    }

    /// Create a new GColor with a specific initial RGBA value.
    pub fn with_value(id: impl Into<String>, value: RgbaColor) -> Self {
        let inner = Arc::new(RwLock::new(GColorInner {
            id: id.into(),
            delegate: value,
            _alpha_override: None,
        }));
        let gc = Self { inner };
        register_gcolor(Arc::downgrade(&gc.inner));
        gc
    }

    /// Returns the theme id for this color.
    pub fn id(&self) -> String { self.inner.read().unwrap().id.clone() }

    /// Returns the current resolved RGBA value.
    pub fn get(&self) -> RgbaColor { self.inner.read().unwrap().delegate }

    /// Update the delegate RGBA value (called by the theme manager).
    pub fn set(&self, value: RgbaColor) { self.inner.write().unwrap().delegate = value; }

    /// Create a transparent variant with the specified alpha.
    pub fn with_alpha(&self, alpha: u8) -> Self {
        let base = self.get();
        let inner = Arc::new(RwLock::new(GColorInner {
            id: self.id(),
            delegate: RgbaColor::new(base.r, base.g, base.b),
            _alpha_override: Some(alpha),
        }));
        let gc = Self { inner };
        register_gcolor(Arc::downgrade(&gc.inner));
        gc
    }

    /// Refresh all registered GColor instances from a color table.
    pub fn refresh_all(color_table: &std::collections::HashMap<String, RgbaColor>) {
        let guard = IN_USE_COLORS.get_or_init(|| Mutex::new(Vec::new()));
        let mut lock = guard.lock().unwrap();
        lock.retain(|weak| {
            if let Some(arc) = weak.upgrade() {
                let id = arc.read().unwrap().id.clone();
                if let Some(&new_rgba) = color_table.get(&id) {
                    arc.write().unwrap().delegate = new_rgba;
                }
                true
            } else { false }
        });
    }
}

impl PartialEq for GColor {
    fn eq(&self, other: &Self) -> bool { self.id() == other.id() }
}
impl Eq for GColor {}

impl std::fmt::Display for GColor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let c = self.get();
        write!(f, "GColor({}) #{:02x}{:02x}{:02x}", self.id(), c.r, c.g, c.b)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gcolor_new_has_missing_color() {
        let gc = GColor::new("color.test.bg");
        assert_eq!(gc.id(), "color.test.bg");
        assert_eq!(gc.get(), MISSING_COLOR_RGB);
    }

    #[test]
    fn gcolor_set_and_get() {
        let gc = GColor::new("color.a");
        gc.set(RgbaColor::new(255, 0, 0));
        assert_eq!(gc.get().r, 255);
    }

    #[test]
    fn gcolor_with_alpha() {
        let gc = GColor::with_value("color.b", RgbaColor::new(0, 128, 255));
        let _alpha = gc.with_alpha(128);
    }

    #[test]
    fn gcolor_refresh_all() {
        let gc = GColor::new("color.refresh_test");
        let mut table = std::collections::HashMap::new();
        table.insert("color.refresh_test".to_string(), RgbaColor::new(10, 20, 30));
        GColor::refresh_all(&table);
        assert_eq!(gc.get(), RgbaColor::new(10, 20, 30));
    }
}
