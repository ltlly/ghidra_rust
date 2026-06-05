//! GIcon: dynamic icon looked up from the active theme.
//!
//! Ported from `generic.theme.GIcon`.

use std::sync::{Arc, Mutex, OnceLock, RwLock, Weak};

static IN_USE_ICONS: OnceLock<Mutex<Vec<Weak<RwLock<GIconInner>>>>> = OnceLock::new();

fn register_gicon(r: Weak<RwLock<GIconInner>>) {
    IN_USE_ICONS.get_or_init(|| Mutex::new(Vec::new())).lock().unwrap().push(r);
}

#[derive(Debug, Clone)]
struct GIconInner {
    id: String,
    delegate_path: Option<String>,
}

/// An icon whose value is dynamically resolved from the active theme.
#[derive(Debug, Clone)]
pub struct GIcon {
    inner: Arc<RwLock<GIconInner>>,
}

impl GIcon {
    pub fn new(id: impl Into<String>) -> Self {
        let inner = Arc::new(RwLock::new(GIconInner { id: id.into(), delegate_path: None }));
        let gi = Self { inner };
        register_gicon(Arc::downgrade(&gi.inner));
        gi
    }

    pub fn with_path(id: impl Into<String>, path: impl Into<String>) -> Self {
        let inner = Arc::new(RwLock::new(GIconInner { id: id.into(), delegate_path: Some(path.into()) }));
        let gi = Self { inner };
        register_gicon(Arc::downgrade(&gi.inner));
        gi
    }

    pub fn id(&self) -> String { self.inner.read().unwrap().id.clone() }
    pub fn get_path(&self) -> Option<String> { self.inner.read().unwrap().delegate_path.clone() }
    pub fn set_path(&self, path: Option<String>) { self.inner.write().unwrap().delegate_path = path; }

    pub fn refresh_all(icon_table: &std::collections::HashMap<String, String>) {
        let guard = IN_USE_ICONS.get_or_init(|| Mutex::new(Vec::new()));
        let mut lock = guard.lock().unwrap();
        lock.retain(|weak| {
            if let Some(arc) = weak.upgrade() {
                let id = arc.read().unwrap().id.clone();
                if let Some(new_path) = icon_table.get(&id) {
                    arc.write().unwrap().delegate_path = Some(new_path.clone());
                }
                true
            } else { false }
        });
    }
}

impl PartialEq for GIcon { fn eq(&self, other: &Self) -> bool { self.id() == other.id() } }
impl Eq for GIcon {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gicon_new_no_path() {
        let gi = GIcon::new("icon.test");
        assert_eq!(gi.id(), "icon.test");
        assert!(gi.get_path().is_none());
    }

    #[test]
    fn gicon_with_path() {
        let gi = GIcon::with_path("icon.refresh", "images/refresh.png");
        assert_eq!(gi.get_path().as_deref(), Some("images/refresh.png"));
    }

    #[test]
    fn gicon_refresh_all() {
        let gi = GIcon::new("icon.refresh_test");
        let mut table = std::collections::HashMap::new();
        table.insert("icon.refresh_test".to_string(), "images/new.png".to_string());
        GIcon::refresh_all(&table);
        assert_eq!(gi.get_path().as_deref(), Some("images/new.png"));
    }
}
