//! `Help` -- global accessor for the active `HelpService`.
//!
//! Ported from `help.Help`. Acts as a singleton that holds the currently
//! installed [`HelpService`].

use std::sync::{Mutex, OnceLock};

use crate::default_help_service::DefaultHelpService;
use crate::help_service::HelpService;

/// Global help service holder.
static HELP_SERVICE: OnceLock<Mutex<Box<dyn HelpService + Send>>> = OnceLock::new();

/// Global accessor for the application's help service.
pub struct Help;

impl Help {
    /// Returns a reference to the active help service.
    ///
    /// If no service has been installed, a [`DefaultHelpService`] is created.
    pub fn get_help_service() -> &'static Mutex<Box<dyn HelpService + Send>> {
        HELP_SERVICE.get_or_init(|| {
            log::debug!("Initializing default help service");
            Mutex::new(Box::new(DefaultHelpService::new()))
        })
    }

    /// Install a custom help service, replacing the current one.
    ///
    /// Passing `None` is a no-op (the Java version logs a debug message for
    /// `null`).
    pub fn install_help_service(service: impl HelpService + Send + 'static) {
        let mutex = Self::get_help_service();
        if let Ok(mut guard) = mutex.lock() {
            *guard = Box::new(service);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_help_service_exists() {
        let _svc = Help::get_help_service();
    }

    #[test]
    fn test_default_help_does_not_exist() {
        let svc = Help::get_help_service().lock().unwrap();
        assert!(!svc.help_exists());
    }
}
