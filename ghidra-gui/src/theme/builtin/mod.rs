//! Built-in themes.
//!
//! Ported from `generic.theme.builtin.*`.
//!
//! All 8 Java built-in themes are now ported:
//! - FlatDark, FlatLight, Metal (existing)
//! - GTK, Mac, Windows, WindowsClassic, Nimbus, CDEMotif (new)

pub mod cde_motif_theme;
pub mod flat_dark;
pub mod flat_light;
pub mod gtk_theme;
pub mod mac_theme;
pub mod metal;
pub mod windows_theme;

pub use cde_motif_theme::{CdeMotifTheme, NimbusTheme};
pub use flat_dark::FlatDarkTheme;
pub use flat_light::FlatLightTheme;
pub use gtk_theme::GtkTheme;
pub use mac_theme::MacTheme;
pub use metal::MetalTheme;
pub use windows_theme::{WindowsClassicTheme, WindowsTheme};
