//! Colorizer commands -- set and clear background colors.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.colorizer` package:
//!
//! - [`SetColorCommand`] -- sets background color over an address range
//! - [`ClearColorCommand`] -- clears background color (range or all)

use super::{Color, ColorizingService};

/// Command that sets a background color over an address range.
///
/// Ported from `ghidra.app.plugin.core.colorizer.SetColorCommand`.
#[derive(Debug)]
pub struct SetColorCommand {
    /// The color to apply.
    color: Color,
    /// Minimum address (inclusive).
    min_addr: u64,
    /// Maximum address (inclusive).
    max_addr: u64,
}

impl SetColorCommand {
    /// Create a command that sets a color on a single address.
    pub fn single(color: Color, addr: u64) -> Self {
        Self {
            color,
            min_addr: addr,
            max_addr: addr,
        }
    }

    /// Create a command that sets a color over an address range.
    pub fn range(color: Color, min_addr: u64, max_addr: u64) -> Self {
        Self {
            color,
            min_addr,
            max_addr,
        }
    }

    /// Apply the command to the given service.
    pub fn apply(&self, service: &mut dyn ColorizingService) {
        service.set_background_color(self.min_addr, self.max_addr, self.color);
    }

    /// The command name.
    pub fn name(&self) -> &str {
        "Set Background Color"
    }
}

/// Command that clears background colors.
///
/// Ported from `ghidra.app.plugin.core.colorizer.ClearColorCommand`.
///
/// When constructed with a range, only that range is cleared.
/// When constructed without a range, all colors are cleared.
#[derive(Debug)]
pub struct ClearColorCommand {
    /// The range to clear (None = clear all).
    range: Option<(u64, u64)>,
}

impl ClearColorCommand {
    /// Create a command that clears all background colors.
    pub fn all() -> Self {
        Self { range: None }
    }

    /// Create a command that clears colors in a specific range.
    pub fn range(min_addr: u64, max_addr: u64) -> Self {
        Self {
            range: Some((min_addr, max_addr)),
        }
    }

    /// Apply the command to the given service.
    pub fn apply(&self, service: &mut dyn ColorizingService) {
        match self.range {
            Some((min, max)) => service.clear_background_color(min, max),
            None => service.clear_all_background_colors(),
        }
    }

    /// The command name.
    pub fn name(&self) -> &str {
        "Clear Background Color"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::base::colorizer::ColorizingServiceImpl;

    #[test]
    fn test_set_color_command_single() {
        let mut svc = ColorizingServiceImpl::new();
        let cmd = SetColorCommand::single(0xFF0000, 0x1000);
        assert_eq!(cmd.name(), "Set Background Color");
        cmd.apply(&mut svc);
        assert_eq!(svc.get_background_color(0x1000), Some(0xFF0000));
        assert_eq!(svc.get_background_color(0x1001), None);
    }

    #[test]
    fn test_set_color_command_range() {
        let mut svc = ColorizingServiceImpl::new();
        let cmd = SetColorCommand::range(0x00FF00, 0x1000, 0x1005);
        cmd.apply(&mut svc);
        assert_eq!(svc.get_background_color(0x1000), Some(0x00FF00));
        assert_eq!(svc.get_background_color(0x1003), Some(0x00FF00));
        assert_eq!(svc.get_background_color(0x1005), Some(0x00FF00));
        assert_eq!(svc.get_background_color(0x1006), None);
    }

    #[test]
    fn test_clear_color_command_range() {
        let mut svc = ColorizingServiceImpl::new();
        svc.set_background_color(0x1000, 0x2000, 0xFF0000);

        let cmd = ClearColorCommand::range(0x1500, 0x1800);
        assert_eq!(cmd.name(), "Clear Background Color");
        cmd.apply(&mut svc);

        assert_eq!(svc.get_background_color(0x1000), Some(0xFF0000));
        assert_eq!(svc.get_background_color(0x1500), None);
        assert_eq!(svc.get_background_color(0x1800), None);
        assert_eq!(svc.get_background_color(0x2000), Some(0xFF0000));
    }

    #[test]
    fn test_clear_color_command_all() {
        let mut svc = ColorizingServiceImpl::new();
        svc.set_background_color(0x1000, 0x2000, 0xFF0000);
        svc.set_background_color(0x3000, 0x4000, 0x00FF00);

        let cmd = ClearColorCommand::all();
        cmd.apply(&mut svc);

        assert!(svc.all_colored_addresses().is_empty());
    }
}
