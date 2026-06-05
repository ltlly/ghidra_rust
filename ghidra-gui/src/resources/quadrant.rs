//! Quadrant positions for composite icons.
//!
//! Ports `resources.QUADRANT` from Ghidra's GUI framework.

/// Quadrant position within a composite icon.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Quadrant {
    /// Top-left quadrant.
    TopLeft,
    /// Top-right quadrant.
    TopRight,
    /// Bottom-left quadrant.
    BottomLeft,
    /// Bottom-right quadrant.
    BottomRight,
}

impl Quadrant {
    /// The horizontal offset multiplier for this quadrant.
    pub fn x_multiplier(&self) -> f32 {
        match self {
            Quadrant::TopLeft | Quadrant::BottomLeft => 0.0,
            Quadrant::TopRight | Quadrant::BottomRight => 1.0,
        }
    }

    /// The vertical offset multiplier for this quadrant.
    pub fn y_multiplier(&self) -> f32 {
        match self {
            Quadrant::TopLeft | Quadrant::TopRight => 0.0,
            Quadrant::BottomLeft | Quadrant::BottomRight => 1.0,
        }
    }

    /// All quadrant values.
    pub fn all() -> &'static [Quadrant] {
        &[
            Quadrant::TopLeft,
            Quadrant::TopRight,
            Quadrant::BottomLeft,
            Quadrant::BottomRight,
        ]
    }
}

impl std::fmt::Display for Quadrant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Quadrant::TopLeft => write!(f, "TopLeft"),
            Quadrant::TopRight => write!(f, "TopRight"),
            Quadrant::BottomLeft => write!(f, "BottomLeft"),
            Quadrant::BottomRight => write!(f, "BottomRight"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_quadrant_multipliers() {
        assert_eq!(Quadrant::TopLeft.x_multiplier(), 0.0);
        assert_eq!(Quadrant::TopLeft.y_multiplier(), 0.0);
        assert_eq!(Quadrant::TopRight.x_multiplier(), 1.0);
        assert_eq!(Quadrant::TopRight.y_multiplier(), 0.0);
        assert_eq!(Quadrant::BottomLeft.x_multiplier(), 0.0);
        assert_eq!(Quadrant::BottomLeft.y_multiplier(), 1.0);
        assert_eq!(Quadrant::BottomRight.x_multiplier(), 1.0);
        assert_eq!(Quadrant::BottomRight.y_multiplier(), 1.0);
    }

    #[test]
    fn test_quadrant_display() {
        assert_eq!(Quadrant::TopLeft.to_string(), "TopLeft");
        assert_eq!(Quadrant::BottomRight.to_string(), "BottomRight");
    }

    #[test]
    fn test_quadrant_all() {
        assert_eq!(Quadrant::all().len(), 4);
    }
}
