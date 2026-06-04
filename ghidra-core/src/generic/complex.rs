//! Complex number support for Ghidra Rust.
//!
//! Ports Ghidra's `generic.complex.Complex` class.

use std::fmt;
use std::ops::{Add, Div, Mul, Neg, Sub};

/// A complex number with `f64` real and imaginary parts.
///
/// Corresponds to Ghidra's `generic.complex.Complex`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Complex {
    /// The real part.
    pub real: f64,
    /// The imaginary part.
    pub imag: f64,
}

impl Complex {
    /// The complex zero (0+0i).
    pub const ZERO: Self = Self { real: 0.0, imag: 0.0 };

    /// The complex one (1+0i).
    pub const ONE: Self = Self { real: 1.0, imag: 0.0 };

    /// The imaginary unit (0+1i).
    pub const I: Self = Self { real: 0.0, imag: 1.0 };

    /// Create a new complex number.
    pub fn new(real: f64, imag: f64) -> Self {
        Self { real, imag }
    }

    /// Create a complex number from polar coordinates.
    pub fn from_polar(r: f64, theta: f64) -> Self {
        Self {
            real: r * theta.cos(),
            imag: r * theta.sin(),
        }
    }

    /// The magnitude (absolute value) of this complex number.
    pub fn abs(&self) -> f64 {
        self.real.hypot(self.imag)
    }

    /// The squared magnitude (avoids sqrt).
    pub fn abs_sq(&self) -> f64 {
        self.real * self.real + self.imag * self.imag
    }

    /// The argument (angle) of this complex number.
    pub fn arg(&self) -> f64 {
        self.imag.atan2(self.real)
    }

    /// The complex conjugate.
    pub fn conj(&self) -> Self {
        Self {
            real: self.real,
            imag: -self.imag,
        }
    }

    /// Returns `true` if the imaginary part is zero (within epsilon).
    pub fn is_real(&self) -> bool {
        self.imag.abs() < f64::EPSILON
    }

    /// Returns `true` if both parts are zero.
    pub fn is_zero(&self) -> bool {
        self.real.abs() < f64::EPSILON && self.imag.abs() < f64::EPSILON
    }

    /// e^z = e^(a+bi) = e^a * (cos(b) + i*sin(b))
    pub fn exp(&self) -> Self {
        let r = self.real.exp();
        Self {
            real: r * self.imag.cos(),
            imag: r * self.imag.sin(),
        }
    }

    /// Natural logarithm.
    pub fn ln(&self) -> Self {
        Self {
            real: self.abs().ln(),
            imag: self.arg(),
        }
    }

    /// Raise to a real power.
    pub fn powf(&self, n: f64) -> Self {
        let r = self.abs().powf(n);
        let theta = self.arg() * n;
        Self {
            real: r * theta.cos(),
            imag: r * theta.sin(),
        }
    }

    /// Square root.
    pub fn sqrt(&self) -> Self {
        self.powf(0.5)
    }
}

impl Default for Complex {
    fn default() -> Self {
        Self::ZERO
    }
}

impl fmt::Display for Complex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.imag >= 0.0 {
            write!(f, "{}+{}i", self.real, self.imag)
        } else {
            write!(f, "{}{}i", self.real, self.imag)
        }
    }
}

impl Add for Complex {
    type Output = Self;
    fn add(self, rhs: Self) -> Self {
        Self {
            real: self.real + rhs.real,
            imag: self.imag + rhs.imag,
        }
    }
}

impl Sub for Complex {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self {
        Self {
            real: self.real - rhs.real,
            imag: self.imag - rhs.imag,
        }
    }
}

impl Mul for Complex {
    type Output = Self;
    fn mul(self, rhs: Self) -> Self {
        Self {
            real: self.real * rhs.real - self.imag * rhs.imag,
            imag: self.real * rhs.imag + self.imag * rhs.real,
        }
    }
}

impl Div for Complex {
    type Output = Self;
    fn div(self, rhs: Self) -> Self {
        let denom = rhs.abs_sq();
        if denom < f64::EPSILON {
            panic!("Division by zero complex number");
        }
        Self {
            real: (self.real * rhs.real + self.imag * rhs.imag) / denom,
            imag: (self.imag * rhs.real - self.real * rhs.imag) / denom,
        }
    }
}

impl Neg for Complex {
    type Output = Self;
    fn neg(self) -> Self {
        Self {
            real: -self.real,
            imag: -self.imag,
        }
    }
}

// Scalar multiplication
impl Mul<f64> for Complex {
    type Output = Self;
    fn mul(self, rhs: f64) -> Self {
        Self {
            real: self.real * rhs,
            imag: self.imag * rhs,
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    const EPS: f64 = 1e-10;

    fn approx_eq(a: Complex, b: Complex) -> bool {
        (a.real - b.real).abs() < EPS && (a.imag - b.imag).abs() < EPS
    }

    #[test]
    fn test_basic_arithmetic() {
        let a = Complex::new(1.0, 2.0);
        let b = Complex::new(3.0, 4.0);
        assert!(approx_eq(a + b, Complex::new(4.0, 6.0)));
        assert!(approx_eq(b - a, Complex::new(2.0, 2.0)));
        // (1+2i)(3+4i) = 3+4i+6i+8i^2 = -5+10i
        assert!(approx_eq(a * b, Complex::new(-5.0, 10.0)));
    }

    #[test]
    fn test_division() {
        let a = Complex::new(1.0, 0.0);
        let b = Complex::new(0.0, 1.0);
        // 1 / i = -i
        assert!(approx_eq(a / b, Complex::new(0.0, -1.0)));
    }

    #[test]
    fn test_conjugate() {
        let c = Complex::new(3.0, 4.0);
        assert_eq!(c.conj(), Complex::new(3.0, -4.0));
    }

    #[test]
    fn test_abs() {
        let c = Complex::new(3.0, 4.0);
        assert!((c.abs() - 5.0).abs() < EPS);
    }

    #[test]
    fn test_polar() {
        let c = Complex::from_polar(1.0, std::f64::consts::PI / 2.0);
        assert!((c.real).abs() < EPS);
        assert!((c.imag - 1.0).abs() < EPS);
    }

    #[test]
    fn test_is_real() {
        assert!(Complex::new(5.0, 0.0).is_real());
        assert!(!Complex::new(5.0, 1.0).is_real());
    }

    #[test]
    fn test_negation() {
        let c = Complex::new(1.0, -2.0);
        assert_eq!(-c, Complex::new(-1.0, 2.0));
    }

    #[test]
    fn test_display() {
        let c = Complex::new(1.0, 2.0);
        assert_eq!(format!("{}", c), "1+2i");

        let c = Complex::new(1.0, -2.0);
        assert_eq!(format!("{}", c), "1-2i");
    }

    #[test]
    fn test_scalar_mul() {
        let c = Complex::new(2.0, 3.0);
        let result = c * 2.0;
        assert_eq!(result, Complex::new(4.0, 6.0));
    }

    #[test]
    fn test_i_squared() {
        let i = Complex::I;
        let result = i * i;
        assert!(approx_eq(result, Complex::new(-1.0, 0.0)));
    }
}
