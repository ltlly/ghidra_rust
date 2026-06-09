//! Checkout status types.
//!
//! Re-exports [`ItemCheckoutStatus`] and [`CheckoutType`] from
//! `crate::filesystem::store` and adds a [`CheckoutStatusBuilder`] for
//! convenient construction.
//!
//! Corresponds to `ghidra.framework.store.ItemCheckoutStatus`.

// Re-export from store.
pub use crate::filesystem::store::{CheckoutType, ItemCheckoutStatus};

// ============================================================================
// CheckoutStatusBuilder
// ============================================================================

/// Builder for constructing [`ItemCheckoutStatus`] instances.
///
/// # Example
///
/// ```
/// use ghidra_core::filesystem::checkout_status::*;
///
/// let status = CheckoutStatusBuilder::new(42, CheckoutType::Normal, "alice")
///     .version(3)
///     .time(100_000)
///     .project_path("myhost::/projects/test")
///     .build();
///
/// assert_eq!(status.checkout_id(), 42);
/// assert_eq!(status.user(), "alice");
/// ```
pub struct CheckoutStatusBuilder {
    checkout_id: i64,
    checkout_type: CheckoutType,
    user: String,
    version: i32,
    time: i64,
    project_path: Option<String>,
}

impl CheckoutStatusBuilder {
    /// Start building a new checkout status.
    pub fn new(
        checkout_id: i64,
        checkout_type: CheckoutType,
        user: impl Into<String>,
    ) -> Self {
        Self {
            checkout_id,
            checkout_type,
            user: user.into(),
            version: 0,
            time: 0,
            project_path: None,
        }
    }

    /// Set the checked-out version.
    pub fn version(mut self, version: i32) -> Self {
        self.version = version;
        self
    }

    /// Set the checkout timestamp (millis since epoch).
    pub fn time(mut self, time: i64) -> Self {
        self.time = time;
        self
    }

    /// Set the project path (host::path format).
    pub fn project_path(mut self, path: impl Into<String>) -> Self {
        self.project_path = Some(path.into());
        self
    }

    /// Build the [`ItemCheckoutStatus`].
    pub fn build(self) -> ItemCheckoutStatus {
        ItemCheckoutStatus::new(
            self.checkout_id,
            self.checkout_type,
            self.user,
            self.version,
            self.time,
            self.project_path,
        )
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_builder_basic() {
        let status = CheckoutStatusBuilder::new(1, CheckoutType::Normal, "alice")
            .version(5)
            .time(12345)
            .build();

        assert_eq!(status.checkout_id(), 1);
        assert_eq!(status.checkout_type(), CheckoutType::Normal);
        assert_eq!(status.user(), "alice");
        assert_eq!(status.checkout_version(), 5);
        assert_eq!(status.checkout_time(), 12345);
        assert_eq!(status.project_path(), None);
    }

    #[test]
    fn test_builder_with_project_path() {
        let status = CheckoutStatusBuilder::new(99, CheckoutType::Exclusive, "bob")
            .project_path("host::/projects/myproj")
            .build();

        assert_eq!(status.checkout_id(), 99);
        assert_eq!(status.checkout_type(), CheckoutType::Exclusive);
        assert_eq!(status.project_path(), Some("host::/projects/myproj"));
        assert_eq!(status.project_name(), Some("myproj"));
    }

    #[test]
    fn test_builder_transient() {
        let status = CheckoutStatusBuilder::new(7, CheckoutType::Transient, "carol")
            .version(2)
            .time(99999)
            .build();

        assert_eq!(status.checkout_type(), CheckoutType::Transient);
    }

    #[test]
    fn test_builder_defaults() {
        let status = CheckoutStatusBuilder::new(0, CheckoutType::Normal, "").build();
        assert_eq!(status.checkout_version(), 0);
        assert_eq!(status.checkout_time(), 0);
    }
}
