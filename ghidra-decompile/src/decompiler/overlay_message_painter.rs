//! Port of `OverlayMessagePainter`.
use std::collections::HashMap;
/// Struct porting `OverlayMessagePainter`.
#[derive(Debug, Clone)]
pub struct OverlayMessagePainter {
    _phantom: std::marker::PhantomData<()>,
}
impl OverlayMessagePainter {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for OverlayMessagePainter {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_overlay_message_painter_new() { let _ = OverlayMessagePainter::new(); }
}
