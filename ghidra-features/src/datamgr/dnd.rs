//! Drag-and-drop support for the data type manager tree.
//!
//! Ported from `ghidra.app.plugin.core.datamgr.DataTypeDragNDropHandler`
//! and `DataDropOnBrowserHandler`.

/// The type of drag-and-drop operation being performed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DndOperation {
    /// Copy data types.
    Copy,
    /// Move data types.
    Move,
    /// Link (create a reference to) data types.
    Link,
}

/// A drag-and-drop transfer containing data type paths.
///
/// Ported from `ghidra.app.plugin.core.datamgr.DataTypeDragNDropHandler`.
#[derive(Debug, Clone)]
pub struct DataTypeTransfer {
    /// The data type paths being transferred.
    pub paths: Vec<String>,
    /// The source archive name.
    pub source_archive: String,
    /// The operation type.
    pub operation: DndOperation,
}

impl DataTypeTransfer {
    /// Create a new transfer.
    pub fn new(
        paths: Vec<String>,
        source_archive: impl Into<String>,
        operation: DndOperation,
    ) -> Self {
        Self {
            paths,
            source_archive: source_archive.into(),
            operation,
        }
    }

    /// Number of data types being transferred.
    pub fn count(&self) -> usize {
        self.paths.len()
    }
}

/// Handles drag-and-drop operations for data types in the data type manager tree.
///
/// Ported from `ghidra.app.plugin.core.datamgr.DataTypeDragNDropHandler`.
#[derive(Debug)]
pub struct DataTypeDragNDropHandler {
    /// Current transfer in progress.
    current_transfer: Option<DataTypeTransfer>,
    /// Whether a drag is in progress.
    dragging: bool,
    /// The drop target category path.
    drop_target: Option<String>,
    /// Supported operations for the current drag.
    supported_operations: Vec<DndOperation>,
}

impl DataTypeDragNDropHandler {
    /// Create a new drag-and-drop handler.
    pub fn new() -> Self {
        Self {
            current_transfer: None,
            dragging: false,
            drop_target: None,
            supported_operations: vec![DndOperation::Copy, DndOperation::Move],
        }
    }

    /// Begin a drag operation.
    pub fn begin_drag(&mut self, transfer: DataTypeTransfer) {
        self.current_transfer = Some(transfer);
        self.dragging = true;
    }

    /// Set the drop target.
    pub fn set_drop_target(&mut self, target: Option<String>) {
        self.drop_target = target;
    }

    /// Whether a drag is in progress.
    pub fn is_dragging(&self) -> bool {
        self.dragging
    }

    /// Get the current transfer.
    pub fn current_transfer(&self) -> Option<&DataTypeTransfer> {
        self.current_transfer.as_ref()
    }

    /// Get the drop target.
    pub fn drop_target(&self) -> Option<&str> {
        self.drop_target.as_deref()
    }

    /// Validate whether the current transfer can be dropped on the target.
    pub fn can_drop(&self) -> bool {
        if !self.dragging {
            return false;
        }
        let transfer = match &self.current_transfer {
            Some(t) => t,
            None => return false,
        };
        let target = match &self.drop_target {
            Some(t) => t,
            None => return false,
        };
        // Cannot drop on the source archive itself
        if transfer.source_archive == *target {
            return false;
        }
        // Cannot drop if the path is the same as the target
        !transfer.paths.iter().any(|p| p == target)
    }

    /// Complete the drop operation.
    pub fn drop(&mut self) -> Result<DataTypeTransfer, String> {
        if !self.can_drop() {
            return Err("Invalid drop operation".into());
        }
        let transfer = self.current_transfer.take().ok_or("No transfer")?;
        self.dragging = false;
        self.drop_target = None;
        Ok(transfer)
    }

    /// Cancel the current drag operation.
    pub fn cancel(&mut self) {
        self.current_transfer = None;
        self.dragging = false;
        self.drop_target = None;
    }

    /// Get the supported operations.
    pub fn supported_operations(&self) -> &[DndOperation] {
        &self.supported_operations
    }

    /// Whether a specific operation is supported.
    pub fn supports_operation(&self, op: DndOperation) -> bool {
        self.supported_operations.contains(&op)
    }
}

impl Default for DataTypeDragNDropHandler {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// DataDropOnBrowserHandler
// ---------------------------------------------------------------------------

/// Handles dropping data types onto the code browser (listing view).
///
/// Ported from `ghidra.app.plugin.core.datamgr.DataDropOnBrowserHandler`.
#[derive(Debug)]
pub struct DataDropOnBrowserHandler {
    /// Whether dropping is currently enabled.
    enabled: bool,
    /// The address where the drop would occur.
    drop_address: Option<u64>,
    /// Data types being dropped.
    pending_types: Vec<String>,
}

impl DataDropOnBrowserHandler {
    /// Create a new browser drop handler.
    pub fn new() -> Self {
        Self {
            enabled: true,
            drop_address: None,
            pending_types: Vec::new(),
        }
    }

    /// Set whether dropping is enabled.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    /// Whether dropping is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Set the drop address.
    pub fn set_drop_address(&mut self, address: Option<u64>) {
        self.drop_address = address;
    }

    /// Get the drop address.
    pub fn drop_address(&self) -> Option<u64> {
        self.drop_address
    }

    /// Begin a drop with data type names.
    pub fn begin_drop(&mut self, types: Vec<String>, address: u64) {
        self.pending_types = types;
        self.drop_address = Some(address);
    }

    /// Complete the drop, returning the types and address.
    pub fn complete_drop(&mut self) -> Option<(Vec<String>, u64)> {
        let addr = self.drop_address.take()?;
        let types = std::mem::take(&mut self.pending_types);
        if types.is_empty() {
            None
        } else {
            Some((types, addr))
        }
    }

    /// Cancel the drop.
    pub fn cancel_drop(&mut self) {
        self.pending_types.clear();
        self.drop_address = None;
    }

    /// Whether there is a pending drop.
    pub fn has_pending_drop(&self) -> bool {
        !self.pending_types.is_empty() && self.drop_address.is_some()
    }
}

impl Default for DataDropOnBrowserHandler {
    fn default() -> Self {
        Self::new()
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_data_type_transfer() {
        let transfer = DataTypeTransfer::new(
            vec!["/MyStruct".into()],
            "archive1",
            DndOperation::Copy,
        );
        assert_eq!(transfer.count(), 1);
        assert_eq!(transfer.source_archive, "archive1");
    }

    #[test]
    fn test_dnd_handler_drag_lifecycle() {
        let mut handler = DataTypeDragNDropHandler::new();
        assert!(!handler.is_dragging());

        let transfer = DataTypeTransfer::new(
            vec!["/Type1".into()],
            "src_archive",
            DndOperation::Move,
        );
        handler.begin_drag(transfer);
        assert!(handler.is_dragging());
        assert_eq!(handler.current_transfer().unwrap().count(), 1);

        handler.set_drop_target(Some("dst_archive".into()));
        assert!(handler.can_drop());

        let dropped = handler.drop().unwrap();
        assert_eq!(dropped.paths, vec!["/Type1"]);
        assert!(!handler.is_dragging());
    }

    #[test]
    fn test_dnd_handler_cannot_drop_same_archive() {
        let mut handler = DataTypeDragNDropHandler::new();
        handler.begin_drag(DataTypeTransfer::new(
            vec!["/T".into()],
            "archive1",
            DndOperation::Copy,
        ));
        handler.set_drop_target(Some("archive1".into()));
        assert!(!handler.can_drop());
    }

    #[test]
    fn test_dnd_handler_cannot_drop_no_target() {
        let mut handler = DataTypeDragNDropHandler::new();
        handler.begin_drag(DataTypeTransfer::new(
            vec!["/T".into()],
            "archive1",
            DndOperation::Copy,
        ));
        assert!(!handler.can_drop());
    }

    #[test]
    fn test_dnd_handler_cancel() {
        let mut handler = DataTypeDragNDropHandler::new();
        handler.begin_drag(DataTypeTransfer::new(
            vec!["/T".into()],
            "archive1",
            DndOperation::Copy,
        ));
        handler.cancel();
        assert!(!handler.is_dragging());
        assert!(handler.current_transfer().is_none());
    }

    #[test]
    fn test_dnd_handler_supported_operations() {
        let handler = DataTypeDragNDropHandler::new();
        assert!(handler.supports_operation(DndOperation::Copy));
        assert!(handler.supports_operation(DndOperation::Move));
        assert!(!handler.supports_operation(DndOperation::Link));
    }

    #[test]
    fn test_browser_drop_handler() {
        let mut handler = DataDropOnBrowserHandler::new();
        assert!(handler.is_enabled());
        assert!(!handler.has_pending_drop());

        handler.begin_drop(vec!["int".into(), "char".into()], 0x400000);
        assert!(handler.has_pending_drop());
        assert_eq!(handler.drop_address(), Some(0x400000));

        let result = handler.complete_drop();
        assert!(result.is_some());
        let (types, addr) = result.unwrap();
        assert_eq!(types.len(), 2);
        assert_eq!(addr, 0x400000);
        assert!(!handler.has_pending_drop());
    }

    #[test]
    fn test_browser_drop_handler_cancel() {
        let mut handler = DataDropOnBrowserHandler::new();
        handler.begin_drop(vec!["int".into()], 0x100);
        handler.cancel_drop();
        assert!(!handler.has_pending_drop());
    }

    #[test]
    fn test_browser_drop_handler_disabled() {
        let mut handler = DataDropOnBrowserHandler::new();
        handler.set_enabled(false);
        assert!(!handler.is_enabled());
    }

    #[test]
    fn test_dnd_operation_variants() {
        assert_ne!(DndOperation::Copy, DndOperation::Move);
        assert_ne!(DndOperation::Move, DndOperation::Link);
    }
}
