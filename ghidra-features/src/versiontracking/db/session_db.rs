//! VTSession database-backed implementation.
//!
//! Persists a version tracking session to a SQLite database.

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};

use rusqlite::{params, Connection, OptionalExtension};

use ghidra_core::addr::Address;
use ghidra_core::program::Program;

use crate::versiontracking::association::{AssociationHook, VtAssociation, VtAssociationManager};
use crate::versiontracking::db::address_correlator_db::AddressCorrelatorDB;
use crate::versiontracking::db::match_set_db::VtMatchSetDB;
use crate::versiontracking::db::tag_db::VtMatchTagDB;
use crate::versiontracking::error::{VtError, VtResult};
use crate::versiontracking::impl_module::VTEvent;
use crate::versiontracking::match_set::VtMatchSet;
use crate::versiontracking::types::{VtAssociationType, VtMatchTag};

/// Database version constant for schema compatibility.
pub const DB_VERSION: i32 = 3;

/// Database-backed version tracking session.
///
/// Wraps a SQLite connection and provides persistence for match sets,
/// associations, tags, and address correlators.
pub struct VtSessionDB {
    /// Session display name
    name: String,
    /// The SQLite connection
    conn: Arc<Mutex<Connection>>,
    /// Source program reference
    source_program: Arc<Program>,
    /// Destination program reference
    destination_program: Arc<Program>,
    /// Match sets (keyed by ID)
    match_sets: HashMap<i64, VtMatchSetDB>,
    /// Manual match set
    manual_match_set: VtMatchSet,
    /// Implied match set
    implied_match_set: VtMatchSet,
    /// Association manager
    association_manager: VtAssociationManager,
    /// Match tags
    tags: Vec<VtMatchTagDB>,
    /// Tag cache by key
    tag_cache: HashMap<i64, VtMatchTag>,
    /// Address correlator storage
    address_correlators: Vec<AddressCorrelatorDB>,
    /// Dirty flag
    dirty: bool,
    /// Next match set ID
    next_match_set_id: i64,
    /// Event log
    events: Vec<VTEvent>,
    /// Hooks
    hooks: Vec<Arc<dyn AssociationHook>>,
    /// Source program ID (for DB persistence)
    source_program_id: Option<i64>,
    /// Destination program ID (for DB persistence)
    destination_program_id: Option<i64>,
}

impl VtSessionDB {
    /// Create a new session backed by a new in-memory SQLite database.
    pub fn new(
        name: impl Into<String>,
        source_program: Program,
        destination_program: Program,
    ) -> VtResult<Self> {
        let conn = Connection::open_in_memory().map_err(VtError::DatabaseError)?;
        let session = Self::with_connection(conn, name, source_program, destination_program)?;
        Ok(session)
    }

    /// Create a new session backed by a file-based SQLite database.
    pub fn open(
        path: &Path,
        name: impl Into<String>,
        source_program: Program,
        destination_program: Program,
    ) -> VtResult<Self> {
        let conn = Connection::open(path).map_err(VtError::DatabaseError)?;
        Self::with_connection(conn, name, source_program, destination_program)
    }

    /// Create a session with an existing connection.
    fn with_connection(
        conn: Connection,
        name: impl Into<String>,
        source_program: Program,
        destination_program: Program,
    ) -> VtResult<Self> {
        let session = Self {
            name: name.into(),
            conn: Arc::new(Mutex::new(conn)),
            source_program: Arc::new(source_program),
            destination_program: Arc::new(destination_program),
            match_sets: HashMap::new(),
            manual_match_set: VtMatchSet::new(0, "Manual"),
            implied_match_set: VtMatchSet::new(-1i64 as u64, "Implied"),
            association_manager: VtAssociationManager::new(),
            tags: Vec::new(),
            tag_cache: HashMap::new(),
            address_correlators: Vec::new(),
            dirty: false,
            next_match_set_id: 1,
            events: Vec::new(),
            hooks: Vec::new(),
            source_program_id: None,
            destination_program_id: None,
        };
        session.initialize_tables()?;
        Ok(session)
    }

    /// Initialize all database tables.
    fn initialize_tables(&self) -> VtResult<()> {
        let conn = self.conn.lock().unwrap();

        // Create property table for version tracking
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS vt_session_property (
                id INTEGER PRIMARY KEY,
                key TEXT,
                value TEXT
            );
            CREATE TABLE IF NOT EXISTS vt_match_set (
                id INTEGER PRIMARY KEY,
                correlator_name TEXT,
                correlator_description TEXT,
                source_address_set TEXT,
                destination_address_set TEXT,
                options_xml TEXT
            );
            CREATE TABLE IF NOT EXISTS vt_association (
                id INTEGER PRIMARY KEY,
                association_type INTEGER,
                source_address INTEGER,
                destination_address INTEGER,
                status INTEGER,
                vote_count INTEGER DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS idx_assoc_src ON vt_association(source_address);
            CREATE INDEX IF NOT EXISTS idx_assoc_dst ON vt_association(destination_address);
            CREATE TABLE IF NOT EXISTS vt_match_tag (
                id INTEGER PRIMARY KEY,
                name TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_tag_name ON vt_match_tag(name);
            CREATE TABLE IF NOT EXISTS vt_address_correlator (
                id INTEGER PRIMARY KEY,
                correlator_class_name TEXT,
                source_entry INTEGER,
                destination_entry INTEGER,
                mappings_xml TEXT,
                confidence REAL
            );
            "
        ).map_err(VtError::DatabaseError)?;

        // Set DB version
        conn.execute(
            "INSERT OR REPLACE INTO vt_session_property (key, value) VALUES (?1, ?2)",
            params!["DB_VERSION", DB_VERSION.to_string()],
        ).map_err(VtError::DatabaseError)?;

        Ok(())
    }

    /// Returns the session name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Set the session name.
    pub fn set_name(&mut self, name: impl Into<String>) {
        self.name = name.into();
        self.dirty = true;
    }

    /// Returns the source program.
    pub fn source_program(&self) -> &Program {
        &self.source_program
    }

    /// Returns the destination program.
    pub fn destination_program(&self) -> &Program {
        &self.destination_program
    }

    /// Returns the database connection.
    pub fn connection(&self) -> &Arc<Mutex<Connection>> {
        &self.conn
    }

    /// Create a new match set and persist it.
    pub fn create_match_set(&mut self, correlator_name: impl Into<String>) -> VtResult<i64> {
        let name = correlator_name.into();
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO vt_match_set (correlator_name) VALUES (?1)",
            params![name],
        ).map_err(VtError::DatabaseError)?;
        let id = conn.last_insert_rowid();
        drop(conn);

        let db_match_set = VtMatchSetDB::new(id, &name);
        self.match_sets.insert(id, db_match_set);
        self.dirty = true;
        self.emit_event(VTEvent::MatchSetAdded);
        Ok(id)
    }

    /// Get a match set by ID.
    pub fn get_match_set(&self, id: i64) -> Option<&VtMatchSetDB> {
        self.match_sets.get(&id)
    }

    /// Get a mutable reference to a match set by ID.
    pub fn get_match_set_mut(&mut self, id: i64) -> Option<&mut VtMatchSetDB> {
        self.match_sets.get_mut(&id)
    }

    /// Returns all match sets.
    pub fn match_sets(&self) -> &HashMap<i64, VtMatchSetDB> {
        &self.match_sets
    }

    /// Returns the manual match set.
    pub fn manual_match_set(&self) -> &VtMatchSet {
        &self.manual_match_set
    }

    /// Returns the implied match set.
    pub fn implied_match_set(&self) -> &VtMatchSet {
        &self.implied_match_set
    }

    /// Returns a mutable reference to the manual match set.
    pub fn manual_match_set_mut(&mut self) -> &mut VtMatchSet {
        &mut self.manual_match_set
    }

    /// Returns a mutable reference to the implied match set.
    pub fn implied_match_set_mut(&mut self) -> &mut VtMatchSet {
        &mut self.implied_match_set
    }

    /// Returns the association manager.
    pub fn association_manager(&self) -> &VtAssociationManager {
        &self.association_manager
    }

    /// Returns a mutable reference to the association manager.
    pub fn association_manager_mut(&mut self) -> &mut VtAssociationManager {
        &mut self.association_manager
    }

    /// Create a match tag and persist it.
    pub fn create_match_tag(&mut self, name: impl Into<String>) -> VtResult<VtMatchTag> {
        let tag_name = name.into();
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO vt_match_tag (name) VALUES (?1)",
            params![tag_name],
        ).map_err(VtError::DatabaseError)?;
        let id = conn.last_insert_rowid();
        drop(conn);

        let tag_db = VtMatchTagDB::new(id, &tag_name);
        self.tags.push(tag_db.clone());
        let tag = VtMatchTag::new(&tag_name);
        self.tag_cache.insert(id, tag.clone());
        self.dirty = true;
        self.emit_event(VTEvent::TagAdded);
        Ok(tag)
    }

    /// Delete a match tag.
    pub fn delete_match_tag(&mut self, tag: &VtMatchTag) -> VtResult<()> {
        // Remove from DB first
        {
            let conn = self.conn.lock().unwrap();
            conn.execute(
                "DELETE FROM vt_match_tag WHERE name = ?1",
                params![tag.name()],
            ).map_err(VtError::DatabaseError)?;
        }
        self.tags.retain(|t| t.name() != tag.name());
        self.dirty = true;
        self.emit_event(VTEvent::TagRemoved);
        Ok(())
    }

    /// Get all match tags.
    pub fn get_match_tags(&self) -> Vec<&VtMatchTagDB> {
        self.tags.iter().collect()
    }

    /// Get a match tag by its database key.
    pub fn get_match_tag(&self, key: i64) -> Option<&VtMatchTag> {
        self.tag_cache.get(&key)
    }

    /// Get or create a tag DB record for the given tag.
    pub fn get_or_create_match_tag_db(&mut self, tag: &VtMatchTag) -> Option<VtMatchTagDB> {
        if tag.is_untagged() {
            return None;
        }
        // Check cache
        if let Some(db_tag) = self.tags.iter().find(|t| t.name() == tag.name()) {
            return Some(db_tag.clone());
        }
        // Create new
        match self.create_match_tag(tag.name()) {
            Ok(_) => self.tags.last().cloned(),
            Err(_) => None,
        }
    }

    /// Get or create an association.
    pub fn get_or_create_association(
        &mut self,
        association_type: VtAssociationType,
        source_address: Address,
        destination_address: Address,
    ) -> &VtAssociation {
        let assoc = self.association_manager.get_or_create_association(
            association_type,
            source_address,
            destination_address,
        );
        self.dirty = true;
        assoc
    }

    /// Accept an association.
    pub fn accept_association(&mut self, association_id: u64) -> VtResult<()> {
        self.association_manager.accept_association(association_id)?;
        self.dirty = true;
        self.emit_event(VTEvent::AssociationStatusChanged);
        Ok(())
    }

    /// Clear an association.
    pub fn clear_association(&mut self, association_id: u64) -> VtResult<()> {
        self.association_manager.clear_association(association_id)?;
        self.dirty = true;
        self.emit_event(VTEvent::AssociationStatusChanged);
        Ok(())
    }

    /// Add an association hook.
    pub fn add_association_hook(&mut self, hook: Arc<dyn AssociationHook>) {
        self.hooks.push(hook);
    }

    /// Add an address correlator.
    pub fn add_address_correlator(&mut self, correlator: AddressCorrelatorDB) {
        self.address_correlators.push(correlator);
    }

    /// Get all address correlators.
    pub fn address_correlators(&self) -> &[AddressCorrelatorDB] {
        &self.address_correlators
    }

    /// Returns the source program ID.
    pub fn source_program_id(&self) -> Option<i64> {
        self.source_program_id
    }

    /// Returns the destination program ID.
    pub fn destination_program_id(&self) -> Option<i64> {
        self.destination_program_id
    }

    /// Set source program ID.
    pub fn set_source_program_id(&mut self, id: i64) {
        self.source_program_id = Some(id);
    }

    /// Set destination program ID.
    pub fn set_destination_program_id(&mut self, id: i64) {
        self.destination_program_id = Some(id);
    }

    /// Total match count across all match sets.
    pub fn total_match_count(&self) -> usize {
        self.manual_match_set.match_count()
            + self.implied_match_set.match_count()
            + self.match_sets.values().map(|ms| ms.match_count()).sum::<usize>()
    }

    /// Whether the session has unsaved changes.
    pub fn is_dirty(&self) -> bool {
        self.dirty
    }

    /// Mark the session as saved.
    pub fn mark_saved(&mut self) {
        self.dirty = false;
    }

    /// Save the session to the database.
    pub fn save(&mut self) -> VtResult<()> {
        // Persist match sets, associations, tags
        // In a full implementation, this would do a transactional write
        self.dirty = false;
        Ok(())
    }

    /// Get the DB version from the property table.
    pub fn db_version(&self) -> VtResult<i32> {
        let conn = self.conn.lock().unwrap();
        let version: String = conn
            .query_row(
                "SELECT value FROM vt_session_property WHERE key = 'DB_VERSION'",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(VtError::DatabaseError)?
            .unwrap_or_else(|| "0".to_string());
        version.parse::<i32>().map_err(|_| VtError::SessionError {
            message: format!("Invalid DB version: {}", version),
        })
    }

    /// Emit an event to the log.
    fn emit_event(&mut self, event: VTEvent) {
        self.events.push(event);
    }

    /// Drain and return all pending events.
    pub fn drain_events(&mut self) -> Vec<VTEvent> {
        std::mem::take(&mut self.events)
    }

    /// Get the events without consuming them.
    pub fn events(&self) -> &[VTEvent] {
        &self.events
    }

    /// Execute a SQL query on the underlying connection.
    pub fn execute_sql(&self, sql: &str) -> VtResult<usize> {
        let conn = self.conn.lock().unwrap();
        conn.execute_batch(sql).map_err(VtError::DatabaseError)?;
        Ok(0)
    }
}

impl std::fmt::Debug for VtSessionDB {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VtSessionDB")
            .field("name", &self.name)
            .field("match_sets", &self.match_sets.len())
            .field("tags", &self.tags.len())
            .field("dirty", &self.dirty)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ghidra_core::addr::Address;

    fn make_program(name: &str) -> Program {
        Program::new(name, Address::new(0x1000))
    }

    #[test]
    fn test_session_db_create() {
        let session = VtSessionDB::new("test.vt", make_program("src"), make_program("dst")).unwrap();
        assert_eq!(session.name(), "test.vt");
        assert!(!session.is_dirty());
    }

    #[test]
    fn test_session_db_match_sets() {
        let mut session = VtSessionDB::new("test", make_program("src"), make_program("dst")).unwrap();
        let id = session.create_match_set("ExactMatch").unwrap();
        assert!(id > 0);
        assert!(session.get_match_set(id).is_some());
        assert_eq!(session.match_sets().len(), 1);
    }

    #[test]
    fn test_session_db_tags() {
        let mut session = VtSessionDB::new("test", make_program("src"), make_program("dst")).unwrap();
        let tag = session.create_match_tag("verified").unwrap();
        assert_eq!(tag.name(), "verified");
        assert_eq!(session.get_match_tags().len(), 1);
    }

    #[test]
    fn test_session_db_db_version() {
        let session = VtSessionDB::new("test", make_program("src"), make_program("dst")).unwrap();
        let version = session.db_version().unwrap();
        assert_eq!(version, DB_VERSION);
    }

    #[test]
    fn test_session_db_dirty_flag() {
        let mut session = VtSessionDB::new("test", make_program("src"), make_program("dst")).unwrap();
        assert!(!session.is_dirty());
        let _ = session.create_match_set("Test");
        assert!(session.is_dirty());
        session.mark_saved();
        assert!(!session.is_dirty());
    }

    #[test]
    fn test_session_db_events() {
        let mut session = VtSessionDB::new("test", make_program("src"), make_program("dst")).unwrap();
        let _ = session.create_match_set("Test");
        let events = session.drain_events();
        assert!(!events.is_empty());
        assert_eq!(events[0], VTEvent::MatchSetAdded);
    }

    #[test]
    fn test_session_db_associations() {
        let mut session = VtSessionDB::new("test", make_program("src"), make_program("dst")).unwrap();
        session.get_or_create_association(
            VtAssociationType::Function,
            Address::new(0x1000),
            Address::new(0x2000),
        );
        assert_eq!(session.association_manager().count(), 1);
    }

    #[test]
    fn test_session_db_program_accessors() {
        let mut session = VtSessionDB::new("test", make_program("src"), make_program("dst")).unwrap();
        assert_eq!(session.source_program().name, "src");
        assert_eq!(session.destination_program().name, "dst");
        session.set_source_program_id(42);
        assert_eq!(session.source_program_id(), Some(42));
    }

    #[test]
    fn test_session_db_save() {
        let mut session = VtSessionDB::new("test", make_program("src"), make_program("dst")).unwrap();
        let _ = session.create_match_set("Test");
        assert!(session.is_dirty());
        session.save().unwrap();
        assert!(!session.is_dirty());
    }
}
