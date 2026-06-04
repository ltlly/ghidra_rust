//! Database-backed symbol storage for traces.
//!
//! Provides SQLite-backed symbol and reference operations for the trace database.

use rusqlite::{params, Connection, Result as SqlResult};

use crate::model::{
    symbol::{TraceSymbol, TraceSymbolKind, TraceReference, TraceReferenceKind},
    Lifespan,
};

/// Extension trait for symbol table operations.
pub trait TraceSymbolDbExt {
    /// Create the symbol tables.
    fn create_symbol_tables(&self) -> SqlResult<()>;

    /// Insert a symbol.
    fn insert_symbol(&self, symbol: &TraceSymbol) -> SqlResult<()>;

    /// Load all symbols.
    fn load_symbols(&self) -> SqlResult<Vec<TraceSymbol>>;

    /// Delete a symbol by key.
    fn delete_symbol(&self, key: i64) -> SqlResult<bool>;

    /// Get symbols by name.
    fn get_symbols_by_name(&self, name: &str, snap: i64) -> SqlResult<Vec<TraceSymbol>>;

    /// Get symbols at an address.
    fn get_symbols_at(&self, address: u64, space: &str, snap: i64) -> SqlResult<Vec<TraceSymbol>>;

    /// Insert a reference.
    fn insert_reference(&self, reference: &TraceReference) -> SqlResult<()>;

    /// Load all references.
    fn load_references(&self) -> SqlResult<Vec<TraceReference>>;

    /// Get references from an address.
    fn get_references_from(&self, address: u64, snap: i64) -> SqlResult<Vec<TraceReference>>;

    /// Get references to an address.
    fn get_references_to(&self, address: u64, snap: i64) -> SqlResult<Vec<TraceReference>>;
}

impl TraceSymbolDbExt for Connection {
    fn create_symbol_tables(&self) -> SqlResult<()> {
        self.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS trace_symbols (
                key INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                address INTEGER,
                space TEXT,
                kind TEXT NOT NULL,
                parent_key INTEGER,
                min_snap INTEGER NOT NULL,
                max_snap INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_symbols_name ON trace_symbols(name);
            CREATE INDEX IF NOT EXISTS idx_symbols_address ON trace_symbols(address, space);
            CREATE INDEX IF NOT EXISTS idx_symbols_snap ON trace_symbols(min_snap, max_snap);

            CREATE TABLE IF NOT EXISTS trace_references (
                key INTEGER PRIMARY KEY,
                from_address INTEGER NOT NULL,
                to_address INTEGER NOT NULL,
                kind TEXT NOT NULL,
                min_snap INTEGER NOT NULL,
                max_snap INTEGER NOT NULL,
                is_primary INTEGER NOT NULL DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS idx_refs_from ON trace_references(from_address);
            CREATE INDEX IF NOT EXISTS idx_refs_to ON trace_references(to_address);
            ",
        )?;
        Ok(())
    }

    fn insert_symbol(&self, symbol: &TraceSymbol) -> SqlResult<()> {
        self.execute(
            "INSERT OR REPLACE INTO trace_symbols (key, name, address, space, kind, parent_key, min_snap, max_snap) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                symbol.key,
                symbol.name,
                symbol.address.map(|a| a as i64),
                symbol.space,
                format!("{:?}", symbol.kind),
                symbol.parent_key,
                symbol.lifespan.lmin(),
                symbol.lifespan.lmax(),
            ],
        )?;
        Ok(())
    }

    fn load_symbols(&self) -> SqlResult<Vec<TraceSymbol>> {
        let mut stmt = self.prepare(
            "SELECT key, name, address, space, kind, parent_key, min_snap, max_snap FROM trace_symbols",
        )?;
        let symbols = stmt
            .query_map([], |row| {
                let kind_str: String = row.get(4)?;
                let kind = match kind_str.as_str() {
                    "Label" => TraceSymbolKind::Label,
                    "Namespace" => TraceSymbolKind::Namespace,
                    "Class" => TraceSymbolKind::Class,
                    "Function" => TraceSymbolKind::Function,
                    _ => TraceSymbolKind::Label,
                };
                Ok(TraceSymbol {
                    key: row.get(0)?,
                    name: row.get(1)?,
                    address: row.get::<_, Option<i64>>(2)?.map(|a| a as u64),
                    space: row.get(3)?,
                    kind,
                    parent_key: row.get(5)?,
                    lifespan: Lifespan::span(row.get(6)?, row.get(7)?),
                })
            })?
            .collect::<SqlResult<Vec<_>>>()?;
        Ok(symbols)
    }

    fn delete_symbol(&self, key: i64) -> SqlResult<bool> {
        let count = self.execute(
            "DELETE FROM trace_symbols WHERE key = ?1",
            params![key],
        )?;
        Ok(count > 0)
    }

    fn get_symbols_by_name(&self, name: &str, snap: i64) -> SqlResult<Vec<TraceSymbol>> {
        let mut stmt = self.prepare(
            "SELECT key, name, address, space, kind, parent_key, min_snap, max_snap FROM trace_symbols WHERE name = ?1 AND min_snap <= ?2 AND max_snap >= ?2",
        )?;
        let symbols = stmt
            .query_map(params![name, snap], |row| {
                let kind_str: String = row.get(4)?;
                let kind = match kind_str.as_str() {
                    "Label" => TraceSymbolKind::Label,
                    "Namespace" => TraceSymbolKind::Namespace,
                    "Class" => TraceSymbolKind::Class,
                    "Function" => TraceSymbolKind::Function,
                    _ => TraceSymbolKind::Label,
                };
                Ok(TraceSymbol {
                    key: row.get(0)?,
                    name: row.get(1)?,
                    address: row.get::<_, Option<i64>>(2)?.map(|a| a as u64),
                    space: row.get(3)?,
                    kind,
                    parent_key: row.get(5)?,
                    lifespan: Lifespan::span(row.get(6)?, row.get(7)?),
                })
            })?
            .collect::<SqlResult<Vec<_>>>()?;
        Ok(symbols)
    }

    fn get_symbols_at(&self, address: u64, space: &str, snap: i64) -> SqlResult<Vec<TraceSymbol>> {
        let mut stmt = self.prepare(
            "SELECT key, name, address, space, kind, parent_key, min_snap, max_snap FROM trace_symbols WHERE address = ?1 AND space = ?2 AND min_snap <= ?3 AND max_snap >= ?3",
        )?;
        let symbols = stmt
            .query_map(params![address as i64, space, snap], |row| {
                let kind_str: String = row.get(4)?;
                let kind = match kind_str.as_str() {
                    "Label" => TraceSymbolKind::Label,
                    "Namespace" => TraceSymbolKind::Namespace,
                    "Class" => TraceSymbolKind::Class,
                    "Function" => TraceSymbolKind::Function,
                    _ => TraceSymbolKind::Label,
                };
                Ok(TraceSymbol {
                    key: row.get(0)?,
                    name: row.get(1)?,
                    address: row.get::<_, Option<i64>>(2)?.map(|a| a as u64),
                    space: row.get(3)?,
                    kind,
                    parent_key: row.get(5)?,
                    lifespan: Lifespan::span(row.get(6)?, row.get(7)?),
                })
            })?
            .collect::<SqlResult<Vec<_>>>()?;
        Ok(symbols)
    }

    fn insert_reference(&self, reference: &TraceReference) -> SqlResult<()> {
        self.execute(
            "INSERT OR REPLACE INTO trace_references (key, from_address, to_address, kind, min_snap, max_snap, is_primary) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                reference.key,
                reference.from_address as i64,
                reference.to_address as i64,
                format!("{:?}", reference.kind),
                reference.lifespan.lmin(),
                reference.lifespan.lmax(),
                reference.is_primary as i32,
            ],
        )?;
        Ok(())
    }

    fn load_references(&self) -> SqlResult<Vec<TraceReference>> {
        let mut stmt = self.prepare(
            "SELECT key, from_address, to_address, kind, min_snap, max_snap, is_primary FROM trace_references",
        )?;
        let refs = stmt
            .query_map([], |row| {
                let kind_str: String = row.get(3)?;
                let kind = match kind_str.as_str() {
                    "Memory" => TraceReferenceKind::Memory,
                    "Offset" => TraceReferenceKind::Offset,
                    "Shifted" => TraceReferenceKind::Shifted,
                    "Stack" => TraceReferenceKind::Stack,
                    _ => TraceReferenceKind::Memory,
                };
                Ok(TraceReference {
                    key: row.get(0)?,
                    from_address: row.get::<_, i64>(1)? as u64,
                    to_address: row.get::<_, i64>(2)? as u64,
                    kind,
                    lifespan: Lifespan::span(row.get(4)?, row.get(5)?),
                    is_primary: row.get::<_, i32>(6)? != 0,
                })
            })?
            .collect::<SqlResult<Vec<_>>>()?;
        Ok(refs)
    }

    fn get_references_from(&self, address: u64, snap: i64) -> SqlResult<Vec<TraceReference>> {
        let mut stmt = self.prepare(
            "SELECT key, from_address, to_address, kind, min_snap, max_snap, is_primary FROM trace_references WHERE from_address = ?1 AND min_snap <= ?2 AND max_snap >= ?2",
        )?;
        let refs = stmt
            .query_map(params![address as i64, snap], |row| {
                let kind_str: String = row.get(3)?;
                let kind = match kind_str.as_str() {
                    "Memory" => TraceReferenceKind::Memory,
                    "Offset" => TraceReferenceKind::Offset,
                    "Shifted" => TraceReferenceKind::Shifted,
                    "Stack" => TraceReferenceKind::Stack,
                    _ => TraceReferenceKind::Memory,
                };
                Ok(TraceReference {
                    key: row.get(0)?,
                    from_address: row.get::<_, i64>(1)? as u64,
                    to_address: row.get::<_, i64>(2)? as u64,
                    kind,
                    lifespan: Lifespan::span(row.get(4)?, row.get(5)?),
                    is_primary: row.get::<_, i32>(6)? != 0,
                })
            })?
            .collect::<SqlResult<Vec<_>>>()?;
        Ok(refs)
    }

    fn get_references_to(&self, address: u64, snap: i64) -> SqlResult<Vec<TraceReference>> {
        let mut stmt = self.prepare(
            "SELECT key, from_address, to_address, kind, min_snap, max_snap, is_primary FROM trace_references WHERE to_address = ?1 AND min_snap <= ?2 AND max_snap >= ?2",
        )?;
        let refs = stmt
            .query_map(params![address as i64, snap], |row| {
                let kind_str: String = row.get(3)?;
                let kind = match kind_str.as_str() {
                    "Memory" => TraceReferenceKind::Memory,
                    "Offset" => TraceReferenceKind::Offset,
                    "Shifted" => TraceReferenceKind::Shifted,
                    "Stack" => TraceReferenceKind::Stack,
                    _ => TraceReferenceKind::Memory,
                };
                Ok(TraceReference {
                    key: row.get(0)?,
                    from_address: row.get::<_, i64>(1)? as u64,
                    to_address: row.get::<_, i64>(2)? as u64,
                    kind,
                    lifespan: Lifespan::span(row.get(4)?, row.get(5)?),
                    is_primary: row.get::<_, i32>(6)? != 0,
                })
            })?
            .collect::<SqlResult<Vec<_>>>()?;
        Ok(refs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;

    fn setup_db() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        conn.create_symbol_tables().unwrap();
        conn
    }

    #[test]
    fn test_create_tables() {
        setup_db();
    }

    #[test]
    fn test_insert_and_load_symbols() {
        let conn = setup_db();
        let sym = TraceSymbol::label(1, "main", 0x400000, "ram", Lifespan::now_on(0));
        conn.insert_symbol(&sym).unwrap();

        let sym2 = TraceSymbol::function(2, "printf", 0x400100, "ram", None, Lifespan::now_on(0));
        conn.insert_symbol(&sym2).unwrap();

        let symbols = conn.load_symbols().unwrap();
        assert_eq!(symbols.len(), 2);
    }

    #[test]
    fn test_get_symbols_by_name() {
        let conn = setup_db();
        let sym = TraceSymbol::label(1, "my_label", 0x400000, "ram", Lifespan::now_on(0));
        conn.insert_symbol(&sym).unwrap();

        let found = conn.get_symbols_by_name("my_label", 5).unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].address, Some(0x400000));
    }

    #[test]
    fn test_get_symbols_at() {
        let conn = setup_db();
        let sym = TraceSymbol::label(1, "entry", 0x400000, "ram", Lifespan::now_on(0));
        conn.insert_symbol(&sym).unwrap();

        let found = conn.get_symbols_at(0x400000, "ram", 5).unwrap();
        assert_eq!(found.len(), 1);

        let none = conn.get_symbols_at(0x500000, "ram", 5).unwrap();
        assert!(none.is_empty());
    }

    #[test]
    fn test_delete_symbol() {
        let conn = setup_db();
        let sym = TraceSymbol::label(1, "test", 0x100, "ram", Lifespan::ALL);
        conn.insert_symbol(&sym).unwrap();
        assert!(conn.delete_symbol(1).unwrap());
        assert!(conn.load_symbols().unwrap().is_empty());
    }

    #[test]
    fn test_references() {
        let conn = setup_db();
        let r = TraceReference::memory(1, 0x400000, 0x400100, Lifespan::now_on(0));
        conn.insert_reference(&r).unwrap();

        let from = conn.get_references_from(0x400000, 5).unwrap();
        assert_eq!(from.len(), 1);
        assert_eq!(from[0].to_address, 0x400100);

        let to = conn.get_references_to(0x400100, 5).unwrap();
        assert_eq!(to.len(), 1);
        assert_eq!(to[0].from_address, 0x400000);
    }

    #[test]
    fn test_references_lifespan() {
        let conn = setup_db();
        let r = TraceReference::memory(1, 0x100, 0x200, Lifespan::span(0, 5));
        conn.insert_reference(&r).unwrap();

        assert_eq!(conn.get_references_from(0x100, 3).unwrap().len(), 1);
        assert_eq!(conn.get_references_from(0x100, 10).unwrap().len(), 0);
    }
}
