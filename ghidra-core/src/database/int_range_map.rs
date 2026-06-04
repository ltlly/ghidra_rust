//! Integer range map backed by the database ported from Java's `IntRangeMap`
//! and `IntRangeMapDB`.
//!
//! Maps address ranges to `i32` values, stored in a SQLite table
//! (Key INTEGER PRIMARY KEY, StartAddr INTEGER, EndAddr INTEGER, Value INTEGER).
//! Used for context register values, property maps, and other range-indexed
//! integer metadata.

use crate::addr::{Address, AddressSet, AddressSpace};
use crate::database::db::{Database, DbResult, Field, FieldType, FieldValue, Schema};
use std::collections::BTreeMap;
use std::fmt;

// ============================================================================
// IntRangeMap trait (port of Java IntRangeMap interface)
// ============================================================================

/// Trait for mapping address ranges to integer values.
///
/// Port of Java `ghidra.program.database.IntRangeMap`.
pub trait IntRangeMap: fmt::Debug + Send + Sync {
    /// Set a value for all addresses in the given set.
    fn set_value_for_set(&mut self, addresses: &AddressSet, value: i32);

    /// Set a value for a contiguous address range.
    fn set_value(&mut self, start: &Address, end: &Address, value: i32);

    /// Get the value at a specific address, or `None` if no value is defined.
    fn get_value(&self, address: &Address) -> Option<i32>;

    /// Get the full set of addresses that have any value defined.
    fn get_address_set(&self) -> AddressSet;

    /// Get the set of addresses that have the specific value.
    fn get_address_set_for_value(&self, value: i32) -> AddressSet;

    /// Clear values for all addresses in the given set.
    fn clear_value_for_set(&mut self, addresses: &AddressSet);

    /// Clear values for a contiguous address range.
    fn clear_value(&mut self, start: &Address, end: &Address);

    /// Clear all values.
    fn clear_all(&mut self);
}

// ============================================================================
// IntRangeMapDB (port of Java IntRangeMapDB)
// ============================================================================

/// Database-backed implementation of [`IntRangeMap`].
///
/// Port of Java `ghidra.program.database.IntRangeMapDB`.
///
/// Stores range-to-value mappings in a SQLite table with the schema:
/// `Key INTEGER PRIMARY KEY AUTOINCREMENT, StartAddr INTEGER, EndAddr INTEGER, Value INTEGER`
#[derive(Debug)]
pub struct IntRangeMapDB {
    /// The name of the backing database table.
    table_name: String,
    /// In-memory cache of ranges sorted by start address.
    ranges: BTreeMap<u64, (u64, i32)>, // start -> (end, value)
}

impl IntRangeMapDB {
    const COL_KEY: &'static str = "Key";
    const COL_START: &'static str = "StartAddr";
    const COL_END: &'static str = "EndAddr";
    const COL_VALUE: &'static str = "Value";

    /// Create a new `IntRangeMapDB`, creating the backing table if needed.
    pub fn new(db: &mut Database, table_name: &str, create: bool) -> DbResult<Self> {
        if create {
            let schema = Self::make_schema(table_name);
            db.create_table(schema)?;
        } else if db.table_exists(table_name)? {
            // Load existing data from the table into the in-memory cache.
            let sql = format!(
                "SELECT {}, {}, {} FROM {} ORDER BY {}",
                Self::COL_START,
                Self::COL_END,
                Self::COL_VALUE,
                table_name,
                Self::COL_START,
            );
            let rows: Vec<(i64, i64, i32)> = db.query_map(&sql, &[], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i32>(2)?,
                ))
            })?;
            let mut ranges = BTreeMap::new();
            for (start, end, value) in rows {
                ranges.insert(start as u64, (end as u64, value));
            }
            return Ok(Self {
                table_name: table_name.to_string(),
                ranges,
            });
        }
        Ok(Self {
            table_name: table_name.to_string(),
            ranges: BTreeMap::new(),
        })
    }

    fn make_schema(table_name: &str) -> Schema {
        Schema::new(table_name, 0)
            .with_field(Field::new(Self::COL_KEY, FieldType::Int).primary_key())
            .with_field(Field::new(Self::COL_START, FieldType::Long).indexed())
            .with_field(Field::new(Self::COL_END, FieldType::Long))
            .with_field(Field::new(Self::COL_VALUE, FieldType::Int))
    }

    /// Flush the in-memory cache to the database.
    pub fn flush(&self, db: &Database) -> DbResult<()> {
        // Clear and re-write all ranges.
        let del_sql = format!("DELETE FROM {}", self.table_name);
        db.execute(&del_sql, &[])?;
        let ins_sql = format!(
            "INSERT INTO {} ({}, {}, {}) VALUES (?1, ?2, ?3)",
            self.table_name,
            Self::COL_START,
            Self::COL_END,
            Self::COL_VALUE,
        );
        for (&start, &(end, value)) in &self.ranges {
            db.execute(
                &ins_sql,
                &[
                    FieldValue::Long(start as i64),
                    FieldValue::Long(end as i64),
                    FieldValue::Int(value),
                ],
            )?;
        }
        Ok(())
    }

    /// Return the backing table name.
    pub fn table_name(&self) -> &str {
        &self.table_name
    }

    /// Return the number of range entries.
    pub fn len(&self) -> usize {
        self.ranges.len()
    }

    /// Return true if there are no entries.
    pub fn is_empty(&self) -> bool {
        self.ranges.is_empty()
    }

    /// Get all range entries as `(start, end, value)` tuples.
    pub fn entries(&self) -> Vec<(u64, u64, i32)> {
        self.ranges
            .iter()
            .map(|(&start, &(end, value))| (start, end, value))
            .collect()
    }
}

impl IntRangeMap for IntRangeMapDB {
    fn set_value_for_set(&mut self, addresses: &AddressSet, value: i32) {
        for range in addresses.iter() {
            let start = range.get_min_address().offset;
            let end = range.get_max_address().offset;
            self.ranges.insert(start, (end, value));
        }
    }

    fn set_value(&mut self, start: &Address, end: &Address, value: i32) {
        self.ranges
            .insert(start.offset, (end.offset, value));
    }

    fn get_value(&self, address: &Address) -> Option<i32> {
        let addr_offset = address.offset;
        // Find the range whose start is <= addr_offset and whose end is >= addr_offset.
        for (&start, &(end, value)) in self.ranges.range(..=addr_offset).rev() {
            if addr_offset <= end && addr_offset >= start {
                return Some(value);
            }
            break; // only need to check the nearest entry at or below
        }
        None
    }

    fn get_address_set(&self) -> AddressSet {
        let mut result = AddressSet::new();
        for (&start, &(end, _)) in &self.ranges {
            result.add_range(Address::new(start), Address::new(end));
        }
        result
    }

    fn get_address_set_for_value(&self, value: i32) -> AddressSet {
        let mut result = AddressSet::new();
        for (&start, &(end, v)) in &self.ranges {
            if v == value {
                result.add_range(Address::new(start), Address::new(end));
            }
        }
        result
    }

    fn clear_value_for_set(&mut self, addresses: &AddressSet) {
        for range in addresses.iter() {
            let start = range.get_min_address().offset;
            let end = range.get_max_address().offset;
            // Remove entries that fall within [start, end].
            let keys_to_remove: Vec<u64> = self
                .ranges
                .range(start..=end)
                .map(|(&k, _)| k)
                .collect();
            for k in keys_to_remove {
                self.ranges.remove(&k);
            }
        }
    }

    fn clear_value(&mut self, start: &Address, end: &Address) {
        let s = start.offset;
        let e = end.offset;
        let keys_to_remove: Vec<u64> = self.ranges.range(s..=e).map(|(&k, _)| k).collect();
        for k in keys_to_remove {
            self.ranges.remove(&k);
        }
    }

    fn clear_all(&mut self) {
        self.ranges.clear();
    }
}

impl fmt::Display for IntRangeMapDB {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "IntRangeMapDB(table={}, ranges={})",
            self.table_name,
            self.ranges.len()
        )
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn make_addr(offset: u64) -> Address {
        Address::new(offset)
    }

    #[test]
    fn test_set_and_get_value() {
        let mut db = Database::in_memory().unwrap();
        let mut map = IntRangeMapDB::new(&mut db, "test_range", true).unwrap();

        let start = make_addr(0x1000);
        let end = make_addr(0x1010);
        map.set_value(&start, &end, 42);

        assert_eq!(map.get_value(&make_addr(0x1000)), Some(42));
        assert_eq!(map.get_value(&make_addr(0x1005)), Some(42));
        assert_eq!(map.get_value(&make_addr(0x1010)), Some(42));
        assert_eq!(map.get_value(&make_addr(0x1011)), None);
        assert_eq!(map.get_value(&make_addr(0x0FFF)), None);
    }

    #[test]
    fn test_set_value_for_set() {
        let mut db = Database::in_memory().unwrap();
        let mut map = IntRangeMapDB::new(&mut db, "range_set", true).unwrap();

        let mut addrs = AddressSet::new();
        addrs.add_range(Address::new(0x2000), Address::new(0x2010));
        addrs.add_range(Address::new(0x3000), Address::new(0x3010));

        map.set_value_for_set(&addrs, 99);

        assert_eq!(map.get_value(&make_addr(0x2000)), Some(99));
        assert_eq!(map.get_value(&make_addr(0x3005)), Some(99));
        assert_eq!(map.get_value(&make_addr(0x2500)), None);
    }

    #[test]
    fn test_clear_value() {
        let mut db = Database::in_memory().unwrap();
        let mut map = IntRangeMapDB::new(&mut db, "clear_test", true).unwrap();

        // Set two separate ranges.
        map.set_value(&make_addr(0x1000), &make_addr(0x1004), 1);
        map.set_value(&make_addr(0x1005), &make_addr(0x1015), 2);
        assert_eq!(map.get_value(&make_addr(0x1010)), Some(2));

        // Clearing [0x1005, 0x1015] removes the entry whose start key is in that range.
        map.clear_value(&make_addr(0x1005), &make_addr(0x1015));
        assert_eq!(map.get_value(&make_addr(0x1010)), None);
        // The entry at 0x1000 is unaffected since its start key is not in [0x1005, 0x1015].
        assert_eq!(map.get_value(&make_addr(0x1002)), Some(1));
    }

    #[test]
    fn test_clear_all() {
        let mut db = Database::in_memory().unwrap();
        let mut map = IntRangeMapDB::new(&mut db, "clear_all", true).unwrap();

        map.set_value(&make_addr(0x1000), &make_addr(0x1010), 1);
        map.set_value(&make_addr(0x2000), &make_addr(0x2010), 2);
        assert_eq!(map.len(), 2);

        map.clear_all();
        assert!(map.is_empty());
    }

    #[test]
    fn test_get_address_set() {
        let mut db = Database::in_memory().unwrap();
        let mut map = IntRangeMapDB::new(&mut db, "addr_set", true).unwrap();

        map.set_value(&make_addr(0x1000), &make_addr(0x1005), 10);
        map.set_value(&make_addr(0x2000), &make_addr(0x2005), 20);

        let set = map.get_address_set();
        assert_eq!(set.num_address_ranges(), 2);
    }

    #[test]
    fn test_get_address_set_for_value() {
        let mut db = Database::in_memory().unwrap();
        let mut map = IntRangeMapDB::new(&mut db, "val_set", true).unwrap();

        map.set_value(&make_addr(0x1000), &make_addr(0x1005), 10);
        map.set_value(&make_addr(0x2000), &make_addr(0x2005), 20);
        map.set_value(&make_addr(0x3000), &make_addr(0x3005), 10);

        let set10 = map.get_address_set_for_value(10);
        assert_eq!(set10.num_address_ranges(), 2);

        let set20 = map.get_address_set_for_value(20);
        assert_eq!(set20.num_address_ranges(), 1);

        let set99 = map.get_address_set_for_value(99);
        assert!(set99.is_empty());
    }

    #[test]
    fn test_flush_and_reload() {
        let mut db = Database::in_memory().unwrap();

        // Write data.
        {
            let mut map = IntRangeMapDB::new(&mut db, "flush_test", true).unwrap();
            map.set_value(&make_addr(0x1000), &make_addr(0x1010), 42);
            map.set_value(&make_addr(0x2000), &make_addr(0x2010), 99);
            map.flush(&db).unwrap();
        }

        // Reload from database.
        {
            let map = IntRangeMapDB::new(&mut db, "flush_test", false).unwrap();
            assert_eq!(map.len(), 2);
            assert_eq!(map.get_value(&make_addr(0x1005)), Some(42));
            assert_eq!(map.get_value(&make_addr(0x2005)), Some(99));
        }
    }
}
