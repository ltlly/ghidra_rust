//! Record translation ported from Java's `db.RecordTranslator` and
//! `db.TranslatedRecordIterator`.
//!
//! Provides [`RecordTranslator`] for converting records between different
//! schemas, and [`TranslatedRecordIterator`] for wrapping an iterator with
//! automatic translation.

use crate::database::db::{DBRecord, DbResult, Schema};
use crate::database::iterator::RecordIterator;

/// A callback trait for translating records between schemas.
///
/// Port of Java `db.RecordTranslator`.
pub trait RecordTranslator: Send + Sync {
    /// Translate a record from one schema to another.
    fn translate(&self, record: &DBRecord) -> DbResult<DBRecord>;

    /// Get the source schema (the schema records are expected to have).
    fn source_schema(&self) -> &Schema;

    /// Get the target schema (the schema records will be translated to).
    fn target_schema(&self) -> &Schema;
}

/// A simple column-mapping translator that maps source columns to target
/// columns by name.
pub struct ColumnMappingTranslator {
    source: Schema,
    target: Schema,
    /// Mapping from source column indices to target column indices.
    mappings: Vec<(usize, usize)>,
}

impl ColumnMappingTranslator {
    /// Create a new translator that maps columns by name.
    pub fn new(source: Schema, target: Schema) -> Self {
        let mut mappings = Vec::new();
        for (src_idx, src_field) in source.fields.iter().enumerate() {
            if let Some(tgt_idx) = target.field_index(&src_field.name) {
                mappings.push((src_idx, tgt_idx));
            }
        }
        Self {
            source,
            target,
            mappings,
        }
    }
}

impl RecordTranslator for ColumnMappingTranslator {
    fn translate(&self, record: &DBRecord) -> DbResult<DBRecord> {
        let mut result = DBRecord::new(self.target.clone());
        for &(src_idx, tgt_idx) in &self.mappings {
            if let Some(val) = record.get_at(src_idx) {
                result.set_at(tgt_idx, val.clone());
            }
        }
        // Preserve key
        if let Some(key) = record.key() {
            let _ = result.set_key(key.clone());
        }
        Ok(result)
    }

    fn source_schema(&self) -> &Schema {
        &self.source
    }

    fn target_schema(&self) -> &Schema {
        &self.target
    }
}

/// An iterator that automatically translates records from one schema to
/// another.
///
/// Port of Java `db.TranslatedRecordIterator`.
pub struct TranslatedRecordIterator<I: RecordIterator> {
    inner: I,
    translator: Box<dyn RecordTranslator>,
}

impl<I: RecordIterator> TranslatedRecordIterator<I> {
    /// Create a new translated record iterator.
    pub fn new(inner: I, translator: Box<dyn RecordTranslator>) -> Self {
        Self { inner, translator }
    }
}

impl<I: RecordIterator> RecordIterator for TranslatedRecordIterator<I> {
    fn has_next(&self) -> DbResult<bool> {
        self.inner.has_next()
    }

    fn has_previous(&self) -> DbResult<bool> {
        self.inner.has_previous()
    }

    fn next(&mut self) -> DbResult<Option<DBRecord>> {
        if let Some(rec) = self.inner.next()? {
            let translated = self.translator.translate(&rec)?;
            Ok(Some(translated))
        } else {
            Ok(None)
        }
    }

    fn previous(&mut self) -> DbResult<Option<DBRecord>> {
        if let Some(rec) = self.inner.previous()? {
            let translated = self.translator.translate(&rec)?;
            Ok(Some(translated))
        } else {
            Ok(None)
        }
    }

    fn delete(&mut self) -> DbResult<bool> {
        self.inner.delete()
    }
}

/// An iterator that converts between FieldValue types.
///
/// Port of Java `db.ConvertedRecordIterator`.
pub struct ConvertedRecordIterator<I: RecordIterator> {
    inner: I,
    conversion_fn: Box<dyn Fn(&DBRecord) -> DBRecord>,
}

impl<I: RecordIterator> ConvertedRecordIterator<I> {
    /// Create a new converted record iterator.
    pub fn new(inner: I, conversion_fn: Box<dyn Fn(&DBRecord) -> DBRecord>) -> Self {
        Self { inner, conversion_fn }
    }
}

impl<I: RecordIterator> RecordIterator for ConvertedRecordIterator<I> {
    fn has_next(&self) -> DbResult<bool> {
        self.inner.has_next()
    }

    fn has_previous(&self) -> DbResult<bool> {
        self.inner.has_previous()
    }

    fn next(&mut self) -> DbResult<Option<DBRecord>> {
        if let Some(rec) = self.inner.next()? {
            let converted = (self.conversion_fn)(&rec);
            Ok(Some(converted))
        } else {
            Ok(None)
        }
    }

    fn previous(&mut self) -> DbResult<Option<DBRecord>> {
        if let Some(rec) = self.inner.previous()? {
            let converted = (self.conversion_fn)(&rec);
            Ok(Some(converted))
        } else {
            Ok(None)
        }
    }

    fn delete(&mut self) -> DbResult<bool> {
        self.inner.delete()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::db::{Field, FieldType, FieldValue};
    use crate::database::iterator::SqlRecordIterator;

    #[test]
    fn test_column_mapping_translator() {
        let source = Schema::new("src", 1)
            .with_field(Field::new("id", FieldType::Int).primary_key())
            .with_field(Field::new("name", FieldType::String))
            .with_field(Field::new("extra", FieldType::Int));
        let target = Schema::new("tgt", 1)
            .with_field(Field::new("id", FieldType::Int).primary_key())
            .with_field(Field::new("name", FieldType::String));

        let translator = ColumnMappingTranslator::new(source.clone(), target);

        let mut rec = DBRecord::new(source);
        rec.set("id", FieldValue::Int(1)).unwrap();
        rec.set("name", FieldValue::String("Alice".into())).unwrap();
        rec.set("extra", FieldValue::Int(99)).unwrap();

        let translated = translator.translate(&rec).unwrap();
        assert_eq!(translated.get_int("id").unwrap(), 1);
        assert_eq!(translated.get_string("name").unwrap(), "Alice");
        // "extra" column doesn't exist in target, so it's dropped
    }

    #[test]
    fn test_translated_record_iterator() {
        let source = Schema::new("src", 1)
            .with_field(Field::new("id", FieldType::Int).primary_key())
            .with_field(Field::new("val", FieldType::String));
        let target = Schema::new("tgt", 1)
            .with_field(Field::new("id", FieldType::Int).primary_key())
            .with_field(Field::new("val", FieldType::String));

        let mut records = Vec::new();
        for i in 1..=3 {
            let mut rec = DBRecord::new(source.clone());
            rec.set("id", FieldValue::Int(i)).unwrap();
            rec.set("val", FieldValue::String(format!("v{}", i))).unwrap();
            records.push(rec);
        }

        let inner = SqlRecordIterator::new(records);
        let translator = ColumnMappingTranslator::new(source.clone(), target);
        let mut iter = TranslatedRecordIterator::new(inner, Box::new(translator));

        let rec = iter.next().unwrap().unwrap();
        assert_eq!(rec.get_int("id").unwrap(), 1);
    }

    #[test]
    fn test_converted_record_iterator() {
        let schema = Schema::new("test", 1)
            .with_field(Field::new("id", FieldType::Int).primary_key())
            .with_field(Field::new("val", FieldType::Int));

        let mut records = Vec::new();
        for i in 1..=3 {
            let mut rec = DBRecord::new(schema.clone());
            rec.set("id", FieldValue::Int(i)).unwrap();
            rec.set("val", FieldValue::Int(i * 10)).unwrap();
            records.push(rec);
        }

        let inner = SqlRecordIterator::new(records);
        let mut iter = ConvertedRecordIterator::new(inner, Box::new(|rec| {
            let mut new_rec = rec.clone();
            // Double the val
            if let Ok(v) = rec.get_int("val") {
                let _ = new_rec.set("val", FieldValue::Int(v * 2));
            }
            new_rec
        }));

        let rec = iter.next().unwrap().unwrap();
        assert_eq!(rec.get_int("val").unwrap(), 20);
    }
}
