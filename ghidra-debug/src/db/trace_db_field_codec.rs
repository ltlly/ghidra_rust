//! Database field codecs for trace objects.
//!
//! Ported from Ghidra's `DBTraceObjectDBFieldCodec`.
//!
//! Provides serialization and deserialization of trace object fields
//! to and from the SQLite database. Each codec handles one field of a
//! trace object, converting between the in-memory representation and
//! the database column representation.

use serde::{Deserialize, Serialize};


/// The data type of a trace object field in the database.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FieldDataType {
    /// A string field.
    String,
    /// An integer field (i64).
    Long,
    /// An unsigned integer field (u64).
    ULong,
    /// A boolean field.
    Boolean,
    /// A binary blob field.
    Blob,
    /// A serialized JSON field.
    Json,
    /// A null field (absent value).
    Null,
}

impl FieldDataType {
    /// Get a human-readable name for this data type.
    pub fn name(&self) -> &'static str {
        match self {
            FieldDataType::String => "string",
            FieldDataType::Long => "long",
            FieldDataType::ULong => "ulong",
            FieldDataType::Boolean => "boolean",
            FieldDataType::Blob => "blob",
            FieldDataType::Json => "json",
            FieldDataType::Null => "null",
        }
    }
}

/// A codec for a single field of a trace object.
///
/// Maps between the database column and the in-memory field.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DBTraceFieldCodec {
    /// The field name (maps to a database column).
    pub field_name: String,
    /// The data type of this field.
    pub data_type: FieldDataType,
    /// Whether this field is a primary key component.
    pub is_primary_key: bool,
    /// Whether this field can be null.
    pub nullable: bool,
    /// The default value (as a string representation).
    pub default_value: Option<String>,
    /// An index into the schema for this codec.
    pub schema_index: usize,
}

impl DBTraceFieldCodec {
    /// Create a new field codec.
    pub fn new(
        field_name: impl Into<String>,
        data_type: FieldDataType,
        schema_index: usize,
    ) -> Self {
        Self {
            field_name: field_name.into(),
            data_type,
            is_primary_key: false,
            nullable: true,
            default_value: None,
            schema_index,
        }
    }

    /// Mark this field as a primary key component.
    pub fn as_primary_key(mut self) -> Self {
        self.is_primary_key = true;
        self.nullable = false;
        self
    }

    /// Mark this field as not nullable.
    pub fn not_null(mut self) -> Self {
        self.nullable = false;
        self
    }

    /// Set a default value for this field.
    pub fn with_default(mut self, default: impl Into<String>) -> Self {
        self.default_value = Some(default.into());
        self
    }

    /// Encode a string value to its database representation.
    pub fn encode_string(&self, value: &str) -> EncodedField {
        EncodedField {
            field_name: self.field_name.clone(),
            data_type: self.data_type,
            value: FieldValue::String(value.to_string()),
        }
    }

    /// Encode a long value to its database representation.
    pub fn encode_long(&self, value: i64) -> EncodedField {
        EncodedField {
            field_name: self.field_name.clone(),
            data_type: self.data_type,
            value: FieldValue::Long(value),
        }
    }

    /// Encode a ulong value to its database representation.
    pub fn encode_ulong(&self, value: u64) -> EncodedField {
        EncodedField {
            field_name: self.field_name.clone(),
            data_type: self.data_type,
            value: FieldValue::ULong(value),
        }
    }

    /// Encode a boolean value to its database representation.
    pub fn encode_boolean(&self, value: bool) -> EncodedField {
        EncodedField {
            field_name: self.field_name.clone(),
            data_type: self.data_type,
            value: FieldValue::Boolean(value),
        }
    }

    /// Encode a blob value to its database representation.
    pub fn encode_blob(&self, value: Vec<u8>) -> EncodedField {
        EncodedField {
            field_name: self.field_name.clone(),
            data_type: self.data_type,
            value: FieldValue::Blob(value),
        }
    }

    /// Encode a null value.
    pub fn encode_null(&self) -> EncodedField {
        EncodedField {
            field_name: self.field_name.clone(),
            data_type: FieldDataType::Null,
            value: FieldValue::Null,
        }
    }
}

/// The value of a field in its encoded (database) form.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FieldValue {
    /// A string value.
    String(String),
    /// A signed long value.
    Long(i64),
    /// An unsigned long value.
    ULong(u64),
    /// A boolean value.
    Boolean(bool),
    /// A binary blob value.
    Blob(Vec<u8>),
    /// A null (absent) value.
    Null,
}

impl FieldValue {
    /// Get the data type of this field value.
    pub fn data_type(&self) -> FieldDataType {
        match self {
            FieldValue::String(_) => FieldDataType::String,
            FieldValue::Long(_) => FieldDataType::Long,
            FieldValue::ULong(_) => FieldDataType::ULong,
            FieldValue::Boolean(_) => FieldDataType::Boolean,
            FieldValue::Blob(_) => FieldDataType::Blob,
            FieldValue::Null => FieldDataType::Null,
        }
    }

    /// Try to get this value as a string reference.
    pub fn as_string(&self) -> Option<&str> {
        match self {
            FieldValue::String(s) => Some(s),
            _ => None,
        }
    }

    /// Try to get this value as a long.
    pub fn as_long(&self) -> Option<i64> {
        match self {
            FieldValue::Long(v) => Some(*v),
            _ => None,
        }
    }

    /// Try to get this value as a ulong.
    pub fn as_ulong(&self) -> Option<u64> {
        match self {
            FieldValue::ULong(v) => Some(*v),
            _ => None,
        }
    }

    /// Try to get this value as a boolean.
    pub fn as_boolean(&self) -> Option<bool> {
        match self {
            FieldValue::Boolean(v) => Some(*v),
            _ => None,
        }
    }

    /// Try to get this value as a blob reference.
    pub fn as_blob(&self) -> Option<&[u8]> {
        match self {
            FieldValue::Blob(v) => Some(v),
            _ => None,
        }
    }

    /// Check if this value is null.
    pub fn is_null(&self) -> bool {
        matches!(self, FieldValue::Null)
    }
}

/// An encoded field ready for database storage.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncodedField {
    /// The field name.
    pub field_name: String,
    /// The data type.
    pub data_type: FieldDataType,
    /// The encoded value.
    pub value: FieldValue,
}

/// A collection of field codecs for a trace object schema.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceObjectFieldCodecSet {
    /// The codecs in schema order.
    pub codecs: Vec<DBTraceFieldCodec>,
    /// The name of the table this codec set applies to.
    pub table_name: String,
}

impl TraceObjectFieldCodecSet {
    /// Create a new codec set for the given table.
    pub fn new(table_name: impl Into<String>) -> Self {
        Self {
            codecs: Vec::new(),
            table_name: table_name.into(),
        }
    }

    /// Add a codec to this set.
    pub fn add_codec(&mut self, codec: DBTraceFieldCodec) {
        self.codecs.push(codec);
    }

    /// Get a codec by field name.
    pub fn get_codec(&self, field_name: &str) -> Option<&DBTraceFieldCodec> {
        self.codecs.iter().find(|c| c.field_name == field_name)
    }

    /// Get the number of codecs.
    pub fn len(&self) -> usize {
        self.codecs.len()
    }

    /// Check if the codec set is empty.
    pub fn is_empty(&self) -> bool {
        self.codecs.is_empty()
    }

    /// Get all primary key codecs.
    pub fn primary_key_codecs(&self) -> Vec<&DBTraceFieldCodec> {
        self.codecs.iter().filter(|c| c.is_primary_key).collect()
    }

    /// Build a SQL CREATE TABLE statement for this codec set.
    pub fn build_create_table_sql(&self) -> String {
        let mut sql = format!("CREATE TABLE {} (\n", self.table_name);
        let columns: Vec<String> = self
            .codecs
            .iter()
            .map(|c| {
                let col_type = match c.data_type {
                    FieldDataType::String => "TEXT",
                    FieldDataType::Long | FieldDataType::ULong => "INTEGER",
                    FieldDataType::Boolean => "INTEGER",
                    FieldDataType::Blob => "BLOB",
                    FieldDataType::Json => "TEXT",
                    FieldDataType::Null => "TEXT",
                };
                let mut col = format!("  {} {}", c.field_name, col_type);
                if c.is_primary_key {
                    col.push_str(" PRIMARY KEY");
                }
                if !c.nullable {
                    col.push_str(" NOT NULL");
                }
                if let Some(ref default) = c.default_value {
                    col.push_str(&format!(" DEFAULT '{}'", default));
                }
                col
            })
            .collect();
        sql.push_str(&columns.join(",\n"));
        sql.push_str("\n)");
        sql
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_field_data_type_names() {
        assert_eq!(FieldDataType::String.name(), "string");
        assert_eq!(FieldDataType::Long.name(), "long");
        assert_eq!(FieldDataType::ULong.name(), "ulong");
        assert_eq!(FieldDataType::Boolean.name(), "boolean");
        assert_eq!(FieldDataType::Blob.name(), "blob");
        assert_eq!(FieldDataType::Json.name(), "json");
        assert_eq!(FieldDataType::Null.name(), "null");
    }

    #[test]
    fn test_field_codec_creation() {
        let codec = DBTraceFieldCodec::new("name", FieldDataType::String, 0)
            .as_primary_key()
            .with_default("unnamed");
        assert_eq!(codec.field_name, "name");
        assert!(codec.is_primary_key);
        assert!(!codec.nullable);
        assert_eq!(codec.default_value, Some("unnamed".to_string()));
    }

    #[test]
    fn test_field_codec_not_null() {
        let codec = DBTraceFieldCodec::new("value", FieldDataType::Long, 1).not_null();
        assert!(!codec.nullable);
        assert!(!codec.is_primary_key);
    }

    #[test]
    fn test_field_value_as_methods() {
        let string_val = FieldValue::String("hello".to_string());
        assert_eq!(string_val.as_string(), Some("hello"));
        assert!(string_val.as_long().is_none());
        assert!(!string_val.is_null());

        let long_val = FieldValue::Long(42);
        assert_eq!(long_val.as_long(), Some(42));
        assert!(long_val.as_string().is_none());

        let ulong_val = FieldValue::ULong(100);
        assert_eq!(ulong_val.as_ulong(), Some(100));

        let bool_val = FieldValue::Boolean(true);
        assert_eq!(bool_val.as_boolean(), Some(true));

        let blob_val = FieldValue::Blob(vec![1, 2, 3]);
        assert_eq!(blob_val.as_blob(), Some(&[1u8, 2, 3][..]));

        let null_val = FieldValue::Null;
        assert!(null_val.is_null());
    }

    #[test]
    fn test_field_value_data_type() {
        assert_eq!(FieldValue::String("".to_string()).data_type(), FieldDataType::String);
        assert_eq!(FieldValue::Long(0).data_type(), FieldDataType::Long);
        assert_eq!(FieldValue::ULong(0).data_type(), FieldDataType::ULong);
        assert_eq!(FieldValue::Boolean(false).data_type(), FieldDataType::Boolean);
        assert_eq!(FieldValue::Blob(vec![]).data_type(), FieldDataType::Blob);
        assert_eq!(FieldValue::Null.data_type(), FieldDataType::Null);
    }

    #[test]
    fn test_encode_methods() {
        let codec = DBTraceFieldCodec::new("test", FieldDataType::String, 0);

        let encoded = codec.encode_string("hello");
        assert_eq!(encoded.field_name, "test");
        assert_eq!(encoded.value.as_string(), Some("hello"));

        let encoded = codec.encode_long(42);
        assert_eq!(encoded.value.as_long(), Some(42));

        let encoded = codec.encode_boolean(true);
        assert_eq!(encoded.value.as_boolean(), Some(true));

        let encoded = codec.encode_blob(vec![0x90, 0xC3]);
        assert_eq!(encoded.value.as_blob(), Some(&[0x90u8, 0xC3][..]));

        let encoded = codec.encode_null();
        assert!(encoded.value.is_null());
    }

    #[test]
    fn test_codec_set() {
        let mut set = TraceObjectFieldCodecSet::new("objects");
        set.add_codec(DBTraceFieldCodec::new("key", FieldDataType::Long, 0).as_primary_key());
        set.add_codec(DBTraceFieldCodec::new("name", FieldDataType::String, 1).not_null());
        set.add_codec(DBTraceFieldCodec::new("data", FieldDataType::Blob, 2));

        assert_eq!(set.len(), 3);
        assert!(!set.is_empty());
        assert_eq!(set.table_name, "objects");

        let name_codec = set.get_codec("name");
        assert!(name_codec.is_some());
        assert_eq!(name_codec.unwrap().field_name, "name");

        let missing = set.get_codec("nonexistent");
        assert!(missing.is_none());
    }

    #[test]
    fn test_codec_set_primary_keys() {
        let mut set = TraceObjectFieldCodecSet::new("test");
        set.add_codec(DBTraceFieldCodec::new("pk1", FieldDataType::Long, 0).as_primary_key());
        set.add_codec(DBTraceFieldCodec::new("col", FieldDataType::String, 1));
        set.add_codec(DBTraceFieldCodec::new("pk2", FieldDataType::String, 2).as_primary_key());

        let pks = set.primary_key_codecs();
        assert_eq!(pks.len(), 2);
        assert!(pks.iter().all(|c| c.is_primary_key));
    }

    #[test]
    fn test_build_create_table_sql() {
        let mut set = TraceObjectFieldCodecSet::new("trace_objects");
        set.add_codec(
            DBTraceFieldCodec::new("id", FieldDataType::Long, 0)
                .as_primary_key(),
        );
        set.add_codec(
            DBTraceFieldCodec::new("name", FieldDataType::String, 1)
                .not_null()
                .with_default("unnamed"),
        );
        set.add_codec(DBTraceFieldCodec::new("value", FieldDataType::Blob, 2));

        let sql = set.build_create_table_sql();
        assert!(sql.contains("CREATE TABLE trace_objects"));
        assert!(sql.contains("id INTEGER PRIMARY KEY"));
        assert!(sql.contains("name TEXT NOT NULL DEFAULT 'unnamed'"));
        assert!(sql.contains("value BLOB"));
    }

    #[test]
    fn test_field_codec_serialization() {
        let codec = DBTraceFieldCodec::new("test", FieldDataType::String, 0);
        let json = serde_json::to_string(&codec).unwrap();
        let deserialized: DBTraceFieldCodec = serde_json::from_str(&json).unwrap();
        assert_eq!(codec.field_name, deserialized.field_name);
    }

    #[test]
    fn test_codec_set_empty() {
        let set = TraceObjectFieldCodecSet::new("empty");
        assert!(set.is_empty());
        assert!(set.primary_key_codecs().is_empty());
        assert!(set.get_codec("any").is_none());
    }
}
