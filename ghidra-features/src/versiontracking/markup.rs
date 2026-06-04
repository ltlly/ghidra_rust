//! Markup items and types.

use std::fmt;
use ghidra_core::addr::Address;
use crate::versiontracking::types::{VtAssociationType, VtMarkupItemApplyActionType, VtMarkupItemConsideredStatus, VtMarkupItemDestinationAddressEditStatus, VtMarkupItemStatus};

#[derive(Debug, Clone, PartialEq)]
pub enum Stringable {
    FunctionName(String),
    FunctionSignature(String),
    DataType { name: String, type_id: i64, manager_id: i64, size: i32 },
    Label(String),
    Comment { comment_type: CommentType, text: String },
    Parameter { name: String, data_type: String, ordinal: i32 },
    MultipleSymbols(Vec<String>),
    Generic(String),
}

impl Stringable {
    pub fn short_name(&self) -> &str {
        match self { Stringable::FunctionName(_) => "FN", Stringable::FunctionSignature(_) => "FS",
            Stringable::DataType { .. } => "DT", Stringable::Label(_) => "LB", Stringable::Comment { .. } => "CM",
            Stringable::Parameter { .. } => "PM", Stringable::MultipleSymbols(_) => "MS", Stringable::Generic(_) => "GS" }
    }
    pub fn to_storage_string(&self) -> String {
        match self {
            Stringable::FunctionName(name) => format!("FN:{}", name),
            Stringable::FunctionSignature(sig) => format!("FS:{}", sig),
            Stringable::DataType { name, type_id, manager_id, size } => format!("DT:{}/{}/{}/{}", manager_id, type_id, name, size),
            Stringable::Label(label) => format!("LB:{}", label),
            Stringable::Comment { comment_type, text } => format!("CM:{:?}:{}", comment_type, text),
            Stringable::Parameter { name, data_type, ordinal } => format!("PM:{}/{}/{}", ordinal, data_type, name),
            Stringable::MultipleSymbols(names) => format!("MS:{}", names.join(";")),
            Stringable::Generic(s) => format!("GS:{}", s),
        }
    }
    pub fn from_storage_string(s: &str) -> Option<Self> {
        let (prefix, rest) = s.split_once(':')?;
        match prefix {
            "FN" => Some(Stringable::FunctionName(rest.to_string())),
            "FS" => Some(Stringable::FunctionSignature(rest.to_string())),
            "DT" => { let parts: Vec<&str> = rest.splitn(4, '/').collect();
                if parts.len() >= 4 { Some(Stringable::DataType { manager_id: parts[0].parse().ok()?, type_id: parts[1].parse().ok()?,
                    name: parts[2].to_string(), size: parts[3].parse().ok()? }) } else { None } }
            "LB" => Some(Stringable::Label(rest.to_string())),
            "CM" => { let (ct, text) = rest.split_once(':')?;
                let comment_type = match ct { "Eol" => CommentType::Eol, "Pre" => CommentType::Pre, "Post" => CommentType::Post,
                    "Plate" => CommentType::Plate, "Repeatable" => CommentType::Repeatable, _ => CommentType::Eol };
                Some(Stringable::Comment { comment_type, text: text.to_string() }) }
            "PM" => { let parts: Vec<&str> = rest.splitn(3, '/').collect();
                if parts.len() >= 3 { Some(Stringable::Parameter { ordinal: parts[0].parse().ok()?,
                    data_type: parts[1].to_string(), name: parts[2].to_string() }) } else { None } }
            "MS" => Some(Stringable::MultipleSymbols(rest.split(';').map(String::from).collect())),
            "GS" => Some(Stringable::Generic(rest.to_string())),
            _ => None,
        }
    }
}

impl fmt::Display for Stringable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self { Stringable::FunctionName(n) => write!(f, "{}", n), Stringable::FunctionSignature(s) => write!(f, "{}", s),
            Stringable::DataType { name, .. } => write!(f, "{}", name), Stringable::Label(l) => write!(f, "{}", l),
            Stringable::Comment { text, .. } => write!(f, "{}", text), Stringable::Parameter { name, .. } => write!(f, "{}", name),
            Stringable::MultipleSymbols(names) => write!(f, "{}", names.join(", ")), Stringable::Generic(s) => write!(f, "{}", s) }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CommentType { Eol, Pre, Post, Plate, Repeatable }

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MarkupType {
    FunctionName, FunctionSignature, DataType, Label, EolComment, PreComment, PostComment,
    PlateComment, RepeatableComment, Comment, FunctionParameterName, FunctionReturnType,
    DataReference, FunctionInline, FunctionNoReturn,
}

impl MarkupType {
    pub fn display_name(&self) -> &str {
        match self { MarkupType::FunctionName => "Function Name", MarkupType::FunctionSignature => "Function Signature",
            MarkupType::DataType => "Data Type", MarkupType::Label => "Label", MarkupType::EolComment => "EOL Comment",
            MarkupType::PreComment => "Pre Comment", MarkupType::PostComment => "Post Comment", MarkupType::PlateComment => "Plate Comment",
            MarkupType::RepeatableComment => "Repeatable Comment", MarkupType::Comment => "Comment",
            MarkupType::FunctionParameterName => "Function Parameter Name", MarkupType::FunctionReturnType => "Function Return Type",
            MarkupType::DataReference => "Data Reference", MarkupType::FunctionInline => "Function Inline",
            MarkupType::FunctionNoReturn => "Function No Return" }
    }
    pub fn supports_association_type(&self, at: VtAssociationType) -> bool {
        match self { MarkupType::FunctionName | MarkupType::FunctionSignature | MarkupType::FunctionParameterName |
            MarkupType::FunctionReturnType | MarkupType::FunctionInline | MarkupType::FunctionNoReturn => at == VtAssociationType::Function,
            MarkupType::DataType | MarkupType::DataReference => at == VtAssociationType::Data, _ => true }
    }
    pub fn db_id(&self) -> i32 {
        match self { MarkupType::DataReference => 11, MarkupType::EolComment => 12, MarkupType::FunctionName => 13,
            MarkupType::FunctionReturnType => 14, MarkupType::FunctionParameterName => 15, MarkupType::Label => 16,
            MarkupType::PlateComment => 17, MarkupType::PostComment => 18, MarkupType::PreComment => 19,
            MarkupType::RepeatableComment => 20, MarkupType::DataType => 25, MarkupType::FunctionSignature => 29,
            MarkupType::Comment => 99, MarkupType::FunctionInline => 31, MarkupType::FunctionNoReturn => 32 }
    }
    pub fn from_db_id(id: i32) -> Option<Self> {
        match id { 11 => Some(MarkupType::DataReference), 12 => Some(MarkupType::EolComment), 13 => Some(MarkupType::FunctionName),
            14 => Some(MarkupType::FunctionReturnType), 15 => Some(MarkupType::FunctionParameterName), 16 => Some(MarkupType::Label),
            17 => Some(MarkupType::PlateComment), 18 => Some(MarkupType::PostComment), 19 => Some(MarkupType::PreComment),
            20 => Some(MarkupType::RepeatableComment), 25 => Some(MarkupType::DataType), 29 => Some(MarkupType::FunctionSignature),
            31 => Some(MarkupType::FunctionInline), 32 => Some(MarkupType::FunctionNoReturn), _ => None }
    }
    pub fn all_types() -> &'static [MarkupType] {
        &[MarkupType::EolComment, MarkupType::FunctionName, MarkupType::Label, MarkupType::PlateComment,
            MarkupType::PostComment, MarkupType::PreComment, MarkupType::RepeatableComment, MarkupType::DataType, MarkupType::FunctionSignature]
    }
}

impl fmt::Display for MarkupType { fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "{}", self.display_name()) } }

pub struct VtMarkupTypeFactory;
impl VtMarkupTypeFactory {
    pub fn get_markup_type(id: i32) -> Option<MarkupType> { MarkupType::from_db_id(id) }
    pub fn get_id(markup_type: MarkupType) -> i32 { markup_type.db_id() }
    pub fn get_markup_types() -> Vec<MarkupType> { MarkupType::all_types().to_vec() }
}

#[derive(Debug, Clone)]
pub struct VtMarkupItem {
    pub id: u64,
    pub markup_type: MarkupType,
    source_address: Address,
    destination_address: Option<Address>,
    destination_address_source: String,
    source_value: Option<Stringable>,
    current_destination_value: Option<Stringable>,
    original_destination_value: Option<Stringable>,
    status: VtMarkupItemStatus,
    status_description: Option<String>,
    has_source_location: bool,
}

impl VtMarkupItem {
    pub fn new(id: u64, markup_type: MarkupType, source_address: Address) -> Self {
        Self { id, markup_type, source_address, destination_address: None, destination_address_source: String::new(),
            source_value: None, current_destination_value: None, original_destination_value: None,
            status: VtMarkupItemStatus::Unapplied, status_description: None, has_source_location: true }
    }
    pub fn can_apply(&self) -> bool { self.status.is_appliable() }
    pub fn can_unapply(&self) -> bool { self.status.is_unappliable() }
    pub fn source_address(&self) -> Address { self.source_address }
    pub fn destination_address(&self) -> Option<Address> { self.destination_address }
    pub fn set_destination_address(&mut self, address: Address) { self.destination_address = Some(address); self.destination_address_source = "User Defined".to_string(); }
    pub fn set_default_destination_address(&mut self, address: Address, source: impl Into<String>) { self.destination_address = Some(address); self.destination_address_source = source.into(); }
    pub fn destination_address_source(&self) -> &str { &self.destination_address_source }
    pub fn destination_address_edit_status(&self) -> VtMarkupItemDestinationAddressEditStatus {
        if self.can_unapply() { VtMarkupItemDestinationAddressEditStatus::Applied }
        else if self.destination_address.is_some() { VtMarkupItemDestinationAddressEditStatus::Editable }
        else { VtMarkupItemDestinationAddressEditStatus::NotSupported }
    }
    pub fn source_value(&self) -> Option<&Stringable> { self.source_value.as_ref() }
    pub fn set_source_value(&mut self, value: Stringable) { self.source_value = Some(value); }
    pub fn current_destination_value(&self) -> Option<&Stringable> { self.current_destination_value.as_ref() }
    pub fn set_current_destination_value(&mut self, value: Stringable) { self.current_destination_value = Some(value); }
    pub fn original_destination_value(&self) -> Option<&Stringable> { self.original_destination_value.as_ref() }
    pub fn set_original_destination_value(&mut self, value: Stringable) { self.original_destination_value = Some(value); }
    pub fn status(&self) -> VtMarkupItemStatus { self.status }
    pub fn set_status(&mut self, status: VtMarkupItemStatus) { self.status = status; }
    pub fn status_description(&self) -> Option<&str> { self.status_description.as_deref() }
    pub fn set_status_description(&mut self, desc: impl Into<String>) { self.status_description = Some(desc.into()); }
    pub fn markup_type(&self) -> MarkupType { self.markup_type }
    pub fn apply(&mut self, action: VtMarkupItemApplyActionType) -> Result<(), String> {
        if !self.can_apply() { return Err(format!("Cannot apply: status is {}", self.status.description())); }
        if self.destination_address.is_none() { return Err("Destination address not set".to_string()); }
        self.status = action.apply_status(); Ok(())
    }
    pub fn unapply(&mut self) -> Result<(), String> {
        if !self.can_unapply() { return Err(format!("Cannot unapply: status is {}", self.status.description())); }
        self.status = VtMarkupItemStatus::Unapplied; Ok(())
    }
    pub fn set_considered(&mut self, status: VtMarkupItemConsideredStatus) -> Result<(), String> {
        if self.can_unapply() { return Err("Cannot set considered on applied item".to_string()); }
        self.status = status.markup_item_status(); Ok(())
    }
    pub fn has_same_source_and_destination_values(&self) -> bool {
        match (&self.source_value, &self.current_destination_value) { (Some(s), Some(d)) => s == d, (None, None) => true, _ => false }
    }
}

impl fmt::Display for VtMarkupItem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {} @ {} -> {}", self.markup_type, self.status, self.source_address,
            self.destination_address.map(|a| format!("{}", a)).unwrap_or_else(|| "unset".to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(v: u64) -> Address { Address::new(v) }

    #[test]
    fn test_stringable_roundtrip() {
        let items = vec![Stringable::FunctionName("main".to_string()),
            Stringable::DataType { name: "uint32".to_string(), type_id: 42, manager_id: 1, size: 4 },
            Stringable::Label("global_var".to_string()),
            Stringable::Generic("hello".to_string())];
        for item in items {
            let storage = item.to_storage_string();
            let restored = Stringable::from_storage_string(&storage).unwrap();
            assert_eq!(item, restored, "Roundtrip failed for: {}", storage);
        }
    }

    #[test]
    fn test_markup_item_lifecycle() {
        let mut item = VtMarkupItem::new(1, MarkupType::FunctionName, addr(0x1000));
        assert!(item.can_apply());
        assert!(!item.can_unapply());
        item.set_destination_address(addr(0x2000));
        item.set_source_value(Stringable::FunctionName("main".to_string()));
        item.apply(VtMarkupItemApplyActionType::Replace).unwrap();
        assert!(item.can_unapply());
        item.unapply().unwrap();
        assert!(item.can_apply());
    }

    #[test]
    fn test_markup_type_supports() {
        assert!(MarkupType::FunctionName.supports_association_type(VtAssociationType::Function));
        assert!(!MarkupType::FunctionName.supports_association_type(VtAssociationType::Data));
        assert!(MarkupType::EolComment.supports_association_type(VtAssociationType::Data));
    }

    #[test]
    fn test_markup_type_db_id_roundtrip() {
        for mt in MarkupType::all_types() {
            assert_eq!(MarkupType::from_db_id(mt.db_id()), Some(*mt));
        }
    }

    #[test]
    fn test_markup_type_factory() {
        assert_eq!(VtMarkupTypeFactory::get_markup_type(13), Some(MarkupType::FunctionName));
        assert_eq!(VtMarkupTypeFactory::get_id(MarkupType::EolComment), 12);
    }
}
