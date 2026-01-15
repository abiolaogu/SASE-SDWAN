//! Forms value objects
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FormField {
    pub id: String,
    pub field_type: FieldType,
    pub label: String,
    pub placeholder: Option<String>,
    pub required: bool,
    pub options: Option<Vec<String>>,
    pub validation: Option<FieldValidation>,
    pub order: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum FieldType { ShortText, LongText, Email, Phone, Number, Date, Dropdown, MultiSelect, Checkbox, Radio, FileUpload, Rating, Signature }

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FieldValidation { pub min_length: Option<u32>, pub max_length: Option<u32>, pub pattern: Option<String>, pub min: Option<f64>, pub max: Option<f64> }

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FieldResponse { pub field_id: String, pub value: serde_json::Value }
