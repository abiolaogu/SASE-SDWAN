//! Form Aggregate
use chrono::{DateTime, Utc};
use crate::domain::value_objects::{FormField, FieldResponse};
use crate::domain::events::{DomainEvent, FormEvent};

#[derive(Clone, Debug)]
pub struct Form {
    id: String, name: String, description: Option<String>, status: FormStatus,
    fields: Vec<FormField>, settings: FormSettings, submission_count: u64,
    created_at: DateTime<Utc>, updated_at: DateTime<Utc>, events: Vec<DomainEvent>,
}

#[derive(Clone, Debug, Default)] pub struct FormSettings { pub collect_email: bool, pub one_response_per_email: bool, pub show_progress: bool, pub redirect_url: Option<String>, pub confirmation_message: Option<String> }
#[derive(Clone, Debug, Default, PartialEq, Eq)] pub enum FormStatus { #[default] Draft, Published, Closed, Archived }

impl Form {
    pub fn create(name: impl Into<String>) -> Self {
        Self { id: uuid::Uuid::new_v4().to_string(), name: name.into(), description: None, status: FormStatus::Draft, fields: vec![], settings: FormSettings::default(), submission_count: 0, created_at: Utc::now(), updated_at: Utc::now(), events: vec![] }
    }
    pub fn id(&self) -> &str { &self.id }
    pub fn status(&self) -> &FormStatus { &self.status }
    pub fn fields(&self) -> &[FormField] { &self.fields }
    pub fn add_field(&mut self, field: FormField) { self.fields.push(field); self.touch(); }
    pub fn remove_field(&mut self, field_id: &str) { self.fields.retain(|f| f.id != field_id); self.touch(); }
    pub fn publish(&mut self) -> Result<(), FormError> { if self.fields.is_empty() { return Err(FormError::NoFields); } self.status = FormStatus::Published; self.touch(); Ok(()) }
    pub fn close(&mut self) { self.status = FormStatus::Closed; self.touch(); }
    pub fn archive(&mut self) { self.status = FormStatus::Archived; self.touch(); }
    pub fn record_submission(&mut self) { self.submission_count += 1; }
    pub fn take_events(&mut self) -> Vec<DomainEvent> { std::mem::take(&mut self.events) }
    fn touch(&mut self) { self.updated_at = Utc::now(); }
}

#[derive(Clone, Debug)]
pub struct FormSubmission {
    pub id: String, pub form_id: String, pub responses: Vec<FieldResponse>,
    pub submitter_email: Option<String>, pub ip_address: Option<String>,
    pub submitted_at: DateTime<Utc>,
}

impl FormSubmission {
    pub fn create(form_id: impl Into<String>, responses: Vec<FieldResponse>) -> Self {
        Self { id: uuid::Uuid::new_v4().to_string(), form_id: form_id.into(), responses, submitter_email: None, ip_address: None, submitted_at: Utc::now() }
    }
}

#[derive(Debug, Clone)] pub enum FormError { NoFields, NotPublished }
impl std::error::Error for FormError {}
impl std::fmt::Display for FormError { fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { write!(f, "Form error") } }

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::value_objects::FieldType;
    #[test]
    fn test_form() {
        let mut f = Form::create("Contact Form");
        f.add_field(FormField { id: "1".into(), field_type: FieldType::Email, label: "Email".into(), placeholder: None, required: true, options: None, validation: None, order: 0 });
        f.publish().unwrap();
        assert_eq!(f.status(), &FormStatus::Published);
    }
}
