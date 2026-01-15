//! Form events
#[derive(Clone, Debug)]
pub enum DomainEvent { Form(FormEvent) }

#[derive(Clone, Debug)]
pub enum FormEvent { Published { form_id: String }, Submitted { form_id: String, submission_id: String }, Closed { form_id: String } }
