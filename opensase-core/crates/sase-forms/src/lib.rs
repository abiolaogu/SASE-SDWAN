//! OpenSASE Forms Platform - DDD Implementation (Typeform replacement)
pub mod domain;
pub use domain::aggregates::{Form, FormSubmission, FormError};
pub use domain::value_objects::{FormField, FieldType};
pub use domain::events::{DomainEvent, FormEvent};
