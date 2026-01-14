//! Multi-Tenant Isolation Framework (MTIF)
//!
//! Enterprise-grade multi-tenancy for 10,000+ customers.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────┐
//! │                   MULTI-TENANT ISOLATION FRAMEWORK                      │
//! │                                                                         │
//! │  ┌──────────────────────────────────────────────────────────────────┐  │
//! │  │                      TENANT REGISTRY                             │  │
//! │  │   ┌───────┐  ┌───────┐  ┌───────┐  ┌───────┐  ┌───────┐        │  │
//! │  │   │Tenant1│  │Tenant2│  │Tenant3│  │Tenant4│  │...10K+│        │  │
//! │  │   └───┬───┘  └───┬───┘  └───┬───┘  └───┬───┘  └───────┘        │  │
//! │  └───────┼──────────┼──────────┼──────────┼──────────────────────────┘  │
//! │          │          │          │          │                             │
//! │  ┌───────▼──────────▼──────────▼──────────▼──────────────────────────┐  │
//! │  │                      ISOLATION LAYER                              │  │
//! │  │  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐              │  │
//! │  │  │ VRF/    │  │Resource │  │Identity │  │ Config  │              │  │
//! │  │  │ Network │  │ Limits  │  │  Store  │  │  Store  │              │  │
//! │  │  └─────────┘  └─────────┘  └─────────┘  └─────────┘              │  │
//! │  └──────────────────────────────────────────────────────────────────┘  │
//! │                                                                         │
//! │  ┌──────────────────────────────────────────────────────────────────┐  │
//! │  │                      DATA PLANE ENFORCEMENT                       │  │
//! │  │      Every packet tagged with tenant_id | Verified at each hop    │  │
//! │  └──────────────────────────────────────────────────────────────────┘  │
//! └─────────────────────────────────────────────────────────────────────────┘
//! ```

#![warn(missing_docs)]
#![allow(dead_code)]

pub mod model;
pub mod isolation;
pub mod limits;
pub mod identity;
pub mod billing;
pub mod lifecycle;

pub use model::{Tenant, TenantTier, TenantId, TenantRole, ResourceLimits};
pub use isolation::IsolationEngine;
pub use limits::QuotaEnforcer;
pub use identity::IdentityManager;
