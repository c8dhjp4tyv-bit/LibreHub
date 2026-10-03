//! Trusted publishing boundary. Never pass these credentials to BuildExecutor.
pub mod artifact;
pub mod error;
pub mod flat_manager;
pub mod publish;
pub mod repository;
pub use error::PublishError;
pub use publish::{FlatManagerPublisher, PublishJob, PublishJournal, Publisher};
