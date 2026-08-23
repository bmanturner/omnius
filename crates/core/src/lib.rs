//! Stable service-kit types shared across transports and capabilities.
//!
//! This crate owns identifiers, time access, coded errors, and safe build
//! metadata. It deliberately contains no provider clients or runtime globals.

mod clock;
mod error;
mod id;
mod metadata;

pub use clock::{Clock, SystemClock};
pub use error::{ErrorCode, InvalidErrorCode, ServiceError};
pub use id::{CausationId, CorrelationId, ParseIdError, RequestId};
pub use metadata::{BuildMetadata, BuildMetadataInput, InvalidBuildMetadata, SchemaCompatibility};
