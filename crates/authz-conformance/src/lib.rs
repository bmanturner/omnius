//! Cross-transport authorization conformance tests.
//!
//! The integration suite drives the public HTTP shell, typed job handler, administration service,
//! `GraphQL` router, gRPC service, and realtime service with one built-in policy and canonical
//! principal/resource/context fixtures. It deliberately does not model transports with a synthetic
//! enum: each matrix row crosses the real transport boundary and asserts its native rejection plus
//! the protected operation's side-effect counter.

#![forbid(unsafe_code)]
