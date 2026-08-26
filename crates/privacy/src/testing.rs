//! Deterministic privacy test doubles with no provider payload support.

use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
};

use thiserror::Error;

use crate::{
    AdapterEvidence, AdapterFailure, AdapterFailureCode, AdapterFuture, AdapterWork,
    DataInventoryAdapter, InventoryDescriptor,
};

/// A fake adapter mutex was poisoned by a panicking test thread.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("fake privacy adapter state is unavailable")]
pub struct FakeAdapterError;

/// Deterministic fake data-inventory adapter for lifecycle contract tests.
///
/// It captures only typed [`AdapterWork`] and never accepts or records provider payloads.
pub struct FakeInventoryAdapter {
    descriptor: InventoryDescriptor,
    outcomes: Mutex<VecDeque<Result<AdapterEvidence, AdapterFailure>>>,
    fallback: Result<AdapterEvidence, AdapterFailure>,
    calls: Mutex<Vec<AdapterWork>>,
}

impl FakeInventoryAdapter {
    /// Creates a fake with a finite outcome sequence and a repeated fallback.
    #[must_use]
    pub fn new(
        descriptor: InventoryDescriptor,
        outcomes: impl IntoIterator<Item = Result<AdapterEvidence, AdapterFailure>>,
        fallback: Result<AdapterEvidence, AdapterFailure>,
    ) -> Self {
        Self {
            descriptor,
            outcomes: Mutex::new(outcomes.into_iter().collect()),
            fallback,
            calls: Mutex::new(Vec::new()),
        }
    }

    /// Creates an always-successful fake.
    #[must_use]
    pub fn succeeding(descriptor: InventoryDescriptor, evidence: AdapterEvidence) -> Self {
        Self::new(descriptor, [], Ok(evidence))
    }

    /// Creates an always-failing fake with a closed failure code.
    #[must_use]
    pub fn failing(descriptor: InventoryDescriptor, code: AdapterFailureCode) -> Self {
        Self::new(descriptor, [], Err(AdapterFailure::new(code)))
    }

    /// Returns captured typed work in invocation order.
    ///
    /// # Errors
    ///
    /// Returns [`FakeAdapterError`] if a prior test panic poisoned the capture mutex.
    pub fn calls(&self) -> Result<Vec<AdapterWork>, FakeAdapterError> {
        self.calls
            .lock()
            .map(|calls| calls.clone())
            .map_err(|_| FakeAdapterError)
    }

    /// Erases the fake into the heterogeneous registry type.
    #[must_use]
    pub fn shared(self) -> Arc<dyn DataInventoryAdapter> {
        Arc::new(self)
    }
}

impl DataInventoryAdapter for FakeInventoryAdapter {
    fn descriptor(&self) -> &InventoryDescriptor {
        &self.descriptor
    }

    fn reconcile<'a>(&'a self, work: &'a AdapterWork) -> AdapterFuture<'a> {
        Box::pin(async move {
            let mut calls = self
                .calls
                .lock()
                .map_err(|_| AdapterFailure::new(AdapterFailureCode::Unavailable))?;
            calls.push(*work);
            drop(calls);
            let mut outcomes = self
                .outcomes
                .lock()
                .map_err(|_| AdapterFailure::new(AdapterFailureCode::Unavailable))?;
            outcomes.pop_front().unwrap_or(self.fallback)
        })
    }
}
