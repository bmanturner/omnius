//! Strict runtime toggle and list-resource bounds for tenancy.

use serde::Deserialize;
use thiserror::Error;

const MIN_LIST_ITEMS: u16 = 1;
const MAX_LIST_ITEMS: u16 = 1_000;

/// Runtime tenancy toggle and bounded-query policy.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct TenancyConfig {
    /// Whether organization tenancy is enabled.
    pub enabled: bool,
    /// Maximum rows accepted from one organization, membership, or invitation list query.
    ///
    /// The store fetches one sentinel row beyond this bound and returns a stable error instead of
    /// silently returning an incomplete list.
    pub max_list_items: u16,
}

impl Default for TenancyConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_list_items: 100,
        }
    }
}

impl TenancyConfig {
    /// Validates every resource bound independent of the runtime toggle.
    ///
    /// # Errors
    ///
    /// Returns [`TenancyConfigError::InvalidMaxListItems`] unless `max_list_items` is between 1
    /// and 1,000 inclusive.
    pub fn validate(&self) -> Result<(), TenancyConfigError> {
        if !(MIN_LIST_ITEMS..=MAX_LIST_ITEMS).contains(&self.max_list_items) {
            return Err(TenancyConfigError::InvalidMaxListItems);
        }
        Ok(())
    }
}

/// Stable, value-free tenancy configuration failure classification.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum TenancyConfigError {
    /// The list-result resource bound was zero or exceeded 1,000 rows.
    #[error("tenancy list-result limit is invalid")]
    InvalidMaxListItems,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_configuration_is_enabled_and_valid() {
        let config = TenancyConfig::default();
        assert!(config.enabled);
        assert_eq!(config.validate(), Ok(()));
    }

    #[test]
    fn disabled_configuration_still_validates_resource_bounds() {
        let config = TenancyConfig {
            enabled: false,
            max_list_items: 0,
        };
        assert_eq!(
            config.validate(),
            Err(TenancyConfigError::InvalidMaxListItems)
        );
    }
}
