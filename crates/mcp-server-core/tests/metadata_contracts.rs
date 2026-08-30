//! Contracts for complete, bounded, request-scoped MCP metadata.

use std::error::Error;

use omnius_mcp_server_core::{
    MAX_CLIENT_CAPABILITIES, MCP_PROTOCOL_REVISION, McpClientIdentity, McpLogLevel,
    McpMetadataError, McpRequestMetadata,
};

#[test]
fn complete_metadata_is_owned_sorted_and_request_scoped() -> Result<(), Box<dyn Error>> {
    let metadata = McpRequestMetadata::new(
        MCP_PROTOCOL_REVISION,
        McpClientIdentity::new("contract-client", "1.0.0")?,
        ["tools".to_owned(), "elicitation".to_owned()],
        ["io.omnius/progress@1".to_owned()],
        Some(McpLogLevel::Warning),
    )?;

    assert_eq!(metadata.protocol_revision(), "2026-07-28");
    assert_eq!(metadata.client().name(), "contract-client");
    assert_eq!(metadata.client().version(), "1.0.0");
    assert_eq!(
        metadata
            .client_capabilities()
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        ["elicitation", "tools"]
    );
    assert_eq!(
        metadata
            .negotiated_extensions()
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        ["io.omnius/progress@1"]
    );
    assert_eq!(metadata.requested_log_level(), Some(McpLogLevel::Warning));
    Ok(())
}

#[test]
fn incomplete_or_ambiguous_metadata_fails_closed_without_echoing_values()
-> Result<(), Box<dyn Error>> {
    let client = McpClientIdentity::new("private-client", "1.0.0")?;
    let old_revision = required_error(McpRequestMetadata::new(
        "2025-11-25",
        client.clone(),
        std::iter::empty(),
        std::iter::empty(),
        None,
    ))?;
    assert_eq!(old_revision, McpMetadataError::UnsupportedProtocolRevision);

    let duplicate = required_error(McpRequestMetadata::new(
        MCP_PROTOCOL_REVISION,
        client.clone(),
        ["tools".to_owned(), "tools".to_owned()],
        std::iter::empty(),
        None,
    ))?;
    assert_eq!(duplicate, McpMetadataError::InvalidClientCapabilities);

    let excessive = required_error(McpRequestMetadata::new(
        MCP_PROTOCOL_REVISION,
        client,
        vec!["tools".to_owned(); MAX_CLIENT_CAPABILITIES + 1],
        std::iter::empty(),
        None,
    ))?;
    assert_eq!(excessive, McpMetadataError::InvalidClientCapabilities);

    let rendered = format!("{old_revision} {old_revision:?} {duplicate} {duplicate:?}");
    assert!(!rendered.contains("private-client"));
    assert!(!rendered.contains("2025-11-25"));
    Ok(())
}

#[test]
fn client_identity_rejects_whitespace_controls_and_oversize() {
    assert_eq!(
        McpClientIdentity::new("client with spaces", "1.0.0"),
        Err(McpMetadataError::InvalidClientIdentity)
    );
    assert_eq!(
        McpClientIdentity::new("client", "1.0\nsecret"),
        Err(McpMetadataError::InvalidClientIdentity)
    );
}

fn required_error<T>(
    result: Result<T, McpMetadataError>,
) -> Result<McpMetadataError, Box<dyn Error>> {
    result
        .err()
        .ok_or_else(|| std::io::Error::other("metadata validation unexpectedly succeeded").into())
}
