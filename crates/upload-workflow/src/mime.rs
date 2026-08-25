use bytes::Bytes;

use crate::{DeclaredMime, UploadError};

const PREFIX_BYTES: usize = 16;

/// Bounded magic-signature inspector used while the full object stream continues to EOF.
#[derive(Clone, Debug, Default)]
pub struct MimeInspector {
    prefix: [u8; PREFIX_BYTES],
    length: usize,
}

impl MimeInspector {
    /// Copies only the still-needed prefix bytes from a streamed chunk.
    pub fn observe(&mut self, chunk: &Bytes) {
        let remaining = PREFIX_BYTES.saturating_sub(self.length);
        let take = remaining.min(chunk.len());
        self.prefix[self.length..self.length + take].copy_from_slice(&chunk[..take]);
        self.length += take;
    }

    /// Detects one supported MIME type strictly from server-observed magic bytes.
    ///
    /// # Errors
    ///
    /// Returns [`UploadError::MimeMismatch`] for empty, truncated, polyglot-leading, or unsupported
    /// content. File extensions and client metadata are never consulted.
    pub fn detected(&self) -> Result<DeclaredMime, UploadError> {
        let prefix = &self.prefix[..self.length];
        if prefix.starts_with(b"\x89PNG\r\n\x1a\n") {
            Ok(DeclaredMime::Png)
        } else if prefix.starts_with(&[0xff, 0xd8, 0xff]) {
            Ok(DeclaredMime::Jpeg)
        } else if prefix.starts_with(b"GIF87a") || prefix.starts_with(b"GIF89a") {
            Ok(DeclaredMime::Gif)
        } else if prefix.starts_with(b"%PDF-") {
            Ok(DeclaredMime::Pdf)
        } else if prefix.starts_with(b"PK\x03\x04")
            || prefix.starts_with(b"PK\x05\x06")
            || prefix.starts_with(b"PK\x07\x08")
        {
            Ok(DeclaredMime::Zip)
        } else {
            Err(UploadError::MimeMismatch)
        }
    }
}
