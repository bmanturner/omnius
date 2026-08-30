use std::io::Write;

use serde::Serialize;

pub(crate) enum BoundedJsonEncodeError {
    TooLarge,
    Encode,
}

pub(crate) fn encode_bounded<T>(
    value: &T,
    limit: usize,
) -> Result<Box<[u8]>, BoundedJsonEncodeError>
where
    T: Serialize + ?Sized,
{
    let mut writer = BoundedJsonWriter::new(limit);
    if serde_json::to_writer(&mut writer, value).is_err() {
        return if writer.exceeded {
            Err(BoundedJsonEncodeError::TooLarge)
        } else {
            Err(BoundedJsonEncodeError::Encode)
        };
    }
    Ok(writer.bytes.into_boxed_slice())
}

struct BoundedJsonWriter {
    bytes: Vec<u8>,
    limit: usize,
    exceeded: bool,
}

impl BoundedJsonWriter {
    fn new(limit: usize) -> Self {
        Self {
            bytes: Vec::with_capacity(limit.min(8 * 1024)),
            limit,
            exceeded: false,
        }
    }
}

impl Write for BoundedJsonWriter {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        let remaining = self.limit.saturating_sub(self.bytes.len());
        if buffer.len() > remaining {
            self.exceeded = true;
            return Err(std::io::Error::other("bounded JSON value exceeded"));
        }
        self.bytes.extend_from_slice(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
