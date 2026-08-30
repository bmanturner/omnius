use std::io;

pub(crate) fn serialized_len<T: serde::Serialize>(value: &T) -> u64 {
    let mut counter = CountingWriter::default();
    if serde_json::to_writer(&mut counter, value).is_err() {
        return u64::MAX;
    }
    counter.bytes
}

#[derive(Default)]
struct CountingWriter {
    bytes: u64,
}

impl io::Write for CountingWriter {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.bytes = self
            .bytes
            .saturating_add(u64::try_from(buffer.len()).unwrap_or(u64::MAX));
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
