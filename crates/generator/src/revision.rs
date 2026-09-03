pub(crate) const fn is_valid_release_revision(revision: &str) -> bool {
    let bytes = revision.as_bytes();
    if bytes.len() != 40 {
        return false;
    }

    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        if !matches!(byte, b'0'..=b'9' | b'a'..=b'f') {
            return false;
        }
        index += 1;
    }

    true
}
