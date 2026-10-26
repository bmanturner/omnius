/// Merges an operation result with the result of its cleanup step.
///
/// The operation's own error wins; otherwise a cleanup failure is surfaced, so
/// a successful operation never hides a failed close or flush.
///
/// # Errors
///
/// Returns `result`'s error if present, else `cleanup`'s error.
pub fn finish_with_close<T, E>(result: Result<T, E>, cleanup: Result<(), E>) -> Result<T, E> {
    match (result, cleanup) {
        (Err(primary), _) => Err(primary),
        (Ok(_), Err(error)) => Err(error),
        (Ok(output), Ok(())) => Ok(output),
    }
}

#[cfg(test)]
mod tests {
    use super::finish_with_close;

    #[test]
    fn primary_error_wins_over_cleanup_error() {
        assert_eq!(finish_with_close::<(), _>(Err("a"), Err("b")), Err("a"));
    }

    #[test]
    fn cleanup_error_surfaces_after_success() {
        assert_eq!(finish_with_close(Ok(1), Err("b")), Err("b"));
    }

    #[test]
    fn success_passes_through() {
        assert_eq!(finish_with_close::<_, &str>(Ok(1), Ok(())), Ok(1));
    }
}
