use thiserror::Error;

/// Errors that can occur during PE parse, validation, or transformation.
///
/// This enum is `#[non_exhaustive]` — new variants may be added without a
/// semver bump.  Match with a wildcard arm to stay forward-compatible.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum NaegiaPeError {
    /// The input does not conform to PE32+ structural expectations:
    /// fields are out of bounds, magic numbers are wrong, or layout
    /// assumptions are violated.
    ///
    /// The static string provides a human-readable description of *what*
    /// failed.  For programmatic context (offset, section index, etc.)
    /// open an issue against <https://github.com/naegia/naegia>.
    #[error("invalid PE image: {0}")]
    InvalidPe(&'static str),
    /// Low-level PE parse failure from the `goblin` library.
    #[error("parse error: {0}")]
    Parse(#[from] goblin::error::Error),
    /// Filesystem I/O error (read / write).
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    /// The requested protection mode / layer is not implemented yet.
    #[error("unsupported: {0}")]
    Unsupported(&'static str),
}

/// Convenience alias for [`NaegiaPeError`] results throughout the crate.
pub type Result<T> = std::result::Result<T, NaegiaPeError>;
