use thiserror::Error;

#[derive(Debug, Error)]
pub enum NaegiaPeError {
    #[error("invalid PE image: {0}")]
    InvalidPe(&'static str),
    #[error("parse error: {0}")]
    Parse(#[from] goblin::error::Error),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("unsupported: {0}")]
    Unsupported(&'static str),
}

pub type Result<T> = std::result::Result<T, NaegiaPeError>;
