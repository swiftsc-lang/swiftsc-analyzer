pub mod security;

pub use security::{SecurityAnalyzer, SecurityWarning};

/// Analyzer version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
