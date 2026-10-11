//! Structured failures with stable exit codes. No variant ever carries a credential.
use serde_json::{Value, json};

#[derive(Debug)]
pub enum CliError {
    /// The server answered with a structured error.
    Api {
        status: u16,
        code: String,
        message: String,
    },
    /// Bad arguments or configuration.
    Usage(String),
    /// A bounded wait ran out.
    Timeout(String),
    /// The watched operation reached a failed or cancelled state.
    Failed {
        code: String,
        message: String,
    },
    /// DNS, TLS, connection or protocol trouble.
    Network(String),
    Interrupted,
}

pub const EXIT_FAILED: u8 = 1;
pub const EXIT_USAGE: u8 = 2;
pub const EXIT_AUTH: u8 = 3;
pub const EXIT_NOT_FOUND: u8 = 4;
pub const EXIT_TIMEOUT: u8 = 5;
pub const EXIT_OPERATION_FAILED: u8 = 6;
pub const EXIT_CONFLICT: u8 = 7;
pub const EXIT_UNAVAILABLE: u8 = 8;
pub const EXIT_INTERRUPTED: u8 = 130;

impl CliError {
    pub fn usage(message: impl Into<String>) -> Self {
        Self::Usage(message.into())
    }
    pub fn exit_code(&self) -> u8 {
        match self {
            Self::Usage(_) => EXIT_USAGE,
            Self::Timeout(_) => EXIT_TIMEOUT,
            Self::Failed { .. } => EXIT_OPERATION_FAILED,
            Self::Network(_) => EXIT_UNAVAILABLE,
            Self::Interrupted => EXIT_INTERRUPTED,
            Self::Api { status, .. } => match status {
                401 | 403 => EXIT_AUTH,
                404 => EXIT_NOT_FOUND,
                409 | 422 => EXIT_CONFLICT,
                429 | 500..=599 => EXIT_UNAVAILABLE,
                _ => EXIT_FAILED,
            },
        }
    }
    pub fn code(&self) -> String {
        match self {
            Self::Api { code, .. } | Self::Failed { code, .. } => code.clone(),
            Self::Usage(_) => "usage".into(),
            Self::Timeout(_) => "timeout".into(),
            Self::Network(_) => "network_error".into(),
            Self::Interrupted => "interrupted".into(),
        }
    }
    pub fn message(&self) -> String {
        match self {
            Self::Api { message, .. } | Self::Failed { message, .. } => message.clone(),
            Self::Usage(m) | Self::Timeout(m) | Self::Network(m) => m.clone(),
            Self::Interrupted => "Interrupted; any server-side run continues (cancel it with `librehub automation cancel`)".into(),
        }
    }
    pub fn to_json(&self) -> Value {
        let mut error =
            json!({"code": self.code(), "message": self.message(), "exit_code": self.exit_code()});
        if let Self::Api { status, .. } = self {
            error["status"] = json!(status);
        }
        json!({"error": error})
    }
}
impl std::fmt::Display for CliError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code(), self.message())
    }
}
impl std::error::Error for CliError {}
impl From<anyhow::Error> for CliError {
    fn from(error: anyhow::Error) -> Self {
        Self::Usage(error.to_string())
    }
}
