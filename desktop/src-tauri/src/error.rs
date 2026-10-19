use packetcity_capture::CaptureError;
use packetcity_core::capture_file::CaptureFileError;
use serde::Serialize;

/// Error shape returned to the UI: a stable code, a user-readable message and an optional hint.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CommandError {
    pub code: &'static str,
    pub message: String,
    pub hint: Option<&'static str>,
}

impl CommandError {
    pub fn internal(message: impl Into<String>) -> Self {
        Self { code: "internal", message: message.into(), hint: None }
    }

    pub fn capture_file(e: &CaptureFileError) -> Self {
        let code = match e {
            CaptureFileError::Io(_) => "fileUnreadable",
            CaptureFileError::NotACaptureFile => "notACaptureFile",
            CaptureFileError::UnsupportedLinkType(_) => "unsupportedLinkType",
            CaptureFileError::Corrupt(_) => "corruptCapture",
        };
        let hint = matches!(e, CaptureFileError::UnsupportedLinkType(_))
            .then_some("Supported: Ethernet, loopback (NULL/LOOP), raw IP and Linux cooked (SLL) captures.");
        let mut message = e.to_string();
        if let Some(first) = message.get_mut(0..1) {
            first.make_ascii_uppercase();
        }
        Self { code, message: format!("{message}."), hint }
    }
}

impl From<CaptureError> for CommandError {
    fn from(e: CaptureError) -> Self {
        Self { code: e.code(), message: e.to_string(), hint: e.hint() }
    }
}
