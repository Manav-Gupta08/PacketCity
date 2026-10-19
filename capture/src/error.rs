use thiserror::Error;

use crate::platform;

#[derive(Debug, Clone, Error)]
pub enum CaptureError {
    #[error("The packet capture driver is not available. {0}")]
    DriverUnavailable(String),
    #[error("Permission denied while opening the interface: {0}")]
    PermissionDenied(String),
    #[error("Interface \"{0}\" was not found. It may have been disconnected.")]
    InterfaceNotFound(String),
    #[error("The interface \"{0}\" was removed or disabled.")]
    InterfaceRemoved(String),
    #[error("This interface uses an unsupported link type ({0}).")]
    UnsupportedLinkType(i32),
    #[error("The capture filter is invalid: {0}")]
    InvalidFilter(String),
    #[error("Could not open the interface: {0}")]
    Open(String),
    #[error("Capture stopped unexpectedly: {0}")]
    Read(String),
}

impl CaptureError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::DriverUnavailable(_) => "driverUnavailable",
            Self::PermissionDenied(_) => "permissionDenied",
            Self::InterfaceNotFound(_) => "interfaceNotFound",
            Self::InterfaceRemoved(_) => "interfaceRemoved",
            Self::UnsupportedLinkType(_) => "unsupportedLinkType",
            Self::InvalidFilter(_) => "invalidFilter",
            Self::Open(_) => "openFailed",
            Self::Read(_) => "captureFailed",
        }
    }

    /// Plain-language next step for the user.
    pub fn hint(&self) -> Option<&'static str> {
        match self {
            Self::DriverUnavailable(_) => Some(platform::DRIVER_HINT),
            Self::PermissionDenied(_) => Some(platform::PERMISSION_HINT),
            Self::InterfaceNotFound(_) | Self::InterfaceRemoved(_) | Self::Read(_) => Some("Refresh the interface list and select an active adapter."),
            Self::UnsupportedLinkType(_) => Some("Choose an Ethernet, Wi-Fi or loopback interface."),
            Self::InvalidFilter(_) => Some("Use BPF syntax, e.g. \"tcp port 443\" or \"not arp\"."),
            Self::Open(_) => None,
        }
    }

    /// libpcap reports permission problems as free-form text; recognise the common forms.
    pub(crate) fn from_open(err: pcap::Error) -> Self {
        let text = err.to_string();
        let lower = text.to_ascii_lowercase();
        if ["permission", "access is denied", "operation not permitted", "not permitted"].iter().any(|p| lower.contains(p)) {
            Self::PermissionDenied(text)
        } else if lower.contains("no such device") || lower.contains("doesn't exist") || lower.contains("not exist") {
            Self::InterfaceNotFound(text)
        } else {
            Self::Open(text)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn classify(msg: &str) -> &'static str {
        CaptureError::from_open(pcap::Error::PcapError(msg.into())).code()
    }

    #[test]
    fn recognises_platform_permission_messages() {
        assert_eq!(classify("eth0: You don't have permission to capture on that device (socket: Operation not permitted)"), "permissionDenied");
        assert_eq!(classify("(cannot open BPF device) /dev/bpf0: Permission denied"), "permissionDenied");
        assert_eq!(classify("Error opening adapter: Access is denied.  (5)"), "permissionDenied");
    }

    #[test]
    fn recognises_missing_interface_and_other_errors() {
        assert_eq!(classify("wlan9: No such device exists"), "interfaceNotFound");
        assert_eq!(classify("something odd happened"), "openFailed");
        assert!(CaptureError::DriverUnavailable(String::new()).hint().is_some());
    }
}
