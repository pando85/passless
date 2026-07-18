use std::io;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum UhidError {
    #[error("failed to open /dev/uhid: {0}")]
    Open(#[source] io::Error),

    #[error("failed to send CREATE2: {0}")]
    Create2(#[source] io::Error),

    #[error("failed to send DESTROY: {0}")]
    Destroy(#[source] io::Error),

    #[error("failed to send INPUT2: {0}")]
    Input2(#[source] io::Error),

    #[error("failed to send GET_REPORT_REPLY: {0}")]
    GetReportReply(#[source] io::Error),

    #[error("failed to send SET_REPORT_REPLY: {0}")]
    SetReportReply(#[source] io::Error),

    #[error("failed to read UHID event: {0}")]
    Read(#[source] io::Error),

    #[error("timeout waiting for UHID device start")]
    StartTimeout,

    #[error(
        "packet too large: {0} bytes (max {UHID_DATA_MAX})",
        UHID_DATA_MAX = 4096
    )]
    PacketTooLarge(usize),

    #[error(
        "descriptor too large: {0} bytes (max {HID_MAX_DESCRIPTOR_SIZE})",
        HID_MAX_DESCRIPTOR_SIZE = 4096
    )]
    DescriptorTooLarge(usize),

    #[error("short write: wrote {written} of {expected} bytes")]
    ShortWrite { written: usize, expected: usize },

    #[error("fcntl {0} failed")]
    Fcntl(String),

    #[error("identity field '{field}' contains NUL byte")]
    IdentityNul { field: &'static str },

    #[error("identity field '{field}' too long: {len} bytes (max {max})", field = field, len = len, max = max)]
    IdentityFieldTooLong {
        field: &'static str,
        len: usize,
        max: usize,
    },

    #[error("identity field '{field}' is not valid UTF-8")]
    IdentityInvalidUtf8 { field: &'static str },
}
