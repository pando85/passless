//! Framing shared by the daemon's sign transport and the `sign-proxy` relay (plan D2).
//!
//! Both hops use Chrome's native-messaging framing: a 4-byte little-endian length, then that many
//! bytes of UTF-8 JSON, one object per frame. The length is checked against [`MAX_FRAME_LEN`]
//! before anything is allocated.
//!
//! The relay binary includes this file with `#[path]`, so it depends on `std` and `serde_json`
//! only.

use std::io::{self, Read, Write};
use std::time::Duration;

/// Largest frame payload either side accepts (1 MiB).
pub const MAX_FRAME_LEN: usize = 1024 * 1024;
/// Timeout of every socket write; a write that times out closes the connection (plan V-M5).
pub const WRITE_TIMEOUT: Duration = Duration::from_secs(5);
/// The wire protocol version carried in `hello` (`v`).
pub const PROTOCOL_VERSION: u64 = 2;

/// Why a frame could not be read.
#[derive(Debug)]
pub enum FrameError {
    /// The stream ended cleanly before the first byte of a frame.
    Eof,
    /// The announced length exceeds [`MAX_FRAME_LEN`]; nothing was allocated.
    TooLarge(usize),
    /// The payload is not a JSON object.
    NotAnObject,
    /// A read failed, timed out, or the stream ended inside a frame.
    Io(io::Error),
}

impl std::fmt::Display for FrameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Eof => write!(f, "end of stream"),
            Self::TooLarge(len) => write!(f, "frame of {len} bytes exceeds the 1 MiB cap"),
            Self::NotAnObject => write!(f, "frame is not a JSON object"),
            Self::Io(e) => write!(f, "frame read failed: {e}"),
        }
    }
}

/// Read one frame's raw payload. The length is checked before the payload buffer is allocated.
pub fn read_frame_bytes(reader: &mut impl Read) -> Result<Vec<u8>, FrameError> {
    let mut len_buf = [0u8; 4];
    let mut filled = 0;
    while filled < len_buf.len() {
        match reader.read(&mut len_buf[filled..]) {
            Ok(0) if filled == 0 => return Err(FrameError::Eof),
            Ok(0) => {
                return Err(FrameError::Io(io::Error::from(
                    io::ErrorKind::UnexpectedEof,
                )));
            }
            Ok(n) => filled += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(FrameError::Io(e)),
        }
    }
    let len = u32::from_le_bytes(len_buf) as usize;
    if len > MAX_FRAME_LEN {
        return Err(FrameError::TooLarge(len));
    }
    let mut payload = vec![0u8; len];
    reader.read_exact(&mut payload).map_err(FrameError::Io)?;
    Ok(payload)
}

/// Read one frame and parse it as a JSON object.
pub fn read_frame(
    reader: &mut impl Read,
) -> Result<serde_json::Map<String, serde_json::Value>, FrameError> {
    let payload = read_frame_bytes(reader)?;
    match serde_json::from_slice::<serde_json::Value>(&payload) {
        Ok(serde_json::Value::Object(map)) => Ok(map),
        _ => Err(FrameError::NotAnObject),
    }
}

/// Encode `payload` as one frame (length prefix included), or `None` when it is over the cap.
pub fn encode_frame(payload: &[u8]) -> Option<Vec<u8>> {
    if payload.len() > MAX_FRAME_LEN {
        return None;
    }
    let mut frame = Vec::with_capacity(4 + payload.len());
    frame.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    frame.extend_from_slice(payload);
    Some(frame)
}

/// Write one frame in a single `write_all`, then flush.
pub fn write_frame(writer: &mut impl Write, payload: &[u8]) -> io::Result<()> {
    let frame = encode_frame(payload).ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "frame exceeds the 1 MiB cap")
    })?;
    writer.write_all(&frame)?;
    writer.flush()
}

/// The build version the daemon and the relay report (plan V-L5): the package version, plus the
/// short git commit when the build knows it.
pub fn build_version_from(pkg_version: &str, short_commit: &str) -> String {
    if short_commit.is_empty() {
        pkg_version.to_string()
    } else {
        format!("{pkg_version}+{short_commit}")
    }
}
