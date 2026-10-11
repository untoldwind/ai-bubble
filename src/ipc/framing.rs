//! The shared wire framing for every inter-process JSON channel: each
//! frame is a 4-byte big-endian length prefix followed by the payload
//! (the [`netmux`] precedent). Reads go through
//! `tokio_util::codec::LengthDelimitedCodec`; writes use [`encode_frame`]
//! so the mutex-guarded shared streams (audit batches and control
//! replies on one socket) never need a second framed handle — encoding
//! one frame is pure and the write stays a single `write_all`.

use tokio_util::codec::LengthDelimitedCodec;

/// Bytes per frame length prefix (u32 big-endian, like [`netmux`]).
pub(crate) const LENGTH_FIELD_LENGTH: usize = 4;

/// One frame's wire bytes: `u32::BE(len) || payload`.
pub(crate) fn encode_frame(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + LENGTH_FIELD_LENGTH);
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// A decoding codec for length-prefixed frames, capped at
/// `max_frame_length` (over-long frames end the reader, like the old
/// `LinesCodec::new_with_max_length` behaviour).
pub(crate) fn decoder(max_frame_length: usize) -> LengthDelimitedCodec {
    LengthDelimitedCodec::builder()
        .max_frame_length(max_frame_length)
        .length_field_length(LENGTH_FIELD_LENGTH)
        .new_codec()
}

/// Blocking read of one length-prefixed frame (the CLI control client
/// and the tests; async readers use [`decoder`]).
pub(crate) fn read_blocking_frame(
    stream: &mut std::os::unix::net::UnixStream,
    cap: usize,
) -> std::io::Result<Vec<u8>> {
    use std::io::Read as _;
    let mut header = [0u8; LENGTH_FIELD_LENGTH];
    stream.read_exact(&mut header)?;
    let len = u32::from_be_bytes(header) as usize;
    if len > cap {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "frame over the size cap",
        ));
    }
    let mut frame = vec![0u8; len];
    stream.read_exact(&mut frame)?;
    Ok(frame)
}

/// Blocking write of one length-prefixed frame.
pub(crate) fn write_blocking_frame(
    stream: &mut std::os::unix::net::UnixStream,
    payload: &[u8],
) -> std::io::Result<()> {
    use std::io::Write as _;
    stream.write_all(&encode_frame(payload))
}
