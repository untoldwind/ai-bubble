//! The one-line command/reply protocol shared by the in-sandbox frontends
//! and the host-side connector (both talk over a Unix socket: one
//! newline-terminated line out, one line or a raw pipe back).
//!
//! All three readers used to be hand-rolled copies of the same
//! byte-at-a-time loop; this module is the single implementation.

use std::io;
use tokio::io::AsyncReadExt;
use tokio::net::UnixStream;

/// Read one newline-terminated line, byte at a time, capped at `cap`
/// bytes. Returns:
///
/// * `Ok(Some(line))` — a trimmed, non-empty line without NUL bytes
///   (the only thing the protocol's commands and replies may carry);
/// * `Ok(None)` — clean EOF before any byte, an over-limit line, or a
///   line that is empty / non-UTF-8 / contains NUL. In all of these the
///   connection is malformed for the protocol and should be closed;
/// * `Err(e)` — an I/O error other than `Interrupted`.
pub(crate) async fn read_line_limited(
    stream: &mut UnixStream,
    cap: usize,
) -> io::Result<Option<String>> {
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        match stream.read(&mut byte).await {
            Ok(0) => return Ok(None),
            Ok(_) => {
                if byte[0] == b'\n' {
                    break;
                }
                if buf.len() > cap {
                    return Ok(None);
                }
                buf.push(byte[0]);
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    let s = match String::from_utf8(buf) {
        Ok(s) => s,
        Err(_) => return Ok(None),
    };
    let t = s.trim().to_string();
    if t.is_empty() || t.contains('\0') {
        return Ok(None);
    }
    Ok(Some(t))
}

/// Read one newline-terminated frame, byte at a time, capped at `cap`.
/// Unlike [`read_line_limited`], this distinguishes a clean EOF (no
/// bytes at all) from a malformed frame: only a clean EOF returns
/// `Ok(None)`. Anything malformed — an over-limit line, non-UTF-8, a
/// NUL byte, an empty line, or bytes ending in EOF without a newline —
/// comes back as `Err`, so the caller can warn and close instead of
/// silently treating a bug as "peer is done".
pub(crate) async fn read_frame_limited(
    stream: &mut UnixStream,
    cap: usize,
) -> io::Result<Option<String>> {
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        match stream.read(&mut byte).await {
            Ok(0) => {
                return if buf.is_empty() {
                    Ok(None)
                } else {
                    Err(io::Error::other("frame ends in EOF without a newline"))
                };
            }
            Ok(_) => {
                if byte[0] == b'\n' {
                    break;
                }
                if buf.len() > cap {
                    return Err(io::Error::other("frame over the size cap"));
                }
                buf.push(byte[0]);
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    let s = String::from_utf8(buf).map_err(|_| io::Error::other("frame is not UTF-8"))?;
    let t = s.trim().to_string();
    if t.is_empty() || t.contains('\0') {
        return Err(io::Error::other("frame is empty or contains NUL"));
    }
    Ok(Some(t))
}
