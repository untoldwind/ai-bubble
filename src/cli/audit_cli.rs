//! The `audit` sub-command: show where the audit log is (and, with
//! `--follow`, follow it like `tail -f`).
//!
//! The plan deliberately keeps log streaming out of the control protocol
//! ("viewing the audit log needs no API"): the log is a host-side JSONL
//! file with a single writer (the launcher — FS and P forward their
//! events over the control channels), so lines never tear and any
//! process can tail it. This sub-command is pure sugar over that fact:
//! it resolves the configured log path from the spec and tails the file,
//! no protocol involved.

use std::io::Read as _;
use std::path::{Path, PathBuf};

use crate::{sandbox, spec};

/// Runs the `audit` sub-command: without `--follow`, print the audit log
/// path configured in the spec; with `--follow`, print the last `lines`
/// lines and then keep printing every appended line until interrupted.
pub fn audit(spec_dir: Option<&Path>, follow: bool, lines: usize) {
    let path = audit_log_path(spec_dir);
    if !follow {
        println!("{}", path.display());
        return;
    }
    follow_log(&path, lines);
}

/// The audit log path from the spec (expanded, like every downstream
/// consumer sees it). A hard error when the spec configures none — there
/// is nothing to show.
fn audit_log_path(spec_dir: Option<&Path>) -> PathBuf {
    let spec = spec::Spec::load(spec_dir);
    match spec.audit.log {
        Some(log) => PathBuf::from(log),
        None => sandbox::die("the spec configures no audit log (audit.log is unset)"),
    }
}

/// `tail -f` over the audit log: the last `lines` lines, then every
/// appended line, until interrupted. Rotation (the log's size cap moves
/// it to `<name>.1`, see `crate::audit::writer`) is detected by inode
/// change and followed — the follower reopens the (fresh) file and
/// continues from its start.
fn follow_log(path: &Path, lines: usize) {
    // Non-following viewers keep their own fd; the audit writer holds
    // its own descriptor (opened eagerly, `O_NOFOLLOW`), so reading the
    // path races nothing.
    let mut file = open(path);
    // The inode of the currently-open file, for rotation detection.
    let mut inode = file_inode(path);

    print_last_lines(&mut file, lines);

    let mut buf = [0u8; 8192];
    let mut carry: Vec<u8> = Vec::new();
    loop {
        match file.read(&mut buf) {
            Ok(0) => {
                // EOF: a regular file does not block here, so poll. A
                // different inode means the log was rotated (or removed
                // and recreated): reopen and continue from the start of
                // the new generation.
                std::thread::sleep(std::time::Duration::from_millis(250));
                let current = file_inode(path);
                if current != inode {
                    file = open(path);
                    inode = current;
                    carry.clear();
                }
            }
            Ok(n) => {
                carry.extend_from_slice(&buf[..n]);
                // Print whole lines only: the writer appends ≤32 KiB
                // `O_APPEND` chunks, but a *reader* may catch a partial
                // line at any instant.
                if let Some(last_nl) = carry.iter().rposition(|b| *b == b'\n') {
                    let complete: Vec<u8> = carry.drain(..last_nl + 1).collect();
                    print!("{}", String::from_utf8_lossy(&complete));
                    let _ = std::io::Write::flush(&mut std::io::stdout());
                }
                if carry.len() > crate::audit::FRAME_CAP {
                    // An incomplete line over the frame cap cannot be a
                    // real audit event; drop it instead of growing.
                    carry.clear();
                }
            }
            Err(e) => sandbox::die(&format!("Can't read {}: {e}", path.display())),
        }
    }
}

fn open(path: &Path) -> std::fs::File {
    std::fs::File::open(path)
        .unwrap_or_else(|e| sandbox::die(&format!("Can't open {}: {e}", path.display())))
}

fn file_inode(path: &Path) -> Option<u64> {
    use std::os::unix::fs::MetadataExt as _;
    std::fs::metadata(path).ok().map(|md| md.ino())
}

/// Print the last `lines` lines of the file's current content, each
/// terminated with a newline.
fn print_last_lines(file: &mut std::fs::File, lines: usize) {
    let mut text = String::new();
    if file.read_to_string(&mut text).is_err() {
        return;
    }
    for line in trailing_lines(&text, lines) {
        println!("{line}");
    }
}

/// The trailing `lines` lines of `text` (all of them when `lines`
/// exceeds the count).
fn trailing_lines(text: &str, lines: usize) -> Vec<&str> {
    let all: Vec<&str> = text.lines().collect();
    let start = all.len().saturating_sub(lines);
    all[start..].to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `trailing_lines` slices exactly the trailing `lines` lines.
    #[test]
    fn last_lines_are_the_trailing_ones() {
        let text = "one\ntwo\nthree\nfour\n";
        assert_eq!(trailing_lines(text, 2), vec!["three", "four"]);
        // More lines requested than present: everything is printed.
        assert_eq!(
            trailing_lines(text, 100),
            vec!["one", "two", "three", "four"]
        );
        // No newline at the end of the file: the last partial line is a
        // line too.
        assert_eq!(trailing_lines("one\ntwo", 1), vec!["two"]);
        assert_eq!(trailing_lines("", 5), Vec::<&str>::new());
    }
}
