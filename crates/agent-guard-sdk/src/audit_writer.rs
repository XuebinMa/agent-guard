//! Async audit-file writer.
//!
//! `AuditFileWriter` moves the synchronous `writeln!` to an audit file off the
//! request hot path. Each `Guard` instance configured with `audit.output: file`
//! owns one writer, which spawns a dedicated `std::thread` that holds the
//! `File` handle and drains lines from a bounded `mpsc::sync_channel` in
//! arrival order.
//!
//! # Backpressure
//!
//! The channel is **bounded** (default capacity [`DEFAULT_AUDIT_CHANNEL_CAPACITY`]).
//! When full, [`AuditFileWriter::send`] **drops the line** and emits a
//! `tracing::warn!` instead of blocking the producer. This is a deliberate
//! choice for an execution-control layer: blocking a real tool call so an
//! audit line can flush would defeat the purpose of moving I/O off the hot
//! path. Audit losses on sustained burst overload are preferable to coupling
//! request latency to disk-write latency. The SIEM webhook is the durable,
//! redundant export path; the local JSONL file is best-effort under
//! sustained burst >capacity.
//!
//! # Ordering
//!
//! Unlike SIEM (fire-and-forget tokio spawns, no ordering), this writer
//! preserves arrival order: a single worker thread receives one line at a
//! time and writes it before pulling the next.
//!
//! # Lifecycle
//!
//! - Construction (`new`) opens the file in append mode and spawns the worker.
//! - `Drop` closes the sender and joins the worker thread with a 5-second
//!   timeout. If the join times out, the writer logs and gives up rather than
//!   stalling shutdown indefinitely.
//! - During an `ArcSwap` policy reload that produces a fresh `GuardState`,
//!   the old state's writer is dropped when its last `Arc` reference goes
//!   away. Rapid back-to-back reloads will churn worker threads. That is
//!   acceptable for the wedge release; do not add pooling.

use std::fs::File;
use std::io::Write;
use std::path::Path;
use std::sync::mpsc::{self, SyncSender, TrySendError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

/// Default size of the bounded audit channel.
///
/// Sized to absorb short bursts (1024 events) without dropping while still
/// providing fast feedback when an audit consumer falls behind.
pub const DEFAULT_AUDIT_CHANNEL_CAPACITY: usize = 1024;

/// How long [`AuditFileWriter::Drop`] waits for the worker thread to drain.
const SHUTDOWN_JOIN_TIMEOUT: Duration = Duration::from_secs(5);

/// Async, single-producer-friendly audit-file writer.
///
/// See the [module docs](self) for the backpressure and ordering contract.
///
/// This type is `pub` only to support integration tests that need to exercise
/// the drop-on-full path with a shrunken channel capacity. It is not part of
/// the SDK's stable public surface; treat it as `#[doc(hidden)]`.
#[doc(hidden)]
pub struct AuditFileWriter {
    sender: Option<SyncSender<String>>,
    worker: Option<JoinHandle<()>>,
}

impl AuditFileWriter {
    /// Open `path` in append mode and spawn the writer thread.
    #[doc(hidden)]
    pub fn open(path: &Path) -> std::io::Result<Self> {
        Self::open_with_capacity(path, DEFAULT_AUDIT_CHANNEL_CAPACITY)
    }

    /// Like [`Self::open`] but with an explicit channel capacity. Intended
    /// for tests that want to exercise the drop-on-full path without
    /// generating thousands of lines.
    #[doc(hidden)]
    pub fn open_with_capacity(path: &Path, capacity: usize) -> std::io::Result<Self> {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;
        Ok(Self::from_file(file, capacity))
    }

    fn from_file(file: File, capacity: usize) -> Self {
        let (tx, rx) = mpsc::sync_channel::<String>(capacity);
        let worker = thread::Builder::new()
            .name("agent-guard-audit-writer".to_string())
            .spawn(move || run_worker(file, rx))
            .expect("failed to spawn audit-writer thread");

        Self {
            sender: Some(tx),
            worker: Some(worker),
        }
    }

    /// Enqueue a pre-serialized JSONL line for the worker.
    ///
    /// Returns immediately. If the channel is full, the line is dropped and
    /// a `tracing::warn!` is emitted; the request thread is never blocked.
    #[doc(hidden)]
    pub fn send(&self, line: String) {
        let Some(sender) = self.sender.as_ref() else {
            // Sender already torn down (mid-Drop). Best-effort: drop silently.
            return;
        };
        match sender.try_send(line) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => {
                tracing::warn!(
                    "audit file writer channel full; dropping audit line (capacity exceeded)"
                );
            }
            Err(TrySendError::Disconnected(_)) => {
                tracing::error!("audit file writer worker disconnected; audit line dropped");
            }
        }
    }
}

impl Drop for AuditFileWriter {
    fn drop(&mut self) {
        // Close the sender so the worker observes a `recv()` error and exits.
        drop(self.sender.take());

        if let Some(handle) = self.worker.take() {
            let deadline = Instant::now() + SHUTDOWN_JOIN_TIMEOUT;
            // `JoinHandle::join` blocks; we approximate a timed join by
            // polling `is_finished` so a hung worker can't stall shutdown
            // indefinitely.
            while !handle.is_finished() && Instant::now() < deadline {
                thread::sleep(Duration::from_millis(10));
            }
            if handle.is_finished() {
                if let Err(e) = handle.join() {
                    tracing::error!("audit-writer thread panicked during shutdown: {:?}", e);
                }
            } else {
                tracing::warn!(
                    "audit-writer thread did not finish within {:?}; abandoning join",
                    SHUTDOWN_JOIN_TIMEOUT
                );
            }
        }
    }
}

fn run_worker(mut file: File, rx: mpsc::Receiver<String>) {
    while let Ok(line) = rx.recv() {
        if let Err(e) = writeln!(file, "{}", line) {
            tracing::error!("Failed to write to audit file: {}", e);
        }
    }
    if let Err(e) = file.flush() {
        tracing::error!("Failed to flush audit file on shutdown: {}", e);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader};
    use tempfile::NamedTempFile;

    #[test]
    fn writes_lines_in_order() {
        let tmp = NamedTempFile::new().unwrap();
        let path = tmp.path().to_path_buf();
        let writer = AuditFileWriter::open(&path).unwrap();
        for i in 0..50 {
            writer.send(format!("line-{i}"));
        }
        drop(writer);

        let f = std::fs::File::open(&path).unwrap();
        let lines: Vec<String> = BufReader::new(f).lines().map(|l| l.unwrap()).collect();
        assert_eq!(lines.len(), 50);
        for (i, line) in lines.iter().enumerate() {
            assert_eq!(line, &format!("line-{i}"));
        }
    }
}
