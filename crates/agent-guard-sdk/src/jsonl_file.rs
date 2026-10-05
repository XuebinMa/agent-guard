//! Complete JSONL frames for cooperating writers/readers on a local file.
//! Advisory locks do not authenticate the contents or prevent hostile writes.
use std::fs::File;
use std::io::{self, Read, Write};
use std::time::{Duration, Instant};

struct FileLock<'a>(&'a File);

impl<'a> FileLock<'a> {
    fn acquire(file: &'a File, exclusive: bool) -> io::Result<Self> {
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let result = if exclusive {
                fs2::FileExt::try_lock_exclusive(file)
            } else {
                fs2::FileExt::try_lock_shared(file)
            };
            match result {
                Ok(()) => return Ok(Self(file)),
                Err(error)
                    if error.raw_os_error() == fs2::lock_contended_error().raw_os_error() =>
                {
                    if Instant::now() >= deadline {
                        return Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "JSONL file lock timed out",
                        ));
                    }
                    std::thread::sleep(Duration::from_millis(2));
                }
                Err(error) => return Err(error),
            }
        }
    }
}

impl Drop for FileLock<'_> {
    fn drop(&mut self) {
        if let Err(error) = fs2::FileExt::unlock(self.0) {
            tracing::error!(%error, "failed to release JSONL file lock");
        }
    }
}

pub(crate) fn append_line(file: &File, line: &str) -> io::Result<()> {
    let mut frame = Vec::with_capacity(line.len() + 1);
    frame.extend_from_slice(line.as_bytes());
    frame.push(b'\n');
    let _lock = FileLock::acquire(file, true)?;
    // write_all may perform multiple writes: hold the lock over all of them,
    // not just a single write(2), even when the file uses O_APPEND.
    let mut writer = file;
    writer.write_all(&frame)
}

pub(crate) fn read(file: &File) -> io::Result<String> {
    let _lock = FileLock::acquire(file, false)?;
    let mut contents = String::new();
    let mut reader = file;
    reader.read_to_string(&mut contents)?;
    Ok(contents)
}
