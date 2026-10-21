use super::*;

#[test]
fn bpf_decode_checks_alignment_length_and_kernel_instruction_limit() {
    let instruction = [0x06, 0, 1, 2, 0x11, 0x22, 0x33, 0x44];
    let mut unaligned = vec![0xff];
    unaligned.extend_from_slice(&instruction);
    let decoded = decode_filter(&unaligned[1..]).expect("field decoding needs no byte alignment");
    assert_eq!(decoded.len(), 1);
    assert_eq!(decoded[0].code, u16::from_ne_bytes([0x06, 0]));
    assert_eq!(decoded[0].jt, 1);
    assert_eq!(decoded[0].jf, 2);
    assert_eq!(decoded[0].k, u32::from_ne_bytes([0x11, 0x22, 0x33, 0x44]));
    assert!(decode_filter(&[]).is_err());
    assert!(decode_filter(&[0; 7]).is_err());
    assert!(decode_filter(&vec![0; MAX_BPF_BYTES]).is_ok());
    assert!(decode_filter(&vec![0; MAX_BPF_BYTES + INSTRUCTION_BYTES]).is_err());
}

#[test]
fn setup_protocol_rejects_truncated_extra_and_invalid_records() {
    assert_eq!(decode_setup_report(&[]).unwrap(), None);
    let mut record = INSTALL_FILTER_STAGE.to_ne_bytes().to_vec();
    record.extend_from_slice(&libc::EINVAL.to_ne_bytes());
    assert_eq!(
        decode_setup_report(&record).unwrap(),
        Some((2, libc::EINVAL))
    );
    for length in 1..8 {
        assert!(decode_setup_report(&record[..length]).is_err());
    }
    record.push(0);
    assert!(decode_setup_report(&record).is_err());
    assert!(decode_setup_report(&[0; 8]).is_err());
    record[..4].copy_from_slice(&99_u32.to_ne_bytes());
    record.truncate(8);
    assert!(decode_setup_report(&record).is_err());
    record[..4].copy_from_slice(&NO_NEW_PRIVILEGES_STAGE.to_ne_bytes());
    for errno in [0_i32, -libc::EPERM] {
        record[4..].copy_from_slice(&errno.to_ne_bytes());
        assert!(decode_setup_report(&record).is_err());
    }
}

#[test]
fn setup_pipe_preserves_a_complete_record_without_waiting_for_eof() {
    let (reader, writer) = failure_pipe().expect("private setup pipe");
    let mut record = NO_NEW_PRIVILEGES_STAGE.to_ne_bytes().to_vec();
    record.extend_from_slice(&libc::EPERM.to_ne_bytes());
    let written = unsafe { libc::write(writer.as_raw_fd(), record.as_ptr().cast(), record.len()) };
    assert_eq!(written, 8);
    // Keep the writer open, as an unrelated concurrent host fork might do.
    assert_eq!(read_setup_report(reader).unwrap(), Some((1, libc::EPERM)));
    drop(writer);
}

#[test]
fn parallel_native_preparation_and_execution_completes_in_bound() {
    use super::super::execute_with_native_seccomp_options;
    use std::sync::mpsc;
    use std::thread;
    use std::time::{Duration, Instant};

    let directory = tempfile::tempdir().expect("private concurrent test directory");
    let (sender, receiver) = mpsc::channel();
    let mut workers = Vec::new();
    for _ in 0..4 {
        let sender = sender.clone();
        let working_directory = directory.path().to_path_buf();
        workers.push(thread::spawn(move || {
            let result = (|| -> Result<(), String> {
                let context = SandboxContext {
                    mode: PolicyMode::ReadOnly,
                    working_directory,
                    timeout_ms: Some(3_000),
                };
                for _ in 0..3 {
                    let output = execute_with_native_seccomp_options(
                        "echo concurrent",
                        &context,
                        SetupOptions::default(),
                    )
                    .map_err(|error| error.to_string())?;
                    if output.exit_code != 0 || output.stdout.trim() != "concurrent" {
                        return Err(format!("unexpected concurrent output: {output:?}"));
                    }
                }
                Ok(())
            })();
            let _ = sender.send(result);
        }));
    }
    drop(sender);
    let deadline = Instant::now() + Duration::from_secs(15);
    for _ in 0..workers.len() {
        let result = receiver
            .recv_timeout(deadline.saturating_duration_since(Instant::now()))
            .expect("concurrent native setup/exec exceeded the shared 15-second bound");
        result.expect("concurrent native setup/exec failed");
    }
    for worker in workers {
        worker.join().expect("concurrent worker panicked");
    }
}
