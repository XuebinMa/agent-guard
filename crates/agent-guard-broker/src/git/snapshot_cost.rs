//! Opt-in measurement of the existing copy functions on owned synthetic data.
//! No networking, grant issuance, production instrumentation or public API.

use std::io;
use std::os::unix::fs::MetadataExt;
use std::time::Instant;

use serde::Serialize;

use super::*;

#[derive(Debug, Default, Serialize)]
struct FileBytes {
    logical_file_bytes: u64,
    allocated_file_bytes_estimate: u64,
    regular_files: u64,
}

fn held_files(path: &Path) -> io::Result<FileBytes> {
    let mut result = FileBytes::default();
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let metadata = fs::symlink_metadata(entry.path())?;
        if metadata.is_dir() {
            let child = held_files(&entry.path())?;
            result.logical_file_bytes += child.logical_file_bytes;
            result.allocated_file_bytes_estimate += child.allocated_file_bytes_estimate;
            result.regular_files += child.regular_files;
        } else if metadata.is_file() {
            result.logical_file_bytes += metadata.len();
            result.allocated_file_bytes_estimate += metadata.blocks() * 512;
            result.regular_files += 1;
        } else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "non-regular measurement data",
            ));
        }
    }
    Ok(result)
}

#[test]
fn held_file_accounting_counts_regular_bytes_and_refuses_links() {
    let dir = tempfile::tempdir().expect("owned scratch");
    let path = dir.path().join("data");
    fs::write(&path, b"public fixture").expect("fixture");
    let files = held_files(dir.path()).expect("accounting");
    assert_eq!(files.logical_file_bytes, 14);
    assert_eq!(files.regular_files, 1);
    assert_eq!(
        files.allocated_file_bytes_estimate,
        fs::metadata(&path).unwrap().blocks() * 512
    );
    std::os::unix::fs::symlink(&path, dir.path().join("link")).expect("fixture link");
    assert_eq!(
        held_files(dir.path()).unwrap_err().kind(),
        io::ErrorKind::InvalidData
    );
}

#[test]
#[ignore = "opt-in cost measurement; invoke only through the bounded synthetic benchmark driver"]
fn synthetic_copy_cost_probe() {
    let repo = PathBuf::from(
        std::env::var_os("AGENT_GUARD_COPY_BENCH_REPOSITORY")
            .expect("benchmark driver must supply its owned synthetic repository"),
    );
    let config = PathBuf::from(
        std::env::var_os("AGENT_GUARD_COPY_BENCH_CONFIG")
            .expect("benchmark driver must supply its empty private config"),
    );
    let options = BrokerGitOptions {
        trusted_config: Some(config),
        allow_local_file_remote: true,
    };

    // Validate an actual ordinary repository with the production capture path.
    // capture() performs no remote query; this time includes config and Git/fsck.
    let start = Instant::now();
    let snapshot =
        GitSnapshot::capture(&repo, "origin", "main", &options).expect("valid fixture snapshot");
    let capture_seconds = start.elapsed().as_secs_f64();
    let local_oid = snapshot.local_oid.clone();
    let capture_held_files = held_files(snapshot._temp.path()).expect("held snapshot accounting");
    drop(snapshot); // Do not retain two simultaneous object-store copies.

    let source = repo.join(".git");
    let destination = tempfile::tempdir().expect("owned copy scratch");
    let start = Instant::now();
    // The same four functions, in the same order as capture(), without setup,
    // Git/config parsing, network or fsck. Filtering/metadata checks are included.
    copy_primary_objects(&source.join("objects"), &destination.path().join("objects"))
        .expect("objects copy");
    copy_heads(
        &source.join("refs/heads"),
        &destination.path().join("refs/heads"),
    )
    .expect("heads copy");
    copy_packed_heads(
        &source.join("packed-refs"),
        &destination.path().join("packed-refs"),
    )
    .expect("packed heads copy");
    copy_optional_plain_file(&source.join("shallow"), &destination.path().join("shallow"))
        .expect("shallow copy");
    let copy_seconds = start.elapsed().as_secs_f64();
    // These functions create each included data file once and do not remove
    // it. For this immutable fixture the retained logical data count is exact;
    // this does NOT measure the physical peak of the entire CLI or filesystem.
    let copy_data = held_files(destination.path()).expect("copy data accounting");
    assert!(copy_data.regular_files > 0);
    assert!(capture_held_files.logical_file_bytes >= copy_data.logical_file_bytes);
    let report = serde_json::json!({
        "schema": 1, "local_oid": local_oid, "capture_seconds": capture_seconds,
        "copy_seconds": copy_seconds, "copy_data": copy_data,
        "capture_held_files": capture_held_files,
    });
    // libtest's progress prefix may precede the first captured stdout byte.
    // Keep the report on its own line; the driver rejects ambiguous reports.
    println!("\nAGENT_GUARD_COPY_BENCH_JSON={report}");
}
