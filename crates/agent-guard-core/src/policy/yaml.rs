//! One bounded, extension-free YAML profile for every PolicyEngine entry point.

use std::io::Read;
use std::path::Path;

use serde::Deserialize;
use serde_saphyr::{DuplicateKeyPolicy, MergeKeyPolicy, NonFiniteFloatPolicy};

use super::{PolicyError, PolicyFile};

mod value;

const MAX_POLICY_BYTES: usize = 1024 * 1024;

pub(super) fn parse(source: &str) -> Result<PolicyFile, PolicyError> {
    check_length(source.len())?;
    // A bounded generic value preserves wire types before the policy schema:
    // e.g. a quoted boolean cannot disable audit by being coerced into bool,
    // and a numeric rule selector cannot become an implicitly allowed string.
    // Check duplicates both as YAML nodes and as final string keys: distinct
    // YAML key spellings must not overwrite the same policy field/tool id.
    let value: value::PolicyValue = serde_saphyr::from_str_with_options(
        source,
        serde_saphyr::options! {
            strict_booleans: true,
            duplicate_keys: DuplicateKeyPolicy::Error,
            merge_keys: MergeKeyPolicy::Error,
            reject_unsupported_tags: true,
            ignore_binary_tag_for_string: true,
            non_finite_float_policy: NonFiniteFloatPolicy::Reject,
            with_snippet: false,
            alias_limits: serde_saphyr::alias_limits! {
                max_total_replayed_events: 8_192,
                max_replay_stack_depth: 16,
                max_alias_expansions_per_anchor: 64,
            },
            budget: serde_saphyr::budget! {
                max_reader_input_bytes: Some(MAX_POLICY_BYTES),
                max_documents: 1,
                max_depth: 64,
                flow_nesting_limit: 64,
                max_events: 32_768,
                max_nodes: 16_384,
                max_aliases: 64,
                max_anchors: 64,
                max_recorded_anchor_events: 8_192,
                max_recorded_anchor_bytes: 256 * 1024,
                max_total_scalar_bytes: MAX_POLICY_BYTES,
                max_merge_keys: 0,
                max_inclusion_depth: 0,
            },
        },
    )
    .map_err(|error| PolicyError::ParseError(error.to_string()))?;
    PolicyFile::deserialize(value.0).map_err(|error| PolicyError::ParseError(error.to_string()))
}

pub(super) fn read_file(path: &Path) -> Result<String, PolicyError> {
    let file =
        std::fs::File::open(path).map_err(|error| PolicyError::IoError(error.to_string()))?;
    let mut source = String::new();
    // Do not read an unbounded file and only then apply the string limit.
    // The extra byte detects overflow even if a file grows during the read.
    file.take((MAX_POLICY_BYTES + 1) as u64)
        .read_to_string(&mut source)
        .map_err(|error| PolicyError::IoError(error.to_string()))?;
    check_length(source.len())?;
    Ok(source)
}

fn check_length(bytes: usize) -> Result<(), PolicyError> {
    if bytes > MAX_POLICY_BYTES {
        return Err(PolicyError::ParseError(format!(
            "policy YAML exceeds the {MAX_POLICY_BYTES}-byte input limit"
        )));
    }
    Ok(())
}
