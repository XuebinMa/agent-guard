#![deny(clippy::all)]

#[macro_use]
extern crate napi_derive;

use agent_guard_sdk::{
    Context as RustContext, ExecuteOutcome as RustExecuteOutcome, Guard as RustGuard,
    GuardDecision, GuardInput, Tool as RustTool, TrustLevel as RustTrustLevel,
};
use napi::bindgen_prelude::*;
use serde::Serialize;
use std::path::PathBuf;

// ── Enums ─────────────────────────────────────────────────────────────────────

#[napi(string_enum)]
pub enum TrustLevel {
    Untrusted,
    Trusted,
    Admin,
}

impl From<TrustLevel> for RustTrustLevel {
    fn from(t: TrustLevel) -> Self {
        match t {
            TrustLevel::Untrusted => RustTrustLevel::Untrusted,
            TrustLevel::Trusted => RustTrustLevel::Trusted,
            TrustLevel::Admin => RustTrustLevel::Admin,
        }
    }
}

// ── Decision ──────────────────────────────────────────────────────────────────

#[napi(object)]
#[derive(Serialize)]
pub struct Decision {
    pub outcome: String,
    pub message: Option<String>,
    pub code: Option<String>,
    pub matched_rule: Option<String>,
    pub ask_prompt: Option<String>,
    pub policy_version: String,
}

fn decision_from_rust(d: GuardDecision, policy_version: String) -> Decision {
    match d {
        GuardDecision::Allow => Decision {
            outcome: "allow".to_string(),
            message: None,
            code: None,
            matched_rule: None,
            ask_prompt: None,
            policy_version,
        },
        GuardDecision::Deny { reason } => Decision {
            outcome: "deny".to_string(),
            message: Some(reason.message),
            code: Some(format!("{:?}", reason.code)),
            matched_rule: reason.matched_rule,
            ask_prompt: None,
            policy_version,
        },
        GuardDecision::AskUser { message, reason } => Decision {
            outcome: "ask_user".to_string(),
            message: Some(reason.message),
            code: Some(format!("{:?}", reason.code)),
            matched_rule: reason.matched_rule,
            ask_prompt: Some(message),
            policy_version,
        },
    }
}

// ── Execution Outcome ─────────────────────────────────────────────────────────

#[napi(object)]
#[derive(Serialize)]
pub struct SandboxOutput {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
}

#[napi(object)]
#[derive(Serialize)]
pub struct ExecuteOutcome {
    pub status: String,
    pub output: Option<SandboxOutput>,
    pub decision: Option<Decision>,
    pub policy_version: String,
    pub sandbox_type: Option<String>,
    pub receipt: Option<String>, // JSON-encoded receipt
}

fn execute_outcome_from_rust(o: RustExecuteOutcome, sandbox_type: String) -> ExecuteOutcome {
    match o {
        RustExecuteOutcome::Executed {
            output,
            policy_version,
            receipt,
        } => ExecuteOutcome {
            status: "executed".to_string(),
            output: Some(SandboxOutput {
                exit_code: output.exit_code,
                stdout: output.stdout,
                stderr: output.stderr,
            }),
            decision: None,
            policy_version,
            sandbox_type: Some(sandbox_type),
            receipt: receipt.map(|r| serde_json::to_string(&r).unwrap_or_default()),
        },
        RustExecuteOutcome::Denied {
            decision,
            policy_version,
        } => ExecuteOutcome {
            status: "denied".to_string(),
            output: None,
            decision: Some(decision_from_rust(decision, policy_version.clone())),
            policy_version,
            sandbox_type: Some(sandbox_type),
            receipt: None,
        },
        RustExecuteOutcome::AskRequired {
            decision,
            policy_version,
        } => ExecuteOutcome {
            status: "ask_required".to_string(),
            output: None,
            decision: Some(decision_from_rust(decision, policy_version.clone())),
            policy_version,
            sandbox_type: Some(sandbox_type),
            receipt: None,
        },
    }
}

// ── Context ───────────────────────────────────────────────────────────────────

#[napi(object)]
pub struct Context {
    pub trust_level: Option<TrustLevel>,
    pub agent_id: Option<String>,
    pub session_id: Option<String>,
    pub actor: Option<String>,
    pub working_directory: Option<String>,
}

// ── Guard ─────────────────────────────────────────────────────────────────────

#[napi(js_name = "Guard")]
pub struct Guard {
    inner: RustGuard,
}

#[napi]
impl Guard {
    #[napi(factory)]
    pub fn from_yaml(yaml: String) -> Result<Guard> {
        let inner = RustGuard::from_yaml(&yaml)
            .map_err(|e| Error::new(Status::GenericFailure, format!("{e}")))?;
        Ok(Guard { inner })
    }

    #[napi(factory)]
    pub fn from_yaml_file(path: String) -> Result<Guard> {
        let inner = RustGuard::from_yaml_file(path)
            .map_err(|e| Error::new(Status::GenericFailure, format!("{e}")))?;
        Ok(Guard { inner })
    }

    /// Set the Ed25519 signing key for provenance receipts.
    /// The key must be a 32-byte hex-encoded string.
    #[napi]
    pub fn set_signing_key(&self, hex_key: String) -> Result<()> {
        use ed25519_dalek::SigningKey;
        let bytes = hex::decode(hex_key)
            .map_err(|e| Error::new(Status::GenericFailure, format!("Invalid hex key: {e}")))?;
        let key_array: [u8; 32] = bytes.try_into().map_err(|_| {
            Error::new(
                Status::GenericFailure,
                "Key must be exactly 32 bytes".to_string(),
            )
        })?;
        let signing_key = SigningKey::from_bytes(&key_array);
        self.inner.with_signing_key(signing_key);
        Ok(())
    }

    #[napi]
    pub fn check(
        &self,
        tool: String,
        payload: String,
        options: Option<Context>,
    ) -> Result<Decision> {
        let normalized_payload = normalize_payload(tool.clone(), payload);
        let rust_tool = parse_tool(&tool)?;
        let rust_ctx = context_from_node(options);

        let decision = self
            .inner
            .check_tool(rust_tool, normalized_payload, rust_ctx);
        Ok(decision_from_rust(decision, self.inner.policy_version()))
    }

    /// High-level execution method.
    /// Uses the default sandbox implementation.
    #[napi]
    pub async fn execute(
        &self,
        tool: String,
        payload: String,
        options: Option<Context>,
    ) -> Result<ExecuteOutcome> {
        let normalized_payload = normalize_payload(tool.clone(), payload);
        let rust_tool = parse_tool(&tool)?;
        let rust_ctx = context_from_node(options);

        let input = GuardInput {
            tool: rust_tool,
            payload: normalized_payload,
            context: rust_ctx,
        };

        let sandbox = RustGuard::default_sandbox();
        let sandbox_type = sandbox.sandbox_type().to_string();

        let result = self
            .inner
            .execute(&input, sandbox.as_ref())
            .map_err(|e| Error::new(Status::GenericFailure, format!("execution error: {e}")))?;

        Ok(execute_outcome_from_rust(result, sandbox_type))
    }

    #[napi]
    pub fn reload(&self, yaml: String) -> Result<()> {
        self.reload_from_yaml(yaml)
    }

    #[napi]
    pub fn reload_from_yaml(&self, yaml: String) -> Result<()> {
        self.inner
            .reload_from_yaml(&yaml)
            .map_err(|e| Error::new(Status::GenericFailure, format!("{e}")))
    }

    #[napi]
    pub fn policy_version(&self) -> String {
        self.inner.policy_version()
    }

    #[napi]
    pub fn policy_hash(&self) -> String {
        self.inner.policy_hash()
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn context_from_node(options: Option<Context>) -> RustContext {
    let mut rust_ctx = RustContext::default();
    if let Some(opts) = options {
        if let Some(tl) = opts.trust_level {
            rust_ctx.trust_level = tl.into();
        }
        rust_ctx.agent_id = opts.agent_id;
        rust_ctx.session_id = opts.session_id;
        rust_ctx.actor = opts.actor;
        rust_ctx.working_directory = opts.working_directory.map(PathBuf::from);
    }
    rust_ctx
}

fn parse_tool(tool_str: &str) -> Result<RustTool> {
    use agent_guard_sdk::CustomToolId;
    match tool_str {
        "bash" => Ok(RustTool::Bash),
        "read_file" => Ok(RustTool::ReadFile),
        "write_file" => Ok(RustTool::WriteFile),
        "http_request" => Ok(RustTool::HttpRequest),
        other => {
            let id = CustomToolId::new(other).map_err(|e| {
                Error::new(
                    Status::GenericFailure,
                    format!("invalid tool id {other:?}: {e}"),
                )
            })?;
            Ok(RustTool::Custom(id))
        }
    }
}

// ── Payload Normalization ─────────────────────────────────────────────────────

/// Normalize a raw input string into the payload format expected by the guard.
/// Shell tools (bash, shell, terminal) are wrapped as {"command": "..."}.
/// Other string inputs are wrapped as {"input": "..."}.
#[napi]
pub fn normalize_payload(tool: String, raw_input: String) -> String {
    let shell_tools = ["bash", "shell", "terminal"];
    if shell_tools.contains(&tool.as_str()) {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&raw_input) {
            if v.get("command").is_some() {
                return raw_input;
            }
        }
        return serde_json::json!({"command": raw_input}).to_string();
    }
    if serde_json::from_str::<serde_json::Value>(&raw_input).is_ok() {
        return raw_input;
    }
    serde_json::json!({"input": raw_input}).to_string()
}

// ── Receipt Verification ──────────────────────────────────────────────────────

/// Verify an Ed25519-signed execution receipt.
/// receipt_json: JSON string of the ExecutionReceipt.
/// public_key_hex: 64 hex chars (32 bytes) of the Ed25519 public key.
#[napi]
pub fn verify_receipt(receipt_json: String, public_key_hex: String) -> Result<bool> {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    #[derive(serde::Deserialize)]
    struct Receipt {
        receipt_version: String,
        agent_id: String,
        tool: String,
        policy_version: String,
        sandbox_type: String,
        decision: String,
        command_hash: String,
        timestamp: u64,
        signature: String,
    }

    let receipt: Receipt = serde_json::from_str(&receipt_json)
        .map_err(|e| Error::new(Status::InvalidArg, format!("invalid receipt JSON: {e}")))?;

    let key_bytes = hex::decode(&public_key_hex)
        .map_err(|e| Error::new(Status::InvalidArg, format!("invalid public key hex: {e}")))?;
    let key_array: [u8; 32] = key_bytes.try_into().map_err(|_| {
        Error::new(
            Status::InvalidArg,
            "public key must be 32 bytes (64 hex chars)",
        )
    })?;

    let Ok(verifying_key) = VerifyingKey::from_bytes(&key_array) else {
        return Ok(false);
    };

    let payload = format!(
        "{}:{}:{}:{}:{}:{}:{}:{}",
        receipt.receipt_version,
        receipt.agent_id,
        receipt.tool,
        receipt.policy_version,
        receipt.sandbox_type,
        receipt.decision,
        receipt.command_hash,
        receipt.timestamp,
    );

    let Ok(sig_bytes) = hex::decode(&receipt.signature) else {
        return Ok(false);
    };
    let Ok(signature) = Signature::from_slice(&sig_bytes) else {
        return Ok(false);
    };

    Ok(verifying_key.verify(payload.as_bytes(), &signature).is_ok())
}

#[cfg(test)]
mod tests {
    use super::normalize_payload;

    #[test]
    fn normalize_payload_wraps_shell_strings() {
        assert_eq!(
            normalize_payload("bash".to_string(), "ls -la".to_string()),
            r#"{"command":"ls -la"}"#
        );
    }

    #[test]
    fn normalize_payload_preserves_existing_shell_objects() {
        let payload = r#"{"command":"ls -la"}"#.to_string();
        assert_eq!(
            normalize_payload("bash".to_string(), payload.clone()),
            payload
        );
    }

    #[test]
    fn normalize_payload_wraps_generic_scalars() {
        assert_eq!(
            normalize_payload("read_file".to_string(), "/tmp/demo.txt".to_string()),
            r#"{"input":"/tmp/demo.txt"}"#
        );
    }
}
