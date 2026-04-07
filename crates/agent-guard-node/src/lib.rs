#![deny(clippy::all)]

#[macro_use]
extern crate napi_derive;

use std::path::PathBuf;
use agent_guard_sdk::{Guard as RustGuard, Context as RustContext, Tool as RustTool, TrustLevel as RustTrustLevel, GuardDecision};
use napi::bindgen_prelude::*;

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
pub struct Decision {
    pub outcome: String,
    pub message: Option<String>,
    pub code: Option<String>,
    pub matched_rule: Option<String>,
    pub ask_prompt: Option<String>,
}

fn decision_from_rust(d: GuardDecision) -> Decision {
    match d {
        GuardDecision::Allow => Decision {
            outcome: "allow".to_string(),
            message: None,
            code: None,
            matched_rule: None,
            ask_prompt: None,
        },
        GuardDecision::Deny { reason } => Decision {
            outcome: "deny".to_string(),
            message: Some(reason.message),
            code: Some(format!("{:?}", reason.code)),
            matched_rule: reason.matched_rule,
            ask_prompt: None,
        },
        GuardDecision::AskUser { message, reason } => Decision {
            outcome: "ask_user".to_string(),
            message: Some(reason.message),
            code: Some(format!("{:?}", reason.code)),
            matched_rule: reason.matched_rule,
            ask_prompt: Some(message),
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

    #[napi]
    pub fn check(
        &self,
        tool: String,
        payload: String,
        options: Option<Context>,
    ) -> Result<Decision> {
        let rust_tool = parse_tool(&tool)?;
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

        let decision = self.inner.check_tool(rust_tool, payload, rust_ctx);
        Ok(decision_from_rust(decision))
    }

    #[napi]
    pub fn reload_from_yaml(&self, yaml: String) -> Result<()> {
        self.inner.reload_from_yaml(&yaml)
            .map_err(|e| Error::new(Status::GenericFailure, format!("{e}")))
    }

    #[napi]
    pub fn policy_version(&self) -> String {
        self.inner.policy_version()
    }

    #[napi]
    pub fn policy_hash(&self) -> String {
        self.inner.policy_version()
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn parse_tool(tool_str: &str) -> Result<RustTool> {
    use agent_guard_sdk::CustomToolId;
    match tool_str {
        "bash" => Ok(RustTool::Bash),
        "read_file" => Ok(RustTool::ReadFile),
        "write_file" => Ok(RustTool::WriteFile),
        "http_request" => Ok(RustTool::HttpRequest),
        other => {
            let id = CustomToolId::new(other)
                .map_err(|e| Error::new(Status::GenericFailure, format!("invalid tool id {other:?}: {e}")))?;
            Ok(RustTool::Custom(id))
        }
    }
}
