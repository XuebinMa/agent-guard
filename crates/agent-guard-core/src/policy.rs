use std::collections::HashMap;
use std::path::Path;

use evalexpr::{context_map, Node};
use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::decision::{DecisionCode, GuardDecision, DecisionReason};
use crate::payload::{extract_bash_command, extract_path, extract_url, ExtractedPayload};
use crate::types::{Context, Tool, TrustLevel};

// ── M3.1: Context-aware Condition ─────────────────────────────────────────────

const CONDITION_WHITELIST: &[&str] = &[
    "actor",
    "agent_id",
    "session_id",
    "trust_level",
    "tool",
    "working_directory",
];

#[derive(Debug, Clone)]
pub struct Condition {
    pub raw: String,
    pub node: Node,
}

impl<'de> serde::Deserialize<'de> for Condition {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let node = evalexpr::build_operator_tree(&s).map_err(serde::de::Error::custom)?;

        // Validate whitelist and no functions (AOT validation)
        for func in node.iter_function_identifiers() {
            return Err(serde::de::Error::custom(format!(
                "Function calls are not allowed in conditions: {}",
                func
            )));
        }
        for var in node.iter_variable_identifiers() {
            if !CONDITION_WHITELIST.contains(&var.as_ref()) {
                return Err(serde::de::Error::custom(format!(
                    "Unknown variable in condition: {}",
                    var
                )));
            }
        }

        Ok(Condition { raw: s, node })
    }
}

impl Condition {
    pub fn evaluate(&self, tool: &Tool, context: &Context) -> bool {
        let eval_ctx = context_map! {
            "actor" => context.actor.as_deref().unwrap_or(""),
            "agent_id" => context.agent_id.as_deref().unwrap_or(""),
            "session_id" => context.session_id.as_deref().unwrap_or(""),
            "trust_level" => trust_level_str(&context.trust_level),
            "tool" => tool.name(),
            "working_directory" => context.working_directory.as_ref().and_then(|p| p.to_str()).unwrap_or(""),
        };

        if let Ok(ctx) = eval_ctx {
            self.node.eval_boolean_with_context(&ctx).unwrap_or(false)
        } else {
            false
        }
    }
}

// ── Policy schema ─────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, Clone)]
pub struct PolicyFile {
    pub version: u32,
    #[serde(default = "default_mode")]
    pub default_mode: PolicyMode,
    #[serde(default)]
    pub tools: ToolsConfig,
    #[serde(default)]
    pub trust: TrustConfig,
    #[serde(default)]
    pub audit: AuditConfig,
    #[serde(default)]
    pub anomaly: AnomalyConfig,
}

#[derive(Debug, Deserialize, Clone)]
pub struct AnomalyConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub rate_limit: RateLimitConfig,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Deserialize, Clone)]
pub struct RateLimitConfig {
    #[serde(default = "default_window")]
    pub window_seconds: u64,
    #[serde(default = "default_max_calls")]
    pub max_calls: usize,
}

fn default_window() -> u64 {
    60
}
fn default_max_calls() -> usize {
    30
}

impl Default for AnomalyConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            rate_limit: RateLimitConfig::default(),
        }
    }
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            window_seconds: 60,
            max_calls: 30,
        }
    }
}

fn default_mode() -> PolicyMode {
    PolicyMode::ReadOnly
}

#[derive(Debug, Deserialize, Default, Clone)]
pub struct ToolsConfig {
    pub bash: Option<ToolPolicy>,
    pub read_file: Option<ToolPolicy>,
    pub write_file: Option<ToolPolicy>,
    pub http_request: Option<ToolPolicy>,
    /// Custom tool policies, keyed by CustomToolId string (e.g. "acme.sql.query").
    /// Parsed separately from builtin tools to maintain clear boundaries.
    #[serde(default)]
    pub custom: HashMap<String, ToolPolicy>,
}

#[derive(Debug, Deserialize, Default, Clone)]
pub struct ToolPolicy {
    pub mode: Option<PolicyMode>,
    #[serde(default)]
    pub deny: Vec<RulePattern>,
    #[serde(default)]
    pub allow: Vec<RulePattern>,
    #[serde(default)]
    pub ask: Vec<RulePattern>,
    #[serde(default)]
    pub allow_paths: Vec<String>,
    #[serde(default)]
    pub deny_paths: Vec<String>,
}

#[derive(Debug, Clone)]
pub enum RulePattern {
    Map(RulePatternMap),
    Plain(String),
}

impl<'de> serde::Deserialize<'de> for RulePattern {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error;
        let value = serde_yaml::Value::deserialize(deserializer)?;
        if let Some(s) = value.as_str() {
            Ok(RulePattern::Plain(s.to_string()))
        } else if value.is_mapping() {
            RulePatternMap::deserialize(value)
                .map(RulePattern::Map)
                .map_err(|e| D::Error::custom(e.to_string()))
        } else {
            Err(D::Error::custom("expected string or map for RulePattern"))
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct RulePatternMap {
    pub prefix: Option<String>,
    pub regex: Option<String>,
    pub plain: Option<String>,
    #[serde(rename = "if")]
    pub condition: Option<Condition>,
}

#[derive(Debug, Deserialize, Clone, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum PolicyMode {
    #[default]
    ReadOnly,
    WorkspaceWrite,
    FullAccess,
}

#[derive(Debug, Deserialize, Default, Clone)]
pub struct TrustConfig {
    pub untrusted: Option<TrustOverride>,
    pub trusted: Option<TrustOverride>,
    // admin: bypass_deny_rules is intentionally NOT supported in Phase 1.
    // See roadmap: Phase 2/3 will introduce hard-deny vs soft-deny distinction.
    pub admin: Option<TrustOverride>,
}

#[derive(Debug, Deserialize, Default, Clone)]
pub struct TrustOverride {
    pub override_mode: Option<PolicyMode>,
}

#[derive(Debug, Deserialize, Default, Clone, Serialize)]
pub struct AuditConfig {
    #[serde(default = "audit_enabled_default")]
    pub enabled: bool,
    #[serde(default = "audit_output_default")]
    pub output: String,
    pub file_path: Option<String>,
    #[serde(default = "audit_hash_default")]
    pub include_payload_hash: bool,
}

fn audit_enabled_default() -> bool { true }
fn audit_output_default() -> String { "stdout".to_string() }
fn audit_hash_default() -> bool { true }

// ── PolicyEngine ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct PolicyEngine {
    policy: PolicyFile,
    hash: String,
}

impl PolicyEngine {
    pub fn from_yaml_str(yaml: &str) -> Result<Self, PolicyError> {
        let policy: PolicyFile = serde_yaml::from_str(yaml)
            .map_err(|e| PolicyError::ParseError(e.to_string()))?;
        if policy.version != 1 {
            return Err(PolicyError::UnsupportedVersion(policy.version));
        }

        let mut hasher = Sha256::new();
        hasher.update(yaml.as_bytes());
        let hash = hex::encode(hasher.finalize());

        Ok(Self { policy, hash })
    }

    pub fn from_yaml_file(path: impl AsRef<Path>) -> Result<Self, PolicyError> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| PolicyError::IoError(e.to_string()))?;
        Self::from_yaml_str(&content)
    }

    pub fn version(&self) -> &str {
        &self.hash
    }

    pub fn hash(&self) -> &str {
        &self.hash
    }

    pub fn audit_config(&self) -> &AuditConfig {
        &self.policy.audit
    }

    pub fn anomaly_config(&self) -> &AnomalyConfig {
        &self.policy.anomaly
    }

    pub fn check(&self, tool: &Tool, payload: &str, context: &Context) -> GuardDecision {
        tracing::debug!(
            tool = tool.name(),
            actor = context.actor.as_deref().unwrap_or("unknown"),
            "PolicyEngine::check"
        );
        let trust_level = &context.trust_level;
        let effective_mode = self.effective_mode(tool, context);
        let tool_policy = self.tool_policy(tool);
        let tool_name = tool.name();

        // Untrusted override: if effective_mode is read_only but the resolved tool mode
        // (tool-level or default) is higher, block the call entirely.
        if effective_mode == PolicyMode::ReadOnly {
            let tool_mode = tool_policy
                .as_ref()
                .and_then(|tp| tp.mode.clone())
                .unwrap_or_else(|| self.policy.default_mode.clone());

            if tool_mode == PolicyMode::WorkspaceWrite || tool_mode == PolicyMode::FullAccess {
                return GuardDecision::deny(
                    DecisionCode::InsufficientPermissionMode,
                    format!(
                        "trust level '{}' does not permit tool '{}' which requires '{:?}' mode",
                        trust_level_str(trust_level),
                        tool_name,
                        tool_mode
                    ),
                );
            }
        }

        // A1: extract structured payload for tools that require it.
        // For ReadFile/WriteFile we need the path; for HttpRequest we need the url.
        // Extraction failure is a hard deny — we never fall back to matching raw JSON.
        let extracted = match tool {
            Tool::ReadFile | Tool::WriteFile => {
                match extract_path(payload) {
                    Ok(ep) => ep,
                    Err(deny) => return deny,
                }
            }
            Tool::HttpRequest => {
                match extract_url(payload) {
                    Ok(ep) => ep,
                    Err(deny) => return deny,
                }
            }
            Tool::Bash => {
                match extract_bash_command(payload) {
                    Ok(ep) => ep,
                    Err(deny) => return deny,
                }
            }
            // Custom tools: rules match against raw payload string.
            _ => ExtractedPayload::Raw(payload),
        };
        let match_value = extracted.match_value();

        if let Some(tp) = tool_policy {
            // deny rules — highest priority, always evaluated first.
            for (i, rule) in tp.deny.iter().enumerate() {
                let res = pattern_matches(rule, match_value, tool, context);
                if res.matched {
                    let rule_ref = format!("tools.{}.deny[{}]", tool_name, i);
                    let mut reason = DecisionReason::new(
                        DecisionCode::DeniedByRule,
                        format!("payload matched deny rule: {}", pattern_display(rule)),
                    )
                    .matched_rule(rule_ref);

                    if let Some(cond) = res.condition {
                        reason = reason.with_condition(cond);
                    }
                    return GuardDecision::Deny { reason };
                }
            }

            // deny_paths — evaluated before ask/allow so paths can't be bypassed.
            for (i, glob_pattern) in tp.deny_paths.iter().enumerate() {
                if path_glob_matches(glob_pattern, match_value) {
                    let rule_ref = format!("tools.{}.deny_paths[{}]", tool_name, i);
                    let reason = DecisionReason::new(
                        DecisionCode::PathOutsideWorkspace,
                        format!("path matched deny_paths rule: {}", glob_pattern),
                    )
                    .matched_rule(rule_ref);
                    return GuardDecision::Deny { reason };
                }
            }

            // ask rules.
            for (i, rule) in tp.ask.iter().enumerate() {
                let res = pattern_matches(rule, match_value, tool, context);
                if res.matched {
                    let rule_ref = format!("tools.{}.ask[{}]", tool_name, i);
                    let mut reason = DecisionReason::new(
                        DecisionCode::AskRequired,
                        format!("ask rule matched: {}", pattern_display(rule)),
                    )
                    .matched_rule(rule_ref);

                    if let Some(cond) = res.condition {
                        reason = reason.with_condition(cond);
                    }
                    return GuardDecision::AskUser {
                        message: format!(
                            "Confirmation required: rule '{}' matched",
                            pattern_display(rule)
                        ),
                        reason,
                    };
                }
            }

            // A2: allow_paths as a positive allowlist.
            // If allow_paths is non-empty and the path doesn't match any entry → deny.
            if !tp.allow_paths.is_empty() {
                let in_allowlist = tp.allow_paths
                    .iter()
                    .any(|p| path_glob_matches(p, match_value));
                if !in_allowlist {
                    let reason = DecisionReason::new(
                        DecisionCode::NotInAllowList,
                        format!(
                            "path '{}' is not in the configured allow_paths list",
                            match_value
                        ),
                    );
                    return GuardDecision::Deny { reason };
                }
            }

            // Explicit allow rules — short-circuit to Allow.
            for rule in tp.allow.iter() {
                if pattern_matches(rule, match_value, tool, context).matched {
                    return GuardDecision::Allow;
                }
            }
        }

        GuardDecision::Allow
    }

    /// Returns the effective `PolicyMode` for a given tool and trust level.
    ///
    /// This is the single source of truth for mode resolution — callers (e.g. the bash
    /// validator in the SDK layer) must use this instead of deriving mode from trust_level
    /// alone, so that tool-level `mode:` overrides in policy YAML are respected.
    pub fn effective_mode(&self, tool: &Tool, context: &Context) -> PolicyMode {
        match context.trust_level {
            TrustLevel::Untrusted => self
                .policy
                .trust
                .untrusted
                .as_ref()
                .and_then(|t| t.override_mode.clone())
                .unwrap_or_else(|| self.policy.default_mode.clone()),
            TrustLevel::Trusted | TrustLevel::Admin => self
                .tool_policy(tool)
                .and_then(|tp| tp.mode.clone())
                .unwrap_or_else(|| self.policy.default_mode.clone()),
        }
    }

    fn tool_policy(&self, tool: &Tool) -> Option<ToolPolicy> {
        match tool {
            Tool::Bash => self.policy.tools.bash.clone(),
            Tool::ReadFile => self.policy.tools.read_file.clone(),
            Tool::WriteFile => self.policy.tools.write_file.clone(),
            Tool::HttpRequest => self.policy.tools.http_request.clone(),
            // Custom tools are resolved from the separate custom map
            Tool::Custom(id) => self.policy.tools.custom.get(id.as_str()).cloned(),
        }
    }
}

// ── Pattern matching helpers ──────────────────────────────────────────────────

#[derive(Debug, Default)]
struct MatchResult {
    matched: bool,
    condition: Option<String>,
}

fn pattern_matches(rule: &RulePattern, value: &str, tool: &Tool, context: &Context) -> MatchResult {
    match rule {
        // Plain string: substring match (explicit, intentional — different from prefix:).
        RulePattern::Plain(s) => MatchResult {
            matched: value.contains(s.as_str()),
            condition: None,
        },
        RulePattern::Map(m) => {
            let mut result = MatchResult {
                matched: false,
                condition: m.condition.as_ref().map(|c| c.raw.clone()),
            };

            // First check condition if present.
            if let Some(ref condition) = m.condition {
                if !condition.evaluate(tool, context) {
                    return MatchResult {
                        matched: false,
                        condition: None,
                    };
                }
            }

            // If condition passed (or was absent), check the pattern.
            if let Some(ref prefix) = m.prefix {
                if value.trim_start().starts_with(prefix.as_str()) {
                    result.matched = true;
                    return result;
                }
            }
            if let Some(ref re_str) = m.regex {
                if let Ok(re) = Regex::new(re_str) {
                    if re.is_match(value) {
                        result.matched = true;
                        return result;
                    }
                }
            }
            if let Some(ref plain) = m.plain {
                if value.contains(plain.as_str()) {
                    result.matched = true;
                    return result;
                }
            }

            // If no pattern fields are present but there's a condition,
            // then the condition itself is the rule.
            if m.prefix.is_none() && m.regex.is_none() && m.plain.is_none() {
                result.matched = true;
            }
            result
        }
    }
}

fn path_glob_matches(pattern: &str, value: &str) -> bool {
    if let Ok(matcher) = glob::Pattern::new(pattern) {
        // Match both the exact string and with glob options for path separators.
        return matcher.matches(value)
            || matcher.matches_with(value, glob::MatchOptions {
                case_sensitive: true,
                require_literal_separator: false,
                require_literal_leading_dot: false,
            });
    }
    false
}

fn pattern_display(rule: &RulePattern) -> String {
    match rule {
        RulePattern::Plain(s) => s.clone(),
        RulePattern::Map(m) => {
            let mut parts = Vec::new();
            if let Some(ref p) = m.prefix {
                parts.push(format!("prefix:{}", p));
            }
            if let Some(ref r) = m.regex {
                parts.push(format!("regex:{}", r));
            }
            if let Some(ref p) = m.plain {
                parts.push(format!("plain:{}", p));
            }
            if let Some(ref c) = m.condition {
                parts.push(format!("if:{}", c.raw));
            }
            if parts.is_empty() {
                "(empty rule)".to_string()
            } else {
                parts.join(", ")
            }
        }
    }
}

fn trust_level_str(level: &TrustLevel) -> &'static str {
    match level {
        TrustLevel::Untrusted => "untrusted",
        TrustLevel::Trusted => "trusted",
        TrustLevel::Admin => "admin",
    }
}

// ── PolicyError ───────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("failed to parse policy YAML: {0}")]
    ParseError(String),
    #[error("unsupported policy version {0} (only version 1 is supported)")]
    UnsupportedVersion(u32),
    #[error("IO error reading policy file: {0}")]
    IoError(String),
}
