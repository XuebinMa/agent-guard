use std::collections::HashMap;
use std::path::Path;

use regex::Regex;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::decision::{DecisionCode, GuardDecision};
use crate::payload::{extract_path, extract_url, ExtractedPayload};
use crate::types::{Tool, TrustLevel};

// ── Policy schema ─────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
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
}

fn default_mode() -> PolicyMode {
    PolicyMode::ReadOnly
}

#[derive(Debug, Deserialize, Default)]
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

#[derive(Debug, Deserialize, Clone)]
#[serde(untagged)]
pub enum RulePattern {
    Map(RulePatternMap),
    Plain(String),
}

#[derive(Debug, Deserialize, Clone)]
pub struct RulePatternMap {
    pub prefix: Option<String>,
    pub regex: Option<String>,
}

#[derive(Debug, Deserialize, Clone, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum PolicyMode {
    #[default]
    ReadOnly,
    WorkspaceWrite,
    FullAccess,
}

#[derive(Debug, Deserialize, Default)]
pub struct TrustConfig {
    pub untrusted: Option<TrustOverride>,
    pub trusted: Option<TrustOverride>,
    // admin: bypass_deny_rules is intentionally NOT supported in Phase 1.
    // See roadmap: Phase 2/3 will introduce hard-deny vs soft-deny distinction.
}

#[derive(Debug, Deserialize, Default)]
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

pub struct PolicyEngine {
    policy: PolicyFile,
}

impl PolicyEngine {
    pub fn from_yaml_str(yaml: &str) -> Result<Self, PolicyError> {
        let policy: PolicyFile = serde_yaml::from_str(yaml)
            .map_err(|e| PolicyError::ParseError(e.to_string()))?;
        if policy.version != 1 {
            return Err(PolicyError::UnsupportedVersion(policy.version));
        }
        Ok(Self { policy })
    }

    pub fn from_yaml_file(path: impl AsRef<Path>) -> Result<Self, PolicyError> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| PolicyError::IoError(e.to_string()))?;
        Self::from_yaml_str(&content)
    }

    pub fn audit_config(&self) -> &AuditConfig {
        &self.policy.audit
    }

    pub fn check(&self, tool: &Tool, payload: &str, trust_level: &TrustLevel) -> GuardDecision {
        let effective_mode = self.effective_mode(tool, trust_level);
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
            // Bash and Custom tools: rules match against raw payload string.
            _ => ExtractedPayload::Raw(payload),
        };
        let match_value = extracted.match_value();

        if let Some(tp) = tool_policy {
            // deny rules — highest priority, always evaluated first.
            for (i, rule) in tp.deny.iter().enumerate() {
                if pattern_matches(rule, match_value) {
                    let rule_ref = format!("tools.{}.deny[{}]", tool_name, i);
                    return GuardDecision::deny_with_rule(
                        DecisionCode::DeniedByRule,
                        format!("payload matched deny rule: {}", pattern_display(rule)),
                        rule_ref,
                    );
                }
            }

            // deny_paths — evaluated before ask/allow so paths can't be bypassed.
            for (i, glob_pattern) in tp.deny_paths.iter().enumerate() {
                if path_glob_matches(glob_pattern, match_value) {
                    let rule_ref = format!("tools.{}.deny_paths[{}]", tool_name, i);
                    return GuardDecision::deny_with_rule(
                        DecisionCode::PathOutsideWorkspace,
                        format!("path matched deny_paths rule: {}", glob_pattern),
                        rule_ref,
                    );
                }
            }

            // ask rules.
            for (i, rule) in tp.ask.iter().enumerate() {
                if pattern_matches(rule, match_value) {
                    let rule_ref = format!("tools.{}.ask[{}]", tool_name, i);
                    return GuardDecision::ask_with_rule(
                        format!("Confirmation required: rule '{}' matched", pattern_display(rule)),
                        DecisionCode::AskRequired,
                        format!("ask rule matched: {}", pattern_display(rule)),
                        rule_ref,
                    );
                }
            }

            // A2: allow_paths as a positive allowlist.
            // If allow_paths is non-empty and the path doesn't match any entry → deny.
            if !tp.allow_paths.is_empty() {
                let in_allowlist = tp.allow_paths.iter().any(|p| path_glob_matches(p, match_value));
                if !in_allowlist {
                    return GuardDecision::deny(
                        DecisionCode::NotInAllowList,
                        format!(
                            "path '{}' is not in the configured allow_paths list",
                            match_value
                        ),
                    );
                }
            }

            // Explicit allow rules — short-circuit to Allow.
            for rule in tp.allow.iter() {
                if pattern_matches(rule, match_value) {
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
    pub fn effective_mode(&self, tool: &Tool, trust_level: &TrustLevel) -> PolicyMode {
        match trust_level {
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

fn pattern_matches(rule: &RulePattern, value: &str) -> bool {
    match rule {
        // Plain string: substring match (explicit, intentional — different from prefix:).
        RulePattern::Plain(s) => value.contains(s.as_str()),
        RulePattern::Map(m) => {
            if let Some(ref prefix) = m.prefix {
                // A3: strict prefix match only — trimmed to handle leading whitespace.
                // Use contains: in policy YAML if substring matching is desired.
                if value.trim_start().starts_with(prefix.as_str()) {
                    return true;
                }
            }
            if let Some(ref re_str) = m.regex {
                if let Ok(re) = Regex::new(re_str) {
                    if re.is_match(value) {
                        return true;
                    }
                }
            }
            false
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
            if let Some(ref p) = m.prefix {
                format!("prefix:{}", p)
            } else if let Some(ref r) = m.regex {
                format!("regex:{}", r)
            } else {
                "(empty rule)".to_string()
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
