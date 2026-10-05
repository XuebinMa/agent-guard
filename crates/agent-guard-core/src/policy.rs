use std::collections::HashMap;
use std::path::Path;
use std::time::{Duration, Instant};

use evalexpr::{context_map, Node};
use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::decision::{DecisionCode, DecisionReason, GuardDecision};
use crate::file_paths::{resolve_path_glob_pattern, resolve_tool_path};
use crate::payload::{extract_bash_command, extract_http_request, extract_path, ExtractedPayload};
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
        if let Some(func) = node.iter_function_identifiers().next() {
            return Err(serde::de::Error::custom(format!(
                "Function calls are not allowed in conditions: {}",
                func
            )));
        }
        for var in node.iter_variable_identifiers() {
            if !CONDITION_WHITELIST.contains(&var) {
                return Err(serde::de::Error::custom(format!(
                    "Unknown variable in condition: {}",
                    var
                )));
            }
        }

        // Every supported condition variable is a string at runtime. Evaluate
        // once with representative string values while loading the policy so
        // operand type errors (for example, `trust_level > 3`) and expressions
        // that do not produce a boolean cannot silently disable a rule later.
        let validation_context = context_map! {
            "actor" => "actor",
            "agent_id" => "agent-id",
            "session_id" => "session-id",
            "trust_level" => "trusted",
            "tool" => "bash",
            "working_directory" => "/workspace",
        }
        .map_err(|e| {
            serde::de::Error::custom(format!(
                "condition type validation failed while building its context: {e}"
            ))
        })?;
        node.eval_boolean_with_context(&validation_context)
            .map_err(|e| {
                serde::de::Error::custom(format!(
                    "condition type validation failed: expression must evaluate to a boolean with string operands: {e}"
                ))
            })?;

        Ok(Condition { raw: s, node })
    }
}

#[derive(Debug, Error)]
pub enum ConditionEvaluationError {
    #[error("failed to construct the condition context: {0}")]
    Context(String),
    #[error("condition evaluation failed: {0}")]
    Evaluation(String),
}

impl Condition {
    pub fn evaluate(
        &self,
        tool: &Tool,
        context: &Context,
    ) -> Result<bool, ConditionEvaluationError> {
        let eval_ctx = context_map! {
            "actor" => context.actor.as_deref().unwrap_or(""),
            "agent_id" => context.agent_id.as_deref().unwrap_or(""),
            "session_id" => context.session_id.as_deref().unwrap_or(""),
            "trust_level" => trust_level_str(&context.trust_level),
            "tool" => tool.name(),
            "working_directory" => context.working_directory.as_ref().and_then(|p| p.to_str()).unwrap_or(""),
        }
        .map_err(|e| ConditionEvaluationError::Context(e.to_string()))?;

        self.node
            .eval_boolean_with_context(&eval_ctx)
            .map_err(|e| ConditionEvaluationError::Evaluation(e.to_string()))
    }
}

// ── Policy schema ─────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
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
    /// Content policy for host-supplied input text (e.g. prompts scanned via
    /// `Guard::check_content` before they reach an LLM provider). Top-level
    /// because an input is not a tool call; same `mode`/`detect` shape as the
    /// per-tool `content:` blocks. Parses on every build; enforced only when
    /// the runtime is compiled with the `content` feature.
    #[serde(default)]
    pub input_content: Option<ContentPolicy>,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct AnomalyConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub rate_limit: RateLimitConfig,
    #[serde(default)]
    pub deny_fuse: DenyFuseConfig,
}

/// Maximum number of observations retained per anomaly subject.
///
/// A rate limit needs one more witness than `max_calls` to prove it fired,
/// while a deny fuse needs exactly `threshold` witnesses. Policy loading keeps
/// both values within this shared bound so neither decision can be disabled by
/// history truncation in the SDK.
pub const MAX_RETAINED_ANOMALY_OBSERVATIONS: usize = 1001;

impl Default for AnomalyConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            rate_limit: RateLimitConfig::default(),
            deny_fuse: DenyFuseConfig::default(),
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct DenyFuseConfig {
    #[serde(default = "default_false")]
    pub enabled: bool,
    #[serde(default = "default_fuse_threshold")]
    pub threshold: usize,
    #[serde(default = "default_window")]
    pub window_seconds: u64,
}

impl Default for DenyFuseConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            threshold: 5,
            window_seconds: 60,
        }
    }
}

fn default_false() -> bool {
    false
}
fn default_fuse_threshold() -> usize {
    5
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct RateLimitConfig {
    #[serde(default = "default_window")]
    pub window_seconds: u64,
    #[serde(default = "default_max_calls")]
    pub max_calls: usize,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            window_seconds: 60,
            max_calls: 30,
        }
    }
}

fn default_window() -> u64 {
    60
}
fn default_max_calls() -> usize {
    30
}

fn default_mode() -> PolicyMode {
    PolicyMode::ReadOnly
}

#[derive(Debug, Deserialize, Default, Clone)]
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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
    /// Path globs that are permitted to fall outside `context.working_directory`.
    /// When a tool path matches one of these, the workspace-bound check in
    /// `resolve_tool_path` is skipped and the path proceeds to the normal
    /// `deny` / `deny_paths` / `ask` / `allow` evaluation. Empty list = old
    /// behaviour (workspace bound is always enforced).
    ///
    /// The waiver is for the location the glob names, not for whatever a path
    /// under it points at: an entry is matched against the path as written and
    /// again against the resolved path, so a symlink leading out of the listed
    /// location is held to the workspace bound like any other path. Bash
    /// targets are governed by the validator's own lexical copy of this list,
    /// which resolves nothing and so makes no such guarantee.
    #[serde(default)]
    pub workspace_escape_paths: Vec<String>,
    /// Optional content-layer policy (S6-4): scan this tool's text payload for
    /// secrets / PII and act per [`ContentPolicy::mode`]. `None` = disabled,
    /// which preserves pre-S6-4 behaviour. The schema always parses; whether it
    /// is enforced depends on the SDK being built with the `content` feature.
    #[serde(default)]
    pub content: Option<ContentPolicy>,
}

/// Per-tool content-layer policy (S6-4).
#[derive(Debug, Deserialize, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ContentPolicy {
    pub mode: ContentMode,
    /// Which detectors to run. Defaults to all of them.
    #[serde(default = "default_content_detectors")]
    pub detect: Vec<ContentDetector>,
}

/// What to do when a content detector matches. Mirrors the validator-side
/// redaction modes, but defined here so `core` does not depend on `validators`.
#[derive(Debug, Deserialize, Serialize, Clone, Copy, PartialEq, Eq)]
pub enum ContentMode {
    #[serde(rename = "block")]
    Block,
    #[serde(rename = "mask")]
    Mask,
    #[serde(rename = "warn")]
    Warn,
}

/// Which content detector to apply.
#[derive(Debug, Deserialize, Serialize, Clone, Copy, PartialEq, Eq)]
pub enum ContentDetector {
    #[serde(rename = "secrets")]
    Secrets,
    #[serde(rename = "pii")]
    Pii,
}

fn default_content_detectors() -> Vec<ContentDetector> {
    vec![ContentDetector::Secrets, ContentDetector::Pii]
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
#[serde(deny_unknown_fields)]
pub struct RulePatternMap {
    pub prefix: Option<String>,
    pub regex: Option<String>,
    pub plain: Option<String>,
    /// HTTP method constraint (e.g. `POST`). When set, the rule only applies to
    /// an `HttpRequest` whose method matches (case-insensitive), and never
    /// matches a tool that carries no method. `None` keeps the pre-existing,
    /// method-agnostic (URL-only) behavior.
    pub method: Option<String>,
    #[serde(rename = "if")]
    pub condition: Option<Condition>,
}

// Variants are declared in increasing-permissiveness order so the derived
// `Ord` is a meaningful permissiveness comparison
// (`Blocked < ReadOnly < WorkspaceWrite < FullAccess`). Serde uses the explicit
// `rename` strings, so reordering is wire-compatible.
#[derive(Debug, Deserialize, Clone, PartialEq, Eq, PartialOrd, Ord, Default, Serialize)]
pub enum PolicyMode {
    #[serde(rename = "blocked")]
    Blocked,
    #[default]
    #[serde(rename = "read_only")]
    ReadOnly,
    #[serde(rename = "workspace_write")]
    WorkspaceWrite,
    #[serde(rename = "full_access")]
    FullAccess,
}

#[derive(Debug, Deserialize, Default, Clone)]
#[serde(deny_unknown_fields)]
pub struct TrustConfig {
    pub untrusted: Option<TrustOverride>,
    pub trusted: Option<TrustOverride>,
    pub admin: Option<TrustOverride>,
}

#[derive(Debug, Deserialize, Default, Clone)]
#[serde(deny_unknown_fields)]
pub struct TrustOverride {
    pub override_mode: Option<PolicyMode>,
}

#[derive(Debug, Deserialize, Clone, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuditConfig {
    #[serde(default = "audit_enabled_default")]
    pub enabled: bool,
    #[serde(default = "audit_output_default")]
    pub output: String,
    pub file_path: Option<String>,
    #[serde(default = "audit_hash_default")]
    pub include_payload_hash: bool,
    pub webhook_url: Option<String>,
    pub otlp_endpoint: Option<String>,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            // Preserve the historical behavior that omitting the entire audit
            // block disables audit, while keeping `output` in a valid state.
            enabled: false,
            output: audit_output_default(),
            file_path: None,
            include_payload_hash: false,
            webhook_url: None,
            otlp_endpoint: None,
        }
    }
}

fn audit_enabled_default() -> bool {
    true
}
fn audit_output_default() -> String {
    "stdout".to_string()
}
fn audit_hash_default() -> bool {
    true
}

// ── Compiled rule shapes ──────────────────────────────────────────────────────
//
// `RulePattern` / `RulePatternMap` mirror the YAML schema and only hold the
// regex source string. To avoid recompiling regex on every check, we build a
// parallel `CompiledRulePattern` graph at load time that owns a `regex::Regex`
// next to the originating rule. The YAML structs are kept intact so the schema
// surface and deserialization path don't change.

#[derive(Debug, Clone)]
enum CompiledRulePattern {
    Plain(String),
    Map(CompiledRulePatternMap),
}

#[derive(Debug, Clone)]
struct CompiledRulePatternMap {
    prefix: Option<String>,
    regex_src: Option<String>,
    regex: Option<Regex>,
    plain: Option<String>,
    method: Option<String>,
    condition: Option<Condition>,
}

#[derive(Debug, Clone, Default)]
struct CompiledToolPolicy {
    deny: Vec<CompiledRulePattern>,
    allow: Vec<CompiledRulePattern>,
    ask: Vec<CompiledRulePattern>,
}

#[derive(Debug, Clone, Default)]
struct CompiledTools {
    bash: Option<CompiledToolPolicy>,
    read_file: Option<CompiledToolPolicy>,
    write_file: Option<CompiledToolPolicy>,
    http_request: Option<CompiledToolPolicy>,
    custom: HashMap<String, CompiledToolPolicy>,
}

fn is_http_method_token(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}

fn compile_rule(
    rule: &RulePattern,
    tool_name: &str,
    supports_http_method: bool,
) -> Result<CompiledRulePattern, PolicyError> {
    match rule {
        RulePattern::Plain(s) => {
            if s.trim().is_empty() {
                return Err(PolicyError::ParseError(
                    "rule selector string must not be empty".to_string(),
                ));
            }
            Ok(CompiledRulePattern::Plain(s.clone()))
        }
        RulePattern::Map(m) => {
            for (selector, value) in [
                ("prefix", m.prefix.as_deref()),
                ("regex", m.regex.as_deref()),
                ("plain", m.plain.as_deref()),
            ] {
                if value.is_some_and(|value| value.trim().is_empty()) {
                    return Err(PolicyError::ParseError(format!(
                        "rule {selector} selector must not be empty"
                    )));
                }
            }

            let method = match m.method.as_deref() {
                Some(value) if value.trim().is_empty() => {
                    return Err(PolicyError::ParseError(
                        "rule method selector must not be empty".to_string(),
                    ));
                }
                Some(_) if !supports_http_method => {
                    return Err(PolicyError::ParseError(format!(
                        "method selectors are only supported for tools.http_request, not tools.{tool_name}"
                    )));
                }
                Some(value) => {
                    if !is_http_method_token(value) {
                        return Err(PolicyError::ParseError(format!(
                            "invalid HTTP method '{value}' in rule; methods must be non-empty RFC 9110 tokens"
                        )));
                    }
                    let normalized = value.to_ascii_uppercase();
                    Some(normalized)
                }
                None => None,
            };

            if m.prefix.is_none()
                && m.regex.is_none()
                && m.plain.is_none()
                && method.is_none()
                && m.condition.is_none()
            {
                return Err(PolicyError::ParseError(
                    "rule map must contain at least one non-empty selector or a valid condition"
                        .to_string(),
                ));
            }

            let regex = match m.regex.as_ref() {
                Some(src) => Some(Regex::new(src).map_err(|e| {
                    PolicyError::ParseError(format!("Invalid regex '{}': {}", src, e))
                })?),
                None => None,
            };
            Ok(CompiledRulePattern::Map(CompiledRulePatternMap {
                prefix: m.prefix.clone(),
                regex_src: m.regex.clone(),
                regex,
                plain: m.plain.clone(),
                method,
                condition: m.condition.clone(),
            }))
        }
    }
}

fn compile_tool_policy(
    p: &ToolPolicy,
    tool_name: &str,
    supports_http_method: bool,
) -> Result<CompiledToolPolicy, PolicyError> {
    let compile = |rule| compile_rule(rule, tool_name, supports_http_method);
    let deny = p.deny.iter().map(compile).collect::<Result<_, _>>()?;
    let allow = p.allow.iter().map(compile).collect::<Result<_, _>>()?;
    let ask = p.ask.iter().map(compile).collect::<Result<_, _>>()?;
    for glob_pat in p
        .deny_paths
        .iter()
        .chain(p.allow_paths.iter())
        .chain(p.workspace_escape_paths.iter())
    {
        glob::Pattern::new(glob_pat)
            .map_err(|e| PolicyError::ParseError(format!("Invalid glob '{}': {}", glob_pat, e)))?;
    }
    Ok(CompiledToolPolicy { deny, allow, ask })
}

fn compile_tools(tools: &ToolsConfig) -> Result<CompiledTools, PolicyError> {
    let bash = tools
        .bash
        .as_ref()
        .map(|p| compile_tool_policy(p, "bash", false))
        .transpose()?;
    let read_file = tools
        .read_file
        .as_ref()
        .map(|p| compile_tool_policy(p, "read_file", false))
        .transpose()?;
    let write_file = tools
        .write_file
        .as_ref()
        .map(|p| compile_tool_policy(p, "write_file", false))
        .transpose()?;
    let http_request = tools
        .http_request
        .as_ref()
        .map(|p| compile_tool_policy(p, "http_request", true))
        .transpose()?;
    let mut custom = HashMap::with_capacity(tools.custom.len());
    for (k, v) in &tools.custom {
        custom.insert(k.clone(), compile_tool_policy(v, k, false)?);
    }
    Ok(CompiledTools {
        bash,
        read_file,
        write_file,
        http_request,
        custom,
    })
}

fn validate_policy_configuration(policy: &PolicyFile) -> Result<(), PolicyError> {
    let anomaly = &policy.anomaly;
    for (field, value) in [
        (
            "anomaly.rate_limit.window_seconds",
            anomaly.rate_limit.window_seconds,
        ),
        (
            "anomaly.deny_fuse.window_seconds",
            anomaly.deny_fuse.window_seconds,
        ),
    ] {
        if value == 0 {
            return Err(PolicyError::ParseError(format!(
                "{field} must be greater than zero"
            )));
        }
        if Instant::now()
            .checked_sub(Duration::from_secs(value))
            .is_none()
        {
            return Err(PolicyError::ParseError(format!(
                "{field} exceeds the supported monotonic clock range"
            )));
        }
    }
    for (field, value) in [
        ("anomaly.rate_limit.max_calls", anomaly.rate_limit.max_calls),
        ("anomaly.deny_fuse.threshold", anomaly.deny_fuse.threshold),
    ] {
        if value == 0 {
            return Err(PolicyError::ParseError(format!(
                "{field} must be greater than zero"
            )));
        }
    }
    if anomaly.rate_limit.max_calls >= MAX_RETAINED_ANOMALY_OBSERVATIONS {
        return Err(PolicyError::ParseError(format!(
            "anomaly.rate_limit.max_calls must be less than the retained observation capacity ({MAX_RETAINED_ANOMALY_OBSERVATIONS})"
        )));
    }
    if anomaly.deny_fuse.threshold > MAX_RETAINED_ANOMALY_OBSERVATIONS {
        return Err(PolicyError::ParseError(format!(
            "anomaly.deny_fuse.threshold must not exceed the retained observation capacity ({MAX_RETAINED_ANOMALY_OBSERVATIONS})"
        )));
    }

    match policy.audit.output.as_str() {
        "stdout" => {}
        "file" => {
            if policy
                .audit
                .file_path
                .as_deref()
                .map(|path| path.trim().is_empty())
                .unwrap_or(true)
            {
                return Err(PolicyError::ParseError(
                    "audit.file_path must be non-empty when audit.output is 'file'".to_string(),
                ));
            }
        }
        output => {
            return Err(PolicyError::ParseError(format!(
                "audit.output must be either 'stdout' or 'file', not '{output}'"
            )));
        }
    }

    Ok(())
}

// ── PolicyEngine ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct PolicyEngine {
    policy: PolicyFile,
    compiled: CompiledTools,
    hash: String,
}

impl PolicyEngine {
    pub fn from_yaml_str(yaml: &str) -> Result<Self, PolicyError> {
        let policy: PolicyFile =
            serde_yaml::from_str(yaml).map_err(|e| PolicyError::ParseError(e.to_string()))?;
        if policy.version != 1 {
            return Err(PolicyError::UnsupportedVersion(policy.version));
        }
        validate_policy_configuration(&policy)?;

        let mut hasher = Sha256::new();
        hasher.update(yaml.as_bytes());
        let hash = hex::encode(hasher.finalize());

        // Compile regex patterns at load time. Invalid regex surfaces here as a
        // `PolicyError::ParseError` rather than being silently ignored at check
        // time. Glob patterns under `deny_paths` / `allow_paths` are validated
        // here as well (they are still re-compiled per-check by `path_glob_matches`).
        let compiled = compile_tools(&policy.tools)?;

        Ok(Self {
            policy,
            compiled,
            hash,
        })
    }

    pub fn from_yaml_file(path: impl AsRef<Path>) -> Result<Self, PolicyError> {
        let content =
            std::fs::read_to_string(path).map_err(|e| PolicyError::IoError(e.to_string()))?;
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
        let trust_level = &context.trust_level;
        let effective_mode = self.effective_mode(tool, context);
        let tool_policy = self.tool_policy(tool);
        let tool_name = tool.name();

        // Guard-owned WriteFile execution in WorkspaceWrite mode requires an
        // explicit workspace capability. Treating a missing bound as
        // "unrestricted" silently turns Context::default() into host-wide
        // write access. FullAccess remains the explicit opt-out.
        if matches!(tool, Tool::WriteFile)
            && effective_mode == PolicyMode::WorkspaceWrite
            && context.working_directory.is_none()
        {
            return GuardDecision::deny(
                DecisionCode::InvalidPayload,
                "working_directory is required for WriteFile in workspace_write mode",
            );
        }

        if effective_mode == PolicyMode::ReadOnly {
            // Intrinsically mutating structured tools are denied in read-only
            // mode regardless of per-tool configuration. `WriteFile` always
            // mutates the filesystem; `HttpRequest` mutates when its method is a
            // mutation verb. Without this, a bare `default_mode: read_only`
            // policy (no tool block) lets these fall through to Allow, because
            // the tool-mode gate below only fires for a *configured* mode
            // `>= WorkspaceWrite`. Bash write-intent is classified separately by
            // the validator layer, and Custom tools are opaque (rules only).
            if let Some(reason) = read_only_tool_violation(tool, payload) {
                return GuardDecision::deny(DecisionCode::WriteInReadOnlyMode, reason);
            }

            let tool_mode = tool_policy
                .map(|tp| tp.mode.as_ref().unwrap_or(&self.policy.default_mode))
                .unwrap_or(&self.policy.default_mode);

            if *tool_mode >= PolicyMode::WorkspaceWrite {
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

        let is_blocked = effective_mode == PolicyMode::Blocked;

        let extracted = match tool {
            Tool::ReadFile | Tool::WriteFile => match extract_path(payload) {
                Ok(ExtractedPayload::Path(path)) => {
                    // A path that matches the tool's `workspace_escape_paths`
                    // bypasses the workspace-bound check inside resolve_tool_path
                    // and is then subject to the normal deny / ask / allow flow.
                    let escape_globs = tool_policy
                        .map(|tp| tp.workspace_escape_paths.as_slice())
                        .unwrap_or_default();
                    let escapes = |candidate: &str| {
                        escape_globs.iter().any(|pat| {
                            path_glob_matches(pat, candidate, context.working_directory.as_deref())
                        })
                    };

                    let escapes_workspace = escapes(&path);
                    let effective_bound = if escapes_workspace {
                        None
                    } else {
                        context.working_directory.as_deref()
                    };
                    match resolve_tool_path(&path, effective_bound) {
                        Ok(resolved) => {
                            let resolved = resolved.to_string_lossy().into_owned();
                            // The escape is granted on the path as written, so
                            // a symlink inside an escape-listed root would
                            // otherwise carry the exemption anywhere it points.
                            // An exemption that does not survive resolution was
                            // never one for this file: hold it to the workspace
                            // bound after all.
                            if escapes_workspace && !escapes(&resolved) {
                                if let Err(deny) = resolve_tool_path(
                                    &resolved,
                                    context.working_directory.as_deref(),
                                ) {
                                    return deny;
                                }
                            }
                            ExtractedPayload::Path(resolved)
                        }
                        Err(deny) => return deny,
                    }
                }
                Ok(_) => unreachable!("path extractor returned a non-path payload"),
                Err(deny) => return deny,
            },
            Tool::HttpRequest => match extract_http_request(payload) {
                Ok(ep) => ep,
                Err(deny) => return deny,
            },
            Tool::Bash => match extract_bash_command(payload) {
                Ok(ep) => ep,
                Err(deny) => return deny,
            },
            _ => ExtractedPayload::Raw(payload),
        };
        let match_value = extracted.match_value();
        let http_method = extracted.http_method();

        if let Some(tp) = tool_policy {
            let compiled_tp = self.compiled_tool_policy(tool);
            // The compiled view is built 1:1 from the YAML view, so when
            // `tool_policy` returns Some, the compiled view is always present.
            let compiled_tp = compiled_tp.expect("compiled tool policy missing for known tool");

            for (i, rule) in compiled_tp.deny.iter().enumerate() {
                let rule_ref = format!("tools.{}.deny[{}]", tool_name, i);
                let res = match pattern_matches(rule, match_value, http_method, tool, context) {
                    Ok(result) => result,
                    Err(error) => return condition_evaluation_denied(rule_ref, error),
                };
                if res.matched {
                    let mut reason = DecisionReason::new(
                        DecisionCode::DeniedByRule,
                        format!("payload matched deny rule: {}", pattern_display(rule)),
                    )
                    .with_matched_rule(rule_ref);

                    if let Some(cond) = res.condition {
                        reason = reason.with_condition(cond);
                    }
                    return GuardDecision::Deny { reason };
                }
            }

            for (i, glob_pattern) in tp.deny_paths.iter().enumerate() {
                if path_glob_matches(
                    glob_pattern,
                    match_value,
                    context.working_directory.as_deref(),
                ) {
                    let rule_ref = format!("tools.{}.deny_paths[{}]", tool_name, i);
                    let reason = DecisionReason::new(
                        DecisionCode::PathOutsideWorkspace,
                        format!("path matched deny_paths rule: {}", glob_pattern),
                    )
                    .with_matched_rule(rule_ref);
                    return GuardDecision::Deny { reason };
                }
            }

            for (i, rule) in compiled_tp.ask.iter().enumerate() {
                let rule_ref = format!("tools.{}.ask[{}]", tool_name, i);
                let res = match pattern_matches(rule, match_value, http_method, tool, context) {
                    Ok(result) => result,
                    Err(error) => return condition_evaluation_denied(rule_ref, error),
                };
                if res.matched {
                    let mut reason = DecisionReason::new(
                        DecisionCode::AskRequired,
                        format!("ask rule matched: {}", pattern_display(rule)),
                    )
                    .with_matched_rule(rule_ref);

                    if let Some(cond) = res.condition {
                        reason = reason.with_condition(cond);
                    }
                    return GuardDecision::ask_with_reason(
                        format!(
                            "Confirmation required: rule '{}' matched",
                            pattern_display(rule)
                        ),
                        reason,
                    );
                }
            }

            if !tp.allow_paths.is_empty() {
                let in_allowlist = tp.allow_paths.iter().any(|p| {
                    path_glob_matches(p, match_value, context.working_directory.as_deref())
                });
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

            for (i, rule) in compiled_tp.allow.iter().enumerate() {
                let rule_ref = format!("tools.{}.allow[{}]", tool_name, i);
                let res = match pattern_matches(rule, match_value, http_method, tool, context) {
                    Ok(result) => result,
                    Err(error) => return condition_evaluation_denied(rule_ref, error),
                };
                if res.matched {
                    return GuardDecision::Allow;
                }
            }
        }

        if is_blocked {
            GuardDecision::deny(
                DecisionCode::BlockedByMode,
                format!(
                    "tool '{}' is in blocked mode and no explicit allow rule matched",
                    tool_name
                ),
            )
        } else {
            GuardDecision::Allow
        }
    }

    pub fn effective_mode(&self, tool: &Tool, context: &Context) -> PolicyMode {
        // Tool-level "blocked" always takes precedence regardless of trust level
        if let Some(tp) = self.tool_policy(tool) {
            if tp.mode.as_ref() == Some(&PolicyMode::Blocked) {
                return PolicyMode::Blocked;
            }
        }

        match context.trust_level {
            TrustLevel::Untrusted => self
                .policy
                .trust
                .untrusted
                .as_ref()
                .and_then(|t| t.override_mode.clone())
                .unwrap_or_else(|| self.policy.default_mode.clone()),
            TrustLevel::Trusted => self
                .policy
                .trust
                .trusted
                .as_ref()
                .and_then(|t| t.override_mode.clone())
                .unwrap_or_else(|| {
                    self.tool_policy(tool)
                        .and_then(|tp| tp.mode.clone())
                        .unwrap_or_else(|| self.policy.default_mode.clone())
                }),
            TrustLevel::Admin => self
                .policy
                .trust
                .admin
                .as_ref()
                .and_then(|t| t.override_mode.clone())
                .unwrap_or_else(|| {
                    self.tool_policy(tool)
                        .and_then(|tp| tp.mode.clone())
                        .unwrap_or_else(|| self.policy.default_mode.clone())
                }),
        }
    }

    fn tool_policy(&self, tool: &Tool) -> Option<&ToolPolicy> {
        match tool {
            Tool::Bash => self.policy.tools.bash.as_ref(),
            Tool::ReadFile => self.policy.tools.read_file.as_ref(),
            Tool::WriteFile => self.policy.tools.write_file.as_ref(),
            Tool::HttpRequest => self.policy.tools.http_request.as_ref(),
            Tool::Custom(id) => self.policy.tools.custom.get(id.as_str()),
        }
    }

    /// Read-only accessor for a tool's `workspace_escape_paths` list. Returns
    /// an empty slice when the tool is unconfigured or has no escape list.
    /// Used by external callers (e.g. the bash validator) that need to honour
    /// the same escape semantics as the in-engine path resolution.
    pub fn workspace_escape_paths(&self, tool: &Tool) -> &[String] {
        self.tool_policy(tool)
            .map(|tp| tp.workspace_escape_paths.as_slice())
            .unwrap_or(&[])
    }

    /// Read-only accessor for a tool's content-layer policy (S6-4). Returns
    /// `None` when the tool is unconfigured or has no `content` block. The SDK
    /// consults this before running the content detectors.
    pub fn content_policy(&self, tool: &Tool) -> Option<&ContentPolicy> {
        self.tool_policy(tool).and_then(|tp| tp.content.as_ref())
    }

    /// Read-only accessor for the top-level `input_content:` policy (issue
    /// #99) — the content policy applied to host-supplied input text via
    /// `Guard::check_content`. `None` when the policy has no such block.
    pub fn input_content_policy(&self) -> Option<&ContentPolicy> {
        self.policy.input_content.as_ref()
    }

    fn compiled_tool_policy(&self, tool: &Tool) -> Option<&CompiledToolPolicy> {
        match tool {
            Tool::Bash => self.compiled.bash.as_ref(),
            Tool::ReadFile => self.compiled.read_file.as_ref(),
            Tool::WriteFile => self.compiled.write_file.as_ref(),
            Tool::HttpRequest => self.compiled.http_request.as_ref(),
            Tool::Custom(id) => self.compiled.custom.get(id.as_str()),
        }
    }
}

#[derive(Debug, Default)]
struct MatchResult {
    matched: bool,
    condition: Option<String>,
}

fn pattern_matches(
    rule: &CompiledRulePattern,
    value: &str,
    http_method: Option<&str>,
    tool: &Tool,
    context: &Context,
) -> Result<MatchResult, ConditionEvaluationError> {
    match rule {
        CompiledRulePattern::Plain(s) => Ok(MatchResult {
            matched: value.contains(s.as_str()),
            condition: None,
        }),
        CompiledRulePattern::Map(m) => {
            let mut result = MatchResult {
                matched: false,
                condition: m.condition.as_ref().map(|c| c.raw.clone()),
            };

            if let Some(ref condition) = m.condition {
                if !condition.evaluate(tool, context)? {
                    return Ok(MatchResult {
                        matched: false,
                        condition: None,
                    });
                }
            }

            // Method gate: a rule with `method:` applies only to a request whose
            // method matches (case-insensitive). A method constraint never
            // matches a tool that carries no method (anything but HttpRequest).
            if let Some(ref want) = m.method {
                match http_method {
                    Some(got) if got.eq_ignore_ascii_case(want) => {}
                    _ => {
                        return Ok(MatchResult {
                            matched: false,
                            condition: None,
                        })
                    }
                }
            }

            if let Some(ref prefix) = m.prefix {
                if value.trim_start().starts_with(prefix.as_str()) {
                    result.matched = true;
                    return Ok(result);
                }
            }
            if let Some(ref re) = m.regex {
                if re.is_match(value) {
                    result.matched = true;
                    return Ok(result);
                }
            }
            if let Some(ref plain) = m.plain {
                if value.contains(plain.as_str()) {
                    result.matched = true;
                    return Ok(result);
                }
            }

            // If no text criteria (prefix, regex, plain) are provided, a
            // method selector or condition that passed makes the rule match.
            if m.prefix.is_none() && m.regex.is_none() && m.plain.is_none() {
                result.matched = true;
            }

            Ok(result)
        }
    }
}

fn condition_evaluation_denied(rule_ref: String, error: ConditionEvaluationError) -> GuardDecision {
    let reason = DecisionReason::new(
        DecisionCode::InternalError,
        format!("policy condition could not be evaluated safely: {error}"),
    )
    .with_matched_rule(rule_ref);
    GuardDecision::Deny { reason }
}

fn pattern_display(rule: &CompiledRulePattern) -> String {
    match rule {
        CompiledRulePattern::Plain(s) => s.clone(),
        CompiledRulePattern::Map(m) => {
            if let Some(ref re) = m.regex_src {
                format!("regex:{}", re)
            } else if let Some(ref prefix) = m.prefix {
                format!("prefix:{}", prefix)
            } else if let Some(ref plain) = m.plain {
                plain.clone()
            } else {
                "complex rule".to_string()
            }
        }
    }
}

fn path_glob_matches(pattern: &str, path: &str, working_directory: Option<&Path>) -> bool {
    let resolved_pattern = resolve_path_glob_pattern(pattern, working_directory);
    if let Ok(glob) = glob::Pattern::new(&resolved_pattern) {
        glob.matches(path)
    } else {
        false
    }
}

/// A structured tool whose call intrinsically mutates state is not permitted in
/// read-only mode. Returns a human-readable reason when the `(tool, payload)`
/// pair is such a mutation. `WriteFile` always qualifies; `HttpRequest`
/// qualifies when its method is a mutation verb. `Bash` is classified by the
/// validator layer and `Custom` tools are opaque, so both return `None` here
/// and are governed by explicit rules / the tool-mode gate instead.
fn read_only_tool_violation(tool: &Tool, payload: &str) -> Option<String> {
    match tool {
        Tool::WriteFile => Some(
            "write_file modifies the filesystem and is not allowed in read-only mode".to_string(),
        ),
        Tool::HttpRequest if http_method_is_mutation(payload) => Some(
            "http_request with a mutation method (POST/PUT/PATCH/DELETE) is not allowed in read-only mode"
                .to_string(),
        ),
        _ => None,
    }
}

/// True when an `HttpRequest` payload declares a mutation method
/// (POST/PUT/PATCH/DELETE). Method parsing is delegated to the canonical
/// [`extract_http_request`] extractor (normalization, `GET` default, size
/// guard) so this predicate cannot drift from the rest of the HTTP path. A
/// malformed payload yields `Err` here and is surfaced as `InvalidPayload` by
/// the extraction step in `check`, so the gate reports no mutation for it; a
/// missing method defaults to `GET` (a read). GET is a legitimate read under
/// read-only, so this is intentionally not fail-closed — contrast the SDK's
/// routing helper, which fails *closed* to the SSRF-guarded Execute path.
fn http_method_is_mutation(payload: &str) -> bool {
    let Ok(extracted) = extract_http_request(payload) else {
        return false;
    };
    matches!(
        extracted.http_method(),
        Some("POST" | "PUT" | "PATCH" | "DELETE")
    )
}

fn trust_level_str(level: &TrustLevel) -> &'static str {
    match level {
        TrustLevel::Untrusted => "untrusted",
        TrustLevel::Trusted => "trusted",
        TrustLevel::Admin => "admin",
    }
}

#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("failed to load policy: {0}")]
    IoError(String),
    #[error("failed to parse policy YAML: {0}")]
    ParseError(String),
    #[error("unsupported policy version: {0}")]
    UnsupportedVersion(u32),
}

#[cfg(test)]
mod condition_runtime_tests {
    use super::*;

    fn replace_first_condition_with_runtime_type_error(
        engine: &mut PolicyEngine,
        list: fn(&mut CompiledToolPolicy) -> &mut Vec<CompiledRulePattern>,
    ) {
        let invalid = Condition {
            raw: "trust_level > 3".to_string(),
            node: evalexpr::build_operator_tree("trust_level > 3").unwrap(),
        };
        let policy = engine.compiled.bash.as_mut().unwrap();
        match &mut list(policy)[0] {
            CompiledRulePattern::Map(rule) => rule.condition = Some(invalid),
            CompiledRulePattern::Plain(_) => panic!("expected a map rule"),
        }
    }

    fn assert_internal_error_deny(decision: GuardDecision, rule_ref: &str) {
        match decision {
            GuardDecision::Deny { reason } => {
                assert_eq!(reason.code(), DecisionCode::InternalError);
                assert_eq!(reason.matched_rule(), Some(rule_ref));
                assert!(reason.message().contains("could not be evaluated safely"));
            }
            other => panic!("condition error must fail closed, got {other:?}"),
        }
    }

    #[test]
    fn deny_condition_runtime_error_fails_closed() {
        let mut engine = PolicyEngine::from_yaml_str(
            r#"
version: 1
default_mode: full_access
tools:
  bash:
    deny:
      - prefix: "danger"
        if: 'actor == "bot"'
"#,
        )
        .unwrap();
        replace_first_condition_with_runtime_type_error(&mut engine, |policy| &mut policy.deny);

        assert_internal_error_deny(
            engine.check(&Tool::Bash, r#"{"command":"danger"}"#, &Context::default()),
            "tools.bash.deny[0]",
        );
    }

    #[test]
    fn ask_condition_runtime_error_fails_closed_instead_of_becoming_approvable() {
        let mut engine = PolicyEngine::from_yaml_str(
            r#"
version: 1
default_mode: full_access
tools:
  bash:
    ask:
      - prefix: "deploy"
        if: 'actor == "bot"'
"#,
        )
        .unwrap();
        replace_first_condition_with_runtime_type_error(&mut engine, |policy| &mut policy.ask);

        assert_internal_error_deny(
            engine.check(&Tool::Bash, r#"{"command":"deploy"}"#, &Context::default()),
            "tools.bash.ask[0]",
        );
    }
}
