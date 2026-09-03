//! Constructing a Guard and swapping its policy underneath running callers.
//!
//! Split out of `guard.rs`: these methods are about the lifecycle of the
//! policy snapshot, not about deciding any one call, and they are the ones
//! that have to keep the signing key and injected metrics alive across a
//! reload.

use std::path::Path;
use std::sync::Arc;

use arc_swap::ArcSwap;

use agent_guard_core::{PolicyEngine, ReloadEvent};

use crate::guard::{Guard, GuardInitError, GuardState};
use crate::guard_audit::AuditSink;
use crate::policy_signing::{
    load_policy_signature_file, load_public_key_file, parse_hex_signing_key, verify_policy,
    PolicyVerification,
};

impl Guard {
    /// Create a Guard from an already-parsed PolicyEngine.
    pub fn new(engine: PolicyEngine) -> Result<Self, GuardInitError> {
        let state = GuardState::new(Arc::new(engine), PolicyVerification::unsigned())?;
        Ok(Self {
            state: ArcSwap::from_pointee(state),
        })
    }

    /// Construct a Guard from a YAML string.
    pub fn from_yaml(yaml: &str) -> Result<Self, GuardInitError> {
        Self::new(PolicyEngine::from_yaml_str(yaml)?)
    }

    /// Construct a Guard from a YAML file.
    pub fn from_yaml_file(path: impl AsRef<std::path::Path>) -> Result<Self, GuardInitError> {
        Self::new(PolicyEngine::from_yaml_file(path)?)
    }

    /// Construct a Guard from a YAML string and detached Ed25519 signature.
    pub fn from_signed_yaml(
        yaml: &str,
        public_key_hex: &str,
        signature_hex: &str,
    ) -> Result<Self, GuardInitError> {
        let engine = PolicyEngine::from_yaml_str(yaml)?;
        Self::new_with_verification(engine, verify_policy(yaml, public_key_hex, signature_hex))
    }

    /// Construct a Guard from a YAML file and detached Ed25519 signature file.
    pub fn from_signed_yaml_file(
        policy_path: impl AsRef<Path>,
        public_key_path: impl AsRef<Path>,
        signature_path: impl AsRef<Path>,
    ) -> Result<Self, GuardInitError> {
        let yaml = std::fs::read_to_string(policy_path)
            .map_err(|error| GuardInitError::SigningKeyLoad(error.to_string()))?;
        let public_key_hex =
            load_public_key_file(public_key_path).map_err(GuardInitError::SigningKeyLoad)?;
        let signature_hex =
            load_policy_signature_file(signature_path).map_err(GuardInitError::SigningKeyLoad)?;
        Self::from_signed_yaml(&yaml, &public_key_hex, &signature_hex)
    }

    fn new_with_verification(
        engine: PolicyEngine,
        policy_verification: PolicyVerification,
    ) -> Result<Self, GuardInitError> {
        let state = GuardState::new(Arc::new(engine), policy_verification)?;
        Ok(Self {
            state: ArcSwap::from_pointee(state),
        })
    }

    /// Set the Ed25519 signing key for provenance receipts.
    pub fn with_signing_key(&self, key: ed25519_dalek::SigningKey) {
        // RCU instead of load→clone→store: a plain store racing with a
        // concurrent reload would silently drop one side's update (#56).
        self.state.rcu(|current| {
            let mut new_state = (**current).clone();
            new_state.signing_key = Some(key.clone());
            new_state
        });
    }

    /// Route this Guard's metrics to a dedicated registry instead of the
    /// process-global one, so co-resident Guards don't blend counters (#60).
    pub fn set_metrics(&self, metrics: Arc<crate::metrics::Metrics>) {
        self.state.rcu(|current| {
            let mut new_state = (**current).clone();
            new_state.metrics = metrics.clone();
            new_state
        });
    }

    /// Redirect non-file audit output (default: process stdout). Survives
    /// policy reloads, like the signing key (#60).
    pub fn set_audit_sink(&self, sink: Box<dyn std::io::Write + Send>) {
        let sink: AuditSink = Arc::new(std::sync::Mutex::new(sink));
        self.state.rcu(|current| {
            let mut new_state = (**current).clone();
            new_state.audit_sink = sink.clone();
            new_state
        });
    }

    /// Construct a Guard from a YAML string with an Ed25519 signing key for provenance.
    pub fn from_yaml_with_key(
        yaml: &str,
        key: ed25519_dalek::SigningKey,
    ) -> Result<Self, GuardInitError> {
        let guard = Self::from_yaml(yaml)?;
        guard.with_signing_key(key);
        Ok(guard)
    }

    /// Load a hex-encoded Ed25519 private key from a file and set it on this Guard.
    pub fn load_signing_key(&self, path: impl AsRef<Path>) -> Result<(), GuardInitError> {
        let hex_str = std::fs::read_to_string(path)
            .map_err(|e| GuardInitError::SigningKeyLoad(e.to_string()))?;
        let key = parse_hex_signing_key(hex_str.trim()).map_err(GuardInitError::SigningKeyLoad)?;
        self.with_signing_key(key);
        Ok(())
    }

    /// Atomically reload the policy engine from a new instance.
    pub fn reload_engine(&self, engine: PolicyEngine) -> Result<(), GuardInitError> {
        self.reload_engine_with_verification(engine, PolicyVerification::unsigned())
    }

    pub fn reload_engine_with_verification(
        &self,
        engine: PolicyEngine,
        policy_verification: PolicyVerification,
    ) -> Result<(), GuardInitError> {
        let new_version = engine.version().to_string();
        let base_state = GuardState::new(Arc::new(engine), policy_verification)?;

        // The carry-over fields must be copied from the state observed at
        // swap time, not from a snapshot taken earlier: a `with_signing_key`
        // landing between that snapshot and the store would be lost (#56).
        // RCU retries the copy until the swap is uncontended.
        let old_state = self.state.rcu(|current| {
            let mut new_state = base_state.clone();
            new_state.anomaly_detector = current.anomaly_detector.clone();
            new_state.signing_key = current.signing_key.clone();
            new_state.metrics = current.metrics.clone();
            new_state.audit_sink = current.audit_sink.clone();
            new_state
        });

        let event = ReloadEvent::success(old_state.engine.version().to_string(), new_version);
        self.write_reload_audit(&event, &old_state);

        Ok(())
    }

    /// Atomically reload the policy from a YAML string.
    pub fn reload_from_yaml(&self, yaml: &str) -> Result<(), GuardInitError> {
        match PolicyEngine::from_yaml_str(yaml) {
            Ok(engine) => self.reload_engine(engine),
            Err(e) => {
                let old_state = self.state.load();
                let old_version = old_state.engine.version().to_string();
                let err = GuardInitError::Policy(e);
                let event = ReloadEvent::failure(old_version, err.to_string());
                self.write_reload_audit(&event, &old_state);
                Err(err)
            }
        }
    }

    pub fn reload_from_signed_yaml(
        &self,
        yaml: &str,
        public_key_hex: &str,
        signature_hex: &str,
    ) -> Result<(), GuardInitError> {
        match PolicyEngine::from_yaml_str(yaml) {
            Ok(engine) => self.reload_engine_with_verification(
                engine,
                verify_policy(yaml, public_key_hex, signature_hex),
            ),
            Err(e) => {
                let old_state = self.state.load();
                let old_version = old_state.engine.version().to_string();
                let err = GuardInitError::Policy(e);
                let event = ReloadEvent::failure(old_version, err.to_string());
                self.write_reload_audit(&event, &old_state);
                Err(err)
            }
        }
    }

    pub fn reload_from_signed_yaml_file(
        &self,
        policy_path: impl AsRef<Path>,
        public_key_path: impl AsRef<Path>,
        signature_path: impl AsRef<Path>,
    ) -> Result<(), GuardInitError> {
        let yaml = std::fs::read_to_string(policy_path)
            .map_err(|error| GuardInitError::SigningKeyLoad(error.to_string()))?;
        let public_key_hex =
            load_public_key_file(public_key_path).map_err(GuardInitError::SigningKeyLoad)?;
        let signature_hex =
            load_policy_signature_file(signature_path).map_err(GuardInitError::SigningKeyLoad)?;
        self.reload_from_signed_yaml(&yaml, &public_key_hex, &signature_hex)
    }

    /// Return the version string of the currently loaded policy.
    pub fn policy_version(&self) -> String {
        self.state.load().engine.version().to_string()
    }

    /// Return the SHA-256 hash of the currently loaded policy.
    pub fn policy_hash(&self) -> String {
        self.state.load().engine.hash().to_string()
    }

    pub fn policy_verification(&self) -> PolicyVerification {
        self.state.load().policy_verification.clone()
    }
}
