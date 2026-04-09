use prometheus_client::encoding::EncodeLabelSet;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::histogram::{exponential_buckets, Histogram};
use prometheus_client::registry::Registry;
use std::sync::{Arc, OnceLock};

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct DecisionLabels {
    pub agent_id: String,
    pub tool: String,
    pub outcome: String, // allow, deny, ask
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct ToolLabels {
    pub agent_id: String,
    pub tool: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct ExecutionLabels {
    pub agent_id: String,
    pub tool: String,
    pub sandbox_type: String,
}

pub struct Metrics {
    pub registry: Registry,
    pub policy_checks_total: Family<ToolLabels, Counter>,
    pub decision_total: Family<DecisionLabels, Counter>,
    pub execution_duration_seconds: Family<ExecutionLabels, Histogram>,
    pub anomaly_triggered_total: Family<ToolLabels, Counter>,
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}

impl Metrics {
    pub fn new() -> Self {
        let mut registry = Registry::default();

        let policy_checks_total = Family::<ToolLabels, Counter>::default();
        registry.register(
            "agent_guard_policy_checks_total",
            "Total number of policy checks initiated",
            policy_checks_total.clone(),
        );

        let decision_total = Family::<DecisionLabels, Counter>::default();
        registry.register(
            "agent_guard_decision_total",
            "Total number of decisions by outcome",
            decision_total.clone(),
        );

        let execution_duration_seconds =
            Family::<ExecutionLabels, Histogram>::new_with_constructor(|| {
                // Buckets from 1ms to ~1s
                Histogram::new(exponential_buckets(0.001, 2.0, 10))
            });
        registry.register(
            "agent_guard_execution_duration_seconds",
            "Histogram of tool execution duration in seconds",
            execution_duration_seconds.clone(),
        );

        let anomaly_triggered_total = Family::<ToolLabels, Counter>::default();
        registry.register(
            "agent_guard_anomaly_triggered_total",
            "Total number of anomalies detected and blocked",
            anomaly_triggered_total.clone(),
        );

        Self {
            registry,
            policy_checks_total,
            decision_total,
            execution_duration_seconds,
            anomaly_triggered_total,
        }
    }
}

pub static GLOBAL_METRICS: OnceLock<Arc<Metrics>> = OnceLock::new();

pub fn get_metrics() -> Arc<Metrics> {
    GLOBAL_METRICS
        .get_or_init(|| Arc::new(Metrics::new()))
        .clone()
}
