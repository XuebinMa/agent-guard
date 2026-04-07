use prometheus_client::encoding::EncodeLabelSet;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::histogram::{exponential_buckets, Histogram};
use prometheus_client::registry::Registry;
use std::sync::{Arc, OnceLock};

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct DecisionLabels {
    pub tool: String,
    pub outcome: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct ExecutionLabels {
    pub tool: String,
    pub sandbox: String,
}

pub struct Metrics {
    pub registry: Registry,
    pub policy_checks: Family<DecisionLabels, Counter>,
    pub execution_duration: Family<ExecutionLabels, Histogram>,
}

impl Metrics {
    pub fn new() -> Self {
        let mut registry = Registry::default();
        
        let policy_checks = Family::<DecisionLabels, Counter>::default();
        registry.register(
            "agent_guard_policy_checks_total",
            "Total number of policy checks performed",
            policy_checks.clone(),
        );

        let execution_duration = Family::<ExecutionLabels, Histogram>::new_with_constructor(|| {
            Histogram::new(exponential_buckets(0.001, 2.0, 10))
        });
        registry.register(
            "agent_guard_execution_duration_seconds",
            "Histogram of tool execution duration in seconds",
            execution_duration.clone(),
        );

        Self {
            registry,
            policy_checks,
            execution_duration,
        }
    }
}

pub static GLOBAL_METRICS: OnceLock<Arc<Metrics>> = OnceLock::new();

pub fn get_metrics() -> Arc<Metrics> {
    GLOBAL_METRICS.get_or_init(|| Arc::new(Metrics::new())).clone()
}
