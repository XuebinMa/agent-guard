mod error;
mod types;

use pyo3::prelude::*;

use error::GuardError;
use types::{Decision, PyGuard};

/// agent-guard Python binding.
///
/// A policy-driven security enforcement layer for AI agent tool calls.
///
/// Quick start
/// -----------
/// .. code-block:: python
///
///     import agent_guard
///
///     guard = agent_guard.Guard.from_yaml(\"\"\"
///     version: 1
///     default_mode: workspace_write
///     tools:
///       bash:
///         deny:
///           - prefix: \"rm -rf\"
///     \"\"\")
///
///     d = guard.check(\"bash\", \"ls -la\", trust_level=\"trusted\")
///     print(d.outcome)  # "allow"
///
///     d = guard.check(\"bash\", \"rm -rf /\", trust_level=\"trusted\")
///     print(d.outcome, d.code)  # "ask_user" "DestructiveCommand"
#[pymodule]
fn agent_guard(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyGuard>()?;
    m.add_class::<Decision>()?;
    m.add("GuardError", m.py().get_type::<GuardError>())?;
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;

    #[pyfn(m)]
    #[pyo3(name = "init_tracing")]
    fn init_tracing_py() {
        let _ = tracing_subscriber::fmt::try_init();
    }

    Ok(())
}
