use pyo3::create_exception;
use pyo3::exceptions::PyException;

create_exception!(agent_guard, GuardError, PyException,
    "Raised when agent-guard fails to initialise or encounters an internal error.");
