use std::borrow::Cow;

use ldap3::{ldap_escape, parse_filter};
use pyo3::prelude::*;

#[pyfunction]
fn is_ldap_filter_valid(filter: &str) -> PyResult<bool> {
    let parse_result = parse_filter(filter);
    if parse_result.is_err() {
        return Ok(false);
    }
    return Ok(true);
}

#[pyfunction]
#[pyo3(name = "ldap_escape")]
fn ldap_escape_py(lit: &str) -> Cow<'_, str> {
    return ldap_escape(lit);
}

#[pymodule]
fn ruldap3(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(is_ldap_filter_valid, m)?)?;
    m.add_function(wrap_pyfunction!(ldap_escape_py, m)?)?;
    Ok(())
}
