use ldap3::parse_filter;
use pyo3::prelude::*;

#[pyfunction]
fn is_ldap_filter_valid(filter: String) -> PyResult<bool> {
    let parse_result = parse_filter(filter);
    if parse_result.is_err() {
        return Ok(false);
    }
    return Ok(false);
}

#[pymodule]
fn ruldap3(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(is_ldap_filter_valid, m)?)?;
    Ok(())
}
