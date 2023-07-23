use std::collections::HashMap;
use std::time::Duration;

use ldap3::result::LdapError;
use ldap3::{Ldap, LdapConnAsync, LdapConnSettings, Scope, SearchEntry};
use pyo3::create_exception;
use pyo3::exceptions::PyException;
use std::borrow::Cow;

use ldap3::{ldap_escape, parse_filter};
use pyo3::prelude::*;
use pyo3::types::PyType;

// TODO: When pyo3 gets better exception support
// (see https://github.com/PyO3/pyo3/issues/295.),
// add some properties to the exceptions.
create_exception!(ruldap3, Ruldap3Error, PyException);
create_exception!(ruldap3, InvalidFilterError, Ruldap3Error);
create_exception!(ruldap3, LdapSearchFailedError, Ruldap3Error);

struct PyLdapError(LdapError);
impl From<PyLdapError> for PyErr {
    fn from(error: PyLdapError) -> Self {
        match error.0 {
            // TODO: split out more as needed
            LdapError::FilterParsing => InvalidFilterError::new_err(error.0.to_string()),

            LdapError::LdapResult { result } => LdapSearchFailedError::new_err(format!(
                "Received error from ldap server: {}",
                result.to_string()
            )),
            _ => Ruldap3Error::new_err(error.0.to_string()),
        }
    }
}

#[pyclass]
#[pyo3(name = "Scope")]
pub enum PyScope {
    BASE,
    ONE,
    SUB,
}
impl From<&PyScope> for Scope {
    fn from(scope: &PyScope) -> Self {
        match scope {
            PyScope::BASE => Scope::Base,
            PyScope::ONE => Scope::OneLevel,
            PyScope::SUB => Scope::Subtree,
        }
    }
}

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

#[derive(Debug)]
#[pyclass]
#[pyo3(name = "SearchEntry")]
pub struct PySearchEntry {
    #[pyo3(get)]
    pub dn: String,
    #[pyo3(get)]
    pub attrs: HashMap<String, Vec<String>>,
    #[pyo3(get)]
    pub bin_attrs: HashMap<String, Vec<Vec<u8>>>,
}
impl From<SearchEntry> for PySearchEntry {
    fn from(search_entry: SearchEntry) -> Self {
        PySearchEntry {
            dn: search_entry.dn,
            attrs: search_entry.attrs,
            bin_attrs: search_entry.bin_attrs,
        }
    }
}

#[pyclass]
#[pyo3(name = "LdapConnection")]
struct PyLdapConnection {
    ldap: Ldap,
}

#[pymethods]
impl PyLdapConnection {
    pub fn __aenter__(slf: Py<Self>, py: pyo3::Python<'_>) -> PyResult<&PyAny> {
        pyo3_asyncio::tokio::future_into_py(py, async {
            return Ok(slf);
        })
    }

    pub fn __aexit__<'a>(
        &self,
        py: pyo3::Python<'a>,
        _exc_type: &pyo3::PyAny,
        _exc_value: &pyo3::PyAny,
        _exc_tb: &pyo3::PyAny,
    ) -> PyResult<&'a PyAny> {
        let mut ldap = self.ldap.clone();

        pyo3_asyncio::tokio::future_into_py(py, async move {
            if let Err(e) = ldap.unbind().await {
                return Err(PyLdapError(e).into());
            }
            return Ok(());
        })
    }

    pub fn search<'a>(
        &self,
        py: pyo3::Python<'a>,
        base: String,
        scope: &PyScope,
        filtr: String,
        attrlist: Vec<String>,
        timeout_sec: u64,
    ) -> PyResult<&'a PyAny> {
        let mut ldap = self.ldap.clone();

        let rust_scope = Scope::from(scope);

        pyo3_asyncio::tokio::future_into_py(py, async move {
            let (rs, _res) = ldap
                .with_timeout(Duration::new(timeout_sec, 0))
                .search(&base, rust_scope, &filtr, attrlist)
                .await
                .map_err(PyLdapError)?
                .success()
                .map_err(PyLdapError)?;

            let mut vec: Vec<PySearchEntry> = Vec::new();

            for entry in rs {
                let py_search_entry = PySearchEntry::from(SearchEntry::construct(entry));
                vec.push(py_search_entry);
            }

            return Ok(vec);
        })
    }

    #[classmethod]
    fn connect<'a>(
        _cls: &PyType,
        py: Python<'a>,
        ldap_server: String,
        timeout_sec: u64,
    ) -> PyResult<&'a PyAny> {
        pyo3_asyncio::tokio::future_into_py(py, async move {
            let settings: LdapConnSettings =
                LdapConnSettings::new().set_conn_timeout(Duration::new(timeout_sec, 0));

            let (conn, ldap) = LdapConnAsync::with_settings(settings, &ldap_server)
                .await
                .map_err(PyLdapError)?;

            ldap3::drive!(conn);

            return Ok(PyLdapConnection { ldap });
        })
    }
}

#[pymodule]
fn ruldap3(py: Python, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(is_ldap_filter_valid, m)?)?;
    m.add_function(wrap_pyfunction!(ldap_escape_py, m)?)?;
    m.add_class::<PySearchEntry>()?;
    m.add_class::<PyScope>()?;
    m.add_class::<PyLdapConnection>()?;
    m.add("Ruldap3Error", py.get_type::<Ruldap3Error>())?;
    m.add("InvalidFilterError", py.get_type::<InvalidFilterError>())?;
    m.add(
        "LdapSearchFailedError",
        py.get_type::<LdapSearchFailedError>(),
    )?;
    Ok(())
}
