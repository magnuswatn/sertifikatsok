use std::collections::HashMap;
use std::time::Duration;

use ldap3::parse_filter;
use ldap3::result::LdapError as RustLdapError;
use ldap3::{
    Ldap, LdapConnAsync, LdapConnSettings, Scope as RustScope, SearchEntry as RustSearchEntry,
};
use pyo3::create_exception;
use pyo3::exceptions::PyException;
use pyo3::prelude::*;

// TODO: When pyo3 gets better exception support
// (see https://github.com/PyO3/pyo3/issues/295.),
// add some properties to the exceptions.
create_exception!(ruldap3, Ruldap3Error, PyException);
create_exception!(ruldap3, InvalidFilterError, Ruldap3Error);
create_exception!(ruldap3, LdapSearchFailedError, Ruldap3Error);

struct LdapError(RustLdapError);
impl From<LdapError> for PyErr {
    fn from(error: LdapError) -> Self {
        match error.0 {
            // TODO: split out more as needed
            RustLdapError::FilterParsing => InvalidFilterError::new_err(error.0.to_string()),

            RustLdapError::LdapResult { result } => LdapSearchFailedError::new_err(format!(
                "Received error from ldap server: {}",
                result.to_string()
            )),
            _ => Ruldap3Error::new_err(error.0.to_string()),
        }
    }
}

impl From<RustLdapError> for LdapError {
    fn from(other: RustLdapError) -> Self {
        Self(other)
    }
}
#[pyclass]
pub enum LDAPSearchScope {
    BASE,
    ONE,
    SUB,
}
impl From<&LDAPSearchScope> for RustScope {
    fn from(scope: &LDAPSearchScope) -> Self {
        match scope {
            LDAPSearchScope::BASE => RustScope::Base,
            LDAPSearchScope::ONE => RustScope::OneLevel,
            LDAPSearchScope::SUB => RustScope::Subtree,
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

#[derive(Debug)]
#[pyclass]
pub struct SearchEntry {
    #[pyo3(get)]
    pub dn: String,
    #[pyo3(get)]
    pub attrs: HashMap<String, Vec<String>>,
    #[pyo3(get)]
    pub bin_attrs: HashMap<String, Vec<Vec<u8>>>,
}
impl From<RustSearchEntry> for SearchEntry {
    fn from(search_entry: RustSearchEntry) -> Self {
        SearchEntry {
            dn: search_entry.dn,
            attrs: search_entry.attrs,
            bin_attrs: search_entry.bin_attrs,
        }
    }
}

#[pyclass]
struct Connection {
    ldap: Ldap,
}

#[pymethods]
impl Connection {
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
                return Err(LdapError::from(e).into());
            }
            return Ok(());
        })
    }

    pub fn search<'a>(
        &self,
        py: pyo3::Python<'a>,
        base: String,
        filtr: String,
        attrs: Vec<String>,
        scope: &LDAPSearchScope,
        timeout_sec: u64,
    ) -> PyResult<&'a PyAny> {
        let mut ldap = self.ldap.clone();

        let rust_scope = RustScope::from(scope);

        pyo3_asyncio::tokio::future_into_py(py, async move {
            let ldap_result = match ldap
                .with_timeout(Duration::new(timeout_sec, 0))
                .search(&base, rust_scope, &filtr, attrs)
                .await
            {
                Ok(ldap_result) => ldap_result,
                Err(e) => return Err(LdapError::from(e).into()),
            };

            let (rs, _res) = match ldap_result.success() {
                Ok((rs, _res)) => (rs, _res),
                Err(e) => return Err(LdapError::from(e).into()),
            };

            let mut vec: Vec<SearchEntry> = Vec::new();

            for entry in rs {
                let py_search_entry = SearchEntry::from(RustSearchEntry::construct(entry));
                vec.push(py_search_entry);
            }

            return Ok(vec);
        })
    }
}

#[pyfunction]
fn connect<'a>(py: Python<'a>, ldap_server: String, timeout_sec: u64) -> PyResult<&'a PyAny> {
    pyo3_asyncio::tokio::future_into_py(py, async move {
        let settings: LdapConnSettings =
            LdapConnSettings::new().set_conn_timeout(Duration::new(timeout_sec, 0));

        let ldap_conn = LdapConnAsync::with_settings(settings, &ldap_server).await;

        let (conn, ldap) = match ldap_conn {
            Ok((conn, ldap)) => (conn, ldap),
            Err(e) => {
                return Err(LdapError::from(e).into());
            }
        };

        ldap3::drive!(conn);

        return Ok(Connection { ldap });
    })
}

#[pymodule]
fn ruldap3(py: Python, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(is_ldap_filter_valid, m)?)?;
    m.add_function(wrap_pyfunction!(connect, m)?)?;
    m.add_class::<SearchEntry>()?;
    m.add_class::<Connection>()?;
    m.add_class::<LDAPSearchScope>()?;
    m.add("Ruldap3Error", py.get_type::<Ruldap3Error>())?;
    m.add("InvalidFilterError", py.get_type::<InvalidFilterError>())?;
    m.add(
        "LdapSearchFailedError",
        py.get_type::<LdapSearchFailedError>(),
    )?;
    Ok(())
}
