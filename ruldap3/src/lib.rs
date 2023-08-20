use std::collections::HashMap;
use std::time::Duration;

use ldap3::result::LdapError;
use ldap3::{Ldap, LdapConnAsync, LdapConnSettings, Scope, SearchEntry};
use pyo3::create_exception;
use pyo3::exceptions::PyException;
use std::borrow::Cow;

use ldap3::{ldap_escape, parse_filter};
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyType};

// TODO: When pyo3 gets better exception support
// (see https://github.com/PyO3/pyo3/issues/295.),
// add some properties to the exceptions.
create_exception!(ruldap3, Ruldap3Error, PyException);
create_exception!(ruldap3, IoError, Ruldap3Error);
create_exception!(ruldap3, OpSendError, Ruldap3Error);
create_exception!(ruldap3, ResultRecvError, Ruldap3Error);
create_exception!(ruldap3, IdScrubSendError, Ruldap3Error);
create_exception!(ruldap3, MiscSendError, Ruldap3Error);
create_exception!(ruldap3, TimeoutError, Ruldap3Error);
create_exception!(ruldap3, FilterParsingError, Ruldap3Error);
create_exception!(ruldap3, EndOfStreamError, Ruldap3Error);
create_exception!(ruldap3, UrlParsingError, Ruldap3Error);
create_exception!(ruldap3, LdapResultError, Ruldap3Error);
create_exception!(ruldap3, DecodingUTF8Error, Ruldap3Error);

struct PyLdapError(LdapError);
impl From<PyLdapError> for PyErr {
    fn from(error: PyLdapError) -> Self {
        match error.0 {
            // We map every error in `ldap3::result::LdapError` that seems likely that
            // we'll ever stumble across (so no TLS etc.) to a corresponding Python exception.
            LdapError::Io { source } => IoError::new_err(source.to_string()),
            LdapError::OpSend { source } => OpSendError::new_err(source.to_string()),
            LdapError::ResultRecv { source } => ResultRecvError::new_err(source.to_string()),
            LdapError::IdScrubSend { source } => IdScrubSendError::new_err(source.to_string()),
            LdapError::MiscSend { source } => MiscSendError::new_err(source.to_string()),
            LdapError::Timeout { elapsed } => TimeoutError::new_err(elapsed.to_string()),
            LdapError::FilterParsing => FilterParsingError::new_err(error.0.to_string()),
            LdapError::EndOfStream => EndOfStreamError::new_err(error.0.to_string()),
            LdapError::UrlParsing { source } => UrlParsingError::new_err(source.to_string()),
            LdapError::LdapResult { result } => LdapResultError::new_err(format!(
                "Received error from ldap server: {}",
                result.to_string()
            )),
            LdapError::DecodingUTF8 => DecodingUTF8Error::new_err(error.0.to_string()),
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
    pub bin_attrs: HashMap<String, Vec<Py<PyBytes>>>,
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

            // The binary attributes are returned as `Vec<u8>` from ldap3,
            // and that doesn't play very well with pyo3, as it gets
            // mapped to `list[int]` and it's all very slow. So we grab the
            // GIL and do the conversion ourselves.
            // TODO: Should we convert all the types?
            Python::with_gil(|py| {
                let vec: Vec<PySearchEntry> = rs
                    .into_iter()
                    .map(|re| {
                        let search_entry = SearchEntry::construct(re);
                        PySearchEntry {
                            dn: search_entry.dn,
                            attrs: search_entry.attrs,
                            bin_attrs: search_entry
                                .bin_attrs
                                .into_iter()
                                .map(|(k, v)| {
                                    (
                                        k,
                                        v.into_iter()
                                            .map(|f| PyBytes::new(py, &f).into())
                                            .collect(),
                                    )
                                })
                                .collect(),
                        }
                    })
                    .collect();

                return Ok(vec);
            })
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

    // Exceptions
    m.add("Ruldap3Error", py.get_type::<Ruldap3Error>())?;

    m.add("IoError", py.get_type::<IoError>())?;
    m.add("OpSendError", py.get_type::<OpSendError>())?;
    m.add("ResultRecvError", py.get_type::<ResultRecvError>())?;
    m.add("IdScrubSendError", py.get_type::<IdScrubSendError>())?;
    m.add("MiscSendError", py.get_type::<MiscSendError>())?;
    m.add("TimeoutError", py.get_type::<TimeoutError>())?;
    m.add("FilterParsingError", py.get_type::<FilterParsingError>())?;
    m.add("EndOfStreamError", py.get_type::<EndOfStreamError>())?;
    m.add("UrlParsingError", py.get_type::<UrlParsingError>())?;
    m.add("LdapResultError", py.get_type::<LdapResultError>())?;
    m.add("DecodingUTF8Error", py.get_type::<DecodingUTF8Error>())?;

    Ok(())
}
