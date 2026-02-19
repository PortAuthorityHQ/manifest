use std::path::Path;

use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyList};

use manifest_core::{
    self, AgentIdentity, IdentitySource, MerkleTree as RustMerkleTree, PolicyConfig as RustPolicyConfig,
    Receipt as RustReceipt, ReceiptBuilder as RustReceiptBuilder, Signer as RustSigner,
    Storage as RustStorage, StorageBackend,
};

// ── Error conversion ────────────────────────────────────────────────────

fn to_py_err(e: manifest_core::ManifestError) -> PyErr {
    PyRuntimeError::new_err(format!("{e}"))
}

// ── Helper: Receipt <-> Python dict ─────────────────────────────────────

fn receipt_to_py(py: Python<'_>, receipt: &RustReceipt) -> PyResult<PyObject> {
    let value = serde_json::to_value(receipt).map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
    let bound = pythonize::pythonize(py, &value).map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
    Ok(bound.unbind())
}

fn py_to_json_value(obj: &Bound<'_, PyAny>) -> PyResult<serde_json::Value> {
    pythonize::depythonize(obj).map_err(|e| PyRuntimeError::new_err(e.to_string()))
}

// ── Signer ──────────────────────────────────────────────────────────────

#[pyclass(unsendable)]
struct PySigner {
    inner: RustSigner,
}

#[pymethods]
impl PySigner {
    #[staticmethod]
    fn generate() -> Self {
        PySigner {
            inner: RustSigner::generate(),
        }
    }

    #[staticmethod]
    fn from_file(path: &str) -> PyResult<Self> {
        let signer = RustSigner::from_file(Path::new(path)).map_err(to_py_err)?;
        Ok(PySigner { inner: signer })
    }

    fn save(&self, path: &str) -> PyResult<()> {
        self.inner.save(Path::new(path)).map_err(to_py_err)
    }

    fn save_public_key(&self, path: &str) -> PyResult<()> {
        self.inner.save_public_key(Path::new(path)).map_err(to_py_err)
    }

    fn sign(&self, data: &[u8]) -> String {
        self.inner.sign(data)
    }

    fn verify(&self, data: &[u8], signature: &str) -> PyResult<bool> {
        self.inner.verify(data, signature).map_err(to_py_err)
    }

    fn public_key_bytes<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        let bytes = self.inner.verifying_key().to_bytes();
        PyBytes::new(py, &bytes)
    }
}

// ── MerkleTree ──────────────────────────────────────────────────────────

#[pyclass(unsendable)]
struct PyMerkleTree {
    inner: RustMerkleTree,
}

#[pymethods]
impl PyMerkleTree {
    #[new]
    fn new() -> Self {
        PyMerkleTree {
            inner: RustMerkleTree::new(),
        }
    }

    #[staticmethod]
    fn from_leaves(leaves: Vec<Vec<u8>>) -> PyResult<Self> {
        let leaves: Vec<[u8; 32]> = leaves
            .into_iter()
            .map(|v| {
                v.try_into()
                    .map_err(|_| PyRuntimeError::new_err("each leaf must be exactly 32 bytes"))
            })
            .collect::<PyResult<_>>()?;
        Ok(PyMerkleTree {
            inner: RustMerkleTree::from_leaves(leaves),
        })
    }

    fn append(&mut self, leaf: Vec<u8>) -> PyResult<()> {
        let arr: [u8; 32] = leaf
            .try_into()
            .map_err(|_| PyRuntimeError::new_err("leaf must be exactly 32 bytes"))?;
        self.inner.append(arr);
        Ok(())
    }

    fn root(&self) -> String {
        self.inner.root()
    }

    fn __len__(&self) -> usize {
        self.inner.len()
    }

    fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    fn proof<'py>(&self, py: Python<'py>, index: usize) -> PyResult<Option<PyObject>> {
        match self.inner.proof(index) {
            None => Ok(None),
            Some(proof) => {
                let list = PyList::empty(py);
                for (is_left, hash) in proof {
                    let tuple = (is_left, PyBytes::new(py, &hash));
                    list.append(tuple)?;
                }
                Ok(Some(list.into_any().unbind()))
            }
        }
    }

    #[staticmethod]
    fn verify_proof(leaf: Vec<u8>, proof: Vec<(bool, Vec<u8>)>, root: Vec<u8>) -> PyResult<bool> {
        let leaf: [u8; 32] = leaf
            .try_into()
            .map_err(|_| PyRuntimeError::new_err("leaf must be 32 bytes"))?;
        let root: [u8; 32] = root
            .try_into()
            .map_err(|_| PyRuntimeError::new_err("root must be 32 bytes"))?;
        let proof: Vec<(bool, [u8; 32])> = proof
            .into_iter()
            .map(|(is_left, h)| {
                let arr: [u8; 32] = h
                    .try_into()
                    .map_err(|_| PyRuntimeError::new_err("proof hash must be 32 bytes"))?;
                Ok((is_left, arr))
            })
            .collect::<PyResult<_>>()?;
        Ok(RustMerkleTree::verify_proof(leaf, &proof, &root))
    }

    fn leaves<'py>(&self, py: Python<'py>) -> PyObject {
        let list = PyList::empty(py);
        for leaf in self.inner.leaves() {
            let _ = list.append(PyBytes::new(py, leaf));
        }
        list.into_any().unbind()
    }
}

// ── Storage ─────────────────────────────────────────────────────────────

#[pyclass(unsendable)]
struct PyStorage {
    inner: Option<RustStorage>,
}

#[pymethods]
impl PyStorage {
    #[staticmethod]
    fn open(path: &str) -> PyResult<Self> {
        let storage = RustStorage::open(Path::new(path)).map_err(to_py_err)?;
        Ok(PyStorage {
            inner: Some(storage),
        })
    }

    #[staticmethod]
    fn in_memory() -> PyResult<Self> {
        let storage = RustStorage::in_memory().map_err(to_py_err)?;
        Ok(PyStorage {
            inner: Some(storage),
        })
    }

    #[pyo3(signature = (receipt_dict, session_id=None))]
    fn insert_receipt(&self, receipt_dict: &Bound<'_, PyAny>, session_id: Option<&str>) -> PyResult<()> {
        let s = self.storage()?;
        let value: serde_json::Value = py_to_json_value(receipt_dict)?;
        let receipt: RustReceipt =
            serde_json::from_value(value).map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
        s.insert_receipt(&receipt, session_id).map_err(to_py_err)
    }

    fn get_receipt_by_id(&self, py: Python<'_>, id: &str) -> PyResult<Option<PyObject>> {
        let s = self.storage()?;
        match s.get_receipt_by_id(id).map_err(to_py_err)? {
            None => Ok(None),
            Some(r) => Ok(Some(receipt_to_py(py, &r)?)),
        }
    }

    fn get_receipt_by_hash(&self, py: Python<'_>, hash: &str) -> PyResult<Option<PyObject>> {
        let s = self.storage()?;
        match s.get_receipt_by_hash(hash).map_err(to_py_err)? {
            None => Ok(None),
            Some(r) => Ok(Some(receipt_to_py(py, &r)?)),
        }
    }

    fn list_receipts(&self, py: Python<'_>, limit: usize, offset: usize) -> PyResult<PyObject> {
        let s = self.storage()?;
        let receipts = s.list_receipts(limit, offset).map_err(to_py_err)?;
        receipts_to_py_list(py, &receipts)
    }

    fn list_by_session(
        &self,
        py: Python<'_>,
        session_id: &str,
        limit: usize,
        offset: usize,
    ) -> PyResult<PyObject> {
        let s = self.storage()?;
        let receipts = s.list_by_session(session_id, limit, offset).map_err(to_py_err)?;
        receipts_to_py_list(py, &receipts)
    }

    fn latest_receipt_hash(&self) -> PyResult<Option<String>> {
        let s = self.storage()?;
        s.latest_receipt_hash().map_err(to_py_err)
    }

    fn count_receipts(&self) -> PyResult<usize> {
        let s = self.storage()?;
        s.count_receipts().map_err(to_py_err)
    }

    fn insert_merkle_leaf(&self, index: u64, leaf_hash: Vec<u8>) -> PyResult<()> {
        let s = self.storage()?;
        let arr: [u8; 32] = leaf_hash
            .try_into()
            .map_err(|_| PyRuntimeError::new_err("leaf_hash must be 32 bytes"))?;
        s.insert_merkle_leaf(index, &arr).map_err(to_py_err)
    }

    fn load_merkle_leaves<'py>(&self, py: Python<'py>) -> PyResult<PyObject> {
        let s = self.storage()?;
        let leaves = s.load_merkle_leaves().map_err(to_py_err)?;
        let list = PyList::empty(py);
        for leaf in leaves {
            let _ = list.append(PyBytes::new(py, &leaf));
        }
        Ok(list.into_any().unbind())
    }

    fn prune_before(&self, cutoff: &str) -> PyResult<usize> {
        let s = self.storage()?;
        s.prune_before(cutoff).map_err(to_py_err)
    }

    fn close(&mut self) {
        self.inner = None;
    }
}

impl PyStorage {
    fn storage(&self) -> PyResult<&RustStorage> {
        self.inner
            .as_ref()
            .ok_or_else(|| PyRuntimeError::new_err("storage is closed"))
    }
}

fn receipts_to_py_list(py: Python<'_>, receipts: &[RustReceipt]) -> PyResult<PyObject> {
    let list = PyList::empty(py);
    for r in receipts {
        list.append(receipt_to_py(py, r)?)?;
    }
    Ok(list.into_any().unbind())
}

// ── PolicyConfig ────────────────────────────────────────────────────────

#[pyclass(unsendable)]
struct PyPolicyConfig {
    inner: RustPolicyConfig,
}

#[pymethods]
impl PyPolicyConfig {
    #[staticmethod]
    fn load(path: &str) -> PyResult<Self> {
        let config = RustPolicyConfig::load(Path::new(path)).map_err(to_py_err)?;
        Ok(PyPolicyConfig { inner: config })
    }

    #[pyo3(signature = (tool_name, input, output=None, agent_name=None))]
    fn evaluate(
        &self,
        tool_name: &str,
        input: &Bound<'_, PyAny>,
        output: Option<&Bound<'_, PyAny>>,
        agent_name: Option<&str>,
    ) -> PyResult<Vec<String>> {
        let input_val = py_to_json_value(input)?;
        let output_val = match output {
            Some(o) => Some(py_to_json_value(o)?),
            None => None,
        };
        Ok(self
            .inner
            .evaluate(tool_name, &input_val, output_val.as_ref(), agent_name))
    }

    #[pyo3(signature = (agent_name=None))]
    fn to_snapshot(&self, py: Python<'_>, agent_name: Option<&str>) -> PyResult<PyObject> {
        let snapshot = self.inner.to_snapshot(agent_name);
        let value =
            serde_json::to_value(&snapshot).map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
        let bound = pythonize::pythonize(py, &value).map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
        Ok(bound.unbind())
    }

    #[pyo3(signature = (tool_name, agent_name=None))]
    fn is_tool_allowed(&self, tool_name: &str, agent_name: Option<&str>) -> Option<bool> {
        self.inner.is_tool_allowed(tool_name, agent_name)
    }

    fn snapshot_hash(&self) -> String {
        self.inner.snapshot_hash()
    }

    fn reset_rate_limits(&self) {
        self.inner.reset_rate_limits();
    }
}

// ── build_receipt (replaces ReceiptBuilder for Python) ───────────────────

#[pyfunction]
#[pyo3(signature = (
    signer,
    merkle,
    agent_name,
    tool,
    input,
    output = None,
    error_code = None,
    error_message = None,
    error_data = None,
    policy_snapshot = None,
    delta_authorized = None,
    delta_violations = None,
    previous_receipt = None,
    agent_version = None,
    agent_source = None,
))]
fn build_receipt(
    py: Python<'_>,
    signer: &PySigner,
    merkle: &mut PyMerkleTree,
    agent_name: &str,
    tool: &str,
    input: &Bound<'_, PyAny>,
    output: Option<&Bound<'_, PyAny>>,
    error_code: Option<i64>,
    error_message: Option<String>,
    error_data: Option<&Bound<'_, PyAny>>,
    policy_snapshot: Option<&Bound<'_, PyAny>>,
    delta_authorized: Option<bool>,
    delta_violations: Option<Vec<String>>,
    previous_receipt: Option<String>,
    agent_version: Option<String>,
    agent_source: Option<String>,
) -> PyResult<PyObject> {
    let input_val = py_to_json_value(input)?;
    let output_val = match output {
        Some(o) => Some(py_to_json_value(o)?),
        None => None,
    };

    let error = match (error_code, error_message) {
        (Some(code), Some(msg)) => {
            let data = match error_data {
                Some(d) => Some(py_to_json_value(d)?),
                None => None,
            };
            Some(manifest_core::ActionError {
                code,
                message: msg,
                data,
            })
        }
        _ => None,
    };

    let action = manifest_core::Action {
        tool: tool.to_string(),
        input: input_val,
        output: output_val,
        error,
    };

    let source = match agent_source.as_deref() {
        Some("mcp_handshake") => IdentitySource::McpHandshake,
        Some("config") => IdentitySource::Config,
        _ => IdentitySource::Environment,
    };

    let agent = AgentIdentity {
        name: agent_name.to_string(),
        version: agent_version,
        deployer: None,
        environment: None,
        source,
        verified: false,
    };

    let policy = match policy_snapshot {
        Some(snap) => {
            let val: manifest_core::PolicySnapshot =
                pythonize::depythonize(snap).map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
            Some(val)
        }
        None => None,
    };

    let delta = match delta_authorized {
        Some(auth) => Some(manifest_core::receipt::Delta {
            authorized: auth,
            violations: delta_violations.unwrap_or_default(),
        }),
        None => None,
    };

    let receipt = RustReceiptBuilder::new()
        .agent(agent)
        .action(action)
        .policy(policy)
        .delta(delta)
        .previous_receipt(previous_receipt)
        .build(&signer.inner, &mut merkle.inner)
        .map_err(to_py_err)?;

    receipt_to_py(py, &receipt)
}

// ── Free functions ──────────────────────────────────────────────────────

#[pyfunction]
fn sha256<'py>(py: Python<'py>, data: &[u8]) -> Bound<'py, PyBytes> {
    let hash = manifest_core::sha256(data);
    PyBytes::new(py, &hash)
}

#[pyfunction]
fn sha256_hex(data: &[u8]) -> String {
    manifest_core::sha256_hex(data)
}

#[pyfunction]
fn load_public_key<'py>(py: Python<'py>, path: &str) -> PyResult<Bound<'py, PyBytes>> {
    let key = manifest_core::load_public_key(Path::new(path)).map_err(to_py_err)?;
    Ok(PyBytes::new(py, &key))
}

#[pyfunction]
fn verify_with_public_key(pub_key: Vec<u8>, data: &[u8], signature: &str) -> PyResult<bool> {
    let arr: [u8; 32] = pub_key
        .try_into()
        .map_err(|_| PyRuntimeError::new_err("public key must be 32 bytes"))?;
    manifest_core::verify_with_public_key(&arr, data, signature).map_err(to_py_err)
}

// ── content_hash helper ─────────────────────────────────────────────────

#[pyfunction]
fn content_hash(receipt_dict: &Bound<'_, PyAny>) -> PyResult<String> {
    let value: serde_json::Value = py_to_json_value(receipt_dict)?;
    let receipt: RustReceipt =
        serde_json::from_value(value).map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
    Ok(receipt.content_hash())
}

#[pyfunction]
fn canonical_bytes<'py>(py: Python<'py>, receipt_dict: &Bound<'_, PyAny>) -> PyResult<Bound<'py, PyBytes>> {
    let value: serde_json::Value = py_to_json_value(receipt_dict)?;
    let receipt: RustReceipt =
        serde_json::from_value(value).map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
    Ok(PyBytes::new(py, &receipt.canonical_bytes()))
}

// ── Module ──────────────────────────────────────────────────────────────

#[pymodule]
fn manifest_py(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PySigner>()?;
    m.add_class::<PyMerkleTree>()?;
    m.add_class::<PyStorage>()?;
    m.add_class::<PyPolicyConfig>()?;
    m.add_function(wrap_pyfunction!(build_receipt, m)?)?;
    m.add_function(wrap_pyfunction!(sha256, m)?)?;
    m.add_function(wrap_pyfunction!(sha256_hex, m)?)?;
    m.add_function(wrap_pyfunction!(load_public_key, m)?)?;
    m.add_function(wrap_pyfunction!(verify_with_public_key, m)?)?;
    m.add_function(wrap_pyfunction!(content_hash, m)?)?;
    m.add_function(wrap_pyfunction!(canonical_bytes, m)?)?;
    Ok(())
}
