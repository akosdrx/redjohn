//! Native process-tree memory sampling for RedJohn's resource governor.
//!
//! Replaces repeated `ps` subprocess spawns with one sysinfo snapshot per
//! sample. The Python side keeps its exact `ps` fallback and semantics: an
//! RSS-summed tree walk with shared pages counted once per process, and a
//! deduplicated union for overlapping trees.

use std::collections::{HashMap, HashSet};

use pyo3::prelude::*;
use pyo3::types::PyDict;
use sysinfo::{ProcessesToUpdate, System};

fn snapshot() -> System {
    let mut system = System::new();
    system.refresh_processes(ProcessesToUpdate::All, true);
    system
}

fn children_map(system: &System) -> HashMap<u32, Vec<u32>> {
    let mut children: HashMap<u32, Vec<u32>> = HashMap::new();
    for (pid, process) in system.processes() {
        if let Some(parent) = process.parent() {
            children.entry(parent.as_u32()).or_default().push(pid.as_u32());
        }
    }
    children
}

fn walk(
    system: &System,
    children: &HashMap<u32, Vec<u32>>,
    roots: &[u32],
) -> (u64, usize, Vec<u32>) {
    let mut seen: HashSet<u32> = HashSet::new();
    let mut stack: Vec<u32> = roots.to_vec();
    let mut rss_bytes = 0u64;
    let mut pids: Vec<u32> = Vec::new();
    while let Some(pid) = stack.pop() {
        if !seen.insert(pid) {
            continue;
        }
        if let Some(process) = system.process(sysinfo::Pid::from_u32(pid)) {
            rss_bytes += process.memory();
            pids.push(pid);
        }
        if let Some(kids) = children.get(&pid) {
            stack.extend(kids.iter().copied());
        }
    }
    pids.sort_unstable();
    (rss_bytes, pids.len(), pids)
}

fn sample_dict(py: Python<'_>, rss_bytes: u64, pids: Vec<u32>, available: bool) -> PyResult<Bound<'_, PyDict>> {
    let dict = PyDict::new(py);
    dict.set_item("rss_bytes", rss_bytes)?;
    dict.set_item("process_count", pids.len())?;
    dict.set_item("pids", pids)?;
    dict.set_item("available", available)?;
    Ok(dict)
}

/// Sum resident memory over the process tree rooted at `pid`.
#[pyfunction]
fn sample_process_tree(py: Python<'_>, pid: u32) -> PyResult<Bound<'_, PyDict>> {
    let system = snapshot();
    let children = children_map(&system);
    let (rss_bytes, _count, pids) = walk(&system, &children, &[pid]);
    let available = !pids.is_empty();
    sample_dict(py, rss_bytes, pids, available)
}

/// Sum resident memory over the deduplicated union of the given root trees.
#[pyfunction]
fn sample_process_forest(py: Python<'_>, roots: Vec<u32>) -> PyResult<Bound<'_, PyDict>> {
    let system = snapshot();
    let children = children_map(&system);
    let (rss_bytes, _count, pids) = walk(&system, &children, &roots);
    let pid_set: HashSet<u32> = pids.iter().copied().collect();
    // Matches the ps fallback: an empty root set vacuously satisfies the
    // "all roots found" contract.
    let available = roots.iter().all(|root| pid_set.contains(root));
    sample_dict(py, rss_bytes, pids, available)
}

#[pymodule]
fn redjohn_native(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_function(wrap_pyfunction!(sample_process_tree, module)?)?;
    module.add_function(wrap_pyfunction!(sample_process_forest, module)?)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tree_includes_the_root_process() {
        let system = snapshot();
        let children = children_map(&system);
        let self_pid = std::process::id();
        let (rss_bytes, count, pids) = walk(&system, &children, &[self_pid]);
        assert!(count >= 1);
        assert!(pids.contains(&self_pid));
        assert!(rss_bytes > 0);
    }

    #[test]
    fn forest_union_deduplicates_overlapping_roots() {
        let system = snapshot();
        let children = children_map(&system);
        let self_pid = std::process::id();
        let single = walk(&system, &children, &[self_pid]);
        let double = walk(&system, &children, &[self_pid, self_pid]);
        assert_eq!(single.1, double.1);
        assert_eq!(single.0, double.0);
    }
}
