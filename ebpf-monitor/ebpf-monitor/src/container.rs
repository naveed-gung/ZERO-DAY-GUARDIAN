//! Container identity resolution.
//!
//! Maps kernel cgroup IDs to container IDs by reading the cgroup hierarchy
//! from `/proc/{pid}/cgroup` and resolving container runtime metadata.
//!
//! Author: Naveed Gung

use std::collections::HashMap;
use std::fs;
use std::sync::{Arc, RwLock};

use log::{debug, warn};

/// Cache for cgroup ID to container ID mappings.
#[derive(Clone)]
pub struct ContainerResolver {
    cache: Arc<RwLock<HashMap<u64, String>>>,
}

impl ContainerResolver {
    pub fn new() -> Self {
        Self {
            cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Resolve a cgroup ID to a container ID string.
    ///
    /// First checks the cache, then falls back to reading /proc/{pid}/cgroup
    /// to extract the container ID from the cgroup path.
    pub fn resolve(&self, cgroup_id: u64, pid: u32) -> Option<String> {
        // Check cache first
        if let Ok(cache) = self.cache.read() {
            if let Some(id) = cache.get(&cgroup_id) {
                return Some(id.clone());
            }
        }

        // Try to resolve from /proc
        let container_id = self.resolve_from_proc(pid)?;

        // Cache the result
        if let Ok(mut cache) = self.cache.write() {
            cache.insert(cgroup_id, container_id.clone());
        }

        Some(container_id)
    }

    /// Read /proc/{pid}/cgroup and extract the container ID from the path.
    ///
    /// Container cgroup paths typically look like:
    ///   - Docker: /docker/<container_id>
    ///   - containerd: /kubepods/pod<pod_uid>/<container_id>
    ///   - CRI-O: /crio-<container_id>
    fn resolve_from_proc(&self, pid: u32) -> Option<String> {
        let cgroup_path = format!("/proc/{}/cgroup", pid);
        let content = match fs::read_to_string(&cgroup_path) {
            Ok(c) => c,
            Err(e) => {
                debug!("Failed to read {}: {}", cgroup_path, e);
                return None;
            }
        };

        for line in content.lines() {
            // Format: hierarchy-ID:controller-list:cgroup-path
            let parts: Vec<&str> = line.splitn(3, ':').collect();
            if parts.len() < 3 {
                continue;
            }

            let cgroup_path = parts[2];

            // Try to extract container ID from various runtime patterns
            if let Some(id) = extract_container_id(cgroup_path) {
                return Some(id);
            }
        }

        warn!("Could not resolve container ID for pid {}", pid);
        None
    }

    /// Evict stale entries from the cache (call periodically).
    pub fn evict_stale(&self) {
        if let Ok(mut cache) = self.cache.write() {
            // Keep cache bounded to prevent memory leaks
            if cache.len() > 10_000 {
                cache.clear();
                debug!("Container resolver cache cleared (exceeded 10k entries)");
            }
        }
    }
}

/// Extract a container ID from a cgroup path string.
///
/// Handles Docker, containerd (Kubernetes), and CRI-O cgroup path formats.
fn extract_container_id(cgroup_path: &str) -> Option<String> {
    // Pattern: /docker/<64-hex-char-id>
    if let Some(idx) = cgroup_path.rfind("/docker/") {
        let id_start = idx + "/docker/".len();
        let candidate = &cgroup_path[id_start..];
        if is_hex_id(candidate, 64) {
            return Some(candidate[..64].to_string());
        }
    }

    // Pattern: /kubepods/.../pod<uid>/<64-hex-char-id>
    // The last path component is the container ID
    if cgroup_path.contains("/kubepods") {
        if let Some(last_slash) = cgroup_path.rfind('/') {
            let candidate = &cgroup_path[last_slash + 1..];
            // Strip common prefixes
            let cleaned = candidate
                .strip_prefix("cri-containerd-")
                .or_else(|| candidate.strip_prefix("crio-"))
                .or_else(|| candidate.strip_suffix(".scope"))
                .unwrap_or(candidate);

            if cleaned.len() >= 12 && cleaned.chars().all(|c| c.is_ascii_hexdigit()) {
                return Some(cleaned.to_string());
            }
        }
    }

    // Pattern: /crio-<container_id>
    if let Some(idx) = cgroup_path.find("crio-") {
        let id_start = idx + "crio-".len();
        let candidate = &cgroup_path[id_start..];
        let end = candidate.find('.').unwrap_or(candidate.len());
        let cleaned = &candidate[..end];
        if cleaned.len() >= 12 && cleaned.chars().all(|c| c.is_ascii_hexdigit()) {
            return Some(cleaned.to_string());
        }
    }

    None
}

/// Check if a string starts with `expected_len` hexadecimal characters.
fn is_hex_id(s: &str, expected_len: usize) -> bool {
    s.len() >= expected_len
        && s[..expected_len].chars().all(|c| c.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_docker_id() {
        let path = "/docker/abc123def456abc123def456abc123def456abc123def456abc123def456abcd";
        let id = extract_container_id(path);
        assert!(id.is_some());
        assert_eq!(id.unwrap().len(), 64);
    }

    #[test]
    fn test_extract_kubepods_id() {
        let path = "/kubepods/besteffort/pod1234/abc123def456abc123def456abc123def456abc123def456abc123def456abcd";
        let id = extract_container_id(path);
        assert!(id.is_some());
    }

    #[test]
    fn test_extract_crio_id() {
        let path = "/kubepods/crio-abc123def456.scope";
        let id = extract_container_id(path);
        assert!(id.is_some());
    }

    #[test]
    fn test_no_container_id() {
        let path = "/user.slice/user-1000.slice";
        let id = extract_container_id(path);
        assert!(id.is_none());
    }
}
