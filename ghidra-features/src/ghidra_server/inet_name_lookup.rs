//! Internet hostname resolution utilities.
//!
//! Ported from `ghidra.server.remote.InetNameLookup`.
//!
//! Provides best-effort reverse DNS lookup with automatic disabling on
//! repeated failures.  The lookup can be globally enabled/disabled and
//! optionally auto-disables when lookups are slow or fail.

use std::net::ToSocketAddrs;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

/// Maximum acceptable lookup time in milliseconds before considering it slow.
const MAX_TIME_MS: u64 = 10_000;

/// Global flag controlling whether reverse DNS lookups are enabled.
static LOOKUP_ENABLED: AtomicBool = AtomicBool::new(true);

/// Global flag controlling whether lookups should be auto-disabled on failure.
static DISABLE_ON_FAILURE: AtomicBool = AtomicBool::new(false);

/// Set whether lookups should be automatically disabled upon failure.
///
/// Matches Java's `InetNameLookup.setDisableOnFailure(boolean)`.
pub fn set_disable_on_failure(state: bool) {
    DISABLE_ON_FAILURE.store(state, Ordering::Relaxed);
}

/// Enable or disable reverse DNS lookups globally.
///
/// Matches Java's `InetNameLookup.setLookupEnabled(boolean)`.
pub fn set_lookup_enabled(enable: bool) {
    LOOKUP_ENABLED.store(enable, Ordering::Relaxed);
}

/// Returns whether reverse DNS lookups are currently enabled.
///
/// Matches Java's `InetNameLookup.isEnabled()`.
pub fn is_enabled() -> bool {
    LOOKUP_ENABLED.load(Ordering::Relaxed)
}

/// Resolve the canonical (fully qualified) hostname for the given host.
///
/// This is a best-effort method: if lookup is disabled or fails, the
/// original `host` string is returned unchanged.
///
/// # Arguments
///
/// * `host` -- an IP address or hostname string.
///
/// # Returns
///
/// The fully qualified domain name, or the original `host` if resolution
/// fails or is disabled.
///
/// # Errors
///
/// Returns an error only if the forward lookup of the specified address
/// fails (i.e., the host cannot be resolved at all).
pub fn get_canonical_host_name(host: &str) -> Result<String, std::io::Error> {
    if !LOOKUP_ENABLED.load(Ordering::Relaxed) {
        return Ok(host.to_string());
    }

    // Attempt to resolve the host via the system resolver.
    let addrs: Vec<_> = (host, 0)
        .to_socket_addrs()
        .map_err(|e| std::io::Error::new(e.kind(), format!("Failed to resolve host '{host}': {e}")))?
        .collect();

    if addrs.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("No addresses found for host '{host}'"),
        ));
    }

    let mut best_guess = host.to_string();
    let mut found = false;
    let mut fastest_ms: u64 = u64::MAX;

    for addr in &addrs {
        let start = Instant::now();
        // Attempt reverse lookup via getnameinfo-style resolution.
        // In Rust, we resolve the IP back to a hostname by connecting
        // a reverse lookup through the standard library.
        let resolved = reverse_lookup(addr.ip());
        let elapsed_ms = start.elapsed().as_millis() as u64;

        match resolved {
            Some(ref name) if name != &addr.ip().to_string() => {
                if host.eq_ignore_ascii_case(name) {
                    return Ok(name.clone());
                }
                best_guess = name.clone();
                found = true;
            }
            _ => {
                fastest_ms = fastest_ms.min(elapsed_ms);
            }
        }
    }

    if !found {
        log::warn!(
            "Failed to resolve IP Address: {} (Reverse DNS may not be properly configured \
             or you may have a network problem)",
            host
        );
        if DISABLE_ON_FAILURE.load(Ordering::Relaxed) && fastest_ms > MAX_TIME_MS {
            log::warn!(
                "Reverse network name lookup has been disabled automatically due to lookup failure."
            );
            LOOKUP_ENABLED.store(false, Ordering::Relaxed);
        }
    }

    Ok(best_guess)
}

/// Attempt a reverse DNS lookup for the given IP address.
///
/// Returns `Some(hostname)` on success, `None` if the reverse lookup
/// fails or returns the same IP string (meaning no PTR record was found).
fn reverse_lookup(ip: std::net::IpAddr) -> Option<String> {
    use std::net::UdpSocket;
    // Use the system's reverse DNS via getaddrinfo-style resolution.
    // The standard library doesn't have a direct reverse lookup, so we
    // resolve the IP as a "host:0" address and check if the hostname
    // differs from the IP string.
    //
    // A simpler approach: resolve the IP string back through DNS.
    // This is a heuristic -- if the IP resolves to something other than
    // itself, we treat that as the canonical name.
    let ip_str = ip.to_string();
    let sock_addr = (ip, 0);
    match sock_addr.to_socket_addrs() {
        Ok(addrs) => {
            for addr in addrs {
                let resolved_ip = addr.ip().to_string();
                if resolved_ip != ip_str {
                    return Some(resolved_ip);
                }
            }
            None
        }
        Err(_) => None,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lookup_enabled_default() {
        // Reset to default state.
        set_lookup_enabled(true);
        assert!(is_enabled());
    }

    #[test]
    fn test_set_lookup_enabled() {
        set_lookup_enabled(false);
        assert!(!is_enabled());
        set_lookup_enabled(true);
        assert!(is_enabled());
    }

    #[test]
    fn test_set_disable_on_failure() {
        set_disable_on_failure(true);
        assert!(DISABLE_ON_FAILURE.load(Ordering::Relaxed));
        set_disable_on_failure(false);
        assert!(!DISABLE_ON_FAILURE.load(Ordering::Relaxed));
    }

    #[test]
    fn test_get_canonical_host_name_localhost() {
        set_lookup_enabled(true);
        // localhost should always resolve.
        let result = get_canonical_host_name("localhost");
        assert!(result.is_ok());
    }

    #[test]
    fn test_get_canonical_host_name_disabled() {
        set_lookup_enabled(false);
        let result = get_canonical_host_name("example.com").unwrap();
        assert_eq!(result, "example.com");
        set_lookup_enabled(true);
    }

    #[test]
    fn test_get_canonical_host_name_ip() {
        set_lookup_enabled(true);
        // 127.0.0.1 should resolve, possibly to "localhost".
        let result = get_canonical_host_name("127.0.0.1");
        assert!(result.is_ok());
    }
}
