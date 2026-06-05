//! Extra utility functions for the debugger plugin.
//!
//! Ported from Ghidra's `MiscellaneousUtils`, `ProgramLocationUtils`,
//! and `ProgramURLUtils`.
//!
//! Provides helper functions for program locations, URL handling,
//! and miscellaneous debugger operations.

use serde::{Deserialize, Serialize};

/// Parse a Ghidra program URL into its component parts.
///
/// Ported from `ProgramURLUtils.parseProgramURL()`.
///
/// A Ghidra program URL has the format:
/// `scheme://authority/path#fragment`
///
/// For example: `file:///home/user/program#0x400000`
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProgramUrl {
    /// The URL scheme (e.g., "file", "ghidra").
    pub scheme: String,
    /// The URL authority (host/port).
    pub authority: String,
    /// The path to the program file.
    pub path: String,
    /// The fragment (often an address).
    pub fragment: Option<String>,
}

impl ProgramUrl {
    /// Parse a URL string into a ProgramUrl.
    pub fn parse(url: &str) -> Option<Self> {
        let (scheme, rest) = if let Some(pos) = url.find("://") {
            (&url[..pos], &url[pos + 3..])
        } else {
            return None;
        };

        let (authority, path_and_fragment) = if let Some(pos) = rest.find('/') {
            (&rest[..pos], &rest[pos..])
        } else {
            (rest, "")
        };

        let (path, fragment) = if let Some(pos) = path_and_fragment.find('#') {
            (
                &path_and_fragment[..pos],
                Some(path_and_fragment[pos + 1..].to_string()),
            )
        } else {
            (path_and_fragment, None)
        };

        Some(ProgramUrl {
            scheme: scheme.to_string(),
            authority: authority.to_string(),
            path: path.to_string(),
            fragment,
        })
    }

    /// Get the full URL string.
    pub fn to_url(&self) -> String {
        let mut url = format!("{}://{}{}", self.scheme, self.authority, self.path);
        if let Some(ref fragment) = self.fragment {
            url.push('#');
            url.push_str(fragment);
        }
        url
    }

    /// Get the address from the fragment, if it's a valid hex address.
    pub fn fragment_address(&self) -> Option<u64> {
        self.fragment.as_ref().and_then(|f| {
            let clean = f.trim_start_matches("0x").trim_start_matches("0X");
            u64::from_str_radix(clean, 16).ok()
        })
    }
}

/// Create a Ghidra program URL from components.
pub fn make_program_url(scheme: &str, path: &str, address: Option<u64>) -> String {
    let mut url = format!("{}:///{}", scheme, path);
    if let Some(addr) = address {
        url.push_str(&format!("#0x{:x}", addr));
    }
    url
}

/// Check if a string looks like a Ghidra program URL.
pub fn is_program_url(s: &str) -> bool {
    s.contains("://") && (s.starts_with("file:") || s.starts_with("ghidra:"))
}

/// Extract the file name from a program URL path.
pub fn extract_program_name(url: &str) -> Option<String> {
    ProgramUrl::parse(url).map(|pu| {
        pu.path
            .rsplit('/')
            .next()
            .unwrap_or(&pu.path)
            .to_string()
    })
}

/// A reference to a program location (address within a program).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProgramLocationRef {
    /// The program URL.
    pub program_url: String,
    /// The address within the program.
    pub address: u64,
    /// The address space name.
    pub space: Option<String>,
}

impl ProgramLocationRef {
    /// Create a new program location reference.
    pub fn new(program_url: impl Into<String>, address: u64) -> Self {
        Self {
            program_url: program_url.into(),
            address,
            space: None,
        }
    }

    /// Set the address space.
    pub fn with_space(mut self, space: impl Into<String>) -> Self {
        self.space = Some(space.into());
        self
    }

    /// Get the display string for this location.
    pub fn display_string(&self) -> String {
        let name = extract_program_name(&self.program_url).unwrap_or_else(|| "unknown".to_string());
        match &self.space {
            Some(s) => format!("{}:{}:0x{:x}", name, s, self.address),
            None => format!("{}:0x{:x}", name, self.address),
        }
    }
}

/// Debounce coalescer for program events.
///
/// Prevents rapid-fire event delivery by coalescing events that occur
/// within a short time window.
#[derive(Debug, Clone)]
pub struct EventDebouncer<T: Clone> {
    /// The pending event.
    pending: Option<T>,
    /// The debounce window in milliseconds.
    window_ms: u64,
    /// The last event time (logical counter).
    last_time: u64,
    /// Current logical time.
    current_time: u64,
}

impl<T: Clone> EventDebouncer<T> {
    /// Create a new event debouncer with the given window.
    pub fn new(window_ms: u64) -> Self {
        Self {
            pending: None,
            window_ms,
            last_time: 0,
            current_time: 0,
        }
    }

    /// Submit an event to the debouncer.
    ///
    /// Returns `true` if the event should be delivered immediately.
    /// The first event after creation is always delivered immediately.
    pub fn submit(&mut self, event: T) -> bool {
        self.current_time += 1;
        let time_since_last = self.current_time - self.last_time;

        if self.last_time == 0 || time_since_last >= self.window_ms {
            self.last_time = self.current_time;
            self.pending = None;
            true
        } else {
            self.pending = Some(event);
            false
        }
    }

    /// Flush any pending event.
    pub fn flush(&mut self) -> Option<T> {
        if self.pending.is_some() {
            self.last_time = self.current_time;
            self.pending.take()
        } else {
            None
        }
    }

    /// Check if there's a pending event.
    pub fn has_pending(&self) -> bool {
        self.pending.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_program_url_parse() {
        let url = ProgramUrl::parse("file:///home/user/prog#0x400000").unwrap();
        assert_eq!(url.scheme, "file");
        assert_eq!(url.authority, "");
        assert_eq!(url.path, "/home/user/prog");
        assert_eq!(url.fragment, Some("0x400000".to_string()));
    }

    #[test]
    fn test_program_url_parse_no_fragment() {
        let url = ProgramUrl::parse("ghidra://server/trace").unwrap();
        assert_eq!(url.scheme, "ghidra");
        assert_eq!(url.authority, "server");
        assert_eq!(url.path, "/trace");
        assert!(url.fragment.is_none());
    }

    #[test]
    fn test_program_url_parse_invalid() {
        assert!(ProgramUrl::parse("not-a-url").is_none());
        assert!(ProgramUrl::parse("").is_none());
    }

    #[test]
    fn test_program_url_to_url() {
        let url = ProgramUrl {
            scheme: "file".to_string(),
            authority: "".to_string(),
            path: "/home/user/prog".to_string(),
            fragment: Some("0x400000".to_string()),
        };
        assert_eq!(url.to_url(), "file:///home/user/prog#0x400000");
    }

    #[test]
    fn test_program_url_to_url_no_fragment() {
        let url = ProgramUrl {
            scheme: "ghidra".to_string(),
            authority: "server".to_string(),
            path: "/trace".to_string(),
            fragment: None,
        };
        assert_eq!(url.to_url(), "ghidra://server/trace");
    }

    #[test]
    fn test_fragment_address() {
        let url = ProgramUrl::parse("file:///prog#0x400000").unwrap();
        assert_eq!(url.fragment_address(), Some(0x400000));

        let url2 = ProgramUrl::parse("file:///prog#400000").unwrap();
        assert_eq!(url2.fragment_address(), Some(0x400000));

        let url3 = ProgramUrl::parse("file:///prog#not-a-number").unwrap();
        assert!(url3.fragment_address().is_none());

        let url4 = ProgramUrl::parse("file:///prog").unwrap();
        assert!(url4.fragment_address().is_none());
    }

    #[test]
    fn test_make_program_url() {
        let url = make_program_url("file", "home/user/prog", Some(0x400000));
        assert_eq!(url, "file:///home/user/prog#0x400000");

        let url2 = make_program_url("ghidra", "server/trace", None);
        assert_eq!(url2, "ghidra:///server/trace");
    }

    #[test]
    fn test_is_program_url() {
        assert!(is_program_url("file:///home/user/prog"));
        assert!(is_program_url("ghidra://server/trace"));
        assert!(!is_program_url("http://example.com"));
        assert!(!is_program_url("not-a-url"));
    }

    #[test]
    fn test_extract_program_name() {
        assert_eq!(
            extract_program_name("file:///home/user/my_program"),
            Some("my_program".to_string())
        );
        assert_eq!(
            extract_program_name("file:///prog.exe#0x400"),
            Some("prog.exe".to_string())
        );
        assert!(extract_program_name("not-a-url").is_none());
    }

    #[test]
    fn test_program_location_ref() {
        let loc = ProgramLocationRef::new("file:///prog", 0x400000);
        assert_eq!(loc.address, 0x400000);
        assert!(loc.space.is_none());
        assert_eq!(loc.display_string(), "prog:0x400000");

        let loc = loc.with_space("ram");
        assert_eq!(loc.space, Some("ram".to_string()));
        assert_eq!(loc.display_string(), "prog:ram:0x400000");
    }

    #[test]
    fn test_event_debouncer_immediate() {
        let mut debouncer = EventDebouncer::<String>::new(5);
        // First event should be delivered immediately
        assert!(debouncer.submit("event1".to_string()));
        assert!(!debouncer.has_pending());
    }

    #[test]
    fn test_event_debouncer_coalesce() {
        let mut debouncer = EventDebouncer::<String>::new(10);
        debouncer.submit("event1".to_string());

        // Subsequent events within the window should be coalesced
        for i in 0..5 {
            let coalesced = debouncer.submit(format!("event{}", i + 2));
            assert!(!coalesced);
        }
        assert!(debouncer.has_pending());

        let flushed = debouncer.flush();
        assert!(flushed.is_some());
        assert!(!debouncer.has_pending());
    }

    #[test]
    fn test_event_debouncer_flush_empty() {
        let mut debouncer = EventDebouncer::<String>::new(5);
        assert!(debouncer.flush().is_none());
    }

    #[test]
    fn test_program_url_roundtrip() {
        let original = "file:///home/user/prog#0x400000";
        let parsed = ProgramUrl::parse(original).unwrap();
        assert_eq!(parsed.to_url(), original);
    }
}
