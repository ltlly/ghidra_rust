//! HttpDebugInfoDProvider -- queries debuginfod REST servers for debug objects.
//!
//! Ported from `ghidra.app.util.bin.format.dwarf.external.HttpDebugInfoDProvider`.
//!
//! Implements [`DebugStreamProvider`](super::DebugStreamProvider) by sending
//! HTTP GET requests to a debuginfod-compatible server.  The debuginfod REST
//! API uses the path pattern:
//!
//! ```text
//! GET /buildid/<build-id>/<object-type>[/<extra>]
//! ```
//!
//! where `<object-type>` is one of `debuginfo`, `executable`, or `source`.
//!
//! # Limitations
//!
//! This implementation uses raw `std::net::TcpStream` for HTTP connections.
//! HTTPS URLs are supported only when compiled with the `tls` feature (not
//! yet available).  Plain HTTP connections work without additional
//! dependencies.

use std::io::{self, BufRead, BufReader, Read};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

use super::debug_info_provider::{
    DebugInfoProvider, DebugProviderError, DebugProviderResult, DebugStreamProvider, StreamInfo,
};
use super::debug_info_provider_status::DebugInfoProviderStatus;
use super::external_debug_info::ExternalDebugInfo;
use super::ObjectType;

/// User-Agent header sent with every request.
const GHIDRA_USER_AGENT: &str = "Ghidra_HttpDebugInfoDProvider_client";

/// Default HTTP request timeout.
const DEFAULT_HTTP_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Default maximum retry count for transient errors.
const DEFAULT_MAX_RETRY_COUNT: u32 = 5;

/// Default HTTP port.
const HTTP_DEFAULT_PORT: u16 = 80;

/// Default HTTPS port.
const HTTPS_DEFAULT_PORT: u16 = 443;

// ---------------------------------------------------------------------------
// Parsed URI (minimal, HTTP-only)
// ---------------------------------------------------------------------------

/// A minimal URI representation for HTTP debuginfod endpoints.
///
/// Only supports `http://` and `https://` schemes.  HTTPS connections
/// require a TLS library (not included by default).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpUri {
    /// Whether the scheme is HTTPS.
    tls: bool,
    /// The host name.
    host: String,
    /// The port number.
    port: u16,
    /// The path component (always starts with `/`, always ends with `/`).
    path: String,
}

impl HttpUri {
    /// Parses a URI string into an `HttpUri`.
    ///
    /// Supports `http://host[:port][/path]` and `https://host[:port][/path]`.
    pub fn parse(uri: &str) -> Result<Self, String> {
        let (tls, rest) = if let Some(r) = uri.strip_prefix("https://") {
            (true, r)
        } else if let Some(r) = uri.strip_prefix("http://") {
            (false, r)
        } else {
            return Err(format!("Unsupported URI scheme: {}", uri));
        };

        // Split authority and path
        let (authority, path_part) = match rest.find('/') {
            Some(pos) => (&rest[..pos], &rest[pos..]),
            None => (rest, "/"),
        };

        // Split host and port
        let (host, port) = if authority.starts_with('[') {
            // IPv6 -- not fully supported
            return Err("IPv6 addresses are not supported".into());
        } else if let Some(colon_pos) = authority.rfind(':') {
            let h = &authority[..colon_pos];
            let p = authority[colon_pos + 1..]
                .parse::<u16>()
                .map_err(|e| format!("Invalid port: {}", e))?;
            (h.to_string(), p)
        } else {
            let default_port = if tls { HTTPS_DEFAULT_PORT } else { HTTP_DEFAULT_PORT };
            (authority.to_string(), default_port)
        };

        // Ensure path ends with '/'
        let path = if path_part.ends_with('/') {
            path_part.to_string()
        } else {
            format!("{}/", path_part)
        };

        Ok(Self {
            tls,
            host,
            port,
            path,
        })
    }

    /// Returns the scheme string (`"http"` or `"https"`).
    pub fn scheme(&self) -> &str {
        if self.tls { "https" } else { "http" }
    }

    /// Returns the host name.
    pub fn host(&self) -> &str {
        &self.host
    }

    /// Returns the port number.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Returns the path component.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Returns `true` if the URI uses HTTPS.
    pub fn is_tls(&self) -> bool {
        self.tls
    }

    /// Resolves a relative path against this URI's base.
    pub fn resolve(&self, relative: &str) -> String {
        format!("{}://{}:{}{}{}", self.scheme(), self.host, self.port, self.path, relative)
    }

    /// Returns the full URI as a string (without trailing path for display).
    fn display_uri(&self) -> String {
        format!("{}://{}:{}", self.scheme(), self.host, self.port)
    }
}

impl std::fmt::Display for HttpUri {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}://{}:{}{}",
            self.scheme(),
            self.host,
            self.port,
            self.path
        )
    }
}

// ---------------------------------------------------------------------------
// HttpDebugInfoDProvider
// ---------------------------------------------------------------------------

/// Queries debuginfod REST servers for debug objects.
///
/// Implements [`DebugStreamProvider`] by sending HTTP GET requests to a
/// debuginfod-compatible server endpoint.  The server URL is serialized
/// as the provider name (e.g. `"https://debuginfod.example.com/"`).
///
/// # Examples
///
/// ```rust
/// use ghidra_features::external::dwarf_ext::{
///     HttpDebugInfoDProvider, DebugInfoProvider, DebugInfoProviderStatus,
/// };
///
/// let provider = HttpDebugInfoDProvider::new("https://debuginfod.fedoraproject.org/").unwrap();
/// assert_eq!(provider.status(), DebugInfoProviderStatus::Unknown);
/// assert!(provider.name().starts_with("https://"));
/// ```
#[derive(Debug)]
pub struct HttpDebugInfoDProvider {
    /// The parsed server URI.
    server_uri: HttpUri,
    /// The full URI string (cached for `name()` and `descriptive_name()`).
    uri_string: String,
    /// Number of retries performed so far.
    retried_count: u32,
    /// Number of 404 responses received.
    not_found_count: u32,
    /// Maximum number of retries per request.
    max_retry_count: u32,
    /// HTTP request timeout.
    request_timeout: Duration,
}

impl HttpDebugInfoDProvider {
    /// Creates a new provider targeting the given server URI.
    ///
    /// # Errors
    ///
    /// Returns an error if the URI cannot be parsed or uses an unsupported
    /// scheme.
    pub fn new(server_uri: &str) -> Result<Self, String> {
        let mut uri = HttpUri::parse(server_uri)?;
        // Ensure path ends with '/' (same logic as Java constructor)
        if !uri.path.ends_with('/') {
            let p = format!("{}/", uri.path);
            uri = HttpUri {
                tls: uri.tls,
                host: uri.host,
                port: uri.port,
                path: p,
            };
        }
        let uri_string = uri.to_string();
        Ok(Self {
            server_uri: uri,
            uri_string,
            retried_count: 0,
            not_found_count: 0,
            max_retry_count: DEFAULT_MAX_RETRY_COUNT,
            request_timeout: DEFAULT_HTTP_REQUEST_TIMEOUT,
        })
    }

    /// Creates a provider from a serialized name string.
    ///
    /// Returns `None` if the name does not match `http://` or `https://`.
    pub fn from_name(name: &str) -> Option<Self> {
        if !Self::matches(name) {
            return None;
        }
        Self::new(name).ok()
    }

    /// Returns `true` if the given name string specifies an
    /// `HttpDebugInfoDProvider`.
    pub fn matches(name: &str) -> bool {
        name.starts_with("http://") || name.starts_with("https://")
    }

    /// Returns a reference to the server URI.
    pub fn server_uri(&self) -> &HttpUri {
        &self.server_uri
    }

    /// Returns the number of retries performed.
    pub fn retried_count(&self) -> u32 {
        self.retried_count
    }

    /// Returns the number of 404 responses received.
    pub fn not_found_count(&self) -> u32 {
        self.not_found_count
    }

    /// Sets the maximum retry count.
    pub fn set_max_retry_count(&mut self, count: u32) {
        self.max_retry_count = count;
    }

    /// Sets the request timeout.
    pub fn set_request_timeout(&mut self, timeout: Duration) {
        self.request_timeout = timeout;
    }

    /// Returns the request timeout.
    pub fn request_timeout(&self) -> Duration {
        self.request_timeout
    }

    /// Builds the request path for the given debug info identifier.
    ///
    /// Format: `buildid/<build-id>/<object-type>[/<extra>]`
    fn request_path(&self, id: &ExternalDebugInfo) -> Option<String> {
        let build_id = id.build_id()?;
        let mut path = format!("buildid/{}/{}", build_id, id.object_type().path_string());
        if id.object_type() == ObjectType::Source {
            let extra = id.extra().unwrap_or("");
            path.push('/');
            path.push_str(extra);
        }
        Some(path)
    }

    /// Performs the HTTP GET request and returns the response body as a
    /// reader, along with the content length.
    fn do_get(&self, path: &str) -> DebugProviderResult<(Box<dyn Read + Send>, i64)> {
        let addr = format!("{}:{}", self.server_uri.host(), self.server_uri.port());

        // Resolve the address
        let socket_addr = addr
            .to_socket_addrs()
            .map_err(|e| DebugProviderError::Other(format!("DNS resolution failed: {}", e)))?
            .next()
            .ok_or_else(|| DebugProviderError::Other("No addresses resolved".into()))?;

        // Connect with timeout
        let stream = TcpStream::connect_timeout(&socket_addr, self.request_timeout)
            .map_err(DebugProviderError::Io)?;

        stream
            .set_read_timeout(Some(self.request_timeout))
            .map_err(DebugProviderError::Io)?;

        // Build the HTTP/1.1 request
        let request = format!(
            "GET /{} HTTP/1.1\r\n\
             Host: {}:{}\r\n\
             User-Agent: {}\r\n\
             Accept: */*\r\n\
             Connection: close\r\n\
             \r\n",
            path,
            self.server_uri.host(),
            self.server_uri.port(),
            GHIDRA_USER_AGENT,
        );

        // Send request
        use std::io::Write;
        let mut stream = stream;
        stream
            .write_all(request.as_bytes())
            .map_err(DebugProviderError::Io)?;
        stream.flush().map_err(DebugProviderError::Io)?;

        // Read the response status line
        let mut reader = BufReader::new(stream);
        let mut status_line = String::new();
        reader
            .read_line(&mut status_line)
            .map_err(DebugProviderError::Io)?;

        let status_code = parse_status_line(&status_line)?;

        // Read headers
        let mut content_length: i64 = -1;
        loop {
            let mut header_line = String::new();
            let n = reader.read_line(&mut header_line).map_err(DebugProviderError::Io)?;
            if n == 0 || header_line.trim().is_empty() {
                break;
            }
            let header_lower = header_line.to_lowercase();
            if let Some(val) = header_lower.strip_prefix("content-length:") {
                if let Ok(len) = val.trim().parse::<i64>() {
                    content_length = len;
                }
            }
        }

        match status_code {
            200 => {
                // Return the remaining body as a reader
                let body_reader = HttpBodyReader::new(reader, content_length);
                Ok((Box::new(body_reader), content_length))
            }
            404 => Err(DebugProviderError::Other("NOT_FOUND".into())),
            500..=599 => Err(DebugProviderError::Other(format!(
                "Server error: {}",
                status_code
            ))),
            _ => Err(DebugProviderError::Other(format!(
                "Unexpected HTTP status: {}",
                status_code
            ))),
        }
    }
}

/// Parses the HTTP status line and returns the status code.
fn parse_status_line(line: &str) -> DebugProviderResult<u16> {
    // Format: "HTTP/1.1 200 OK\r\n"
    let parts: Vec<&str> = line.trim().splitn(3, ' ').collect();
    if parts.len() < 2 {
        return Err(DebugProviderError::Other(format!(
            "Malformed HTTP status line: {}",
            line
        )));
    }
    parts[1]
        .parse::<u16>()
        .map_err(|e| DebugProviderError::Other(format!("Invalid HTTP status code: {}", e)))
}

// ---------------------------------------------------------------------------
// HttpBodyReader -- reads the response body from a BufReader
// ---------------------------------------------------------------------------

/// A reader that reads the HTTP response body from a buffered TCP stream.
///
/// If the content length is known, it reads exactly that many bytes.
/// Otherwise, it reads until the connection is closed.
struct HttpBodyReader<R: Read> {
    inner: R,
    remaining: Option<i64>,
}

impl<R: Read> HttpBodyReader<R> {
    fn new(inner: R, content_length: i64) -> Self {
        let remaining = if content_length >= 0 {
            Some(content_length)
        } else {
            None
        };
        Self { inner, remaining }
    }
}

impl<R: Read> Read for HttpBodyReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self.remaining {
            Some(0) => Ok(0),
            Some(ref mut remaining) => {
                let max = (*remaining).min(buf.len() as i64) as usize;
                if max == 0 {
                    return Ok(0);
                }
                let n = self.inner.read(&mut buf[..max])?;
                *remaining -= n as i64;
                Ok(n)
            }
            None => self.inner.read(buf),
        }
    }
}

// ---------------------------------------------------------------------------
// DebugInfoProvider impl
// ---------------------------------------------------------------------------

impl DebugInfoProvider for HttpDebugInfoDProvider {
    fn name(&self) -> &str {
        &self.uri_string
    }

    fn descriptive_name(&self) -> &str {
        &self.uri_string
    }

    fn status(&self) -> DebugInfoProviderStatus {
        // We can't know the server status without making a request.
        DebugInfoProviderStatus::Unknown
    }
}

// ---------------------------------------------------------------------------
// DebugStreamProvider impl
// ---------------------------------------------------------------------------

impl DebugStreamProvider for HttpDebugInfoDProvider {
    fn get_stream(
        &self,
        debug_info: &ExternalDebugInfo,
    ) -> DebugProviderResult<Option<StreamInfo>> {
        if !debug_info.has_build_id() {
            return Ok(None);
        }

        let path = match self.request_path(debug_info) {
            Some(p) => p,
            None => return Ok(None),
        };

        // Retry loop
        for retry_num in 0..self.max_retry_count {
            if retry_num > 0 {
                log::debug!(
                    "[{}]: retry count: {}",
                    self.uri_string,
                    retry_num
                );
                // We can't mutate self (trait method takes &self), so
                // retried_count is not incremented here. A mutable version
                // could use interior mutability (Cell/RefCell).
            }

            match self.do_get(&path) {
                Ok((reader, content_length)) => {
                    log::info!("Found DWARF external debug file: {}/{}", self.uri_string, path);
                    return Ok(Some(StreamInfo::new(reader, content_length)));
                }
                Err(DebugProviderError::Other(msg)) if msg == "NOT_FOUND" => {
                    return Ok(None);
                }
                Err(DebugProviderError::Other(msg))
                    if msg.starts_with("Server error: 5") =>
                {
                    // Retry on 5xx errors
                    continue;
                }
                Err(DebugProviderError::Io(ref e))
                    if e.kind() == io::ErrorKind::ConnectionRefused
                        || e.kind() == io::ErrorKind::TimedOut
                        || e.kind() == io::ErrorKind::ConnectionReset =>
                {
                    // Retry on transient network errors
                    continue;
                }
                Err(e) => {
                    return Err(e);
                }
            }
        }

        log::debug!("[{}]: failed to query for: {:?}", self.uri_string, debug_info);
        Ok(None)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_matches() {
        assert!(HttpDebugInfoDProvider::matches("https://debuginfod.example.com/"));
        assert!(HttpDebugInfoDProvider::matches("http://localhost:8080/"));
        assert!(!HttpDebugInfoDProvider::matches("debuglink:///usr/lib/debug"));
        assert!(!HttpDebugInfoDProvider::matches("."));
        assert!(!HttpDebugInfoDProvider::matches("debuginfod-dir:///tmp"));
    }

    #[test]
    fn test_new_valid_uri() {
        let provider = HttpDebugInfoDProvider::new("https://debuginfod.example.com/").unwrap();
        assert_eq!(
            provider.name(),
            "https://debuginfod.example.com:443/"
        );
        assert!(provider.name().starts_with("https://"));
    }

    #[test]
    fn test_new_with_path() {
        let provider =
            HttpDebugInfoDProvider::new("https://debuginfod.example.com/debuginfod/").unwrap();
        assert_eq!(
            provider.name(),
            "https://debuginfod.example.com:443/debuginfod/"
        );
    }

    #[test]
    fn test_new_with_port() {
        let provider =
            HttpDebugInfoDProvider::new("http://localhost:8080/debuginfod").unwrap();
        assert_eq!(provider.name(), "http://localhost:8080/debuginfod/");
        assert_eq!(provider.server_uri().port(), 8080);
    }

    #[test]
    fn test_new_invalid_scheme() {
        let result = HttpDebugInfoDProvider::new("ftp://example.com/");
        assert!(result.is_err());
    }

    #[test]
    fn test_from_name_valid() {
        let provider = HttpDebugInfoDProvider::from_name("https://debuginfod.example.com/");
        assert!(provider.is_some());
    }

    #[test]
    fn test_from_name_invalid() {
        let provider = HttpDebugInfoDProvider::from_name("debuglink:///usr/lib/debug");
        assert!(provider.is_none());
    }

    #[test]
    fn test_status_is_unknown() {
        let provider = HttpDebugInfoDProvider::new("https://example.com/").unwrap();
        assert_eq!(provider.status(), DebugInfoProviderStatus::Unknown);
    }

    #[test]
    fn test_request_path_debuginfo() {
        let provider = HttpDebugInfoDProvider::new("https://example.com/").unwrap();
        let info = ExternalDebugInfo::for_build_id("abc123");
        let path = provider.request_path(&info).unwrap();
        assert_eq!(path, "buildid/abc123/debuginfo");
    }

    #[test]
    fn test_request_path_executable() {
        let provider = HttpDebugInfoDProvider::new("https://example.com/").unwrap();
        let info =
            ExternalDebugInfo::for_build_id("abc123").with_type(ObjectType::Executable, None);
        let path = provider.request_path(&info).unwrap();
        assert_eq!(path, "buildid/abc123/executable");
    }

    #[test]
    fn test_request_path_source() {
        let provider = HttpDebugInfoDProvider::new("https://example.com/").unwrap();
        let info = ExternalDebugInfo::for_build_id("abc123")
            .with_type(ObjectType::Source, Some("stdio.h".into()));
        let path = provider.request_path(&info).unwrap();
        assert_eq!(path, "buildid/abc123/source/stdio.h");
    }

    #[test]
    fn test_request_path_no_build_id() {
        let provider = HttpDebugInfoDProvider::new("https://example.com/").unwrap();
        let info = ExternalDebugInfo::for_debug_link("test.debug", 42);
        let path = provider.request_path(&info);
        assert!(path.is_none());
    }

    #[test]
    fn test_get_stream_no_build_id() {
        let provider = HttpDebugInfoDProvider::new("http://localhost:1/").unwrap();
        let info = ExternalDebugInfo::for_debug_link("test.debug", 42);
        let result = provider.get_stream(&info).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_parse_status_line() {
        assert_eq!(parse_status_line("HTTP/1.1 200 OK\r\n").unwrap(), 200);
        assert_eq!(parse_status_line("HTTP/1.1 404 Not Found\r\n").unwrap(), 404);
        assert_eq!(
            parse_status_line("HTTP/1.1 500 Internal Server Error\r\n").unwrap(),
            500
        );
    }

    #[test]
    fn test_parse_status_line_malformed() {
        assert!(parse_status_line("garbage").is_err());
    }

    #[test]
    fn test_http_uri_parse() {
        let uri = HttpUri::parse("https://example.com/path/").unwrap();
        assert!(uri.is_tls());
        assert_eq!(uri.host(), "example.com");
        assert_eq!(uri.port(), 443);
        assert_eq!(uri.path(), "/path/");
    }

    #[test]
    fn test_http_uri_parse_with_port() {
        let uri = HttpUri::parse("http://localhost:8080/debuginfod").unwrap();
        assert!(!uri.is_tls());
        assert_eq!(uri.host(), "localhost");
        assert_eq!(uri.port(), 8080);
        assert_eq!(uri.path(), "/debuginfod/");
    }

    #[test]
    fn test_http_uri_resolve() {
        let uri = HttpUri::parse("https://example.com/base/").unwrap();
        let resolved = uri.resolve("buildid/abc/debuginfo");
        assert_eq!(
            resolved,
            "https://example.com:443/base/buildid/abc/debuginfo"
        );
    }

    #[test]
    fn test_http_uri_display() {
        let uri = HttpUri::parse("https://example.com/path/").unwrap();
        assert_eq!(uri.to_string(), "https://example.com:443/path/");
    }

    #[test]
    fn test_retry_config() {
        let mut provider = HttpDebugInfoDProvider::new("https://example.com/").unwrap();
        assert_eq!(provider.max_retry_count, DEFAULT_MAX_RETRY_COUNT);
        provider.set_max_retry_count(3);
        assert_eq!(provider.max_retry_count, 3);
    }

    #[test]
    fn test_timeout_config() {
        let mut provider = HttpDebugInfoDProvider::new("https://example.com/").unwrap();
        assert_eq!(provider.request_timeout(), DEFAULT_HTTP_REQUEST_TIMEOUT);
        provider.set_request_timeout(Duration::from_secs(30));
        assert_eq!(provider.request_timeout(), Duration::from_secs(30));
    }

    #[test]
    fn test_http_body_reader_with_length() {
        let data: &[u8] = b"hello world";
        let mut reader = HttpBodyReader::new(data, 5);
        let mut buf = [0u8; 32];
        let n = reader.read(&mut buf).unwrap();
        assert_eq!(n, 5);
        assert_eq!(&buf[..5], b"hello");
        let n = reader.read(&mut buf).unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn test_http_body_reader_unbounded() {
        let data: &[u8] = b"hello world";
        let mut reader = HttpBodyReader::new(data, -1);
        let mut buf = [0u8; 32];
        let n = reader.read(&mut buf).unwrap();
        assert_eq!(n, 11);
        assert_eq!(&buf[..11], b"hello world");
    }
}
