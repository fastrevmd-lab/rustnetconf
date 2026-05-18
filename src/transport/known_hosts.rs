//! OpenSSH `known_hosts(5)` parser + host-key lookup.
//!
//! Used by [`crate::transport::ssh::HostKeyVerification::KnownHosts`] to pin
//! host keys for a fleet of devices via an OpenSSH-format file. See `man 5
//! known_hosts` for the file format.
//!
//! Supported features:
//! - Plain hostnames, comma-separated host lists
//! - `[host]:port` form (per OpenSSH convention when port != 22)
//! - Wildcard patterns (`*`, `?`)
//! - CIDR patterns (`10.0.0.0/8`, `2001:db8::/32`)
//! - Hashed entries (`|1|<salt>|<hmac>` — HMAC-SHA1)
//! - Multiple key types per host (rsa/ed25519/ecdsa) — match any
//! - `@revoked` markers (fail closed if matched)
//!
//! Deferred: `@cert-authority` (SSH host certificates).

use std::path::Path;

/// A parsed `known_hosts` entry (one non-blank, non-comment line).
#[derive(Debug, Clone)]
pub(crate) struct Entry {
    pub host_spec: HostSpec,
    /// SSH key type label (e.g. `ssh-ed25519`, `ssh-rsa`). Parsed and validated
    /// during line parsing but not currently used at lookup time — the
    /// fingerprint comparison subsumes it.
    #[allow(dead_code)]
    pub key_type: String,
    pub key_blob_b64: String,
    pub marker: Option<Marker>,
}

#[derive(Debug, Clone)]
pub(crate) enum HostSpec {
    /// One or more comma-separated patterns (literal/wildcard/CIDR/`[host]:port`).
    Plain(Vec<Pattern>),
    /// OpenSSH hashed-hostname entry: `|1|<salt>|<HMAC-SHA1(salt, hostname)>`.
    /// The hostname is the literal lookup string OpenSSH would feed in — plain
    /// `host` if port is default 22, else `[host]:port`.
    Hashed { salt: Vec<u8>, mac: Vec<u8> },
}

#[derive(Debug, Clone)]
pub(crate) enum Pattern {
    /// Literal hostname (no wildcards), port-agnostic — matches the host
    /// regardless of port (compat with OpenSSH which treats plain entries
    /// as matching the default port but not strictly).
    Literal(String),
    /// `[host]:port` form — host AND port must match.
    HostPort { host: String, port: u16 },
    /// Glob pattern containing `*` (zero-or-more) and/or `?` (exactly one).
    Wildcard(String),
    /// CIDR network — match host IPs that fall inside the prefix.
    Cidr(CidrNet),
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum CidrNet {
    V4 { network: u32, prefix_len: u8 },
    V6 { network: u128, prefix_len: u8 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Marker {
    Revoked,
    /// Recognized but not validated — see module docs. Lines with this marker
    /// are skipped by [`parse_line`], never reaching this variant in practice;
    /// retained for completeness in case we later honor SSH certs.
    #[allow(dead_code)]
    CertAuthority,
}

impl Entry {
    pub fn host_matches(&self, host: &str, port: u16) -> bool {
        match &self.host_spec {
            HostSpec::Plain(patterns) => patterns.iter().any(|p| p.matches(host, port)),
            HostSpec::Hashed { salt, mac } => {
                // OpenSSH feeds plain `host` for default port, `[host]:port` otherwise.
                let key = if port == 22 {
                    host.to_string()
                } else {
                    format!("[{host}]:{port}")
                };
                hashed_host_matches(salt, mac, key.as_bytes())
            }
        }
    }
}

/// Compute the OpenSSH-style SHA-256 fingerprint (`"SHA256:<base64-unpadded>"`)
/// of a base64-encoded SSH wire-format public key blob.
///
/// Matches the format produced by `russh::keys::PublicKey::fingerprint(Sha256)`
/// and by `ssh-keygen -lf`.
fn fingerprint_from_key_blob_b64(blob_b64: &str) -> Result<String, base64ct::Error> {
    use aws_lc_rs::digest;
    use base64ct::{Base64, Base64Unpadded, Encoding};
    let raw = Base64::decode_vec(blob_b64)?;
    let digest = digest::digest(&digest::SHA256, &raw);
    Ok(format!(
        "SHA256:{}",
        Base64Unpadded::encode_string(digest.as_ref())
    ))
}

/// Constant-time compare of `HMAC-SHA1(salt, key)` against `expected_mac`.
fn hashed_host_matches(salt: &[u8], expected_mac: &[u8], key: &[u8]) -> bool {
    use aws_lc_rs::hmac;
    let hmac_key = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, salt);
    let computed = hmac::sign(&hmac_key, key);
    // Length-then-bytewise compare; aws-lc-rs Tag impls AsRef<[u8]>.
    let computed_bytes = computed.as_ref();
    if computed_bytes.len() != expected_mac.len() {
        return false;
    }
    // Constant-time compare to avoid timing leaks of the file's contents.
    let mut diff: u8 = 0;
    for (a, b) in computed_bytes.iter().zip(expected_mac.iter()) {
        diff |= a ^ b;
    }
    diff == 0
}

impl Pattern {
    fn matches(&self, host: &str, port: u16) -> bool {
        match self {
            Pattern::Literal(s) => s == host,
            Pattern::HostPort { host: h, port: p } => h == host && *p == port,
            Pattern::Wildcard(glob) => glob_matches(glob, host),
            Pattern::Cidr(net) => net.contains(host),
        }
    }
}

impl CidrNet {
    fn contains(&self, host: &str) -> bool {
        use std::net::IpAddr;
        let Ok(addr) = host.parse::<IpAddr>() else {
            return false;
        };
        match (self, addr) {
            (CidrNet::V4 { network, prefix_len }, IpAddr::V4(v4)) => {
                let bits = u32::from(v4);
                let mask = if *prefix_len == 0 {
                    0
                } else {
                    u32::MAX << (32 - *prefix_len)
                };
                (bits & mask) == (*network & mask)
            }
            (CidrNet::V6 { network, prefix_len }, IpAddr::V6(v6)) => {
                let bits = u128::from(v6);
                let mask = if *prefix_len == 0 {
                    0
                } else {
                    u128::MAX << (128 - *prefix_len)
                };
                (bits & mask) == (*network & mask)
            }
            _ => false,
        }
    }
}

fn parse_cidr(token: &str) -> Option<CidrNet> {
    use std::net::IpAddr;
    let (addr_str, prefix_str) = token.split_once('/')?;
    let prefix_len: u8 = prefix_str.parse().ok()?;
    match addr_str.parse::<IpAddr>().ok()? {
        IpAddr::V4(v4) => {
            if prefix_len > 32 {
                return None;
            }
            Some(CidrNet::V4 {
                network: u32::from(v4),
                prefix_len,
            })
        }
        IpAddr::V6(v6) => {
            if prefix_len > 128 {
                return None;
            }
            Some(CidrNet::V6 {
                network: u128::from(v6),
                prefix_len,
            })
        }
    }
}

/// Match a glob pattern (`*` = zero-or-more, `?` = exactly-one) against `text`.
///
/// Iterative implementation with backtracking on `*`. O(n*m) worst case, but
/// inputs are short hostnames so it's negligible. Matches the *entire* text.
fn glob_matches(pattern: &str, text: &str) -> bool {
    let pattern: Vec<char> = pattern.chars().collect();
    let text: Vec<char> = text.chars().collect();
    let (mut pi, mut ti) = (0usize, 0usize);
    let (mut star_pi, mut star_ti): (Option<usize>, usize) = (None, 0);
    while ti < text.len() {
        if pi < pattern.len() && (pattern[pi] == '?' || pattern[pi] == text[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < pattern.len() && pattern[pi] == '*' {
            star_pi = Some(pi);
            star_ti = ti;
            pi += 1;
        } else if let Some(sp) = star_pi {
            pi = sp + 1;
            star_ti += 1;
            ti = star_ti;
        } else {
            return false;
        }
    }
    // Consume trailing `*`s in the pattern.
    while pi < pattern.len() && pattern[pi] == '*' {
        pi += 1;
    }
    pi == pattern.len()
}

/// Parse a single host pattern token (one comma-separated piece of the
/// host field). Recognizes `[host]:port` form.
fn parse_pattern(token: &str) -> Result<Pattern, String> {
    if let Some(rest) = token.strip_prefix('[') {
        let close = rest
            .find(']')
            .ok_or_else(|| format!("unterminated '[' in pattern {token:?}"))?;
        let host = &rest[..close];
        let after = &rest[close + 1..];
        let port_str = after
            .strip_prefix(':')
            .ok_or_else(|| format!("missing ':port' after ']' in pattern {token:?}"))?;
        let port: u16 = port_str
            .parse()
            .map_err(|_| format!("invalid port in pattern {token:?}"))?;
        return Ok(Pattern::HostPort {
            host: host.to_string(),
            port,
        });
    }
    if token.contains('/') {
        if let Some(net) = parse_cidr(token) {
            return Ok(Pattern::Cidr(net));
        }
        // Falls through to literal/wildcard — '/' isn't otherwise meaningful.
    }
    if token.contains('*') || token.contains('?') {
        return Ok(Pattern::Wildcard(token.to_string()));
    }
    Ok(Pattern::Literal(token.to_string()))
}

/// Parse one line of a `known_hosts` file.
///
/// Returns `Ok(None)` for blank lines and comments. Returns `Ok(Some(Entry))`
/// for a valid entry. Returns `Err` for malformed lines.
pub(crate) fn parse_line(line: &str, line_no: usize) -> Result<Option<Entry>, KnownHostsError> {
    let trimmed = line.trim_start();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return Ok(None);
    }
    let mut parts = trimmed.split_whitespace();
    let first = parts.next().ok_or_else(|| KnownHostsError::Parse {
        line: line_no,
        reason: "missing host field".into(),
    })?;
    let (marker, host_field) = match first {
        "@revoked" => {
            let host = parts.next().ok_or_else(|| KnownHostsError::Parse {
                line: line_no,
                reason: "@revoked: missing host field".into(),
            })?;
            (Some(Marker::Revoked), host)
        }
        "@cert-authority" => {
            // SSH host certificates — not yet supported. Skip silently.
            tracing::debug!(
                line = line_no,
                "skipping unsupported @cert-authority known_hosts line"
            );
            return Ok(None);
        }
        s if s.starts_with('@') => {
            return Err(KnownHostsError::Parse {
                line: line_no,
                reason: format!("unknown marker {s:?}"),
            });
        }
        host => (None, host),
    };
    let key_type = parts.next().ok_or_else(|| KnownHostsError::Parse {
        line: line_no,
        reason: "missing key type".into(),
    })?;
    let key_blob = parts.next().ok_or_else(|| KnownHostsError::Parse {
        line: line_no,
        reason: "missing key blob".into(),
    })?;

    let host_spec = parse_host_spec(host_field, line_no)?;
    Ok(Some(Entry {
        host_spec,
        key_type: key_type.to_string(),
        key_blob_b64: key_blob.to_string(),
        marker,
    }))
}

fn parse_host_spec(host_field: &str, line_no: usize) -> Result<HostSpec, KnownHostsError> {
    use base64ct::{Base64, Encoding};
    if let Some(rest) = host_field.strip_prefix("|1|") {
        let (salt_b64, mac_b64) = rest.split_once('|').ok_or_else(|| KnownHostsError::Parse {
            line: line_no,
            reason: "hashed entry missing second '|' separator".into(),
        })?;
        let salt = Base64::decode_vec(salt_b64).map_err(|e| KnownHostsError::Parse {
            line: line_no,
            reason: format!("hashed entry: bad base64 salt: {e}"),
        })?;
        let mac = Base64::decode_vec(mac_b64).map_err(|e| KnownHostsError::Parse {
            line: line_no,
            reason: format!("hashed entry: bad base64 hmac: {e}"),
        })?;
        return Ok(HostSpec::Hashed { salt, mac });
    }
    let mut patterns: Vec<Pattern> = Vec::new();
    for token in host_field.split(',').filter(|s| !s.is_empty()) {
        let pat = parse_pattern(token).map_err(|reason| KnownHostsError::Parse {
            line: line_no,
            reason,
        })?;
        patterns.push(pat);
    }
    if patterns.is_empty() {
        return Err(KnownHostsError::Parse {
            line: line_no,
            reason: "empty host field".into(),
        });
    }
    Ok(HostSpec::Plain(patterns))
}

/// Outcome of looking up `host:port` against a `known_hosts` file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum LookupOutcome {
    /// At least one entry matched the host and the fingerprint.
    Match,
    /// Host matched but no entry's fingerprint matched the actual key.
    /// Includes one example file fingerprint for diagnostics.
    Mismatch { file_fp: String },
    /// No entry in the file matched the host.
    NotFound,
    /// An `@revoked` marker matched the host + key. Fail closed.
    Revoked,
}

/// Errors raised while reading or parsing a `known_hosts` file.
#[derive(Debug, thiserror::Error)]
pub(crate) enum KnownHostsError {
    #[error("known_hosts I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("known_hosts parse error at line {line}: {reason}")]
    Parse { line: usize, reason: String },
}

/// Look up `host:port` in `path` and compare against `actual_fp`.
///
/// `actual_fp` is expected in the format produced by
/// `russh::keys::PublicKey::fingerprint(HashAlg::Sha256).to_string()` —
/// typically `"SHA256:<base64>"`.
pub(crate) fn lookup(
    path: &Path,
    host: &str,
    port: u16,
    actual_fp: &str,
) -> Result<LookupOutcome, KnownHostsError> {
    use std::io::{BufRead, BufReader};
    let file = std::fs::File::open(path)?;
    let reader = BufReader::new(file);

    let mut matched_host = false;
    let mut fp_match_found = false;
    let mut first_mismatch_fp: Option<String> = None;

    for (i, line_res) in reader.lines().enumerate() {
        let line = line_res?;
        let line_no = i + 1;
        let entry = match parse_line(&line, line_no) {
            Ok(Some(e)) => e,
            Ok(None) => continue,
            Err(e) => {
                tracing::warn!(error = %e, "skipping malformed known_hosts line");
                continue;
            }
        };
        if !entry.host_matches(host, port) {
            continue;
        }
        matched_host = true;

        let entry_fp = match fingerprint_from_key_blob_b64(&entry.key_blob_b64) {
            Ok(fp) => fp,
            Err(e) => {
                tracing::warn!(
                    line = line_no,
                    error = %e,
                    "skipping known_hosts entry with invalid base64 key blob"
                );
                continue;
            }
        };

        let fp_matches = entry_fp == actual_fp;

        // @revoked is short-circuit: if ANY revoked line matches the host AND
        // the server's key, fail closed immediately.
        if entry.marker == Some(Marker::Revoked) && fp_matches {
            return Ok(LookupOutcome::Revoked);
        }
        if entry.marker.is_some() {
            // Non-revoked markers we don't honor (cert-authority is skipped
            // earlier in parse_line; this is defense-in-depth).
            continue;
        }

        if fp_matches {
            fp_match_found = true;
            // Keep scanning — a later @revoked for the same key must win.
        } else if first_mismatch_fp.is_none() {
            first_mismatch_fp = Some(entry_fp);
        }
    }

    if !matched_host {
        return Ok(LookupOutcome::NotFound);
    }
    if fp_match_found {
        return Ok(LookupOutcome::Match);
    }
    Ok(LookupOutcome::Mismatch {
        file_fp: first_mismatch_fp.unwrap_or_default(),
    })
}

#[cfg(test)]
mod tests {
    #[test]
    fn parse_line_plain_host_match() {
        // A single plain-hostname entry; the line should parse and the host
        // pattern should match exactly.
        let line = "device-a.lab ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleKeyBlobForTesting";
        let entry = super::parse_line(line, 1).expect("parses").expect("not blank");
        assert!(entry.host_matches("device-a.lab", 22));
        assert!(!entry.host_matches("device-b.lab", 22));
    }

    // ---------- helpers ----------

    /// Build a known_hosts file with `lines`, return the path + tempdir guard.
    fn write_known_hosts(lines: &[&str]) -> (tempfile::TempDir, std::path::PathBuf) {
        use std::io::Write;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("known_hosts");
        let mut f = std::fs::File::create(&path).unwrap();
        for line in lines {
            writeln!(f, "{line}").unwrap();
        }
        (dir, path)
    }

    /// Compute a real SHA256 fingerprint over `blob` for use as `actual_fp`,
    /// and return both the base64 blob (for embedding in a known_hosts line)
    /// and the fingerprint string.
    fn blob_and_fp(blob: &[u8]) -> (String, String) {
        use base64ct::{Base64, Encoding};
        let blob_b64 = Base64::encode_string(blob);
        let fp = super::fingerprint_from_key_blob_b64(&blob_b64).unwrap();
        (blob_b64, fp)
    }

    // ---------- lookup() integration tests ----------

    #[test]
    fn lookup_match_plain_host() {
        let (blob_b64, fp) = blob_and_fp(b"device-a-key");
        let (_dir, path) = write_known_hosts(&[&format!("device-a.lab ssh-ed25519 {blob_b64}")]);
        let out = super::lookup(&path, "device-a.lab", 22, &fp).unwrap();
        assert_eq!(out, super::LookupOutcome::Match);
    }

    #[test]
    fn lookup_mismatch_returns_file_fp() {
        let (blob_b64, file_fp) = blob_and_fp(b"on-file-key");
        let (_, server_fp) = blob_and_fp(b"different-key-from-server");
        let (_dir, path) = write_known_hosts(&[&format!("device-a.lab ssh-ed25519 {blob_b64}")]);
        let out = super::lookup(&path, "device-a.lab", 22, &server_fp).unwrap();
        assert_eq!(out, super::LookupOutcome::Mismatch { file_fp });
    }

    #[test]
    fn lookup_not_found_when_host_absent() {
        let (blob_b64, _fp) = blob_and_fp(b"someone-elses-key");
        let (_dir, path) = write_known_hosts(&[&format!("device-a.lab ssh-ed25519 {blob_b64}")]);
        let out = super::lookup(&path, "device-b.lab", 22, "SHA256:anything").unwrap();
        assert_eq!(out, super::LookupOutcome::NotFound);
    }

    #[test]
    fn lookup_revoked_takes_precedence_over_match() {
        // Even if a non-revoked match exists, an @revoked entry for the same
        // host must fail closed.
        let (blob_b64, fp) = blob_and_fp(b"compromised-key");
        let (_dir, path) = write_known_hosts(&[
            &format!("device-a.lab ssh-ed25519 {blob_b64}"),
            &format!("@revoked device-a.lab ssh-ed25519 {blob_b64}"),
        ]);
        let out = super::lookup(&path, "device-a.lab", 22, &fp).unwrap();
        assert_eq!(out, super::LookupOutcome::Revoked);
    }

    #[test]
    fn lookup_multiple_key_types_accepts_if_any_matches() {
        // Device advertises ssh-rsa OR ssh-ed25519 keys; whichever the
        // server presents, we should accept.
        let (rsa_blob, _rsa_fp) = blob_and_fp(b"the-rsa-key");
        let (ed_blob, ed_fp) = blob_and_fp(b"the-ed25519-key");
        let (_dir, path) = write_known_hosts(&[
            &format!("device-a.lab ssh-rsa {rsa_blob}"),
            &format!("device-a.lab ssh-ed25519 {ed_blob}"),
        ]);
        let out = super::lookup(&path, "device-a.lab", 22, &ed_fp).unwrap();
        assert_eq!(out, super::LookupOutcome::Match);
    }

    #[test]
    fn lookup_io_error_on_missing_file() {
        let path = std::path::PathBuf::from("/nonexistent/path/to/known_hosts");
        let err = super::lookup(&path, "h", 22, "SHA256:x").unwrap_err();
        assert!(
            matches!(err, super::KnownHostsError::Io(_)),
            "expected Io error, got {err:?}"
        );
    }

    #[test]
    fn lookup_skips_blank_and_comment_lines() {
        let (blob_b64, fp) = blob_and_fp(b"key");
        let (_dir, path) = write_known_hosts(&[
            "",
            "# comment",
            "   ",
            &format!("device-a.lab ssh-ed25519 {blob_b64}"),
        ]);
        let out = super::lookup(&path, "device-a.lab", 22, &fp).unwrap();
        assert_eq!(out, super::LookupOutcome::Match);
    }

    // ---------- parse-line tests ----------

    #[test]
    fn parse_line_blank_and_comment_yield_none() {
        assert!(super::parse_line("", 1).unwrap().is_none());
        assert!(super::parse_line("   ", 1).unwrap().is_none());
        assert!(super::parse_line("# this is a comment", 1).unwrap().is_none());
        assert!(super::parse_line("   # indented comment", 1).unwrap().is_none());
    }

    #[test]
    fn parse_line_malformed_returns_error() {
        // Missing key type and blob.
        let err = super::parse_line("just-a-hostname", 7).unwrap_err();
        match err {
            super::KnownHostsError::Parse { line, reason } => {
                assert_eq!(line, 7);
                assert!(reason.contains("key type"), "reason was {reason:?}");
            }
            other => panic!("expected Parse error, got {other:?}"),
        }
        // Missing key blob.
        let err = super::parse_line("host ssh-rsa", 3).unwrap_err();
        assert!(matches!(err, super::KnownHostsError::Parse { line: 3, .. }));
    }

    #[test]
    fn parse_line_host_port_form() {
        // OpenSSH convention: [host]:port for any non-default port.
        let line = "[192.168.1.10]:830 ssh-ed25519 AAAAblob";
        let entry = super::parse_line(line, 1).unwrap().unwrap();
        assert!(entry.host_matches("192.168.1.10", 830));
        // Same host, different port — must not match.
        assert!(!entry.host_matches("192.168.1.10", 22));
        // Different host — must not match.
        assert!(!entry.host_matches("192.168.1.11", 830));
    }

    #[test]
    fn parse_line_wildcard_star_and_question() {
        // `*` matches any run of characters, `?` matches exactly one.
        let line = "*.lab.example.org ssh-ed25519 AAAAblob";
        let entry = super::parse_line(line, 1).unwrap().unwrap();
        assert!(entry.host_matches("a.lab.example.org", 22));
        assert!(entry.host_matches("longer.lab.example.org", 22));
        assert!(!entry.host_matches("lab.example.org", 22), "literal '.' in pattern must match");
        assert!(!entry.host_matches("a.other.example.org", 22));

        let line = "device?.lab ssh-ed25519 AAAAblob";
        let entry = super::parse_line(line, 1).unwrap().unwrap();
        assert!(entry.host_matches("device1.lab", 22));
        assert!(entry.host_matches("deviceX.lab", 22));
        assert!(!entry.host_matches("device.lab", 22));
        assert!(!entry.host_matches("device12.lab", 22));
    }

    #[test]
    fn entry_fingerprint_matches_russh_format() {
        // The fingerprint we compute for an entry must match what russh produces
        // for the server's public key: SHA-256 over the wire-format blob,
        // base64-encoded (no padding), prefixed with "SHA256:".
        //
        // Verifiable cross-tool: ssh-keygen -lf prints the same hash for the
        // same blob. Test with a fixed 32-byte blob to keep the expectation
        // deterministic.
        let blob = b"hello world for fingerprint test";
        // sha256("hello world for fingerprint test"), unpadded base64:
        let expected = "SHA256:Y8DAbifEb7qz0xN/BjIW76kakks+3wR5SjMdPrQhNpE";
        use base64ct::{Base64, Encoding};
        let blob_b64 = Base64::encode_string(blob);
        let fp = super::fingerprint_from_key_blob_b64(&blob_b64).expect("computes");
        assert_eq!(fp, expected);
    }

    #[test]
    fn parse_line_revoked_marker() {
        let line = "@revoked device-a.lab ssh-ed25519 AAAAblob";
        let entry = super::parse_line(line, 1).unwrap().unwrap();
        assert_eq!(entry.marker, Some(super::Marker::Revoked));
        assert!(entry.host_matches("device-a.lab", 22));
    }

    #[test]
    fn parse_line_cert_authority_marker_is_skipped() {
        // We don't implement @cert-authority (SSH certs) — but a line with
        // that marker must not crash the parser; we treat it as skipped.
        let line = "@cert-authority *.example.com ssh-rsa AAAAblob";
        // For now, accept the line by reporting None (skip semantics) OR a
        // parse error. We pick "skip with a debug log" — return Ok(None).
        let res = super::parse_line(line, 1).unwrap();
        assert!(res.is_none(), "cert-authority lines must be skipped");
    }

    #[test]
    fn parse_line_hashed_entry_matches_host() {
        // OpenSSH `HashKnownHosts yes` format: |1|<base64-salt>|<base64-hmac-sha1>
        // Computed offline: salt = b"aaaabbbbccccddddeeee", host = "device-a.lab".
        let line = "|1|YWFhYWJiYmJjY2NjZGRkZGVlZWU=|rxu231q7p1LEiU6fuhmWDfkVu9I= \
                    ssh-ed25519 AAAAblob";
        let entry = super::parse_line(line, 1).unwrap().unwrap();
        assert!(entry.host_matches("device-a.lab", 22));
        assert!(!entry.host_matches("device-b.lab", 22));
    }

    #[test]
    fn parse_line_cidr_ipv4() {
        let line = "10.0.0.0/8 ssh-ed25519 AAAAblob";
        let entry = super::parse_line(line, 1).unwrap().unwrap();
        assert!(entry.host_matches("10.0.0.1", 22));
        assert!(entry.host_matches("10.255.255.255", 22));
        assert!(!entry.host_matches("11.0.0.1", 22));
        assert!(!entry.host_matches("192.168.1.1", 22));
        // Non-IP hosts must not match a CIDR pattern.
        assert!(!entry.host_matches("device.lab", 22));
    }

    #[test]
    fn parse_line_cidr_ipv6() {
        let line = "2001:db8::/32 ssh-ed25519 AAAAblob";
        let entry = super::parse_line(line, 1).unwrap().unwrap();
        assert!(entry.host_matches("2001:db8::1", 22));
        assert!(entry.host_matches("2001:db8:cafe::1", 22));
        assert!(!entry.host_matches("2001:db9::1", 22));
    }

    #[test]
    fn parse_line_default_port_form_matches_port_22() {
        // Plain hostname (no [host]:port) implicitly means default SSH port 22.
        let line = "device.lab ssh-ed25519 AAAAblob";
        let entry = super::parse_line(line, 1).unwrap().unwrap();
        assert!(entry.host_matches("device.lab", 22));
        // The pattern is hostname-only, so other ports also match it for
        // backward compat with how OpenSSH treats plain entries (port-agnostic).
        assert!(entry.host_matches("device.lab", 830));
    }

    #[test]
    fn parse_line_comma_separated_hosts() {
        let line = "a.lab,b.lab,c.lab ssh-ed25519 AAAAblob";
        let entry = super::parse_line(line, 1).unwrap().unwrap();
        assert!(entry.host_matches("a.lab", 22));
        assert!(entry.host_matches("b.lab", 22));
        assert!(entry.host_matches("c.lab", 22));
        assert!(!entry.host_matches("d.lab", 22));
    }
}
