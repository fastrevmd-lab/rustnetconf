//! Minimal OpenSSH client config (`ssh_config(5)`) parser.
//!
//! Reads files like `~/.ssh/config` and resolves a host alias to a set of
//! connection settings (HostName, Port, User, IdentityFile, ProxyJump,
//! ProxyCommand). Designed to populate [`crate::ClientBuilder`] from a
//! standard OpenSSH config so users don't have to repeat themselves.
//!
//! ## Supported directives
//!
//! - `Host <pattern...>` — start of a section, supports `*`/`?` globs and
//!   `!<pattern>` negation
//! - `HostName`, `Port`, `User`, `IdentityFile`
//! - `ProxyJump` — comma-separated `[user@]host[:port]` chain
//! - `ProxyCommand` — verbatim shell command (with `%h`/`%p` deferred to
//!   the SSH transport layer)
//! - `Include <path>` — recursively reads the file (`~` expansion supported)
//!
//! ## Not supported (yet)
//!
//! - `Match` blocks — parsed but skipped (warning logged)
//! - Token expansion beyond `%h`/`%p`/`%r`
//! - Environment-variable expansion (`$VAR`)
//! - Host-key verification directives (`StrictHostKeyChecking`,
//!   `UserKnownHostsFile`, etc.) — these need known-hosts support which
//!   is out of scope for this module.
//!
//! Unrecognised directives are parsed and silently dropped, matching how
//! OpenSSH treats unknown keys when the parser doesn't strictly
//! validate them.
//!
//! ## Semantics
//!
//! Per `ssh_config(5)`, **first match wins** for every directive: when
//! multiple `Host` blocks match the requested alias, the first
//! occurrence of each setting (in file order) is taken.

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use crate::transport::ssh::{HostKeyVerification, JumpHostConfig, SshAuth};

/// Errors produced while loading or parsing an SSH config file.
#[derive(Debug, thiserror::Error)]
pub enum SshConfigError {
    /// I/O error reading a config file or `Include`d sub-file.
    #[error("failed to read ssh config `{path}`: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    /// Syntax error in the config (line is reported 1-based).
    #[error("ssh config `{path}` line {line}: {message}")]
    Parse {
        path: PathBuf,
        line: usize,
        message: String,
    },

    /// `Include` recursion exceeded the safety limit.
    #[error("ssh config `Include` recursion too deep at `{path}` (limit {limit})")]
    IncludeTooDeep { path: PathBuf, limit: usize },
}

/// Maximum depth for `Include` recursion. OpenSSH itself caps this at 16.
const INCLUDE_DEPTH_LIMIT: usize = 16;

/// One `Host <pattern...>` block plus its directives.
#[derive(Debug, Clone)]
struct Section {
    /// Patterns from the `Host` line (e.g. `*.lab !test.lab`).
    patterns: Vec<HostPattern>,
    hostname: Option<String>,
    port: Option<u16>,
    user: Option<String>,
    identity_file: Option<String>,
    proxy_jump: Option<String>,
    proxy_command: Option<String>,
}

impl Section {
    fn empty(patterns: Vec<HostPattern>) -> Self {
        Self {
            patterns,
            hostname: None,
            port: None,
            user: None,
            identity_file: None,
            proxy_jump: None,
            proxy_command: None,
        }
    }
}

/// A single host pattern with optional negation.
#[derive(Debug, Clone)]
struct HostPattern {
    glob: String,
    /// True if pattern was prefixed with `!` (negation).
    negate: bool,
}

impl HostPattern {
    /// Parse one whitespace-separated token from a `Host` line.
    fn parse(token: &str) -> Self {
        if let Some(rest) = token.strip_prefix('!') {
            Self {
                glob: rest.to_string(),
                negate: true,
            }
        } else {
            Self {
                glob: token.to_string(),
                negate: false,
            }
        }
    }

    /// Match `target` against this glob, OpenSSH-style: `*` = any
    /// sequence, `?` = any single character. Case-insensitive (matches
    /// OpenSSH behavior on hostnames).
    fn matches(&self, target: &str) -> bool {
        glob_match(&self.glob, target)
    }
}

/// OpenSSH-style glob match. `*` matches any (possibly empty) sequence,
/// `?` matches any single character. Other characters match literally.
/// Case-insensitive.
fn glob_match(pattern: &str, candidate: &str) -> bool {
    glob_match_inner(pattern.as_bytes(), candidate.as_bytes())
}

fn glob_match_inner(pat: &[u8], s: &[u8]) -> bool {
    // Iterative backtracking matcher to avoid pathological recursion.
    let mut pi = 0usize;
    let mut si = 0usize;
    let mut star: Option<usize> = None;
    let mut match_si = 0usize;

    while si < s.len() {
        if pi < pat.len() {
            match pat[pi] {
                b'*' => {
                    star = Some(pi);
                    match_si = si;
                    pi += 1;
                    continue;
                }
                b'?' => {
                    pi += 1;
                    si += 1;
                    continue;
                }
                p if eq_ci(p, s[si]) => {
                    pi += 1;
                    si += 1;
                    continue;
                }
                _ => {}
            }
        }
        if let Some(sp) = star {
            pi = sp + 1;
            match_si += 1;
            si = match_si;
        } else {
            return false;
        }
    }
    while pi < pat.len() && pat[pi] == b'*' {
        pi += 1;
    }
    pi == pat.len()
}

fn eq_ci(a: u8, b: u8) -> bool {
    a.eq_ignore_ascii_case(&b)
}

/// Parsed SSH config file with all `Include`s flattened.
#[derive(Debug, Clone, Default)]
pub struct SshConfigFile {
    sections: Vec<Section>,
}

/// Connection settings resolved from an SSH config for a given alias.
///
/// Settings the alias didn't pin in the config are returned as `None`.
///
/// `Debug` is intentionally **not** derived: `jump_hosts` carries
/// [`SshAuth`] which may hold a password, and the rest of the crate's
/// SSH auth types deliberately avoid `Debug` for the same reason.
#[derive(Clone, Default)]
pub struct ResolvedHost {
    /// Real hostname (`HostName` directive). Falls back to the alias if
    /// not set in the config.
    pub hostname: Option<String>,
    /// SSH port (`Port`).
    pub port: Option<u16>,
    /// Username (`User`).
    pub user: Option<String>,
    /// Path to private key (`IdentityFile`). Tilde is expanded.
    pub identity_file: Option<String>,
    /// Parsed `ProxyJump` chain. Empty if not set.
    pub jump_hosts: Vec<JumpHostConfig>,
    /// `ProxyCommand` shell string, verbatim from the config. The
    /// transport layer handles `%h`/`%p` substitution.
    pub proxy_command: Option<String>,
}

impl SshConfigFile {
    /// Read and parse the config at `path`, recursively flattening
    /// `Include` directives.
    pub fn load(path: impl AsRef<Path>) -> Result<Self, SshConfigError> {
        let path = path.as_ref().to_path_buf();
        let mut sections = Vec::new();
        load_into(&path, &mut sections, 0)?;
        Ok(Self { sections })
    }

    /// Parse a config from an in-memory string. `Include` directives are
    /// resolved relative to `base_dir` (use a temp dir / cwd as
    /// appropriate). Pass `None` to skip `Include`s entirely (they will
    /// surface as a parse error).
    pub fn parse_str(text: &str, base_dir: Option<&Path>) -> Result<Self, SshConfigError> {
        let mut sections = Vec::new();
        let virtual_path = PathBuf::from("<memory>");
        parse_into(text, &virtual_path, base_dir, &mut sections, 0)?;
        Ok(Self { sections })
    }

    /// Resolve `alias` against this config. Returns the merged settings
    /// from every `Host` block whose pattern list matches `alias`,
    /// using first-match-wins semantics.
    pub fn resolve(&self, alias: &str) -> ResolvedHost {
        let mut out = ResolvedHost::default();
        for section in &self.sections {
            if !pattern_list_matches(&section.patterns, alias) {
                continue;
            }
            // First-match-wins: only set if not yet populated.
            if out.hostname.is_none() {
                out.hostname = section.hostname.clone();
            }
            if out.port.is_none() {
                out.port = section.port;
            }
            if out.user.is_none() {
                out.user = section.user.clone();
            }
            if out.identity_file.is_none() {
                out.identity_file = section.identity_file.as_ref().map(|p| expand_tilde(p));
            }
            if out.jump_hosts.is_empty() {
                if let Some(pj) = &section.proxy_jump {
                    out.jump_hosts = parse_proxy_jump(pj);
                }
            }
            if out.proxy_command.is_none() {
                out.proxy_command = section.proxy_command.clone();
            }
        }
        out
    }
}

/// Return true if the pattern list matches `target`. OpenSSH semantics:
/// at least one positive pattern must match, and no negative pattern
/// may match.
fn pattern_list_matches(patterns: &[HostPattern], target: &str) -> bool {
    let mut any_positive_match = false;
    for p in patterns {
        if p.matches(target) {
            if p.negate {
                return false;
            }
            any_positive_match = true;
        }
    }
    any_positive_match
}

/// Parse a `ProxyJump` value: comma-separated `[user@]host[:port]`.
///
/// Each entry becomes a [`JumpHostConfig`] with [`SshAuth::Agent`] as
/// the default auth method (matching the most common deployment) and
/// [`HostKeyVerification::AcceptAll`] (the rustnetconf default — the
/// caller can tighten per-hop after resolution).
pub fn parse_proxy_jump(value: &str) -> Vec<JumpHostConfig> {
    value
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|entry| {
            let (user, host_port) = match entry.split_once('@') {
                Some((u, hp)) => (Some(u.to_string()), hp),
                None => (None, entry),
            };
            let (host, port) = match host_port.rsplit_once(':') {
                Some((h, p)) => {
                    let parsed = p.parse::<u16>().unwrap_or(22);
                    (h.to_string(), parsed)
                }
                None => (host_port.to_string(), 22u16),
            };
            JumpHostConfig {
                host,
                port,
                username: user.unwrap_or_else(|| std::env::var("USER").unwrap_or_default()),
                auth: SshAuth::Agent,
                host_key_verification: HostKeyVerification::AcceptAll,
            }
        })
        .collect()
}

/// Expand a leading `~` to the user's home directory. No-op if the path
/// doesn't start with `~`. Falls back to leaving the path untouched if
/// `$HOME` is unset.
fn expand_tilde(path: &str) -> String {
    if let Some(rest) = path.strip_prefix("~/") {
        if let Ok(home) = std::env::var("HOME") {
            return format!("{home}/{rest}");
        }
    } else if path == "~" {
        if let Ok(home) = std::env::var("HOME") {
            return home;
        }
    }
    path.to_string()
}

fn load_into(
    path: &Path,
    sections: &mut Vec<Section>,
    depth: usize,
) -> Result<(), SshConfigError> {
    if depth > INCLUDE_DEPTH_LIMIT {
        return Err(SshConfigError::IncludeTooDeep {
            path: path.to_path_buf(),
            limit: INCLUDE_DEPTH_LIMIT,
        });
    }
    let text = fs::read_to_string(path).map_err(|source| SshConfigError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let base_dir = path.parent().map(Path::to_path_buf);
    parse_into(&text, path, base_dir.as_deref(), sections, depth)
}

fn parse_into(
    text: &str,
    path: &Path,
    base_dir: Option<&Path>,
    sections: &mut Vec<Section>,
    depth: usize,
) -> Result<(), SshConfigError> {
    let mut current: Option<Section> = None;
    let mut in_match_block = false;

    for (idx, raw_line) in text.lines().enumerate() {
        let line_no = idx + 1;
        let line = raw_line
            .split_once('#')
            .map(|(before, _)| before)
            .unwrap_or(raw_line)
            .trim();
        if line.is_empty() {
            continue;
        }

        let (keyword, value) = split_keyword(line);
        let key_lc = keyword.to_ascii_lowercase();

        if key_lc == "host" {
            if let Some(s) = current.take() {
                sections.push(s);
            }
            in_match_block = false;
            let patterns: Vec<HostPattern> =
                tokenize(value).iter().map(|t| HostPattern::parse(t)).collect();
            current = Some(Section::empty(patterns));
            continue;
        }

        if key_lc == "match" {
            // Parsed but skipped — Match blocks are explicitly out of v1 scope.
            if let Some(s) = current.take() {
                sections.push(s);
            }
            in_match_block = true;
            tracing::debug!(path = %path.display(), line = line_no,
                "ssh_config: skipping `Match` block (not yet supported)");
            continue;
        }

        if in_match_block {
            // Consume directives belonging to a Match block silently.
            continue;
        }

        if key_lc == "include" {
            for token in tokenize(value) {
                let resolved = resolve_include_path(&token, base_dir);
                load_into(&resolved, sections, depth + 1)?;
            }
            continue;
        }

        // All remaining keywords belong to the current Host section. If
        // we haven't seen a Host yet, treat them as belonging to an
        // implicit `Host *` (matches OpenSSH behavior for global defaults).
        if current.is_none() {
            current = Some(Section::empty(vec![HostPattern {
                glob: "*".to_string(),
                negate: false,
            }]));
        }
        let section = current.as_mut().expect("just inserted");

        match key_lc.as_str() {
            "hostname" => {
                section.hostname.get_or_insert_with(|| value.to_string());
            }
            "port" => {
                let parsed = value.parse::<u16>().map_err(|_| SshConfigError::Parse {
                    path: path.to_path_buf(),
                    line: line_no,
                    message: format!("invalid Port value: {value}"),
                })?;
                section.port.get_or_insert(parsed);
            }
            "user" => {
                section.user.get_or_insert_with(|| value.to_string());
            }
            "identityfile" => {
                section
                    .identity_file
                    .get_or_insert_with(|| value.to_string());
            }
            "proxyjump" => {
                section
                    .proxy_jump
                    .get_or_insert_with(|| value.to_string());
            }
            "proxycommand" => {
                section
                    .proxy_command
                    .get_or_insert_with(|| value.to_string());
            }
            _ => {
                // Unknown / unsupported directive — silently dropped.
            }
        }
    }

    if let Some(s) = current.take() {
        sections.push(s);
    }
    Ok(())
}

/// Resolve an `Include` path argument relative to `base_dir`. Tilde is
/// expanded. Globs are not supported (yet).
fn resolve_include_path(arg: &str, base_dir: Option<&Path>) -> PathBuf {
    let expanded = expand_tilde(arg);
    let p = PathBuf::from(&expanded);
    if p.is_absolute() {
        return p;
    }
    if let Some(base) = base_dir {
        return base.join(p);
    }
    p
}

/// Split the first whitespace (or `=`) sequence to separate keyword
/// from arguments. OpenSSH allows either form.
fn split_keyword(line: &str) -> (&str, &str) {
    // First non-whitespace token, optionally followed by `=`.
    let trimmed = line.trim_start();
    let split_at = trimmed
        .find(|c: char| c.is_whitespace() || c == '=')
        .unwrap_or(trimmed.len());
    let keyword = &trimmed[..split_at];
    let rest = trimmed[split_at..]
        .trim_start_matches(|c: char| c.is_whitespace() || c == '=')
        .trim_end();
    (keyword, rest)
}

/// Split on whitespace honoring single/double quotes. Used for `Host`
/// pattern lists and `Include` paths.
fn tokenize(value: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut quote: Option<char> = None;
    for ch in value.chars() {
        match (ch, quote) {
            ('\'', None) | ('"', None) => quote = Some(ch),
            ('\'', Some('\'')) | ('"', Some('"')) => quote = None,
            (c, None) if c.is_whitespace() => {
                if !current.is_empty() {
                    out.push(std::mem::take(&mut current));
                }
            }
            (c, _) => current.push(c),
        }
    }
    if !current.is_empty() {
        out.push(current);
    }
    out
}

/// Helper for tests / consumers that want to know which aliases are
/// defined (not exhaustive — matches what's reachable via the
/// configured globs).
#[doc(hidden)]
pub fn defined_host_patterns(file: &SshConfigFile) -> HashSet<String> {
    file.sections
        .iter()
        .flat_map(|s| s.patterns.iter().map(|p| p.glob.clone()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn glob_match_basic_star() {
        assert!(glob_match("*", "anything"));
        assert!(glob_match("*.lab", "host.lab"));
        assert!(glob_match("*.lab", "deep.host.lab"));
        assert!(!glob_match("*.lab", "host.prod"));
    }

    #[test]
    fn glob_match_question_mark() {
        assert!(glob_match("h?st", "host"));
        assert!(glob_match("h?st", "hast"));
        assert!(!glob_match("h?st", "hoost"));
    }

    #[test]
    fn glob_match_case_insensitive() {
        assert!(glob_match("HOST.lab", "host.LAB"));
    }

    #[test]
    fn glob_match_literal() {
        assert!(glob_match("exact", "exact"));
        assert!(!glob_match("exact", "exact.suffix"));
    }

    #[test]
    fn glob_match_multiple_stars() {
        assert!(glob_match("*lab*", "my.lab.example"));
        assert!(glob_match("*a*b*c*", "xayybzzc"));
        assert!(!glob_match("*a*b*c*", "xayybzz"));
    }

    #[test]
    fn host_pattern_parse_negation() {
        let p = HostPattern::parse("!test.lab");
        assert!(p.negate);
        assert_eq!(p.glob, "test.lab");
        let p2 = HostPattern::parse("test.lab");
        assert!(!p2.negate);
    }

    #[test]
    fn pattern_list_matches_requires_positive() {
        // A list of only-negative patterns must never match.
        let patterns = vec![HostPattern {
            glob: "blocked".to_string(),
            negate: true,
        }];
        assert!(!pattern_list_matches(&patterns, "anything"));
    }

    #[test]
    fn pattern_list_matches_negation_blocks() {
        let patterns = vec![
            HostPattern {
                glob: "*.lab".to_string(),
                negate: false,
            },
            HostPattern {
                glob: "test.lab".to_string(),
                negate: true,
            },
        ];
        assert!(pattern_list_matches(&patterns, "prod.lab"));
        assert!(!pattern_list_matches(&patterns, "test.lab"));
    }

    #[test]
    fn parse_minimal_host_block() {
        let cfg = SshConfigFile::parse_str(
            "Host r1\n  HostName 10.0.0.1\n  User admin\n  Port 830\n",
            None,
        )
        .unwrap();
        let r = cfg.resolve("r1");
        assert_eq!(r.hostname.as_deref(), Some("10.0.0.1"));
        assert_eq!(r.user.as_deref(), Some("admin"));
        assert_eq!(r.port, Some(830));
    }

    #[test]
    fn parse_supports_equals_separator() {
        // OpenSSH accepts `key=value` as well as `key value`.
        let cfg = SshConfigFile::parse_str("Host=r1\nHostName=10.0.0.1\nPort=2222\n", None)
            .unwrap();
        let r = cfg.resolve("r1");
        assert_eq!(r.hostname.as_deref(), Some("10.0.0.1"));
        assert_eq!(r.port, Some(2222));
    }

    #[test]
    fn parse_skips_comments_and_blank_lines() {
        let cfg = SshConfigFile::parse_str(
            "# a comment\n\n  # indented comment\nHost r1\n  HostName 10.0.0.1 # trailing\n",
            None,
        )
        .unwrap();
        let r = cfg.resolve("r1");
        assert_eq!(r.hostname.as_deref(), Some("10.0.0.1"));
    }

    #[test]
    fn first_match_wins_across_multiple_blocks() {
        // Per ssh_config(5): "for each parameter, the first obtained
        // value will be used".
        let cfg = SshConfigFile::parse_str(
            "Host r1\n  HostName specific.example\n\n\
             Host *\n  HostName fallback.example\n  Port 22\n",
            None,
        )
        .unwrap();
        let r = cfg.resolve("r1");
        // Specific block wins HostName.
        assert_eq!(r.hostname.as_deref(), Some("specific.example"));
        // But the fallback block contributes Port (specific didn't set it).
        assert_eq!(r.port, Some(22));
    }

    #[test]
    fn glob_host_block_applies_to_matching_aliases() {
        let cfg = SshConfigFile::parse_str(
            "Host *.lab\n  User lab-admin\n  Port 830\n",
            None,
        )
        .unwrap();
        let r = cfg.resolve("device.lab");
        assert_eq!(r.user.as_deref(), Some("lab-admin"));
        assert_eq!(r.port, Some(830));
        let r2 = cfg.resolve("device.prod");
        assert!(r2.user.is_none());
    }

    #[test]
    fn host_block_with_multiple_patterns() {
        let cfg = SshConfigFile::parse_str(
            "Host *.lab !test.lab\n  User lab-admin\n",
            None,
        )
        .unwrap();
        assert_eq!(cfg.resolve("ok.lab").user.as_deref(), Some("lab-admin"));
        // Negation excludes test.lab even though *.lab matches.
        assert!(cfg.resolve("test.lab").user.is_none());
    }

    #[test]
    fn unknown_directives_silently_dropped() {
        let cfg = SshConfigFile::parse_str(
            "Host r1\n  HostName 10.0.0.1\n  IdentitiesOnly yes\n  Tunnel yes\n",
            None,
        )
        .unwrap();
        // Parses without error; unknown keys ignored.
        assert_eq!(cfg.resolve("r1").hostname.as_deref(), Some("10.0.0.1"));
    }

    #[test]
    fn match_blocks_skipped_with_warning() {
        let cfg = SshConfigFile::parse_str(
            "Host r1\n  HostName 10.0.0.1\n\n\
             Match user root\n  HostName should-be-skipped\n  Port 9999\n",
            None,
        )
        .unwrap();
        let r = cfg.resolve("r1");
        assert_eq!(r.hostname.as_deref(), Some("10.0.0.1"));
        // Match-block settings must NOT leak into r1 via the implicit
        // "current section" pattern.
        assert_ne!(r.port, Some(9999));
    }

    #[test]
    fn implicit_global_defaults_before_host() {
        // Settings before any Host line apply to all hosts (implicit Host *).
        let cfg = SshConfigFile::parse_str(
            "Port 830\nUser ops\n\nHost r1\n  HostName 10.0.0.1\n",
            None,
        )
        .unwrap();
        let r = cfg.resolve("r1");
        assert_eq!(r.hostname.as_deref(), Some("10.0.0.1"));
        // Specific block had no Port/User → fall back to global defaults.
        assert_eq!(r.port, Some(830));
        assert_eq!(r.user.as_deref(), Some("ops"));
    }

    #[test]
    fn invalid_port_is_parse_error() {
        let err = SshConfigFile::parse_str(
            "Host r1\n  Port not-a-number\n",
            None,
        )
        .unwrap_err();
        match err {
            SshConfigError::Parse { line, message, .. } => {
                assert_eq!(line, 2);
                assert!(message.contains("invalid Port"));
            }
            other => panic!("expected Parse error, got {other:?}"),
        }
    }

    #[test]
    fn parse_proxy_jump_simple_host() {
        let chain = parse_proxy_jump("bastion.example.com");
        assert_eq!(chain.len(), 1);
        assert_eq!(chain[0].host, "bastion.example.com");
        assert_eq!(chain[0].port, 22);
    }

    #[test]
    fn parse_proxy_jump_user_at_host_port() {
        let chain = parse_proxy_jump("admin@bastion:2222");
        assert_eq!(chain.len(), 1);
        assert_eq!(chain[0].username, "admin");
        assert_eq!(chain[0].host, "bastion");
        assert_eq!(chain[0].port, 2222);
    }

    #[test]
    fn parse_proxy_jump_chain() {
        let chain = parse_proxy_jump("a@h1:22 , b@h2 ,h3:830");
        assert_eq!(chain.len(), 3);
        assert_eq!(chain[0].host, "h1");
        assert_eq!(chain[0].username, "a");
        assert_eq!(chain[1].host, "h2");
        assert_eq!(chain[1].port, 22);
        assert_eq!(chain[2].host, "h3");
        assert_eq!(chain[2].port, 830);
    }

    #[test]
    fn proxy_jump_in_config_resolves_to_chain() {
        let cfg = SshConfigFile::parse_str(
            "Host r1\n  HostName 10.0.0.1\n  ProxyJump admin@bastion:2222,h2\n",
            None,
        )
        .unwrap();
        let r = cfg.resolve("r1");
        assert_eq!(r.jump_hosts.len(), 2);
        assert_eq!(r.jump_hosts[0].host, "bastion");
        assert_eq!(r.jump_hosts[0].username, "admin");
        assert_eq!(r.jump_hosts[0].port, 2222);
        assert_eq!(r.jump_hosts[1].host, "h2");
    }

    #[test]
    fn proxy_command_resolved_verbatim() {
        let cfg = SshConfigFile::parse_str(
            "Host r1\n  HostName 10.0.0.1\n  ProxyCommand ssh -W %h:%p bastion\n",
            None,
        )
        .unwrap();
        let r = cfg.resolve("r1");
        assert_eq!(r.proxy_command.as_deref(), Some("ssh -W %h:%p bastion"));
    }

    #[test]
    fn quoted_host_pattern_tokenized_correctly() {
        let cfg = SshConfigFile::parse_str(
            "Host \"r 1\" r2\n  User admin\n",
            None,
        )
        .unwrap();
        // The quoted pattern preserves the space.
        assert_eq!(cfg.resolve("r 1").user.as_deref(), Some("admin"));
        assert_eq!(cfg.resolve("r2").user.as_deref(), Some("admin"));
    }

    #[test]
    fn nonmatching_alias_returns_empty_resolved_host() {
        let cfg = SshConfigFile::parse_str(
            "Host r1\n  HostName 10.0.0.1\n",
            None,
        )
        .unwrap();
        let r = cfg.resolve("not-defined");
        assert!(r.hostname.is_none());
        assert!(r.user.is_none());
        assert!(r.port.is_none());
        assert!(r.jump_hosts.is_empty());
        assert!(r.proxy_command.is_none());
    }

    #[test]
    fn load_via_file_and_include() {
        // Verify that load() reads from disk and resolves Include
        // recursively. Use tempfiles so the test is hermetic.
        let dir = tempfile::tempdir().unwrap();
        let main_path = dir.path().join("config");
        let inc_path = dir.path().join("included.conf");

        std::fs::write(
            &inc_path,
            "Host included-host\n  HostName 10.9.9.9\n  Port 2222\n",
        )
        .unwrap();
        std::fs::write(
            &main_path,
            format!(
                "Host main-host\n  HostName 10.0.0.1\nInclude {}\n",
                inc_path.display()
            ),
        )
        .unwrap();

        let cfg = SshConfigFile::load(&main_path).unwrap();
        assert_eq!(cfg.resolve("main-host").hostname.as_deref(), Some("10.0.0.1"));
        assert_eq!(
            cfg.resolve("included-host").hostname.as_deref(),
            Some("10.9.9.9")
        );
        assert_eq!(cfg.resolve("included-host").port, Some(2222));
    }

    #[test]
    fn load_missing_file_returns_io_error() {
        let err = SshConfigFile::load("/nonexistent/ssh/config-xyz").unwrap_err();
        assert!(matches!(err, SshConfigError::Io { .. }));
    }

    #[test]
    fn include_recursion_limit_enforced() {
        // self-including config — must error out at the depth limit.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("loop.conf");
        std::fs::write(
            &path,
            format!("Include {}\n", path.display()),
        )
        .unwrap();
        let err = SshConfigFile::load(&path).unwrap_err();
        assert!(matches!(err, SshConfigError::IncludeTooDeep { .. }));
    }

    #[test]
    fn expand_tilde_with_home() {
        // Save & restore HOME to make this hermetic.
        let prev = std::env::var("HOME").ok();
        // SAFETY: tests run single-threaded by default; we restore HOME below.
        unsafe {
            std::env::set_var("HOME", "/home/test-user");
        }
        assert_eq!(expand_tilde("~/foo/bar"), "/home/test-user/foo/bar");
        assert_eq!(expand_tilde("~"), "/home/test-user");
        assert_eq!(expand_tilde("/abs/path"), "/abs/path");
        assert_eq!(expand_tilde("relative"), "relative");
        // SAFETY: restoring HOME after the test.
        unsafe {
            match prev {
                Some(v) => std::env::set_var("HOME", v),
                None => std::env::remove_var("HOME"),
            }
        }
    }

    #[test]
    fn defined_host_patterns_returns_globs() {
        let cfg = SshConfigFile::parse_str(
            "Host r1 r2\n  User admin\n\nHost *.lab\n  User other\n",
            None,
        )
        .unwrap();
        let pats = defined_host_patterns(&cfg);
        assert!(pats.contains("r1"));
        assert!(pats.contains("r2"));
        assert!(pats.contains("*.lab"));
    }

    #[test]
    fn identity_file_tilde_expansion() {
        let prev = std::env::var("HOME").ok();
        unsafe {
            std::env::set_var("HOME", "/home/u");
        }
        let cfg = SshConfigFile::parse_str(
            "Host r1\n  IdentityFile ~/.ssh/id_lab\n",
            None,
        )
        .unwrap();
        assert_eq!(
            cfg.resolve("r1").identity_file.as_deref(),
            Some("/home/u/.ssh/id_lab")
        );
        unsafe {
            match prev {
                Some(v) => std::env::set_var("HOME", v),
                None => std::env::remove_var("HOME"),
            }
        }
    }
}
