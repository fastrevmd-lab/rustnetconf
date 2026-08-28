//! Core types used throughout rustnetconf.
//!
//! These types map directly to NETCONF protocol concepts defined in RFC 6241.

use std::fmt;

/// NETCONF datastore targets.
///
/// # Examples
/// ```
/// use rustnetconf::Datastore;
/// let ds = Datastore::Candidate;
/// assert_eq!(ds.as_xml_tag(), "candidate");
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Datastore {
    /// The running configuration datastore.
    Running,
    /// The candidate configuration datastore (requires `:candidate` capability).
    Candidate,
    /// The startup configuration datastore (requires `:startup` capability).
    Startup,
}

/// Where a `<copy-config>` or `<delete-config>` reads from or writes to.
///
/// RFC 6241 lets these operations name either a datastore or a URL. The URL
/// form needs the `:url` capability, which the session checks before sending.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ConfigLocation {
    /// A NETCONF datastore.
    Datastore(Datastore),
    /// A URL, valid only if the device advertises `:url` and lists the scheme.
    Url(String),
}

/// The `<target>` of a `<delete-config>` (RFC 6241 §7.4).
///
/// Narrower than [`ConfigLocation`] on purpose. The `config-target` choice in
/// RFC 6241's `ietf-netconf` YANG module offers exactly two leaves for this
/// operation:
///
/// ```text
/// rpc delete-config {
///   input { container target { choice config-target {
///     mandatory true;
///     leaf startup { if-feature startup; type empty; }
///     leaf url     { if-feature url;     type inet:uri; }
/// } } } }
/// ```
///
/// Neither `running` nor `candidate` appears — the prose in §7.4 mentions only
/// running, but the module is the normative list. Modelling it as its own type
/// means a conforming server never has to reject what we send, and no runtime
/// check is needed to enforce it.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum DeleteTarget {
    /// The startup datastore (requires `:startup`).
    Startup,
    /// A URL-backed configuration (requires `:url` and the scheme).
    Url(String),
}

impl fmt::Display for DeleteTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DeleteTarget::Startup => f.write_str("startup"),
            DeleteTarget::Url(url) => write!(f, "url({url})"),
        }
    }
}

/// The `<source>` of a `<copy-config>` (RFC 6241 §7.3).
///
/// Wider than [`ConfigLocation`] because the RFC also allows a complete
/// configuration inline: *"the configuration datastore to use as the source of
/// the `<copy-config>` operation, or the `<config>` element containing the
/// complete configuration to copy."* Targets have no such form, so they stay
/// [`ConfigLocation`] and the inline case cannot be expressed where it would be
/// invalid.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum CopySource {
    /// A NETCONF datastore.
    Datastore(Datastore),
    /// A URL, valid only if the device advertises `:url` and the scheme.
    Url(String),
    /// A complete configuration, inline. Replaces the target outright — this
    /// is `copy-config`, not `edit-config`, so there is no merge semantics.
    Config(String),
}

impl From<Datastore> for CopySource {
    fn from(ds: Datastore) -> Self {
        CopySource::Datastore(ds)
    }
}

impl From<ConfigLocation> for CopySource {
    fn from(loc: ConfigLocation) -> Self {
        match loc {
            ConfigLocation::Datastore(ds) => CopySource::Datastore(ds),
            ConfigLocation::Url(u) => CopySource::Url(u),
        }
    }
}

impl fmt::Display for CopySource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CopySource::Datastore(ds) => f.write_str(ds.as_xml_tag()),
            CopySource::Url(url) => write!(f, "url({url})"),
            CopySource::Config(_) => f.write_str("inline-config"),
        }
    }
}

impl From<Datastore> for ConfigLocation {
    fn from(ds: Datastore) -> Self {
        ConfigLocation::Datastore(ds)
    }
}

impl fmt::Display for ConfigLocation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfigLocation::Datastore(ds) => f.write_str(ds.as_xml_tag()),
            ConfigLocation::Url(url) => write!(f, "url({url})"),
        }
    }
}

impl Datastore {
    /// Returns the XML tag name for this datastore.
    pub fn as_xml_tag(&self) -> &'static str {
        match self {
            Datastore::Running => "running",
            Datastore::Candidate => "candidate",
            Datastore::Startup => "startup",
        }
    }
}

impl fmt::Display for Datastore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_xml_tag())
    }
}

/// The `default-operation` parameter for `edit-config`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DefaultOperation {
    Merge,
    Replace,
    None,
}

impl DefaultOperation {
    /// Returns the XML value string.
    pub fn as_str(&self) -> &'static str {
        match self {
            DefaultOperation::Merge => "merge",
            DefaultOperation::Replace => "replace",
            DefaultOperation::None => "none",
        }
    }
}

/// The `test-option` parameter for `edit-config` (requires `:validate` capability).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TestOption {
    TestThenSet,
    Set,
    TestOnly,
}

impl TestOption {
    /// Returns the XML value string.
    pub fn as_str(&self) -> &'static str {
        match self {
            TestOption::TestThenSet => "test-then-set",
            TestOption::Set => "set",
            TestOption::TestOnly => "test-only",
        }
    }
}

/// The `error-option` parameter for `edit-config`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorOption {
    StopOnError,
    ContinueOnError,
    RollbackOnError,
}

impl ErrorOption {
    /// Returns the XML value string.
    pub fn as_str(&self) -> &'static str {
        match self {
            ErrorOption::StopOnError => "stop-on-error",
            ErrorOption::ContinueOnError => "continue-on-error",
            ErrorOption::RollbackOnError => "rollback-on-error",
        }
    }
}

// ── Junos-specific types ────────────────────────────────────────────

/// Configuration database mode for Junos `<open-configuration>`.
///
/// Chassis-clustered Junos devices require a private or exclusive
/// configuration database to be opened before loading configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenConfigurationMode {
    /// Open a private configuration database.
    /// Each session gets an independent candidate; changes are merged on commit.
    Private,
    /// Open an exclusive configuration database.
    /// Only one session can hold the exclusive lock.
    Exclusive,
}

/// The `action` attribute for Junos `<load-configuration>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoadAction {
    Set,
    Merge,
    Replace,
    Override,
    Update,
}

impl LoadAction {
    /// Returns the XML attribute value string.
    pub fn as_str(&self) -> &'static str {
        match self {
            LoadAction::Set => "set",
            LoadAction::Merge => "merge",
            LoadAction::Replace => "replace",
            LoadAction::Override => "override",
            LoadAction::Update => "update",
        }
    }
}

/// The `format` attribute for Junos `<load-configuration>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoadFormat {
    Text,
    Xml,
}

impl LoadFormat {
    /// Returns the XML attribute value string.
    pub fn as_str(&self) -> &'static str {
        match self {
            LoadFormat::Text => "text",
            LoadFormat::Xml => "xml",
        }
    }
}

// ── NETCONF error types ─────────────────────────────────────────────

/// NETCONF error severity levels from `<rpc-error>` responses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorSeverity {
    Error,
    Warning,
}

/// NETCONF error type from `<rpc-error>` responses (RFC 6241 §4.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RpcErrorType {
    Transport,
    Rpc,
    Protocol,
    Application,
}

/// NETCONF error tags from `<rpc-error>` responses (RFC 6241 §4.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ErrorTag {
    InUse,
    InvalidValue,
    TooBig,
    MissingAttribute,
    BadAttribute,
    UnknownAttribute,
    MissingElement,
    BadElement,
    UnknownElement,
    UnknownNamespace,
    AccessDenied,
    LockDenied,
    ResourceDenied,
    RollbackFailed,
    DataExists,
    DataMissing,
    OperationNotSupported,
    OperationFailed,
    MalformedMessage,
    /// Vendor-specific or unrecognized error tag.
    Other(String),
}

impl std::str::FromStr for ErrorTag {
    type Err = std::convert::Infallible;

    /// Parse an error tag from its XML string representation.
    ///
    /// Always succeeds — unknown tags map to [`ErrorTag::Other`].
    fn from_str(tag: &str) -> Result<Self, Self::Err> {
        let variant = match tag {
            "in-use" => ErrorTag::InUse,
            "invalid-value" => ErrorTag::InvalidValue,
            "too-big" => ErrorTag::TooBig,
            "missing-attribute" => ErrorTag::MissingAttribute,
            "bad-attribute" => ErrorTag::BadAttribute,
            "unknown-attribute" => ErrorTag::UnknownAttribute,
            "missing-element" => ErrorTag::MissingElement,
            "bad-element" => ErrorTag::BadElement,
            "unknown-element" => ErrorTag::UnknownElement,
            "unknown-namespace" => ErrorTag::UnknownNamespace,
            "access-denied" => ErrorTag::AccessDenied,
            "lock-denied" => ErrorTag::LockDenied,
            "resource-denied" => ErrorTag::ResourceDenied,
            "rollback-failed" => ErrorTag::RollbackFailed,
            "data-exists" => ErrorTag::DataExists,
            "data-missing" => ErrorTag::DataMissing,
            "operation-not-supported" => ErrorTag::OperationNotSupported,
            "operation-failed" => ErrorTag::OperationFailed,
            "malformed-message" => ErrorTag::MalformedMessage,
            other => ErrorTag::Other(other.to_string()),
        };
        Ok(variant)
    }
}
