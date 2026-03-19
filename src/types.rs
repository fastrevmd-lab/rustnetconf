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

impl ErrorTag {
    /// Parse an error tag from its XML string representation.
    pub fn from_str(tag: &str) -> Self {
        match tag {
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
        }
    }
}
