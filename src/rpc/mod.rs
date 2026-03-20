//! NETCONF RPC serialization and response parsing.
//!
//! Handles converting typed RPC operations into XML messages and
//! parsing XML responses back into typed results.

pub mod filter;
pub mod operations;

use crate::error::RpcError;
use crate::types::{ErrorSeverity, ErrorTag, RpcErrorType};

/// A parsed NETCONF `<rpc-reply>` response.
#[derive(Debug)]
pub enum RpcReply {
    /// Success with data (from `<get>`, `<get-config>`).
    Data(String),
    /// Success with no data (`<ok/>`).
    Ok,
}

/// A fully parsed `<rpc-error>` from the device.
#[derive(Debug, Clone)]
pub struct RpcErrorInfo {
    pub error_type: Option<RpcErrorType>,
    pub tag: ErrorTag,
    pub severity: Option<ErrorSeverity>,
    pub app_tag: Option<String>,
    pub path: Option<String>,
    pub message: String,
    pub info: Option<String>,
}

/// Parse an `<rpc-reply>` XML response.
///
/// Returns `Ok(RpcReply)` for successful responses, or `Err(RpcError)` if
/// the reply contains `<rpc-error>` elements.
pub fn parse_rpc_reply(xml: &str, expected_message_id: &str) -> Result<RpcReply, RpcError> {
    use quick_xml::events::Event;
    use quick_xml::Reader;

    let mut reader = Reader::from_str(xml);
    let mut buf = Vec::new();

    let mut found_message_id: Option<String> = None;
    let mut found_ok = false;
    let mut data_content: Option<String> = None;
    let mut errors: Vec<RpcErrorInfo> = Vec::new();

    // State for parsing rpc-error
    let mut in_rpc_error = false;
    let mut in_rpc_reply = false;
    let mut in_data = false;
    let mut data_depth: u32 = 0;
    let mut data_xml = String::new();

    // rpc-error field tracking
    let mut current_error: Option<RpcErrorBuilder> = None;
    let mut current_field: Option<ErrorField> = None;
    // error-info can contain child elements — accumulate inner XML
    let mut in_error_info = false;
    let mut _error_info_depth: u32 = 0;
    let mut error_info_xml = String::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(ref tag)) => {
                let local = tag.local_name();
                let name = std::str::from_utf8(local.as_ref()).unwrap_or("");

                match name {
                    "rpc-reply" => {
                        in_rpc_reply = true;
                        // Extract message-id attribute
                        for attr in tag.attributes().flatten() {
                            if attr.key.local_name().as_ref() == b"message-id" {
                                found_message_id = Some(
                                    String::from_utf8_lossy(&attr.value).to_string()
                                );
                            }
                        }
                    }
                    "data" if in_rpc_reply && !in_rpc_error => {
                        in_data = true;
                        data_depth = 1;
                        data_xml.clear();
                    }
                    "rpc-error" if in_rpc_reply => {
                        in_rpc_error = true;
                        current_error = Some(RpcErrorBuilder::new());
                    }
                    _ if in_data => {
                        data_depth += 1;
                        // Reconstruct the inner XML
                        data_xml.push('<');
                        data_xml.push_str(name);
                        for attr in tag.attributes().flatten() {
                            data_xml.push(' ');
                            data_xml.push_str(
                                std::str::from_utf8(attr.key.as_ref()).unwrap_or(""),
                            );
                            data_xml.push_str("=\"");
                            data_xml.push_str(
                                &String::from_utf8_lossy(&attr.value),
                            );
                            data_xml.push('"');
                        }
                        data_xml.push('>');
                    }
                    _ if in_error_info => {
                        // Inside <error-info>: accumulate child elements as XML
                        _error_info_depth += 1;
                        error_info_xml.push('<');
                        error_info_xml.push_str(name);
                        error_info_xml.push('>');
                    }
                    _ if in_rpc_error => {
                        if name == "error-info" {
                            in_error_info = true;
                            _error_info_depth = 1;
                            error_info_xml.clear();
                        } else {
                            current_field = ErrorField::from_name(name);
                        }
                    }
                    _ => {}
                }
            }
            Ok(Event::Empty(ref tag)) => {
                let local = tag.local_name();
                let name = std::str::from_utf8(local.as_ref()).unwrap_or("");

                if name == "ok" && in_rpc_reply {
                    found_ok = true;
                } else if in_data {
                    data_xml.push('<');
                    data_xml.push_str(name);
                    for attr in tag.attributes().flatten() {
                        data_xml.push(' ');
                        data_xml.push_str(
                            std::str::from_utf8(attr.key.as_ref()).unwrap_or(""),
                        );
                        data_xml.push_str("=\"");
                        data_xml.push_str(
                            &String::from_utf8_lossy(&attr.value),
                        );
                        data_xml.push('"');
                    }
                    data_xml.push_str("/>");
                } else if in_error_info {
                    error_info_xml.push('<');
                    error_info_xml.push_str(name);
                    error_info_xml.push_str("/>");
                }
            }
            Ok(Event::Text(ref text)) => {
                let value = text.unescape().unwrap_or_default().to_string();

                if in_data {
                    data_xml.push_str(&value);
                } else if in_error_info {
                    error_info_xml.push_str(&value);
                } else if in_rpc_error {
                    if let (Some(ref mut builder), Some(ref field)) =
                        (&mut current_error, &current_field)
                    {
                        builder.set_field(field, &value);
                    }
                }
            }
            Ok(Event::End(ref tag)) => {
                let local = tag.local_name();
                let name = std::str::from_utf8(local.as_ref()).unwrap_or("");

                match name {
                    "rpc-reply" => {
                        in_rpc_reply = false;
                    }
                    "data" if in_data && data_depth == 1 => {
                        in_data = false;
                        data_content = Some(data_xml.clone());
                    }
                    "rpc-error" => {
                        in_rpc_error = false;
                        if let Some(builder) = current_error.take() {
                            errors.push(builder.build());
                        }
                    }
                    _ if in_data => {
                        data_depth -= 1;
                        data_xml.push_str("</");
                        data_xml.push_str(name);
                        data_xml.push('>');
                    }
                    "error-info" if in_error_info => {
                        in_error_info = false;
                        if let Some(ref mut builder) = current_error {
                            let trimmed = error_info_xml.trim().to_string();
                            if !trimmed.is_empty() {
                                builder.info = Some(trimmed);
                            }
                        }
                    }
                    _ if in_error_info => {
                        _error_info_depth -= 1;
                        error_info_xml.push_str("</");
                        error_info_xml.push_str(name);
                        error_info_xml.push('>');
                    }
                    _ if in_rpc_error => {
                        current_field = None;
                    }
                    _ => {}
                }
            }
            Ok(Event::Eof) => break,
            Err(e) => return Err(RpcError::ParseError(format!("XML parse error: {e}"))),
            _ => {}
        }
        buf.clear();
    }

    // Check message-id
    if let Some(ref msg_id) = found_message_id {
        if msg_id != expected_message_id {
            return Err(RpcError::MessageIdMismatch {
                expected: expected_message_id.to_string(),
                actual: msg_id.clone(),
            });
        }
    }

    // Return errors if any
    if let Some(first_error) = errors.into_iter().next() {
        return Err(RpcError::ServerError {
            error_type: first_error.error_type,
            tag: first_error.tag,
            severity: first_error.severity,
            app_tag: first_error.app_tag,
            path: first_error.path,
            message: first_error.message,
            info: first_error.info,
        });
    }

    // Return data or ok
    if let Some(data) = data_content {
        return Ok(RpcReply::Data(data));
    }

    if found_ok {
        return Ok(RpcReply::Ok);
    }

    Err(RpcError::ParseError(
        "rpc-reply contained no <ok/>, <data>, or <rpc-error>".to_string(),
    ))
}

/// Fields within an `<rpc-error>` element.
#[allow(clippy::enum_variant_names)]
enum ErrorField {
    ErrorType,
    ErrorTag,
    ErrorSeverity,
    ErrorAppTag,
    ErrorPath,
    ErrorMessage,
    ErrorInfo,
}

impl ErrorField {
    fn from_name(name: &str) -> Option<Self> {
        match name {
            "error-type" => Some(ErrorField::ErrorType),
            "error-tag" => Some(ErrorField::ErrorTag),
            "error-severity" => Some(ErrorField::ErrorSeverity),
            "error-app-tag" => Some(ErrorField::ErrorAppTag),
            "error-path" => Some(ErrorField::ErrorPath),
            "error-message" => Some(ErrorField::ErrorMessage),
            "error-info" => Some(ErrorField::ErrorInfo),
            _ => None,
        }
    }
}

/// Builder for constructing RpcErrorInfo from parsed XML fields.
struct RpcErrorBuilder {
    error_type: Option<RpcErrorType>,
    tag: Option<ErrorTag>,
    severity: Option<ErrorSeverity>,
    app_tag: Option<String>,
    path: Option<String>,
    message: Option<String>,
    info: Option<String>,
}

impl RpcErrorBuilder {
    fn new() -> Self {
        Self {
            error_type: None,
            tag: None,
            severity: None,
            app_tag: None,
            path: None,
            message: None,
            info: None,
        }
    }

    fn set_field(&mut self, field: &ErrorField, value: &str) {
        match field {
            ErrorField::ErrorType => {
                self.error_type = Some(match value {
                    "transport" => RpcErrorType::Transport,
                    "rpc" => RpcErrorType::Rpc,
                    "protocol" => RpcErrorType::Protocol,
                    "application" => RpcErrorType::Application,
                    _ => RpcErrorType::Application,
                });
            }
            ErrorField::ErrorTag => {
                self.tag = Some(ErrorTag::from_str(value));
            }
            ErrorField::ErrorSeverity => {
                self.severity = Some(match value {
                    "warning" => ErrorSeverity::Warning,
                    _ => ErrorSeverity::Error,
                });
            }
            ErrorField::ErrorAppTag => {
                self.app_tag = Some(value.to_string());
            }
            ErrorField::ErrorPath => {
                self.path = Some(value.to_string());
            }
            ErrorField::ErrorMessage => {
                self.message = Some(value.to_string());
            }
            ErrorField::ErrorInfo => {
                self.info = Some(value.to_string());
            }
        }
    }

    fn build(self) -> RpcErrorInfo {
        RpcErrorInfo {
            error_type: self.error_type,
            tag: self.tag.unwrap_or(ErrorTag::OperationFailed),
            severity: self.severity,
            app_tag: self.app_tag,
            path: self.path,
            message: self
                .message
                .unwrap_or_else(|| "unknown error".to_string()),
            info: self.info,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ok_reply() {
        let xml = r#"<rpc-reply xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="1">
  <ok/>
</rpc-reply>"#;
        let result = parse_rpc_reply(xml, "1").unwrap();
        assert!(matches!(result, RpcReply::Ok));
    }

    #[test]
    fn test_parse_data_reply() {
        let xml = r#"<rpc-reply xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="2">
  <data>
    <configuration><interfaces><interface><name>ge-0/0/0</name></interface></interfaces></configuration>
  </data>
</rpc-reply>"#;
        let result = parse_rpc_reply(xml, "2").unwrap();
        match result {
            RpcReply::Data(data) => {
                assert!(data.contains("ge-0/0/0"));
                assert!(data.contains("<configuration>"));
            }
            _ => panic!("expected Data reply"),
        }
    }

    #[test]
    fn test_parse_rpc_error() {
        let xml = r#"<rpc-reply xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="3">
  <rpc-error>
    <error-type>application</error-type>
    <error-tag>invalid-value</error-tag>
    <error-severity>error</error-severity>
    <error-path>/configuration/interfaces/interface[name='ge-0/0/0']</error-path>
    <error-message>invalid interface name</error-message>
  </rpc-error>
</rpc-reply>"#;
        let err = parse_rpc_reply(xml, "3").unwrap_err();
        match err {
            RpcError::ServerError {
                tag,
                message,
                path,
                ..
            } => {
                assert_eq!(tag, ErrorTag::InvalidValue);
                assert_eq!(message, "invalid interface name");
                assert!(path.unwrap().contains("ge-0/0/0"));
            }
            _ => panic!("expected ServerError, got {err:?}"),
        }
    }

    #[test]
    fn test_parse_message_id_mismatch() {
        let xml = r#"<rpc-reply xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="99">
  <ok/>
</rpc-reply>"#;
        let err = parse_rpc_reply(xml, "1").unwrap_err();
        assert!(matches!(err, RpcError::MessageIdMismatch { .. }));
    }

    #[test]
    fn test_parse_lock_denied_error() {
        let xml = r#"<rpc-reply xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="5">
  <rpc-error>
    <error-type>protocol</error-type>
    <error-tag>lock-denied</error-tag>
    <error-severity>error</error-severity>
    <error-message>Lock failed, lock is already held</error-message>
    <error-info>session-id: 42</error-info>
  </rpc-error>
</rpc-reply>"#;
        let err = parse_rpc_reply(xml, "5").unwrap_err();
        match err {
            RpcError::ServerError {
                tag, info, message, ..
            } => {
                assert_eq!(tag, ErrorTag::LockDenied);
                assert!(message.contains("Lock failed"));
                assert!(info.unwrap().contains("42"));
            }
            _ => panic!("expected ServerError"),
        }
    }
}
