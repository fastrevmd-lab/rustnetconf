use super::capture::{decode_attribute, FragmentCapture};
use super::{RpcErrorInfo, RpcReply};
use crate::error::RpcError;
use crate::types::{ErrorSeverity, ErrorTag, RpcErrorType};
use quick_xml::events::{BytesCData, BytesEnd, BytesRef, BytesStart, BytesText, Event};
use quick_xml::Reader;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EnvelopeState {
    BeforeReply,
    InsideReply,
    AfterReply,
}

#[derive(Debug)]
enum PayloadState {
    None,
    Ok,
    Data {
        capture: FragmentCapture,
        depth: usize,
        closed: bool,
    },
    Direct {
        capture: FragmentCapture,
        depth: usize,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ErrorField {
    Type,
    Tag,
    Severity,
    AppTag,
    Path,
    Message,
}

impl ErrorField {
    fn from_name(name: &[u8]) -> Option<Self> {
        match name {
            b"error-type" => Some(Self::Type),
            b"error-tag" => Some(Self::Tag),
            b"error-severity" => Some(Self::Severity),
            b"error-app-tag" => Some(Self::AppTag),
            b"error-path" => Some(Self::Path),
            b"error-message" => Some(Self::Message),
            _ => None,
        }
    }

    fn xml_name(self) -> &'static [u8] {
        match self {
            Self::Type => b"error-type",
            Self::Tag => b"error-tag",
            Self::Severity => b"error-severity",
            Self::AppTag => b"error-app-tag",
            Self::Path => b"error-path",
            Self::Message => b"error-message",
        }
    }
}

#[derive(Debug, Default)]
struct RpcErrorBuilder {
    error_type: Option<RpcErrorType>,
    tag: Option<ErrorTag>,
    severity: Option<ErrorSeverity>,
    app_tag: Option<String>,
    path: Option<String>,
    message: Option<String>,
    info: Option<String>,
}

#[derive(Debug)]
struct ErrorState {
    builder: RpcErrorBuilder,
    field: Option<ErrorField>,
    field_text: String,
    info_capture: Option<FragmentCapture>,
    info_depth: usize,
    info_seen: bool,
}

impl Default for ErrorState {
    fn default() -> Self {
        Self {
            builder: RpcErrorBuilder::default(),
            field: None,
            field_text: String::new(),
            info_capture: None,
            info_depth: 0,
            info_seen: false,
        }
    }
}

struct ReplyParser<'a> {
    expected_message_id: &'a str,
    envelope: EnvelopeState,
    message_id: Option<String>,
    payload: PayloadState,
    protocol_ok: bool,
    current_error: Option<ErrorState>,
    errors: Vec<RpcErrorInfo>,
}

impl<'a> ReplyParser<'a> {
    fn new(expected_message_id: &'a str) -> Self {
        Self {
            expected_message_id,
            envelope: EnvelopeState::BeforeReply,
            message_id: None,
            payload: PayloadState::None,
            protocol_ok: false,
            current_error: None,
            errors: Vec::new(),
        }
    }
}

pub(super) fn parse_strict(xml: &str, expected_message_id: &str) -> Result<RpcReply, RpcError> {
    let mut parser = ReplyParser::new(expected_message_id);
    let mut reader = Reader::from_str(xml);

    loop {
        match reader.read_event() {
            Ok(Event::Start(tag)) => parser.start(&tag)?,
            Ok(Event::Empty(tag)) => parser.empty(&tag)?,
            Ok(Event::Text(text)) => parser.text(&text)?,
            Ok(Event::CData(cdata)) => parser.cdata(&cdata)?,
            Ok(Event::GeneralRef(entity)) => parser.entity(&entity)?,
            Ok(Event::End(tag)) => parser.end(&tag)?,
            Ok(Event::Decl(_) | Event::Comment(_) | Event::PI(_)) => {}
            Ok(Event::DocType(_)) => {
                return Err(parse_error("DOCTYPE is not allowed in an RPC reply"));
            }
            Ok(Event::Eof) => break,
            Err(error) => {
                return Err(parse_error(format!("XML parse error: {error}")));
            }
        }
    }

    parser.finish()
}

fn parse_error(message: impl Into<String>) -> RpcError {
    RpcError::ParseError(message.into())
}

fn local_name(tag: &[u8]) -> &[u8] {
    tag.rsplit(|byte| *byte == b':').next().unwrap_or(tag)
}

impl ReplyParser<'_> {
    fn start(&mut self, tag: &BytesStart<'_>) -> Result<(), RpcError> {
        if self.current_error.is_none()
            && self.in_open_direct_payload()
            && local_name(tag.name().as_ref()) == b"rpc-reply"
        {
            return Err(parse_error("nested <rpc-reply> is not allowed"));
        }
        if self.current_error.is_none()
            && self.in_open_direct_payload()
            && local_name(tag.name().as_ref()) == b"rpc-error"
        {
            self.current_error = Some(ErrorState::default());
            return Ok(());
        }
        if self.capture_start(tag)? {
            return Ok(());
        }
        if self.current_error.is_some() {
            return self.error_start(tag);
        }

        match (self.envelope, local_name(tag.name().as_ref())) {
            (EnvelopeState::BeforeReply, b"rpc-reply") => self.open_reply(tag),
            (EnvelopeState::InsideReply, b"rpc-reply") => {
                Err(parse_error("nested <rpc-reply> is not allowed"))
            }
            (EnvelopeState::InsideReply, b"data") => self.open_data(),
            (EnvelopeState::InsideReply, b"rpc-error") => {
                self.current_error = Some(ErrorState::default());
                Ok(())
            }
            (EnvelopeState::InsideReply, b"ok") => {
                Err(parse_error("<ok> must be an empty element"))
            }
            (EnvelopeState::InsideReply, _) => self.open_direct(tag),
            (EnvelopeState::AfterReply, _) => Err(parse_error("element found after </rpc-reply>")),
            (EnvelopeState::BeforeReply, _) => Err(parse_error("root element is not <rpc-reply>")),
        }
    }

    fn empty(&mut self, tag: &BytesStart<'_>) -> Result<(), RpcError> {
        if self.current_error.is_none()
            && self.in_open_direct_payload()
            && local_name(tag.name().as_ref()) == b"rpc-reply"
        {
            return Err(parse_error("nested <rpc-reply> is not allowed"));
        }
        if self.current_error.is_none()
            && self.in_open_direct_payload()
            && local_name(tag.name().as_ref()) == b"ok"
        {
            self.protocol_ok = true;
            return Ok(());
        }
        if self.capture_empty(tag)? {
            return Ok(());
        }
        if self.current_error.is_some() {
            return self.error_empty(tag);
        }

        match (self.envelope, local_name(tag.name().as_ref())) {
            (EnvelopeState::BeforeReply, b"rpc-reply") => {
                self.open_reply(tag)?;
                self.envelope = EnvelopeState::AfterReply;
                Ok(())
            }
            (EnvelopeState::InsideReply, b"ok") => self.set_ok(),
            (EnvelopeState::InsideReply, b"data") => self.set_empty_data(),
            (EnvelopeState::InsideReply, b"rpc-error" | b"rpc-reply") => {
                Err(parse_error("invalid empty NETCONF reply element"))
            }
            (EnvelopeState::InsideReply, _) => self.capture_direct_empty(tag),
            (EnvelopeState::AfterReply, _) => Err(parse_error("element found after </rpc-reply>")),
            (EnvelopeState::BeforeReply, _) => Err(parse_error("root element is not <rpc-reply>")),
        }
    }

    fn text(&mut self, text: &BytesText<'_>) -> Result<(), RpcError> {
        if self.capture_text(text)? {
            return Ok(());
        }
        let decoded = text
            .decode()
            .map_err(|error| parse_error(format!("invalid text encoding: {error}")))?;
        if decoded.trim().is_empty() {
            Ok(())
        } else {
            Err(parse_error("significant text outside a reply payload"))
        }
    }

    fn cdata(&mut self, cdata: &BytesCData<'_>) -> Result<(), RpcError> {
        if self.capture_cdata(cdata)? {
            Ok(())
        } else {
            Err(parse_error("CDATA outside a reply payload"))
        }
    }

    fn entity(&mut self, entity: &BytesRef<'_>) -> Result<(), RpcError> {
        if self.capture_entity(entity)? {
            Ok(())
        } else {
            Err(parse_error("entity reference outside a reply payload"))
        }
    }

    fn in_open_direct_payload(&self) -> bool {
        matches!(
            self.payload,
            PayloadState::Direct { depth, .. } if depth > 0
        )
    }

    fn capture_start(&mut self, tag: &BytesStart<'_>) -> Result<bool, RpcError> {
        if let Some(error) = self.current_error.as_mut() {
            if let Some(capture) = error.info_capture.as_mut() {
                capture.start(tag)?;
                error.info_depth += 1;
                return Ok(true);
            }
            if error.field.is_some() {
                return Err(parse_error("nested element inside an rpc-error text field"));
            }
            return Ok(false);
        }

        match &mut self.payload {
            PayloadState::Data {
                capture,
                depth,
                closed: false,
            } => {
                capture.start(tag)?;
                *depth += 1;
                Ok(true)
            }
            PayloadState::Direct { capture, depth } if *depth > 0 => {
                capture.start(tag)?;
                *depth += 1;
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    fn capture_empty(&mut self, tag: &BytesStart<'_>) -> Result<bool, RpcError> {
        if let Some(error) = self.current_error.as_mut() {
            if let Some(capture) = error.info_capture.as_mut() {
                capture.empty(tag)?;
                return Ok(true);
            }
            if let Some(field) = error.field {
                if local_name(tag.name().as_ref()) == field.xml_name() {
                    error.builder.set_field(field, "")?;
                    error.field = None;
                    error.field_text.clear();
                    return Ok(true);
                }
                return Err(parse_error("nested element inside an rpc-error text field"));
            }
            return Ok(false);
        }

        match &mut self.payload {
            PayloadState::Data {
                capture,
                closed: false,
                ..
            } => {
                capture.empty(tag)?;
                Ok(true)
            }
            PayloadState::Direct { capture, depth } if *depth > 0 => {
                capture.empty(tag)?;
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    fn capture_text(&mut self, text: &BytesText<'_>) -> Result<bool, RpcError> {
        if let Some(error) = self.current_error.as_mut() {
            if let Some(capture) = error.info_capture.as_mut() {
                capture.text(text)?;
                return Ok(true);
            }
            if error.field.is_some() {
                let decoded = text
                    .decode()
                    .map_err(|cause| parse_error(format!("invalid text encoding: {cause}")))?;
                error.field_text.push_str(&decoded);
                return Ok(true);
            }
            return Ok(false);
        }

        match &mut self.payload {
            PayloadState::Data {
                capture,
                closed: false,
                ..
            } => {
                capture.text(text)?;
                Ok(true)
            }
            PayloadState::Direct { capture, depth } if *depth > 0 => {
                capture.text(text)?;
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    fn capture_cdata(&mut self, cdata: &BytesCData<'_>) -> Result<bool, RpcError> {
        if let Some(error) = self.current_error.as_mut() {
            if let Some(capture) = error.info_capture.as_mut() {
                capture.cdata(cdata)?;
                return Ok(true);
            }
            if error.field.is_some() {
                let decoded = cdata
                    .decode()
                    .map_err(|cause| parse_error(format!("invalid CDATA encoding: {cause}")))?;
                error.field_text.push_str(&decoded);
                return Ok(true);
            }
            return Ok(false);
        }

        match &mut self.payload {
            PayloadState::Data {
                capture,
                closed: false,
                ..
            } => {
                capture.cdata(cdata)?;
                Ok(true)
            }
            PayloadState::Direct { capture, depth } if *depth > 0 => {
                capture.cdata(cdata)?;
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    fn capture_entity(&mut self, entity: &BytesRef<'_>) -> Result<bool, RpcError> {
        if let Some(error) = self.current_error.as_mut() {
            if let Some(capture) = error.info_capture.as_mut() {
                capture.entity(entity)?;
                return Ok(true);
            }
            if error.field.is_some() {
                let resolved = crate::xml_entity::resolve_entity_ref(entity)
                    .ok_or_else(|| parse_error("invalid entity in rpc-error text field"))?;
                error.field_text.push_str(&resolved);
                return Ok(true);
            }
            return Ok(false);
        }

        match &mut self.payload {
            PayloadState::Data {
                capture,
                closed: false,
                ..
            } => {
                capture.entity(entity)?;
                Ok(true)
            }
            PayloadState::Direct { capture, depth } if *depth > 0 => {
                capture.entity(entity)?;
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    fn open_direct(&mut self, tag: &BytesStart<'_>) -> Result<(), RpcError> {
        match &mut self.payload {
            PayloadState::None => {
                let mut capture = FragmentCapture::default();
                capture.start(tag)?;
                self.payload = PayloadState::Direct { capture, depth: 1 };
                Ok(())
            }
            PayloadState::Direct { capture, depth } if *depth == 0 => {
                capture.start(tag)?;
                *depth = 1;
                Ok(())
            }
            _ => Err(parse_error(
                "direct payload conflicts with an existing payload",
            )),
        }
    }

    fn capture_direct_empty(&mut self, tag: &BytesStart<'_>) -> Result<(), RpcError> {
        match &mut self.payload {
            PayloadState::None => {
                let mut capture = FragmentCapture::default();
                capture.empty(tag)?;
                self.payload = PayloadState::Direct { capture, depth: 0 };
                Ok(())
            }
            PayloadState::Direct { capture, depth } if *depth == 0 => capture.empty(tag),
            _ => Err(parse_error(
                "direct payload conflicts with an existing payload",
            )),
        }
    }

    fn error_start(&mut self, tag: &BytesStart<'_>) -> Result<(), RpcError> {
        let error = self
            .current_error
            .as_mut()
            .expect("error_start requires current_error");
        let qualified_name = tag.name();
        let name = local_name(qualified_name.as_ref());

        if name == b"error-info" {
            if error.info_seen {
                return Err(parse_error("duplicate error-info"));
            }
            error.info_seen = true;
            error.info_capture = Some(FragmentCapture::default());
            error.info_depth = 0;
            return Ok(());
        }

        let field = ErrorField::from_name(name)
            .ok_or_else(|| parse_error("unknown element directly inside rpc-error"))?;
        if error.field.is_some() {
            return Err(parse_error("nested rpc-error text fields"));
        }
        error.field = Some(field);
        error.field_text.clear();
        Ok(())
    }

    fn error_empty(&mut self, tag: &BytesStart<'_>) -> Result<(), RpcError> {
        let error = self
            .current_error
            .as_mut()
            .expect("error_empty requires current_error");
        let qualified_name = tag.name();
        let name = local_name(qualified_name.as_ref());

        if name == b"error-info" {
            if error.info_seen {
                return Err(parse_error("duplicate error-info"));
            }
            error.info_seen = true;
            error.builder.info = Some(String::new());
            return Ok(());
        }

        let field = ErrorField::from_name(name)
            .ok_or_else(|| parse_error("unknown element directly inside rpc-error"))?;
        error.builder.set_field(field, "")
    }

    fn open_reply(&mut self, tag: &BytesStart<'_>) -> Result<(), RpcError> {
        if self.envelope != EnvelopeState::BeforeReply {
            return Err(parse_error("multiple <rpc-reply> envelopes"));
        }

        let mut message_id = None;
        for attribute in tag.attributes().with_checks(true) {
            let attribute = attribute
                .map_err(|error| parse_error(format!("invalid XML attribute: {error}")))?;
            if attribute.key.as_ref() == b"message-id" {
                if message_id.is_some() {
                    return Err(parse_error("duplicate message-id attribute"));
                }
                message_id = Some(decode_attribute(attribute.value.as_ref())?);
            }
        }

        self.message_id = message_id;
        self.envelope = EnvelopeState::InsideReply;
        Ok(())
    }

    fn set_ok(&mut self) -> Result<(), RpcError> {
        match self.payload {
            PayloadState::None => {
                self.payload = PayloadState::Ok;
                Ok(())
            }
            _ => Err(parse_error("<ok/> conflicts with an existing payload")),
        }
    }

    fn open_data(&mut self) -> Result<(), RpcError> {
        match self.payload {
            PayloadState::None => {
                self.payload = PayloadState::Data {
                    capture: FragmentCapture::default(),
                    depth: 0,
                    closed: false,
                };
                Ok(())
            }
            _ => Err(parse_error("<data> conflicts with an existing payload")),
        }
    }

    fn set_empty_data(&mut self) -> Result<(), RpcError> {
        match self.payload {
            PayloadState::None => {
                self.payload = PayloadState::Data {
                    capture: FragmentCapture::default(),
                    depth: 0,
                    closed: true,
                };
                Ok(())
            }
            _ => Err(parse_error("<data/> conflicts with an existing payload")),
        }
    }

    fn end(&mut self, tag: &BytesEnd<'_>) -> Result<(), RpcError> {
        let qualified_name = tag.name();
        let name = local_name(qualified_name.as_ref());

        if self.current_error.is_some() {
            {
                let error = self
                    .current_error
                    .as_mut()
                    .expect("current_error was checked");

                if let Some(capture) = error.info_capture.as_mut() {
                    if error.info_depth > 0 {
                        capture.end(tag)?;
                        error.info_depth -= 1;
                        return Ok(());
                    }
                    if name != b"error-info" {
                        return Err(parse_error("unexpected end inside error-info"));
                    }
                    let info = error
                        .info_capture
                        .take()
                        .expect("error-info capture exists")
                        .finish()?;
                    error.builder.info = Some(info);
                    return Ok(());
                }

                if let Some(field) = error.field {
                    if name != field.xml_name() {
                        return Err(parse_error("rpc-error field closed by wrong element"));
                    }
                    error.builder.set_field(field, &error.field_text)?;
                    error.field = None;
                    error.field_text.clear();
                    return Ok(());
                }
            }

            if name == b"rpc-error" {
                let error = self
                    .current_error
                    .take()
                    .expect("current_error was checked");
                self.errors.push(error.builder.finish()?);
                return Ok(());
            }
            return Err(parse_error("unexpected end directly inside rpc-error"));
        }

        match &mut self.payload {
            PayloadState::Data {
                capture,
                depth,
                closed,
            } if !*closed => {
                if *depth > 0 {
                    capture.end(tag)?;
                    *depth -= 1;
                    return Ok(());
                }
                if name == b"data" {
                    *closed = true;
                    return Ok(());
                }
                return Err(parse_error("unexpected end inside data payload"));
            }
            PayloadState::Direct { capture, depth } if *depth > 0 => {
                capture.end(tag)?;
                *depth -= 1;
                return Ok(());
            }
            _ => {}
        }

        if name != b"rpc-reply" {
            return Err(parse_error("unexpected end directly inside rpc-reply"));
        }
        if self.envelope != EnvelopeState::InsideReply {
            return Err(parse_error("rpc-reply closed outside its envelope"));
        }
        self.envelope = EnvelopeState::AfterReply;
        Ok(())
    }

    fn finish(self) -> Result<RpcReply, RpcError> {
        if self.envelope != EnvelopeState::AfterReply {
            return Err(parse_error("RPC reply envelope did not close"));
        }
        if self.current_error.is_some() {
            return Err(parse_error("<rpc-error> did not close"));
        }

        let message_id = self
            .message_id
            .ok_or_else(|| parse_error("rpc-reply is missing message-id"))?;
        if message_id != self.expected_message_id {
            return Err(RpcError::MessageIdMismatch {
                expected: self.expected_message_id.to_string(),
                actual: message_id,
            });
        }

        let (hard_errors, warnings): (Vec<_>, Vec<_>) = self
            .errors
            .into_iter()
            .partition(|error| error.severity != Some(ErrorSeverity::Warning));

        if let Some(error) = hard_errors.into_iter().next() {
            return Err(RpcError::ServerError {
                error_type: error.error_type,
                tag: error.tag,
                severity: error.severity,
                app_tag: error.app_tag,
                path: error.path,
                message: error.message,
                info: error.info,
            });
        }

        for warning in &warnings {
            tracing::warn!(
                tag = ?warning.tag,
                message = %warning.message,
                "device returned RPC warning"
            );
        }

        if self.protocol_ok {
            return if warnings.is_empty() {
                Ok(RpcReply::Ok)
            } else {
                Ok(RpcReply::OkWithWarnings(warnings))
            };
        }

        match self.payload {
            PayloadState::Data {
                capture,
                closed: true,
                ..
            }
            | PayloadState::Direct { capture, depth: 0 } => {
                let data = capture.finish()?;
                if warnings.is_empty() {
                    Ok(RpcReply::Data(data))
                } else {
                    Ok(RpcReply::DataWithWarnings(data, warnings))
                }
            }
            PayloadState::Ok | PayloadState::None if warnings.is_empty() => Ok(RpcReply::Ok),
            PayloadState::Ok | PayloadState::None => Ok(RpcReply::OkWithWarnings(warnings)),
            PayloadState::Data { .. } | PayloadState::Direct { .. } => {
                Err(parse_error("reply payload did not close"))
            }
        }
    }
}

impl RpcErrorBuilder {
    fn set_field(&mut self, field: ErrorField, value: &str) -> Result<(), RpcError> {
        let duplicate = match field {
            ErrorField::Type => self.error_type.is_some(),
            ErrorField::Tag => self.tag.is_some(),
            ErrorField::Severity => self.severity.is_some(),
            ErrorField::AppTag => self.app_tag.is_some(),
            ErrorField::Path => self.path.is_some(),
            ErrorField::Message => self.message.is_some(),
        };
        if duplicate {
            let name = String::from_utf8_lossy(field.xml_name());
            return Err(parse_error(format!("duplicate rpc-error {name}")));
        }

        match field {
            ErrorField::Type => {
                self.error_type = Some(match value.trim() {
                    "transport" => RpcErrorType::Transport,
                    "rpc" => RpcErrorType::Rpc,
                    "protocol" => RpcErrorType::Protocol,
                    "application" => RpcErrorType::Application,
                    _ => {
                        return Err(parse_error("invalid rpc-error error-type"));
                    }
                });
            }
            ErrorField::Tag => {
                self.tag = Some(
                    value
                        .trim()
                        .parse()
                        .expect("ErrorTag::from_str is infallible"),
                );
            }
            ErrorField::Severity => {
                self.severity = Some(match value.trim() {
                    "error" => ErrorSeverity::Error,
                    "warning" => ErrorSeverity::Warning,
                    _ => {
                        return Err(parse_error("invalid rpc-error error-severity"));
                    }
                });
            }
            ErrorField::AppTag => self.app_tag = Some(value.to_string()),
            ErrorField::Path => self.path = Some(value.to_string()),
            ErrorField::Message => self.message = Some(value.to_string()),
        }
        Ok(())
    }

    fn finish(self) -> Result<RpcErrorInfo, RpcError> {
        Ok(RpcErrorInfo {
            error_type: Some(
                self.error_type
                    .ok_or_else(|| parse_error("rpc-error is missing error-type"))?,
            ),
            tag: self
                .tag
                .ok_or_else(|| parse_error("rpc-error is missing error-tag"))?,
            severity: Some(
                self.severity
                    .ok_or_else(|| parse_error("rpc-error is missing error-severity"))?,
            ),
            app_tag: self.app_tag,
            path: self.path,
            message: self.message.unwrap_or_default(),
            info: self.info,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_state_parses_standard_outcomes() {
        let ok = r#"<rpc-reply message-id="1"><ok/></rpc-reply>"#;
        assert!(matches!(parse_strict(ok, "1"), Ok(RpcReply::Ok)));

        let data = r#"<rpc-reply message-id="2"><data><x/></data></rpc-reply>"#;
        assert!(matches!(parse_strict(data, "2"), Ok(RpcReply::Data(_))));

        let empty_data = r#"<rpc-reply message-id="2b"><data/></rpc-reply>"#;
        assert!(matches!(
            parse_strict(empty_data, "2b"),
            Ok(RpcReply::Data(data)) if data.is_empty()
        ));

        let direct = r#"<rpc-reply message-id="3"><output>done</output></rpc-reply>"#;
        assert!(matches!(parse_strict(direct, "3"), Ok(RpcReply::Data(_))));

        let empty = r#"<rpc-reply message-id="4"></rpc-reply>"#;
        assert!(matches!(parse_strict(empty, "4"), Ok(RpcReply::Ok)));
    }

    #[test]
    fn explicit_state_parses_errors_and_warnings() {
        let warning = r#"<rpc-reply message-id="5">
          <rpc-error>
            <error-type>application</error-type>
            <error-tag>operation-failed</error-tag>
            <error-severity>warning</error-severity>
            <error-message>warning text</error-message>
          </rpc-error>
          <ok/>
        </rpc-reply>"#;
        assert!(matches!(
            parse_strict(warning, "5"),
            Ok(RpcReply::OkWithWarnings(_))
        ));

        let error = r#"<rpc-reply message-id="6">
          <rpc-error>
            <error-type>application</error-type>
            <error-tag>invalid-value</error-tag>
            <error-severity>error</error-severity>
            <error-message>bad value</error-message>
          </rpc-error>
        </rpc-reply>"#;
        assert!(matches!(
            parse_strict(error, "6"),
            Err(RpcError::ServerError { .. })
        ));
    }

    #[test]
    fn direct_vendor_wrappers_preserve_nested_protocol_outcomes() {
        let ok = r#"<rpc-reply message-id="7">
          <routing-engine><commit-check-success/><ok/></routing-engine>
        </rpc-reply>"#;
        assert!(matches!(parse_strict(ok, "7"), Ok(RpcReply::Ok)));

        let error = r#"<rpc-reply message-id="8"><routing-engine>
          <rpc-error>
            <error-type>application</error-type>
            <error-tag>operation-failed</error-tag>
            <error-severity>error</error-severity>
            <error-message>commit check failed</error-message>
          </rpc-error>
        </routing-engine></rpc-reply>"#;
        assert!(matches!(
            parse_strict(error, "8"),
            Err(RpcError::ServerError { .. })
        ));

        let data = r#"<rpc-reply message-id="9"><data>
          <rpc-error><error-message>modeled data</error-message></rpc-error>
          <ok/>
        </data></rpc-reply>"#;
        assert!(matches!(parse_strict(data, "9"), Ok(RpcReply::Data(_))));
    }

    #[test]
    fn rejects_missing_mandatory_rpc_error_fields() {
        let cases = [
            (
                "error-type",
                r#"<error-tag>operation-failed</error-tag>
                   <error-severity>error</error-severity>"#,
            ),
            (
                "error-tag",
                r#"<error-type>application</error-type>
                   <error-severity>error</error-severity>"#,
            ),
            (
                "error-severity",
                r#"<error-type>application</error-type>
                   <error-tag>operation-failed</error-tag>"#,
            ),
        ];

        for (missing, fields) in cases {
            let xml =
                format!(r#"<rpc-reply message-id="1"><rpc-error>{fields}</rpc-error></rpc-reply>"#);
            let error = parse_strict(&xml, "1").expect_err("missing field must fail");
            assert!(matches!(error, RpcError::ParseError(_)));
            assert!(
                error.to_string().contains(missing),
                "error must name {missing}: {error}"
            );
        }
    }

    #[test]
    fn rejects_invalid_rpc_error_type_and_severity() {
        let invalid_type = r#"<rpc-reply message-id="1"><rpc-error>
          <error-type>vendor-layer</error-type>
          <error-tag>operation-failed</error-tag>
          <error-severity>error</error-severity>
        </rpc-error></rpc-reply>"#;
        assert!(matches!(
            parse_strict(invalid_type, "1"),
            Err(RpcError::ParseError(_))
        ));

        let invalid_severity = r#"<rpc-reply message-id="1"><rpc-error>
          <error-type>application</error-type>
          <error-tag>operation-failed</error-tag>
          <error-severity>notice</error-severity>
        </rpc-error></rpc-reply>"#;
        assert!(matches!(
            parse_strict(invalid_severity, "1"),
            Err(RpcError::ParseError(_))
        ));
    }

    #[test]
    fn invalid_rpc_error_value_diagnostics_are_bounded() {
        let marker = "SENSITIVE_DEVICE_VALUE";
        let invalid = format!("{marker}{}", "x".repeat(4096));
        let cases = [
            (
                "error-type",
                format!(
                    r#"<error-type>{invalid}</error-type>
                       <error-tag>operation-failed</error-tag>
                       <error-severity>error</error-severity>"#
                ),
            ),
            (
                "error-severity",
                format!(
                    r#"<error-type>application</error-type>
                       <error-tag>operation-failed</error-tag>
                       <error-severity>{invalid}</error-severity>"#
                ),
            ),
        ];

        for (field, fields) in cases {
            let xml =
                format!(r#"<rpc-reply message-id="1"><rpc-error>{fields}</rpc-error></rpc-reply>"#);
            let error = parse_strict(&xml, "1").expect_err("invalid value must fail");
            let RpcError::ParseError(message) = error else {
                panic!("expected ParseError");
            };
            assert!(
                message.contains(field),
                "error must name {field}: {message}"
            );
            assert!(message.len() < 128, "error must stay bounded: {message}");
            assert!(
                !message.contains(marker),
                "error must not echo device content: {message}"
            );
        }
    }

    #[test]
    fn warning_only_reply_preserves_warning() {
        let xml = r#"<rpc-reply message-id="1"><rpc-error>
          <error-type>application</error-type>
          <error-tag>operation-failed</error-tag>
          <error-severity>warning</error-severity>
          <error-message>device warning</error-message>
        </rpc-error></rpc-reply>"#;

        let reply = parse_strict(xml, "1").expect("warning-only reply succeeds");
        let RpcReply::OkWithWarnings(warnings) = reply else {
            panic!("expected OkWithWarnings");
        };
        assert_eq!(warnings.len(), 1);
        assert_eq!(warnings[0].message, "device warning");
    }

    #[test]
    fn error_info_preserves_nested_attributes() {
        let xml = r#"<rpc-reply message-id="1"><rpc-error>
          <error-type>application</error-type>
          <error-tag>operation-failed</error-tag>
          <error-severity>error</error-severity>
          <error-info>
            <bad-element xmlns:v="urn:vendor" v:source="candidate">x &amp; y</bad-element>
          </error-info>
        </rpc-error></rpc-reply>"#;

        let error = parse_strict(xml, "1").expect_err("hard error");
        let RpcError::ServerError {
            info: Some(info), ..
        } = error
        else {
            panic!("expected ServerError with error-info");
        };
        assert!(info.contains("xmlns:v=\"urn:vendor\""));
        assert!(info.contains("v:source=\"candidate\""));
        assert!(info.contains("x &amp; y"));
    }

    #[test]
    fn missing_optional_error_message_is_empty() {
        let xml = r#"<rpc-reply message-id="1"><rpc-error>
          <error-type>application</error-type>
          <error-tag>operation-failed</error-tag>
          <error-severity>error</error-severity>
        </rpc-error></rpc-reply>"#;

        let error = parse_strict(xml, "1").expect_err("hard error");
        let RpcError::ServerError { message, .. } = error else {
            panic!("expected ServerError");
        };
        assert!(message.is_empty());
    }

    #[test]
    fn rejects_duplicate_rpc_error_fields_and_info() {
        let cases = [
            r#"<error-type>application</error-type>
               <error-type>protocol</error-type>
               <error-tag>operation-failed</error-tag>
               <error-severity>error</error-severity>"#,
            r#"<error-type>application</error-type>
               <error-tag>operation-failed</error-tag>
               <error-severity>error</error-severity>
               <error-info/><error-info/>"#,
        ];

        for fields in cases {
            let xml =
                format!(r#"<rpc-reply message-id="1"><rpc-error>{fields}</rpc-error></rpc-reply>"#);
            assert!(matches!(
                parse_strict(&xml, "1"),
                Err(RpcError::ParseError(_))
            ));
        }
    }

    #[test]
    fn warning_only_reply_preserves_all_optional_details() {
        let xml = r#"<rpc-reply message-id="1"><rpc-error>
          <error-type>application</error-type>
          <error-tag>operation-failed</error-tag>
          <error-severity>warning</error-severity>
          <error-app-tag>vendor-warning</error-app-tag>
          <error-path>/configuration/system</error-path>
          <error-message>device warning</error-message>
          <error-info><detail code="42"><![CDATA[x < y]]></detail></error-info>
        </rpc-error></rpc-reply>"#;

        let reply = parse_strict(xml, "1").expect("warning-only reply succeeds");
        let RpcReply::OkWithWarnings(warnings) = reply else {
            panic!("expected OkWithWarnings");
        };
        let warning = &warnings[0];
        assert_eq!(warning.error_type, Some(RpcErrorType::Application));
        assert_eq!(warning.tag, ErrorTag::OperationFailed);
        assert_eq!(warning.severity, Some(ErrorSeverity::Warning));
        assert_eq!(warning.app_tag.as_deref(), Some("vendor-warning"));
        assert_eq!(warning.path.as_deref(), Some("/configuration/system"));
        assert_eq!(warning.message, "device warning");
        let info = warning.info.as_deref().expect("error-info");
        assert!(info.contains("code=\"42\""));
        assert!(info.contains("x &lt; y"));
    }
}
