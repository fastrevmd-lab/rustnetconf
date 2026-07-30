use super::capture::{
    decode_attribute, is_namespace_declaration, namespace_declarations, validate_qname,
    FragmentCapture, NamespaceBindings,
};
use super::{RpcErrorInfo, RpcReply};
use crate::error::RpcError;
use crate::types::{ErrorSeverity, ErrorTag, RpcErrorType};
use quick_xml::events::{BytesCData, BytesEnd, BytesRef, BytesStart, BytesText, Event};
use quick_xml::Reader;

pub(super) const NETCONF_NAMESPACE: &str = "urn:ietf:params:xml:ns:netconf:base:1.0";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EnvelopeState {
    Before,
    Inside,
    After,
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

#[derive(Debug, Clone, Copy)]
enum IgnoredPayload {
    Data { depth: usize },
    Direct { depth: usize },
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

#[derive(Debug, Default)]
struct ErrorState {
    builder: RpcErrorBuilder,
    field: Option<ErrorField>,
    field_text: String,
    info_capture: Option<FragmentCapture>,
    info_depth: usize,
    info_seen: bool,
}

struct ReplyParser<'a> {
    expected_message_id: &'a str,
    envelope: EnvelopeState,
    message_id: Option<String>,
    payload: PayloadState,
    protocol_ok: bool,
    current_error: Option<ErrorState>,
    errors: Vec<RpcErrorInfo>,
    deferred_payload_error: Option<&'static str>,
    ignored_payload: Option<IgnoredPayload>,
    namespaces: NamespaceBindings,
    namespace_frames: Vec<Vec<(String, Option<String>)>>,
}

impl<'a> ReplyParser<'a> {
    fn new(expected_message_id: &'a str) -> Self {
        Self {
            expected_message_id,
            envelope: EnvelopeState::Before,
            message_id: None,
            payload: PayloadState::None,
            protocol_ok: false,
            current_error: None,
            errors: Vec::new(),
            deferred_payload_error: None,
            ignored_payload: None,
            namespaces: NamespaceBindings::new(),
            namespace_frames: Vec::new(),
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

impl ReplyParser<'_> {
    fn start(&mut self, tag: &BytesStart<'_>) -> Result<(), RpcError> {
        self.push_namespaces(tag)?;
        self.handle_start(tag)
    }

    fn handle_start(&mut self, tag: &BytesStart<'_>) -> Result<(), RpcError> {
        let qualified_name = tag.name();
        let protocol_name = self.netconf_local_name(qualified_name.as_ref());
        if self.current_error.is_some() {
            if self.capture_start(tag)? {
                return Ok(());
            }
            return self.error_start(tag);
        }
        if self.ignored_payload.is_some() {
            return self.ignored_start(tag);
        }
        if self.current_error.is_none()
            && self.in_open_direct_payload()
            && protocol_name == Some(b"rpc-reply")
        {
            return Err(parse_error("nested <rpc-reply> is not allowed"));
        }
        if self.current_error.is_none()
            && self.in_open_direct_payload()
            && protocol_name == Some(b"rpc-error")
        {
            self.current_error = Some(ErrorState::default());
            return Ok(());
        }
        if self.current_error.is_none()
            && self.in_open_direct_payload()
            && protocol_name == Some(b"ok")
        {
            return Err(parse_error("<ok> must be an empty element"));
        }
        if self.capture_start(tag)? {
            return Ok(());
        }
        if self.current_error.is_some() {
            return self.error_start(tag);
        }

        match (self.envelope, protocol_name) {
            (EnvelopeState::Before, Some(b"rpc-reply")) => self.open_reply(tag),
            (EnvelopeState::Inside, Some(b"rpc-reply")) => {
                Err(parse_error("nested <rpc-reply> is not allowed"))
            }
            (EnvelopeState::Inside, Some(b"data")) => self.open_data(),
            (EnvelopeState::Inside, Some(b"rpc-error")) => {
                self.current_error = Some(ErrorState::default());
                Ok(())
            }
            (EnvelopeState::Inside, Some(b"ok")) => {
                Err(parse_error("<ok> must be an empty element"))
            }
            (EnvelopeState::Inside, _) => self.open_direct(tag),
            (EnvelopeState::After, _) => Err(parse_error("element found after </rpc-reply>")),
            (EnvelopeState::Before, _) => Err(parse_error("root element is not <rpc-reply>")),
        }
    }

    fn empty(&mut self, tag: &BytesStart<'_>) -> Result<(), RpcError> {
        self.push_namespaces(tag)?;
        let result = self.handle_empty(tag);
        self.pop_namespaces();
        result
    }

    fn handle_empty(&mut self, tag: &BytesStart<'_>) -> Result<(), RpcError> {
        let qualified_name = tag.name();
        let protocol_name = self.netconf_local_name(qualified_name.as_ref());
        if self.current_error.is_some() {
            if self.capture_empty(tag)? {
                return Ok(());
            }
            return self.error_empty(tag);
        }
        if self.ignored_payload.is_some() {
            return self.ignored_empty(tag);
        }
        if self.current_error.is_none()
            && self.in_open_direct_payload()
            && protocol_name == Some(b"rpc-reply")
        {
            return Err(parse_error("nested <rpc-reply> is not allowed"));
        }
        if self.current_error.is_none()
            && self.in_open_direct_payload()
            && protocol_name == Some(b"ok")
        {
            self.protocol_ok = true;
            return Ok(());
        }
        if self.current_error.is_none()
            && self.in_open_direct_payload()
            && protocol_name == Some(b"rpc-error")
        {
            return RpcErrorBuilder::default().finish().map(|_| ());
        }
        if self.capture_empty(tag)? {
            return Ok(());
        }
        if self.current_error.is_some() {
            return self.error_empty(tag);
        }

        match (self.envelope, protocol_name) {
            (EnvelopeState::Before, Some(b"rpc-reply")) => {
                self.open_reply(tag)?;
                self.envelope = EnvelopeState::After;
                Ok(())
            }
            (EnvelopeState::Inside, Some(b"ok")) => self.set_ok(),
            (EnvelopeState::Inside, Some(b"data")) => self.set_empty_data(),
            (EnvelopeState::Inside, Some(b"rpc-error" | b"rpc-reply")) => {
                Err(parse_error("invalid empty NETCONF reply element"))
            }
            (EnvelopeState::Inside, _) => self.capture_direct_empty(tag),
            (EnvelopeState::After, _) => Err(parse_error("element found after </rpc-reply>")),
            (EnvelopeState::Before, _) => Err(parse_error("root element is not <rpc-reply>")),
        }
    }

    fn text(&mut self, text: &BytesText<'_>) -> Result<(), RpcError> {
        if self.ignored_payload.is_some() && self.current_error.is_none() {
            text.decode()
                .map_err(|error| parse_error(format!("invalid text encoding: {error}")))?;
            return Ok(());
        }
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
        if self.ignored_payload.is_some() && self.current_error.is_none() {
            cdata
                .decode()
                .map_err(|error| parse_error(format!("invalid CDATA encoding: {error}")))?;
            return Ok(());
        }
        if self.capture_cdata(cdata)? {
            Ok(())
        } else {
            Err(parse_error("CDATA outside a reply payload"))
        }
    }

    fn entity(&mut self, entity: &BytesRef<'_>) -> Result<(), RpcError> {
        if self.ignored_payload.is_some() && self.current_error.is_none() {
            let mut validation = FragmentCapture::default();
            validation.entity(entity)?;
            return Ok(());
        }
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
        let qualified_name = tag.name();
        let protocol_name = self
            .netconf_local_name(qualified_name.as_ref())
            .map(<[u8]>::to_vec);
        if let Some(error) = self.current_error.as_mut() {
            if let Some(capture) = error.info_capture.as_mut() {
                capture.empty(tag)?;
                return Ok(true);
            }
            if let Some(field) = error.field {
                if protocol_name.as_deref() == Some(field.xml_name()) {
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
        let parent_namespaces = self.parent_namespaces();
        match &mut self.payload {
            PayloadState::None => {
                let mut capture = FragmentCapture::with_namespaces(parent_namespaces);
                capture.start(tag)?;
                self.payload = PayloadState::Direct { capture, depth: 1 };
                Ok(())
            }
            PayloadState::Direct { capture, depth } if *depth == 0 => {
                capture.start(tag)?;
                *depth = 1;
                Ok(())
            }
            _ => {
                self.defer_payload_conflict("direct payload conflicts with an existing payload");
                self.ignored_payload = Some(IgnoredPayload::Direct { depth: 1 });
                Ok(())
            }
        }
    }

    fn capture_direct_empty(&mut self, tag: &BytesStart<'_>) -> Result<(), RpcError> {
        match &mut self.payload {
            PayloadState::None => {
                let mut capture = FragmentCapture::with_namespaces(self.namespaces.clone());
                capture.empty(tag)?;
                self.payload = PayloadState::Direct { capture, depth: 0 };
                Ok(())
            }
            PayloadState::Direct { capture, depth } if *depth == 0 => capture.empty(tag),
            _ => {
                self.defer_payload_conflict("direct payload conflicts with an existing payload");
                Ok(())
            }
        }
    }

    fn error_start(&mut self, tag: &BytesStart<'_>) -> Result<(), RpcError> {
        let namespaces = self.namespaces.clone();
        let qualified_name = tag.name();
        let name = self.netconf_local_name(qualified_name.as_ref());
        let error = self
            .current_error
            .as_mut()
            .expect("error_start requires current_error");
        if name == Some(b"error-info") {
            if error.info_seen {
                return Err(parse_error("duplicate error-info"));
            }
            error.info_seen = true;
            error.info_capture = Some(FragmentCapture::with_namespaces(namespaces));
            error.info_depth = 0;
            return Ok(());
        }

        let field = name
            .and_then(ErrorField::from_name)
            .ok_or_else(|| parse_error("unknown element directly inside rpc-error"))?;
        if error.field.is_some() {
            return Err(parse_error("nested rpc-error text fields"));
        }
        error.field = Some(field);
        error.field_text.clear();
        Ok(())
    }

    fn error_empty(&mut self, tag: &BytesStart<'_>) -> Result<(), RpcError> {
        let qualified_name = tag.name();
        let name = self.netconf_local_name(qualified_name.as_ref());
        let error = self
            .current_error
            .as_mut()
            .expect("error_empty requires current_error");
        if name == Some(b"error-info") {
            if error.info_seen {
                return Err(parse_error("duplicate error-info"));
            }
            error.info_seen = true;
            error.builder.info = Some(String::new());
            return Ok(());
        }

        let field = name
            .and_then(ErrorField::from_name)
            .ok_or_else(|| parse_error("unknown element directly inside rpc-error"))?;
        error.builder.set_field(field, "")
    }

    fn open_reply(&mut self, tag: &BytesStart<'_>) -> Result<(), RpcError> {
        if self.envelope != EnvelopeState::Before {
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
                message_id = Some(decode_attribute(
                    attribute.value.as_ref(),
                    "message-id attribute",
                )?);
            }
        }

        self.message_id = message_id;
        self.envelope = EnvelopeState::Inside;
        Ok(())
    }

    fn set_ok(&mut self) -> Result<(), RpcError> {
        match self.payload {
            PayloadState::None => {
                self.payload = PayloadState::Ok;
                Ok(())
            }
            _ => {
                self.defer_payload_conflict("<ok/> conflicts with an existing payload");
                Ok(())
            }
        }
    }

    fn open_data(&mut self) -> Result<(), RpcError> {
        match self.payload {
            PayloadState::None => {
                self.payload = PayloadState::Data {
                    capture: FragmentCapture::with_namespaces(self.namespaces.clone()),
                    depth: 0,
                    closed: false,
                };
                Ok(())
            }
            _ => {
                self.defer_payload_conflict("<data> conflicts with an existing payload");
                self.ignored_payload = Some(IgnoredPayload::Data { depth: 1 });
                Ok(())
            }
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
            _ => {
                self.defer_payload_conflict("<data/> conflicts with an existing payload");
                Ok(())
            }
        }
    }

    fn end(&mut self, tag: &BytesEnd<'_>) -> Result<(), RpcError> {
        self.validate_element_name(tag.name().as_ref())?;
        self.handle_end(tag)?;
        self.pop_namespaces();
        Ok(())
    }

    fn handle_end(&mut self, tag: &BytesEnd<'_>) -> Result<(), RpcError> {
        let qualified_name = tag.name();
        let name = self.netconf_local_name(qualified_name.as_ref());

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
                    if name != Some(b"error-info") {
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
                    if name != Some(field.xml_name()) {
                        return Err(parse_error("rpc-error field closed by wrong element"));
                    }
                    error.builder.set_field(field, &error.field_text)?;
                    error.field = None;
                    error.field_text.clear();
                    return Ok(());
                }
            }

            if name == Some(b"rpc-error") {
                let error = self
                    .current_error
                    .take()
                    .expect("current_error was checked");
                self.errors.push(error.builder.finish()?);
                return Ok(());
            }
            return Err(parse_error("unexpected end directly inside rpc-error"));
        }

        if let Some(ignored) = self.ignored_payload.as_mut() {
            let depth = match ignored {
                IgnoredPayload::Data { depth } | IgnoredPayload::Direct { depth } => depth,
            };
            *depth -= 1;
            if *depth == 0 {
                self.ignored_payload = None;
            }
            return Ok(());
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
                if name == Some(b"data") {
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

        if name != Some(b"rpc-reply") {
            return Err(parse_error("unexpected end directly inside rpc-reply"));
        }
        if self.envelope != EnvelopeState::Inside {
            return Err(parse_error("rpc-reply closed outside its envelope"));
        }
        self.envelope = EnvelopeState::After;
        Ok(())
    }

    fn push_namespaces(&mut self, tag: &BytesStart<'_>) -> Result<(), RpcError> {
        let declarations = namespace_declarations(tag)?;
        let mut frame = Vec::with_capacity(declarations.len());
        for (prefix, value) in declarations {
            let previous = if value.is_empty() {
                self.namespaces.remove(&prefix)
            } else {
                self.namespaces.insert(prefix.clone(), value)
            };
            frame.push((prefix, previous));
        }
        self.validate_element_name(tag.name().as_ref())?;
        for attribute in tag.attributes().with_checks(true) {
            let attribute = attribute
                .map_err(|error| parse_error(format!("invalid XML attribute: {error}")))?;
            if is_namespace_declaration(attribute.key.as_ref()) {
                continue;
            }
            let name = validate_qname(attribute.key.as_ref())?;
            self.validate_bound_prefix(name.prefix)?;
        }
        self.namespace_frames.push(frame);
        Ok(())
    }

    fn pop_namespaces(&mut self) {
        let frame = self
            .namespace_frames
            .pop()
            .expect("every end event has a namespace frame");
        for (prefix, previous) in frame.into_iter().rev() {
            if let Some(value) = previous {
                self.namespaces.insert(prefix, value);
            } else {
                self.namespaces.remove(&prefix);
            }
        }
    }

    fn parent_namespaces(&self) -> NamespaceBindings {
        let mut parent = self.namespaces.clone();
        if let Some(frame) = self.namespace_frames.last() {
            for (prefix, previous) in frame.iter().rev() {
                if let Some(value) = previous {
                    parent.insert(prefix.clone(), value.clone());
                } else {
                    parent.remove(prefix);
                }
            }
        }
        parent
    }

    fn ignored_start(&mut self, tag: &BytesStart<'_>) -> Result<(), RpcError> {
        let qualified_name = tag.name();
        let name = self.netconf_local_name(qualified_name.as_ref());
        match self.ignored_payload {
            Some(IgnoredPayload::Data { ref mut depth }) => {
                *depth += 1;
                Ok(())
            }
            Some(IgnoredPayload::Direct { .. }) if name == Some(b"rpc-reply") => {
                Err(parse_error("nested <rpc-reply> is not allowed"))
            }
            Some(IgnoredPayload::Direct { .. }) if name == Some(b"rpc-error") => {
                self.current_error = Some(ErrorState::default());
                Ok(())
            }
            Some(IgnoredPayload::Direct { .. }) if name == Some(b"ok") => {
                Err(parse_error("<ok> must be an empty element"))
            }
            Some(IgnoredPayload::Direct { ref mut depth }) => {
                *depth += 1;
                Ok(())
            }
            None => unreachable!("ignored_start requires an ignored payload"),
        }
    }

    fn ignored_empty(&mut self, tag: &BytesStart<'_>) -> Result<(), RpcError> {
        let qualified_name = tag.name();
        let name = self.netconf_local_name(qualified_name.as_ref());
        match self.ignored_payload {
            Some(IgnoredPayload::Data { .. }) => Ok(()),
            Some(IgnoredPayload::Direct { .. }) if name == Some(b"rpc-reply") => {
                Err(parse_error("nested <rpc-reply> is not allowed"))
            }
            Some(IgnoredPayload::Direct { .. }) if name == Some(b"rpc-error") => {
                RpcErrorBuilder::default().finish().map(|_| ())
            }
            Some(IgnoredPayload::Direct { .. }) if name == Some(b"ok") => {
                self.protocol_ok = true;
                Ok(())
            }
            Some(IgnoredPayload::Direct { .. }) => Ok(()),
            None => unreachable!("ignored_empty requires an ignored payload"),
        }
    }

    fn defer_payload_conflict(&mut self, message: &'static str) {
        if self.deferred_payload_error.is_none() {
            self.deferred_payload_error = Some(message);
        }
    }

    fn netconf_local_name<'a>(&self, qualified_name: &'a [u8]) -> Option<&'a [u8]> {
        let mut parts = qualified_name.split(|byte| *byte == b':');
        let first = parts.next()?;
        let second = parts.next();
        if parts.next().is_some() {
            return None;
        }

        let (namespace, local) = if let Some(local) = second {
            let prefix = std::str::from_utf8(first).ok()?;
            (self.namespaces.get(prefix).map(String::as_str), local)
        } else {
            (self.namespaces.get("").map(String::as_str), first)
        };

        match namespace {
            None if second.is_none() => Some(local),
            Some(NETCONF_NAMESPACE) => Some(local),
            _ => None,
        }
    }

    fn validate_element_name(&self, qualified_name: &[u8]) -> Result<(), RpcError> {
        let name = validate_qname(qualified_name)?;
        if name.prefix == Some("xmlns") {
            return Err(parse_error(
                "the xmlns prefix cannot qualify an element name",
            ));
        }
        self.validate_bound_prefix(name.prefix)
    }

    fn validate_bound_prefix(&self, prefix: Option<&str>) -> Result<(), RpcError> {
        match prefix {
            None | Some("xml") => Ok(()),
            Some(prefix) if self.namespaces.contains_key(prefix) => Ok(()),
            Some(_) => Err(parse_error("QName uses an unbound namespace prefix")),
        }
    }

    fn finish(self) -> Result<RpcReply, RpcError> {
        if self.envelope != EnvelopeState::After {
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

        if let Some(message) = self.deferred_payload_error {
            return Err(parse_error(message));
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
                let value = value.trim();
                if value.is_empty() {
                    return Err(parse_error("invalid empty rpc-error error-tag"));
                }
                self.tag = Some(value.parse().expect("ErrorTag::from_str is infallible"));
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
    use crate::rpc::validate_xml_fragment;

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
    fn hard_rpc_error_precedes_deferred_payload_conflicts() {
        let hard_error = r#"<rpc-error>
          <error-type>application</error-type>
          <error-tag>invalid-value</error-tag>
          <error-severity>error</error-severity>
          <error-message>hard failure</error-message>
        </rpc-error>"#;
        let cases = [
            format!(r#"<rpc-reply message-id="1">{hard_error}<ok/><data/></rpc-reply>"#),
            format!(r#"<rpc-reply message-id="1"><ok/><data/>{hard_error}</rpc-reply>"#),
            format!(
                r#"<rpc-reply message-id="1"><ok/><output><nested/></output>{hard_error}</rpc-reply>"#
            ),
            format!(
                r#"<rpc-reply message-id="1">{hard_error}<ok/><output><nested/></output></rpc-reply>"#
            ),
        ];

        for xml in cases {
            assert!(matches!(
                parse_strict(&xml, "1"),
                Err(RpcError::ServerError {
                    tag: ErrorTag::InvalidValue,
                    message,
                    ..
                }) if message == "hard failure"
            ));
        }

        let no_hard_error = r#"<rpc-reply message-id="1"><ok/><data/></rpc-reply>"#;
        assert!(matches!(
            parse_strict(no_hard_error, "1"),
            Err(RpcError::ParseError(_))
        ));

        let mismatch =
            format!(r#"<rpc-reply message-id="actual"><ok/><data/>{hard_error}</rpc-reply>"#);
        assert!(matches!(
            parse_strict(&mismatch, "expected"),
            Err(RpcError::MessageIdMismatch { .. })
        ));

        let invalid_error = r#"<rpc-reply message-id="1"><ok/><data/><rpc-error>
          <error-type>invalid</error-type>
          <error-tag>operation-failed</error-tag>
          <error-severity>error</error-severity>
        </rpc-error></rpc-reply>"#;
        assert!(matches!(
            parse_strict(invalid_error, "1"),
            Err(RpcError::ParseError(_))
        ));

        let unsafe_nested_reply =
            r#"<rpc-reply message-id="1"><ok/><output><rpc-reply/></output></rpc-reply>"#;
        assert!(matches!(
            parse_strict(unsafe_nested_reply, "1"),
            Err(RpcError::ParseError(_))
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
    fn direct_wrapper_protocol_elements_validate_start_and_empty_forms() {
        let empty_error =
            r#"<rpc-reply message-id="1"><wrapper><rpc-error/></wrapper></rpc-reply>"#;
        let error = parse_strict(empty_error, "1").expect_err("empty rpc-error is incomplete");
        assert!(matches!(error, RpcError::ParseError(_)));
        assert!(error.to_string().contains("error-type"));

        let non_empty_ok =
            r#"<rpc-reply message-id="2"><wrapper><ok>text</ok></wrapper></rpc-reply>"#;
        assert!(matches!(
            parse_strict(non_empty_ok, "2"),
            Err(RpcError::ParseError(_))
        ));

        let empty_ok = r#"<rpc-reply message-id="3"><wrapper><ok/></wrapper></rpc-reply>"#;
        assert!(matches!(parse_strict(empty_ok, "3"), Ok(RpcReply::Ok)));

        let opaque_data = r#"<rpc-reply message-id="4"><data>
          <wrapper><rpc-error/><ok>modeled</ok></wrapper>
        </data></rpc-reply>"#;
        let RpcReply::Data(data) = parse_strict(opaque_data, "4").expect("modeled data is opaque")
        else {
            panic!("expected Data");
        };
        assert!(data.contains("<rpc-error/>"));
        assert!(data.contains("<ok>modeled</ok>"));
    }

    #[test]
    fn vendor_namespace_protocol_lookalikes_remain_opaque_data() {
        let cases = [
            (
                "prefixed ok",
                r#"<rpc-reply xmlns:v="urn:vendor" message-id="1"><v:ok/></rpc-reply>"#,
                "<v:ok",
            ),
            (
                "prefixed rpc-error",
                r#"<rpc-reply xmlns:v="urn:vendor" message-id="1"><v:rpc-error/></rpc-reply>"#,
                "<v:rpc-error",
            ),
            (
                "prefixed rpc-reply",
                r#"<rpc-reply xmlns:v="urn:vendor" message-id="1"><v:rpc-reply/></rpc-reply>"#,
                "<v:rpc-reply",
            ),
            (
                "prefixed data",
                r#"<rpc-reply xmlns:v="urn:vendor" message-id="1"><v:data/></rpc-reply>"#,
                "<v:data",
            ),
            (
                "default vendor lookalikes",
                r#"<rpc-reply message-id="1"><wrapper xmlns="urn:vendor">
                  <ok/><rpc-error/><rpc-reply/><data/>
                </wrapper></rpc-reply>"#,
                "<ok",
            ),
            (
                "prefixed lookalikes in standard data",
                r#"<rpc-reply xmlns:v="urn:vendor" message-id="1"><data>
                  <v:ok/><v:rpc-error/><v:rpc-reply/><v:data/>
                </data></rpc-reply>"#,
                "<v:rpc-error",
            ),
        ];

        for (name, xml, marker) in cases {
            let RpcReply::Data(data) = parse_strict(xml, "1").expect(name) else {
                panic!("{name}: expected Data");
            };
            assert!(
                data.contains(marker),
                "{name}: lookalike was not captured: {data}"
            );
            validate_xml_fragment(&data).expect("vendor lookalike data remains valid XML");
        }
    }

    #[test]
    fn netconf_expanded_names_and_unqualified_compatibility_keep_protocol_meaning() {
        let cases = [
            r#"<nc:rpc-reply
              xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0"
              message-id="1"><nc:ok/></nc:rpc-reply>"#,
            r#"<rpc-reply
              xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"
              message-id="1"><ok/></rpc-reply>"#,
            r#"<rpc-reply message-id="1"><ok/></rpc-reply>"#,
            r#"<rpc-reply
              xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"
              message-id="1"><wrapper xmlns=""><ok/></wrapper></rpc-reply>"#,
        ];
        for xml in cases {
            assert!(matches!(parse_strict(xml, "1"), Ok(RpcReply::Ok)));
        }

        let error = r#"<nc:rpc-reply
          xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0"
          message-id="1"><nc:rpc-error>
            <nc:error-type>application</nc:error-type>
            <nc:error-tag>operation-failed</nc:error-tag>
            <nc:error-severity>error</nc:error-severity>
            <nc:error-info><detail/></nc:error-info>
          </nc:rpc-error></nc:rpc-reply>"#;
        assert!(matches!(
            parse_strict(error, "1"),
            Err(RpcError::ServerError { info: Some(_), .. })
        ));
    }

    #[test]
    fn vendor_namespace_rpc_reply_root_is_rejected() {
        let cases = [
            r#"<v:rpc-reply xmlns:v="urn:vendor" message-id="1"><v:ok/></v:rpc-reply>"#,
            r#"<rpc-reply xmlns="urn:vendor" message-id="1"><ok/></rpc-reply>"#,
        ];
        for xml in cases {
            assert!(matches!(
                parse_strict(xml, "1"),
                Err(RpcError::ParseError(_))
            ));
        }
    }

    #[test]
    fn vendor_namespace_rpc_error_fields_are_not_netconf_fields() {
        let cases = [
            r#"<rpc-reply xmlns:v="urn:vendor" message-id="1"><rpc-error>
              <v:error-type>application</v:error-type>
              <error-tag>operation-failed</error-tag>
              <error-severity>error</error-severity>
            </rpc-error></rpc-reply>"#,
            r#"<rpc-reply xmlns:v="urn:vendor" message-id="1"><rpc-error>
              <error-type>application</error-type>
              <error-tag>operation-failed</error-tag>
              <error-severity>error</error-severity>
              <v:error-info><v:detail/></v:error-info>
            </rpc-error></rpc-reply>"#,
        ];
        for xml in cases {
            assert!(matches!(
                parse_strict(xml, "1"),
                Err(RpcError::ParseError(_))
            ));
        }
    }

    #[test]
    fn rejects_malformed_namespace_declarations_and_qnames() {
        let malformed_children = [
            ("empty xmlns prefix", r#"<item xmlns:="urn:bad"/>"#),
            ("reserved xmlns prefix", r#"<item xmlns:xmlns="urn:bad"/>"#),
            ("invalid xml binding", r#"<item xmlns:xml="urn:wrong"/>"#),
            (
                "other prefix bound to XML URI",
                r#"<item xmlns:v="http://www.w3.org/XML/1998/namespace"/>"#,
            ),
            (
                "default bound to XML URI",
                r#"<item xmlns="http://www.w3.org/XML/1998/namespace"/>"#,
            ),
            (
                "prefix bound to xmlns URI",
                r#"<item xmlns:v="http://www.w3.org/2000/xmlns/"/>"#,
            ),
            (
                "default bound to xmlns URI",
                r#"<item xmlns="http://www.w3.org/2000/xmlns/"/>"#,
            ),
            ("empty prefixed binding", r#"<item xmlns:v=""/>"#),
            ("unbound element prefix", r#"<v:item/>"#),
            ("unbound attribute prefix", r#"<item v:note="x"/>"#),
            ("empty QName prefix", r#"<:item/>"#),
            ("empty QName local name", r#"<v: xmlns:v="urn:vendor"/>"#),
            (
                "multiple element colons",
                r#"<v:item:extra xmlns:v="urn:vendor"/>"#,
            ),
            (
                "multiple attribute colons",
                r#"<item xmlns:v="urn:vendor" v:note:extra="x"/>"#,
            ),
        ];

        for (name, child) in malformed_children {
            let xml = format!(r#"<rpc-reply message-id="1"><data>{child}</data></rpc-reply>"#);
            let error = parse_strict(&xml, "1").expect_err(name);
            assert!(
                matches!(error, RpcError::ParseError(_)),
                "{name}: {error:?}"
            );
            assert!(error.to_string().len() < 256, "{name}: unbounded error");
        }

        let sibling_leak = r#"<rpc-reply message-id="1"><data>
          <v:first xmlns:v="urn:vendor"/><v:second/>
        </data></rpc-reply>"#;
        assert!(matches!(
            parse_strict(sibling_leak, "1"),
            Err(RpcError::ParseError(_))
        ));
    }

    #[test]
    fn accepts_valid_unicode_qnames_and_namespace_controls() {
        let xml = r#"<rpc-reply message-id="1"><data>
          <前:设备 xmlns:前="urn:设备" xml:lang="zh" 属性="值"/>
          <item xmlns="urn:vendor" note="default-does-not-qualify-attributes"/>
        </data></rpc-reply>"#;
        let RpcReply::Data(data) = parse_strict(xml, "1").expect("valid Unicode names") else {
            panic!("expected Data");
        };
        assert!(data.contains("<前:设备"));
        assert!(data.contains("属性=\"值\""));
        validate_xml_fragment(&data).expect("valid namespace controls remain valid");
    }

    #[test]
    fn attribute_decode_errors_are_bounded_and_do_not_echo_values() {
        let marker = format!("SENSITIVE_ATTRIBUTE_ENTITY_{}", "x".repeat(4096));
        let cases = [
            (
                "data attribute",
                format!(
                    r#"<rpc-reply message-id="1"><data><item note="&{marker};"/></data></rpc-reply>"#
                ),
            ),
            (
                "direct attribute",
                format!(r#"<rpc-reply message-id="1"><item note="&{marker};"/></rpc-reply>"#),
            ),
            (
                "error-info attribute",
                format!(
                    r#"<rpc-reply message-id="1"><rpc-error>
                      <error-type>application</error-type>
                      <error-tag>operation-failed</error-tag>
                      <error-severity>error</error-severity>
                      <error-info><item note="&{marker};"/></error-info>
                    </rpc-error></rpc-reply>"#
                ),
            ),
            (
                "namespace declaration",
                format!(
                    r#"<rpc-reply message-id="1"><data><v:item xmlns:v="&{marker};"/></data></rpc-reply>"#
                ),
            ),
            (
                "message-id",
                format!(r#"<rpc-reply message-id="&{marker};"><ok/></rpc-reply>"#),
            ),
        ];

        for (name, xml) in cases {
            let RpcError::ParseError(message) =
                parse_strict(&xml, "1").expect_err("invalid attribute entity must fail")
            else {
                panic!("{name}: expected ParseError");
            };
            assert!(message.len() < 256, "{name}: diagnostic is unbounded");
            assert!(
                !message.contains("SENSITIVE_ATTRIBUTE_ENTITY"),
                "{name}: diagnostic exposes device value"
            );
        }
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
    fn error_tag_must_be_non_empty_but_accepts_vendor_values() {
        for tag in ["<error-tag/>", "<error-tag>   \n </error-tag>"] {
            let xml = format!(
                r#"<rpc-reply message-id="1"><rpc-error>
                  <error-type>application</error-type>
                  {tag}
                  <error-severity>error</error-severity>
                </rpc-error></rpc-reply>"#
            );
            let error = parse_strict(&xml, "1").expect_err("empty error-tag must fail");
            assert!(matches!(error, RpcError::ParseError(_)));
            assert!(error.to_string().contains("error-tag"));
        }

        let vendor = r#"<rpc-reply message-id="1"><rpc-error>
          <error-type>application</error-type>
          <error-tag>vendor-failure</error-tag>
          <error-severity>error</error-severity>
        </rpc-error></rpc-reply>"#;
        assert!(matches!(
            parse_strict(vendor, "1"),
            Err(RpcError::ServerError {
                tag: ErrorTag::Other(tag),
                ..
            }) if tag == "vendor-failure"
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
    fn captured_fragments_inherit_in_scope_namespaces() {
        let direct = r#"<nc:rpc-reply
          xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0"
          xmlns:v="urn:vendor"
          message-id="ns-direct">
          <v:first/>
          <v:second/>
        </nc:rpc-reply>"#;
        let RpcReply::Data(direct) = parse_strict(direct, "ns-direct").expect("direct payload")
        else {
            panic!("expected Data");
        };
        assert_eq!(direct.matches("xmlns:v=\"urn:vendor\"").count(), 2);
        validate_xml_fragment(&direct).expect("every direct root keeps inherited namespaces");

        let data = r#"<rpc-reply
          xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"
          xmlns:v="urn:reply"
          message-id="ns-data">
          <data xmlns:d="urn:data"><v:first/><d:second/></data>
        </rpc-reply>"#;
        let RpcReply::Data(data) = parse_strict(data, "ns-data").expect("data payload") else {
            panic!("expected Data");
        };
        validate_xml_fragment(&data).expect("data roots keep reply and data namespaces");
        assert_eq!(data.matches("xmlns:v=\"urn:reply\"").count(), 2);
        assert_eq!(data.matches("xmlns:d=\"urn:data\"").count(), 2);

        let override_xml = r#"<rpc-reply
          xmlns:v="urn:reply"
          message-id="ns-override">
          <data><v:item xmlns:v="urn:wrapper"/></data>
        </rpc-reply>"#;
        let RpcReply::Data(overridden) =
            parse_strict(override_xml, "ns-override").expect("override payload")
        else {
            panic!("expected Data");
        };
        assert_eq!(overridden.matches("xmlns:v=").count(), 1);
        assert!(overridden.contains("xmlns:v=\"urn:wrapper\""));
        validate_xml_fragment(&overridden).expect("root override is namespace-valid");

        let error = r#"<rpc-reply message-id="ns-error">
          <rpc-error>
            <error-type>application</error-type>
            <error-tag>operation-failed</error-tag>
            <error-severity>error</error-severity>
            <error-info xmlns:e="urn:error-detail"><e:detail/></error-info>
          </rpc-error>
        </rpc-reply>"#;
        let RpcError::ServerError {
            info: Some(info), ..
        } = parse_strict(error, "ns-error").expect_err("hard error")
        else {
            panic!("expected ServerError with error-info");
        };
        assert!(info.contains("xmlns:e=\"urn:error-detail\""));
        validate_xml_fragment(&info).expect("error-info keeps inherited namespace");
    }

    #[test]
    fn fragment_entities_are_validated_without_reencoding_valid_references() {
        let invalid_cases = [
            (
                "data",
                r#"<rpc-reply message-id="entity"><data><x>&SENSITIVE_UNKNOWN;</x></data></rpc-reply>"#,
            ),
            (
                "direct",
                r#"<rpc-reply message-id="entity"><x>&SENSITIVE_UNKNOWN;</x></rpc-reply>"#,
            ),
            (
                "error-info",
                r#"<rpc-reply message-id="entity"><rpc-error>
                  <error-type>application</error-type>
                  <error-tag>operation-failed</error-tag>
                  <error-severity>error</error-severity>
                  <error-info><x>&SENSITIVE_UNKNOWN;</x></error-info>
                </rpc-error></rpc-reply>"#,
            ),
            (
                "invalid numeric",
                r#"<rpc-reply message-id="entity"><data><x>&#0;</x></data></rpc-reply>"#,
            ),
        ];

        for (path, xml) in invalid_cases {
            let RpcError::ParseError(message) =
                parse_strict(xml, "entity").expect_err("invalid entity must fail")
            else {
                panic!("{path}: expected ParseError");
            };
            assert!(message.contains("entity"), "{path}: {message}");
            assert!(message.len() < 128, "{path}: diagnostic is unbounded");
            assert!(
                !message.contains("SENSITIVE_UNKNOWN"),
                "{path}: diagnostic exposes device content"
            );
        }

        let valid = r#"<rpc-reply message-id="entity"><data>
          <x>&amp;&#38;&#x3C;&quot;&apos;&gt;&lt;</x>
        </data></rpc-reply>"#;
        let RpcReply::Data(data) = parse_strict(valid, "entity").expect("valid references") else {
            panic!("expected Data");
        };
        for reference in [
            "&amp;", "&#38;", "&#x3C;", "&quot;", "&apos;", "&gt;", "&lt;",
        ] {
            assert!(data.contains(reference), "reference was reencoded: {data}");
        }
        validate_xml_fragment(&data).expect("valid references remain valid XML");
    }

    #[test]
    fn cdata_is_captured_once_and_escaped_equivalently() {
        let data_xml = r#"<rpc-reply message-id="cdata-data">
          <data><x><![CDATA[once < & >]]></x></data>
        </rpc-reply>"#;
        let RpcReply::Data(data) =
            parse_strict(data_xml, "cdata-data").expect("data CDATA succeeds")
        else {
            panic!("expected Data");
        };
        assert_eq!(data.matches("once &lt; &amp; &gt;").count(), 1);

        let direct_xml = r#"<rpc-reply message-id="cdata-direct">
          <x><![CDATA[once < & >]]></x>
        </rpc-reply>"#;
        let RpcReply::Data(direct) =
            parse_strict(direct_xml, "cdata-direct").expect("direct CDATA succeeds")
        else {
            panic!("expected Data");
        };
        assert_eq!(direct.matches("once &lt; &amp; &gt;").count(), 1);

        let error_xml = r#"<rpc-reply message-id="cdata-error"><rpc-error>
          <error-type>application</error-type>
          <error-tag>operation-failed</error-tag>
          <error-severity>error</error-severity>
          <error-info><x><![CDATA[once < & >]]></x></error-info>
        </rpc-error></rpc-reply>"#;
        let RpcError::ServerError {
            info: Some(info), ..
        } = parse_strict(error_xml, "cdata-error").expect_err("hard error")
        else {
            panic!("expected ServerError with info");
        };
        assert_eq!(info.matches("once &lt; &amp; &gt;").count(), 1);
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
