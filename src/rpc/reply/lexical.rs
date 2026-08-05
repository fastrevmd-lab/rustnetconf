use crate::error::RpcError;
use quick_xml::events::{BytesDecl, BytesStart, Event};
use std::borrow::Cow;
use std::str;

#[derive(Debug, Default)]
pub(super) struct DocumentLexicalState {
    saw_event: bool,
}

impl DocumentLexicalState {
    pub(super) fn validate_event(&mut self, event: &Event<'_>) -> Result<(), RpcError> {
        if let Event::Decl(declaration) = event {
            if self.saw_event {
                return Err(parse_error(
                    "XML declaration must be the first document event",
                ));
            }
            self.saw_event = true;
            return validate_declaration(declaration);
        }
        if !matches!(event, Event::Eof) {
            self.saw_event = true;
        }

        match event {
            Event::Start(tag) | Event::Empty(tag) => {
                validate_attribute_separators(tag)?;
                for attribute in tag.attributes().with_checks(true) {
                    let attribute =
                        attribute.map_err(|_| parse_error("invalid XML attribute syntax"))?;
                    validate_attribute_lexical(attribute.value.as_ref())?;
                }
                Ok(())
            }
            Event::Text(text) => validate_text_lexical(text.as_ref()),
            Event::Comment(comment) => validate_comment(comment.as_ref()),
            Event::PI(instruction) => validate_processing_instruction(instruction),
            Event::DocType(_) => Err(parse_error("DOCTYPE is not allowed in an RPC reply")),
            _ => Ok(()),
        }
    }
}

fn validate_attribute_separators(tag: &BytesStart<'_>) -> Result<(), RpcError> {
    if ordinary_attribute_separators_are_valid(tag.attributes_raw()) {
        Ok(())
    } else {
        Err(parse_error("invalid XML attribute separator"))
    }
}

fn ordinary_attribute_separators_are_valid(raw: &[u8]) -> bool {
    let mut cursor = 0usize;
    loop {
        let separator_start = cursor;
        while raw.get(cursor).is_some_and(|byte| is_xml_space(*byte)) {
            cursor += 1;
        }
        if cursor == raw.len() {
            return true;
        }
        if cursor == separator_start {
            return false;
        }

        let name_start = cursor;
        while raw
            .get(cursor)
            .is_some_and(|byte| !is_xml_space(*byte) && *byte != b'=')
        {
            cursor += 1;
        }
        if cursor == name_start {
            return true;
        }
        while raw.get(cursor).is_some_and(|byte| is_xml_space(*byte)) {
            cursor += 1;
        }
        if raw.get(cursor) != Some(&b'=') {
            return true;
        }
        cursor += 1;
        while raw.get(cursor).is_some_and(|byte| is_xml_space(*byte)) {
            cursor += 1;
        }

        let Some(quote @ (b'\'' | b'"')) = raw.get(cursor).copied() else {
            return true;
        };
        cursor += 1;
        while raw.get(cursor).is_some_and(|byte| *byte != quote) {
            cursor += 1;
        }
        if raw.get(cursor) != Some(&quote) {
            return true;
        }
        cursor += 1;
    }
}

pub(super) fn validate_text_lexical(raw: &[u8]) -> Result<(), RpcError> {
    if raw.windows(3).any(|window| window == b"]]>") {
        Err(parse_error(
            "character data contains forbidden CDATA terminator",
        ))
    } else {
        Ok(())
    }
}

fn validate_comment(raw: &[u8]) -> Result<(), RpcError> {
    if raw.windows(2).any(|window| window == b"--") || raw.ends_with(b"-") {
        return Err(parse_error("invalid XML comment syntax"));
    }
    let decoded = str::from_utf8(raw).map_err(|_| parse_error("invalid comment encoding"))?;
    validate_xml_chars(decoded, "comment")
}

fn validate_processing_instruction(
    instruction: &quick_xml::events::BytesPI<'_>,
) -> Result<(), RpcError> {
    let target = instruction.target();
    if !is_valid_xml_name(target) || target.eq_ignore_ascii_case(b"xml") {
        return Err(parse_error("invalid processing instruction target"));
    }
    let decoded = str::from_utf8(instruction.as_ref())
        .map_err(|_| parse_error("invalid processing instruction encoding"))?;
    validate_xml_chars(decoded, "processing instruction")
}

fn validate_declaration(declaration: &BytesDecl<'_>) -> Result<(), RpcError> {
    let raw = str::from_utf8(declaration.as_ref())
        .map_err(|_| parse_error("invalid XML declaration encoding"))?;
    validate_xml_chars(raw, "XML declaration")?;
    if !declaration_attributes_are_separated(raw.as_bytes()) {
        return Err(parse_error("invalid XML declaration syntax"));
    }

    let declaration = BytesStart::from_content(raw, 3);
    let mut previous_rank = None;
    let mut count = 0usize;
    for attribute in declaration.attributes().with_checks(true) {
        let attribute = attribute.map_err(|_| parse_error("invalid XML declaration syntax"))?;
        let (rank, valid_value) = match attribute.key.as_ref() {
            b"version" => (0, attribute.value.as_ref() == b"1.0"),
            b"encoding" => (1, valid_encoding_name(attribute.value.as_ref())),
            b"standalone" => (2, matches!(attribute.value.as_ref(), b"yes" | b"no")),
            _ => return Err(parse_error("invalid XML declaration syntax")),
        };
        if (count == 0 && rank != 0) || previous_rank.is_some_and(|previous| previous >= rank) {
            return Err(parse_error("invalid XML declaration syntax"));
        }
        if !valid_value {
            return Err(parse_error("invalid XML declaration value"));
        }
        previous_rank = Some(rank);
        count += 1;
    }
    if count == 0 {
        return Err(parse_error("invalid XML declaration syntax"));
    }
    Ok(())
}

fn declaration_attributes_are_separated(raw: &[u8]) -> bool {
    if !raw.starts_with(b"xml") {
        return false;
    }

    let mut cursor = 3usize;
    let mut count = 0usize;
    loop {
        let separator_start = cursor;
        while raw.get(cursor).is_some_and(|byte| is_xml_space(*byte)) {
            cursor += 1;
        }
        if cursor == raw.len() {
            return count > 0;
        }
        if cursor == separator_start {
            return false;
        }

        let name_start = cursor;
        while raw
            .get(cursor)
            .is_some_and(|byte| !is_xml_space(*byte) && *byte != b'=')
        {
            cursor += 1;
        }
        if cursor == name_start {
            return false;
        }
        while raw.get(cursor).is_some_and(|byte| is_xml_space(*byte)) {
            cursor += 1;
        }
        if raw.get(cursor) != Some(&b'=') {
            return false;
        }
        cursor += 1;
        while raw.get(cursor).is_some_and(|byte| is_xml_space(*byte)) {
            cursor += 1;
        }

        let Some(quote @ (b'\'' | b'"')) = raw.get(cursor).copied() else {
            return false;
        };
        cursor += 1;
        while raw.get(cursor).is_some_and(|byte| *byte != quote) {
            cursor += 1;
        }
        if raw.get(cursor) != Some(&quote) {
            return false;
        }
        cursor += 1;
        count += 1;
    }
}

fn is_xml_space(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\r' | b'\n')
}

fn valid_encoding_name(value: &[u8]) -> bool {
    value.first().is_some_and(u8::is_ascii_alphabetic)
        && value[1..]
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn is_valid_xml_name(raw: &[u8]) -> bool {
    let Ok(name) = str::from_utf8(raw) else {
        return false;
    };
    let mut chars = name.chars();
    chars.next().is_some_and(is_xml_name_start) && chars.all(is_xml_name_char)
}

fn is_xml_name_start(value: char) -> bool {
    value == ':' || is_ncname_start(value)
}

fn is_xml_name_char(value: char) -> bool {
    value == ':' || is_ncname_char(value)
}

pub(super) fn validate_ncname(name: &str, field: &str) -> Result<(), RpcError> {
    let mut chars = name.chars();
    if !chars.next().is_some_and(is_ncname_start) || !chars.all(is_ncname_char) {
        return Err(parse_error(format!("invalid {field}")));
    }
    Ok(())
}

fn is_ncname_start(value: char) -> bool {
    matches!(
        value as u32,
        0x41..=0x5A
            | 0x5F
            | 0x61..=0x7A
            | 0xC0..=0xD6
            | 0xD8..=0xF6
            | 0xF8..=0x2FF
            | 0x370..=0x37D
            | 0x37F..=0x1FFF
            | 0x200C..=0x200D
            | 0x2070..=0x218F
            | 0x2C00..=0x2FEF
            | 0x3001..=0xD7FF
            | 0xF900..=0xFDCF
            | 0xFDF0..=0xFFFD
            | 0x10000..=0xEFFFF
    )
}

fn is_ncname_char(value: char) -> bool {
    is_ncname_start(value)
        || matches!(
            value as u32,
            0x2D | 0x2E | 0x30..=0x39 | 0xB7 | 0x300..=0x36F | 0x203F..=0x2040
        )
}

pub(super) fn is_valid_xml_char(value: char) -> bool {
    matches!(
        value as u32,
        0x9 | 0xA | 0xD | 0x20..=0xD7FF | 0xE000..=0xFFFD | 0x10000..=0x10FFFF
    )
}

pub(super) fn validate_xml_chars(value: &str, field: &'static str) -> Result<(), RpcError> {
    if value.chars().all(is_valid_xml_char) {
        Ok(())
    } else {
        Err(parse_error(format!("invalid XML character in {field}")))
    }
}

pub(super) fn decode_attribute(raw: &[u8], field: &'static str) -> Result<String, RpcError> {
    validate_attribute_lexical(raw)?;
    let raw = str::from_utf8(raw).map_err(|_| parse_error(format!("invalid {field} encoding")))?;
    let normalized = normalize_literal_attribute_whitespace(raw);
    let decoded = quick_xml::escape::unescape(&normalized)
        .map(|value| value.into_owned())
        .map_err(|_| parse_error(format!("invalid {field}")))?;
    validate_xml_chars(&decoded, field)?;
    Ok(decoded)
}

fn normalize_literal_attribute_whitespace(raw: &str) -> Cow<'_, str> {
    if !raw
        .bytes()
        .any(|byte| matches!(byte, b'\t' | b'\n' | b'\r'))
    {
        return Cow::Borrowed(raw);
    }

    let mut normalized = String::with_capacity(raw.len());
    let mut chars = raw.chars().peekable();
    while let Some(value) = chars.next() {
        match value {
            '\r' => {
                if chars.peek() == Some(&'\n') {
                    chars.next();
                }
                normalized.push(' ');
            }
            '\t' | '\n' => normalized.push(' '),
            _ => normalized.push(value),
        }
    }
    Cow::Owned(normalized)
}

fn validate_attribute_lexical(raw: &[u8]) -> Result<(), RpcError> {
    if raw.contains(&b'<') {
        return Err(parse_error("attribute value contains raw '<'"));
    }
    Ok(())
}

fn parse_error(message: impl Into<String>) -> RpcError {
    RpcError::ParseError(message.into())
}

#[cfg(test)]
mod tests {
    use super::decode_attribute;

    #[test]
    fn normalizes_literal_attribute_whitespace_before_expanding_references() {
        let literal = decode_attribute(b"left\tmiddle\nright\rend\r\ntail", "test attribute value")
            .expect("literal XML whitespace is valid");
        assert_eq!(literal, "left middle right end tail");

        let referenced =
            decode_attribute(b"left&#x9;middle&#xA;right&#xD;end", "test attribute value")
                .expect("referenced XML whitespace is valid");
        assert_eq!(referenced, "left\tmiddle\nright\rend");
    }

    #[test]
    fn attribute_normalization_preserves_entities_quotes_and_unicode() {
        let decoded = decode_attribute(
            "caf\u{e9} &amp; &quot;quoted&quot; &apos;single&apos;".as_bytes(),
            "test attribute value",
        )
        .expect("ordinary attribute content is valid");
        assert_eq!(decoded, "caf\u{e9} & \"quoted\" 'single'");
    }
}
