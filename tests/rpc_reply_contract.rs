use rustnetconf::error::RpcError;
use rustnetconf::rpc::{parse_rpc_reply, RpcReply};
use rustnetconf::types::ErrorTag;

#[test]
fn public_ok_reply_contract() {
    let xml = r#"<nc:rpc-reply
        xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0"
        message-id="41"><nc:ok/></nc:rpc-reply>"#;

    let reply = parse_rpc_reply(xml, "41").expect("valid ok reply");
    assert!(matches!(reply, RpcReply::Ok));
}

#[test]
fn public_data_reply_preserves_xml_contract() {
    let xml = r#"<rpc-reply
        xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"
        message-id="42">
        <data>
          <if:interfaces xmlns:if="urn:ietf:params:xml:ns:yang:ietf-interfaces">
            <if:interface note='uplink &amp; "core"'>
              <if:name>ge-0/0/0</if:name>
            </if:interface>
          </if:interfaces>
        </data>
      </rpc-reply>"#;

    let reply = parse_rpc_reply(xml, "42").expect("valid data reply");
    let RpcReply::Data(data) = reply else {
        panic!("expected Data");
    };

    assert!(data.contains("<if:interfaces"));
    assert!(data.contains("xmlns:if="));
    assert!(data.contains("<if:name>ge-0/0/0</if:name>"));
    rustnetconf::rpc::validate_xml_fragment(&data).expect("captured XML is well formed");
}

#[test]
fn public_direct_payload_aggregates_siblings_contract() {
    let xml = r#"<rpc-reply
        xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"
        message-id="43">
        <output>first</output>
        <warnings><warning>second</warning></warnings>
      </rpc-reply>"#;

    let reply = parse_rpc_reply(xml, "43").expect("valid direct payload");
    let RpcReply::Data(data) = reply else {
        panic!("expected Data");
    };

    assert!(data.contains("<output"));
    assert!(data.contains(">first</output>"));
    assert!(data.contains("<warnings"));
    assert!(data.contains("<warning>second</warning></warnings>"));
}

#[test]
fn public_hard_error_contract() {
    let xml = r#"<rpc-reply
        xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"
        message-id="44">
        <rpc-error>
          <error-type>application</error-type>
          <error-tag>invalid-value</error-tag>
          <error-severity>error</error-severity>
          <error-message>invalid interface</error-message>
        </rpc-error>
      </rpc-reply>"#;

    let error = parse_rpc_reply(xml, "44").expect_err("hard error must fail");
    match error {
        RpcError::ServerError { tag, message, .. } => {
            assert_eq!(tag, ErrorTag::InvalidValue);
            assert_eq!(message, "invalid interface");
        }
        other => panic!("expected ServerError, got {other:?}"),
    }
}

#[test]
fn public_empty_reply_contract() {
    let xml = r#"<rpc-reply
        xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"
        message-id="45"></rpc-reply>"#;

    let reply = parse_rpc_reply(xml, "45").expect("valid empty reply");
    assert!(matches!(reply, RpcReply::Ok));
}

#[test]
fn public_reply_type_paths_remain_available() {
    fn accepts_reply(_: rustnetconf::rpc::RpcReply) {}
    fn accepts_info(_: rustnetconf::rpc::RpcErrorInfo) {}
    fn accepts_root_info(_: rustnetconf::RpcErrorInfo) {}

    let _ = accepts_reply as fn(rustnetconf::rpc::RpcReply);
    let _ = accepts_info as fn(rustnetconf::rpc::RpcErrorInfo);
    let _ = accepts_root_info as fn(rustnetconf::RpcErrorInfo);
}

#[test]
fn public_parser_validates_ordinary_attributes_before_reply_outcomes() {
    fn cases(value: &str) -> Vec<(&'static str, String)> {
        vec![
            (
                "rpc-reply",
                format!("<rpc-reply message-id=\"1\" probe=\"{value}\"><ok/></rpc-reply>"),
            ),
            (
                "empty ok",
                format!("<rpc-reply message-id=\"1\"><ok probe=\"{value}\"/></rpc-reply>"),
            ),
            (
                "data",
                format!(
                    "<rpc-reply message-id=\"1\"><data probe=\"{value}\"><x/></data></rpc-reply>"
                ),
            ),
            (
                "rpc-error field",
                format!(
                    "<rpc-reply message-id=\"1\"><rpc-error>\
                     <error-type>application</error-type>\
                     <error-tag>operation-failed</error-tag>\
                     <error-severity>error</error-severity>\
                     <error-message probe=\"{value}\"/>\
                     </rpc-error></rpc-reply>"
                ),
            ),
        ]
    }

    for value in ["\0", "&PUBLIC_DEVICE_MARKER;"] {
        for (path, xml) in cases(value) {
            let RpcError::ParseError(message) =
                parse_rpc_reply(&xml, "1").expect_err("invalid attribute must fail")
            else {
                panic!("{path}: expected ParseError");
            };
            assert!(message.contains("attribute"), "{path}: {message}");
            assert!(message.len() < 128, "{path}: diagnostic is unbounded");
            assert!(
                !message.contains("PUBLIC_DEVICE_MARKER") && !message.contains('\0'),
                "{path}: diagnostic exposes device content"
            );
        }
    }
}
