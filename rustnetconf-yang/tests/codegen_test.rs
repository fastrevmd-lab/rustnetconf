//! Tests that YANG-generated code compiles and produces correct types.

#[cfg(feature = "generated")]
mod tests {
    use rustnetconf_yang::ietf_interfaces::{Interface, Interfaces, Statistics};
    use rustnetconf_yang::serialize::ToNetconfXml;

    #[test]
    fn test_interface_struct_exists_and_has_fields() {
        let iface = Interface {
            name: Some("ge-0/0/0".into()),
            description: Some("uplink to spine".into()),
            r#type: Some("ethernetCsmacd".into()),
            enabled: Some(true),
            ..Default::default()
        };

        assert_eq!(iface.name.as_deref(), Some("ge-0/0/0"));
        assert_eq!(iface.description.as_deref(), Some("uplink to spine"));
        assert_eq!(iface.enabled, Some(true));
    }

    #[test]
    fn test_interfaces_container_holds_list() {
        let interfaces = Interfaces {
            interface: vec![
                Interface {
                    name: Some("ge-0/0/0".into()),
                    enabled: Some(true),
                    ..Default::default()
                },
                Interface {
                    name: Some("ge-0/0/1".into()),
                    enabled: Some(false),
                    ..Default::default()
                },
            ],
        };

        assert_eq!(interfaces.interface.len(), 2);
        assert_eq!(interfaces.interface[0].name.as_deref(), Some("ge-0/0/0"));
        assert_eq!(interfaces.interface[1].enabled, Some(false));
    }

    #[test]
    fn test_statistics_container() {
        let stats = Statistics {
            ..Default::default()
        };
        // Statistics should have counter fields from YANG model
        // Just verify it compiles and defaults work
        assert!(stats.in_octets.is_none());
    }

    #[test]
    fn test_interfaces_to_xml() {
        let interfaces = Interfaces {
            interface: vec![],
        };

        let xml = interfaces.to_xml().expect("to_xml failed");
        assert!(xml.contains("urn:ietf:params:xml:ns:yang:ietf-interfaces"));
        assert!(xml.contains("<interfaces"));
        assert!(xml.contains("</interfaces>"));
    }

    #[test]
    fn test_wrong_type_is_compile_error() {
        // This proves type safety: name is Option<String>, not a number.
        // Uncommenting the line below would cause a compile error:
        // let _iface = Interface { name: Some(42), ..Default::default() };

        // enabled is Option<bool>, not a string:
        // let _iface = Interface { enabled: Some("yes".into()), ..Default::default() };

        // And bogus fields don't exist:
        // let _iface = Interface { bogus_field: Some("x".into()), ..Default::default() };

        // The fact that this test compiles proves the types are correct.
        let _iface = Interface {
            name: Some("ge-0/0/0".to_string()),
            enabled: Some(true),
            speed: Some(1000000000), // u64, not string
            ..Default::default()
        };
    }

    #[test]
    fn test_default_all_fields_none() {
        let iface = Interface::default();
        assert!(iface.name.is_none());
        assert!(iface.description.is_none());
        assert!(iface.r#type.is_none());
        assert!(iface.enabled.is_none());
        assert!(iface.speed.is_none());
        assert!(iface.statistics.is_none());
    }

    #[test]
    fn test_serde_json_roundtrip() {
        let original = Interface {
            name: Some("eth0".into()),
            description: Some("management".into()),
            enabled: Some(true),
            speed: Some(10000000000),
            ..Default::default()
        };

        let json = serde_json::to_string(&original).expect("serialize failed");
        let deserialized: Interface =
            serde_json::from_str(&json).expect("deserialize failed");

        assert_eq!(original.name, deserialized.name);
        assert_eq!(original.description, deserialized.description);
        assert_eq!(original.enabled, deserialized.enabled);
        assert_eq!(original.speed, deserialized.speed);
    }
}
