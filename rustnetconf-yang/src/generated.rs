// Auto-generated from YANG models. Do not edit.
// Regenerate with: cargo run -p rustnetconf-yang --features regenerate --bin codegen

use serde::{Deserialize, Serialize};

/// Generated from YANG module `ietf-interfaces`
/// Namespace: `urn:ietf:params:xml:ns:yang:ietf-interfaces`
pub mod ietf_interfaces {
    #[allow(unused_imports)]
    use super::*;
    #[allow(unused_imports)]
    use crate::serialize::*;

    /// Namespace URI for this YANG module.
    pub const NAMESPACE: &str = "urn:ietf:params:xml:ns:yang:ietf-interfaces";

    /// YANG container: `interfaces`
    #[derive(Debug, Clone, Default, Serialize, Deserialize)]
    pub struct Interfaces {
        /// YANG list: `interface`
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub interface: Vec<Interface>,
    }

    impl WriteXmlFields for Interfaces {
        fn write_xml_fields(&self, writer: &mut Writer<Cursor<Vec<u8>>>) -> Result<(), XmlError> {
            for item in &self.interface {
                write_element_with_fields(writer, "interface", item)?;
            }
            Ok(())
        }
    }

    impl ToNetconfXml for Interfaces {
        fn namespace(&self) -> &str {
            NAMESPACE
        }
        fn root_element(&self) -> &str {
            "interfaces"
        }
        fn to_xml(&self) -> Result<String, XmlError> {
            let mut writer = new_writer();
            write_start_with_ns(&mut writer, "interfaces", NAMESPACE)?;
            self.write_xml_fields(&mut writer)?;
            write_end(&mut writer, "interfaces")?;
            finish_writer(writer)
        }
    }

    /// YANG list entry: `interface`
    #[derive(Debug, Clone, Default, Serialize, Deserialize)]
    pub struct Interface {
        /// YANG leaf: `name`
        #[serde(skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
        /// YANG leaf: `description`
        #[serde(skip_serializing_if = "Option::is_none")]
        pub description: Option<String>,
        /// YANG leaf: `type`
        #[serde(skip_serializing_if = "Option::is_none")]
        pub type_: Option<String>,
        /// YANG leaf: `enabled`
        #[serde(skip_serializing_if = "Option::is_none")]
        pub enabled: Option<bool>,
        /// YANG leaf: `oper-status`
        #[serde(skip_serializing_if = "Option::is_none")]
        pub oper_status: Option<String>,
        /// YANG leaf: `last-change`
        #[serde(skip_serializing_if = "Option::is_none")]
        pub last_change: Option<String>,
        /// YANG leaf: `phys-address`
        #[serde(skip_serializing_if = "Option::is_none")]
        pub phys_address: Option<String>,
        /// YANG leaf-list: `higher-layer-if`
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub higher_layer_if: Vec<String>,
        /// YANG leaf-list: `lower-layer-if`
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub lower_layer_if: Vec<String>,
        /// YANG leaf: `speed`
        #[serde(skip_serializing_if = "Option::is_none")]
        pub speed: Option<u64>,
        /// YANG container: `statistics`
        #[serde(skip_serializing_if = "Option::is_none")]
        pub statistics: Option<Statistics>,
        /// YANG container: `ipv4`
        #[serde(skip_serializing_if = "Option::is_none")]
        pub ipv4: Option<Ipv4>,
        /// YANG container: `ipv6`
        #[serde(skip_serializing_if = "Option::is_none")]
        pub ipv6: Option<Ipv6>,
    }

    impl WriteXmlFields for Interface {
        fn write_xml_fields(&self, writer: &mut Writer<Cursor<Vec<u8>>>) -> Result<(), XmlError> {
            if let Some(ref val) = self.name {
                write_text_element(writer, "name", &val.to_string())?;
            }
            if let Some(ref val) = self.description {
                write_text_element(writer, "description", &val.to_string())?;
            }
            if let Some(ref val) = self.type_ {
                write_text_element(writer, "type", &val.to_string())?;
            }
            if let Some(ref val) = self.enabled {
                write_text_element(writer, "enabled", &val.to_string())?;
            }
            if let Some(ref val) = self.oper_status {
                write_text_element(writer, "oper-status", &val.to_string())?;
            }
            if let Some(ref val) = self.last_change {
                write_text_element(writer, "last-change", &val.to_string())?;
            }
            if let Some(ref val) = self.phys_address {
                write_text_element(writer, "phys-address", &val.to_string())?;
            }
            for val in &self.higher_layer_if {
                write_text_element(writer, "higher-layer-if", &val.to_string())?;
            }
            for val in &self.lower_layer_if {
                write_text_element(writer, "lower-layer-if", &val.to_string())?;
            }
            if let Some(ref val) = self.speed {
                write_text_element(writer, "speed", &val.to_string())?;
            }
            if let Some(ref child) = self.statistics {
                write_element_with_fields(writer, "statistics", child)?;
            }
            if let Some(ref child) = self.ipv4 {
                write_element_with_fields(writer, "ipv4", child)?;
            }
            if let Some(ref child) = self.ipv6 {
                write_element_with_fields(writer, "ipv6", child)?;
            }
            Ok(())
        }
    }

    /// YANG container: `statistics`
    #[derive(Debug, Clone, Default, Serialize, Deserialize)]
    pub struct Statistics {
        /// YANG leaf: `discontinuity-time`
        #[serde(skip_serializing_if = "Option::is_none")]
        pub discontinuity_time: Option<String>,
        /// YANG leaf: `in-octets`
        #[serde(skip_serializing_if = "Option::is_none")]
        pub in_octets: Option<u64>,
        /// YANG leaf: `in-unicast-pkts`
        #[serde(skip_serializing_if = "Option::is_none")]
        pub in_unicast_pkts: Option<u64>,
        /// YANG leaf: `in-broadcast-pkts`
        #[serde(skip_serializing_if = "Option::is_none")]
        pub in_broadcast_pkts: Option<u64>,
        /// YANG leaf: `in-multicast-pkts`
        #[serde(skip_serializing_if = "Option::is_none")]
        pub in_multicast_pkts: Option<u64>,
        /// YANG leaf: `in-discards`
        #[serde(skip_serializing_if = "Option::is_none")]
        pub in_discards: Option<u32>,
        /// YANG leaf: `in-errors`
        #[serde(skip_serializing_if = "Option::is_none")]
        pub in_errors: Option<u32>,
        /// YANG leaf: `in-unknown-protos`
        #[serde(skip_serializing_if = "Option::is_none")]
        pub in_unknown_protos: Option<u32>,
        /// YANG leaf: `out-octets`
        #[serde(skip_serializing_if = "Option::is_none")]
        pub out_octets: Option<u64>,
        /// YANG leaf: `out-unicast-pkts`
        #[serde(skip_serializing_if = "Option::is_none")]
        pub out_unicast_pkts: Option<u64>,
        /// YANG leaf: `out-broadcast-pkts`
        #[serde(skip_serializing_if = "Option::is_none")]
        pub out_broadcast_pkts: Option<u64>,
        /// YANG leaf: `out-multicast-pkts`
        #[serde(skip_serializing_if = "Option::is_none")]
        pub out_multicast_pkts: Option<u64>,
        /// YANG leaf: `out-discards`
        #[serde(skip_serializing_if = "Option::is_none")]
        pub out_discards: Option<u32>,
        /// YANG leaf: `out-errors`
        #[serde(skip_serializing_if = "Option::is_none")]
        pub out_errors: Option<u32>,
    }

    impl WriteXmlFields for Statistics {
        fn write_xml_fields(&self, writer: &mut Writer<Cursor<Vec<u8>>>) -> Result<(), XmlError> {
            if let Some(ref val) = self.discontinuity_time {
                write_text_element(writer, "discontinuity-time", &val.to_string())?;
            }
            if let Some(ref val) = self.in_octets {
                write_text_element(writer, "in-octets", &val.to_string())?;
            }
            if let Some(ref val) = self.in_unicast_pkts {
                write_text_element(writer, "in-unicast-pkts", &val.to_string())?;
            }
            if let Some(ref val) = self.in_broadcast_pkts {
                write_text_element(writer, "in-broadcast-pkts", &val.to_string())?;
            }
            if let Some(ref val) = self.in_multicast_pkts {
                write_text_element(writer, "in-multicast-pkts", &val.to_string())?;
            }
            if let Some(ref val) = self.in_discards {
                write_text_element(writer, "in-discards", &val.to_string())?;
            }
            if let Some(ref val) = self.in_errors {
                write_text_element(writer, "in-errors", &val.to_string())?;
            }
            if let Some(ref val) = self.in_unknown_protos {
                write_text_element(writer, "in-unknown-protos", &val.to_string())?;
            }
            if let Some(ref val) = self.out_octets {
                write_text_element(writer, "out-octets", &val.to_string())?;
            }
            if let Some(ref val) = self.out_unicast_pkts {
                write_text_element(writer, "out-unicast-pkts", &val.to_string())?;
            }
            if let Some(ref val) = self.out_broadcast_pkts {
                write_text_element(writer, "out-broadcast-pkts", &val.to_string())?;
            }
            if let Some(ref val) = self.out_multicast_pkts {
                write_text_element(writer, "out-multicast-pkts", &val.to_string())?;
            }
            if let Some(ref val) = self.out_discards {
                write_text_element(writer, "out-discards", &val.to_string())?;
            }
            if let Some(ref val) = self.out_errors {
                write_text_element(writer, "out-errors", &val.to_string())?;
            }
            Ok(())
        }
    }

    /// YANG container: `ipv4`
    #[derive(Debug, Clone, Default, Serialize, Deserialize)]
    pub struct Ipv4 {
        /// YANG leaf: `enabled`
        #[serde(skip_serializing_if = "Option::is_none")]
        pub enabled: Option<bool>,
        /// YANG leaf: `forwarding`
        #[serde(skip_serializing_if = "Option::is_none")]
        pub forwarding: Option<bool>,
        /// YANG leaf: `mtu`
        #[serde(skip_serializing_if = "Option::is_none")]
        pub mtu: Option<u16>,
        /// YANG list: `address`
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub address: Vec<Address>,
        /// YANG list: `neighbor`
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub neighbor: Vec<Neighbor>,
    }

    impl WriteXmlFields for Ipv4 {
        fn write_xml_fields(&self, writer: &mut Writer<Cursor<Vec<u8>>>) -> Result<(), XmlError> {
            if let Some(ref val) = self.enabled {
                write_text_element(writer, "enabled", &val.to_string())?;
            }
            if let Some(ref val) = self.forwarding {
                write_text_element(writer, "forwarding", &val.to_string())?;
            }
            if let Some(ref val) = self.mtu {
                write_text_element(writer, "mtu", &val.to_string())?;
            }
            for item in &self.address {
                write_element_with_fields(writer, "address", item)?;
            }
            for item in &self.neighbor {
                write_element_with_fields(writer, "neighbor", item)?;
            }
            Ok(())
        }
    }

    /// YANG list entry: `address`
    #[derive(Debug, Clone, Default, Serialize, Deserialize)]
    pub struct Address {
        /// YANG leaf: `ip`
        #[serde(skip_serializing_if = "Option::is_none")]
        pub ip: Option<String>,
        /// YANG leaf: `origin`
        #[serde(skip_serializing_if = "Option::is_none")]
        pub origin: Option<String>,
    }

    impl WriteXmlFields for Address {
        fn write_xml_fields(&self, writer: &mut Writer<Cursor<Vec<u8>>>) -> Result<(), XmlError> {
            if let Some(ref val) = self.ip {
                write_text_element(writer, "ip", &val.to_string())?;
            }
            if let Some(ref val) = self.origin {
                write_text_element(writer, "origin", &val.to_string())?;
            }
            Ok(())
        }
    }

    /// YANG list entry: `neighbor`
    #[derive(Debug, Clone, Default, Serialize, Deserialize)]
    pub struct Neighbor {
        /// YANG leaf: `ip`
        #[serde(skip_serializing_if = "Option::is_none")]
        pub ip: Option<String>,
        /// YANG leaf: `link-layer-address`
        #[serde(skip_serializing_if = "Option::is_none")]
        pub link_layer_address: Option<String>,
        /// YANG leaf: `origin`
        #[serde(skip_serializing_if = "Option::is_none")]
        pub origin: Option<String>,
    }

    impl WriteXmlFields for Neighbor {
        fn write_xml_fields(&self, writer: &mut Writer<Cursor<Vec<u8>>>) -> Result<(), XmlError> {
            if let Some(ref val) = self.ip {
                write_text_element(writer, "ip", &val.to_string())?;
            }
            if let Some(ref val) = self.link_layer_address {
                write_text_element(writer, "link-layer-address", &val.to_string())?;
            }
            if let Some(ref val) = self.origin {
                write_text_element(writer, "origin", &val.to_string())?;
            }
            Ok(())
        }
    }

    /// YANG container: `ipv6`
    #[derive(Debug, Clone, Default, Serialize, Deserialize)]
    pub struct Ipv6 {
        /// YANG leaf: `enabled`
        #[serde(skip_serializing_if = "Option::is_none")]
        pub enabled: Option<bool>,
        /// YANG leaf: `forwarding`
        #[serde(skip_serializing_if = "Option::is_none")]
        pub forwarding: Option<bool>,
        /// YANG leaf: `mtu`
        #[serde(skip_serializing_if = "Option::is_none")]
        pub mtu: Option<u32>,
        /// YANG list: `address`
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub address: Vec<Address>,
        /// YANG list: `neighbor`
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub neighbor: Vec<Neighbor>,
        /// YANG leaf: `dup-addr-detect-transmits`
        #[serde(skip_serializing_if = "Option::is_none")]
        pub dup_addr_detect_transmits: Option<u32>,
        /// YANG container: `autoconf`
        #[serde(skip_serializing_if = "Option::is_none")]
        pub autoconf: Option<Autoconf>,
    }

    impl WriteXmlFields for Ipv6 {
        fn write_xml_fields(&self, writer: &mut Writer<Cursor<Vec<u8>>>) -> Result<(), XmlError> {
            if let Some(ref val) = self.enabled {
                write_text_element(writer, "enabled", &val.to_string())?;
            }
            if let Some(ref val) = self.forwarding {
                write_text_element(writer, "forwarding", &val.to_string())?;
            }
            if let Some(ref val) = self.mtu {
                write_text_element(writer, "mtu", &val.to_string())?;
            }
            for item in &self.address {
                write_element_with_fields(writer, "address", item)?;
            }
            for item in &self.neighbor {
                write_element_with_fields(writer, "neighbor", item)?;
            }
            if let Some(ref val) = self.dup_addr_detect_transmits {
                write_text_element(writer, "dup-addr-detect-transmits", &val.to_string())?;
            }
            if let Some(ref child) = self.autoconf {
                write_element_with_fields(writer, "autoconf", child)?;
            }
            Ok(())
        }
    }

    /// YANG container: `autoconf`
    #[derive(Debug, Clone, Default, Serialize, Deserialize)]
    pub struct Autoconf {
        /// YANG leaf: `create-global-addresses`
        #[serde(skip_serializing_if = "Option::is_none")]
        pub create_global_addresses: Option<bool>,
    }

    impl WriteXmlFields for Autoconf {
        fn write_xml_fields(&self, writer: &mut Writer<Cursor<Vec<u8>>>) -> Result<(), XmlError> {
            if let Some(ref val) = self.create_global_addresses {
                write_text_element(writer, "create-global-addresses", &val.to_string())?;
            }
            Ok(())
        }
    }

    /// YANG container: `interfaces-state`
    #[derive(Debug, Clone, Default, Serialize, Deserialize)]
    pub struct InterfacesState {
        /// YANG list: `interface`
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub interface: Vec<Interface>,
    }

    impl WriteXmlFields for InterfacesState {
        fn write_xml_fields(&self, writer: &mut Writer<Cursor<Vec<u8>>>) -> Result<(), XmlError> {
            for item in &self.interface {
                write_element_with_fields(writer, "interface", item)?;
            }
            Ok(())
        }
    }

    impl ToNetconfXml for InterfacesState {
        fn namespace(&self) -> &str {
            NAMESPACE
        }
        fn root_element(&self) -> &str {
            "interfaces-state"
        }
        fn to_xml(&self) -> Result<String, XmlError> {
            let mut writer = new_writer();
            write_start_with_ns(&mut writer, "interfaces-state", NAMESPACE)?;
            self.write_xml_fields(&mut writer)?;
            write_end(&mut writer, "interfaces-state")?;
            finish_writer(writer)
        }
    }
}

/// Generated from YANG module `ietf-ip`
/// Namespace: `urn:ietf:params:xml:ns:yang:ietf-ip`
pub mod ietf_ip {
    #[allow(unused_imports)]
    use super::*;
    #[allow(unused_imports)]
    use crate::serialize::*;

    /// Namespace URI for this YANG module.
    pub const NAMESPACE: &str = "urn:ietf:params:xml:ns:yang:ietf-ip";
}
