//! # rustnetconf-yang
//!
//! Compile-time typed Rust structs generated from YANG models, for use with
//! [`rustnetconf`]. The generated types serialize to NETCONF-ready XML.
//!
//! ## Quick start
//!
//! The generated code is behind the **`generated`** feature, which is **off by
//! default**. You must enable it or the `ietf_*` modules will not exist:
//!
//! ```toml
//! [dependencies]
//! rustnetconf-yang = { version = "0.1", features = ["generated"] }
//! ```
//!
//! Then use a bundled model:
//!
//! ```rust,ignore
//! use rustnetconf_yang::ietf_interfaces::{Interfaces, Interface};
//! use rustnetconf_yang::serialize::ToNetconfXml;
//!
//! let config = Interfaces {
//!     interface: vec![Interface {
//!         name: Some("eth0".into()),
//!         description: Some("uplink".into()),
//!         enabled: Some(true),
//!         ..Default::default()
//!     }],
//! };
//!
//! // Serialize to NETCONF-ready XML for `edit-config`:
//! let xml = config.to_xml().unwrap();
//! ```
//!
//! ## Which models are available?
//!
//! The crate **bundles** these IETF models, generated at build time:
//!
//! - `ietf_interfaces` (from `ietf-interfaces.yang`)
//! - `ietf_ip` (from `ietf-ip.yang`)
//! - plus supporting types from `ietf-yang-types` / `ietf-inet-types`
//!
//! Each module exposes a `NAMESPACE` const and structs named in `PascalCase`
//! after the YANG nodes (e.g. container `interfaces` -> `Interfaces`, list
//! `interface` -> `Interface`). YANG names that are Rust keywords are suffixed
//! with `_` (e.g. leaf `type` -> field `type_`).
//!
//! ## Using your own YANG models
//!
//! Code is generated from the `yang-models/` directory **of this crate**, not
//! of your project: the build script reads `$CARGO_MANIFEST_DIR/yang-models`,
//! which resolves to this crate's source in the Cargo registry cache when used
//! as a dependency. To generate types from custom `.yang` files you must vendor
//! this crate (e.g. a git/path dependency or fork) and add your models to its
//! `yang-models/` directory.
//!
//! [`rustnetconf`]: https://docs.rs/rustnetconf

pub mod serialize;

// Re-export generated types when available
// The build.rs generates code into OUT_DIR, which is included here.
#[cfg(feature = "generated")]
include!(concat!(env!("OUT_DIR"), "/yang_generated.rs"));
