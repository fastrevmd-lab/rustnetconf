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
//! rustnetconf-yang = { version = "0.4", features = ["generated"] }
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
//! The crate **bundles** these IETF models, pregenerated into
//! `src/generated.rs` and committed:
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
//! Not from your own project's directory. The types ship pregenerated, so
//! nothing reads your `.yang` files — there is no build script left to read
//! them with. To generate types from custom models, vendor this crate (a git or
//! path dependency, or a fork), drop your `.yang` files into its
//! `yang-models/` directory, and re-run the generator:
//!
//! ```sh
//! cargo run -p rustnetconf-yang --features regenerate --bin codegen
//! ```
//!
//! That is the one path that needs `cmake` and libyang2; building against the
//! committed types needs neither.
//!
//! [`rustnetconf`]: https://docs.rs/rustnetconf

pub mod serialize;

// Re-export generated types when available.
//
// `generated.rs` is committed rather than produced by a build script: libyang2
// is a ~44 MB C build with a `cmake` prerequisite, and making every consumer pay
// it to regenerate a file that changes only when `yang-models/` does was a bad
// trade (#105). Refresh it with the `regenerate` feature; CI fails on drift.
#[cfg(feature = "generated")]
include!("generated.rs");
