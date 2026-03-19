//! # rustnetconf-yang
//!
//! YANG model code generation for rustnetconf. Generates typed Rust structs
//! from YANG models so your network config is validated at compile time.
//!
//! ## How it works
//!
//! 1. Place `.yang` model files in your project's `yang-models/` directory
//! 2. Add `rustnetconf-yang` as a dependency
//! 3. Run `cargo build` — the build script generates Rust structs in `OUT_DIR`
//! 4. Use the generated types with `edit_config_typed()`
//!
//! ```rust,ignore
//! // Generated from ietf-interfaces.yang:
//! use rustnetconf_yang::ietf_interfaces::Interfaces;
//!
//! let config = Interfaces {
//!     interface: vec![Interface {
//!         name: "ge-0/0/0".into(),
//!         description: Some("uplink".into()),
//!         enabled: Some(true),
//!         ..Default::default()
//!     }],
//! };
//! ```

pub mod serialize;

// Re-export generated types when available
// The build.rs generates code into OUT_DIR, which is included here.
#[cfg(feature = "generated")]
include!(concat!(env!("OUT_DIR"), "/yang_generated.rs"));
