//! # rustnetconf
//!
//! An async-first NETCONF 1.0/1.1 client library for Rust.
//!
//! Built on [tokio](https://tokio.rs) and [russh](https://crates.io/crates/russh)
//! for high-performance, memory-safe network device management.
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! use rustnetconf::{Client, Datastore};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let mut client = Client::connect("10.0.0.1:830")
//!         .username("admin")
//!         .password("secret")
//!         .connect()
//!         .await?;
//!
//!     let config = client.get_config(Datastore::Running).await?;
//!     println!("{config}");
//!
//!     client.close_session().await?;
//!     Ok(())
//! }
//! ```
//!
//! ## Architecture
//!
//! ```text
//! Client (thin wrapper) → Session (protocol state) → Framing → Transport (SSH)
//! ```
//!
//! See [ARCHITECTURE.md](https://github.com/fastrevmd-lab/rustnetconf/blob/main/ARCHITECTURE.md)
//! for full design details.

pub mod capability;
pub mod client;
pub mod error;
pub mod facts;
pub mod framing;
pub mod pool;
pub mod rpc;
pub mod session;
pub mod transport;
pub mod types;
pub mod vendor;

// Re-export the primary public API types
pub use client::{Client, ClientBuilder, EditConfigBuilder};
pub use error::NetconfError;
pub use facts::Facts;
pub use rpc::RpcErrorInfo;
pub use types::{
    Datastore, DefaultOperation, ErrorOption, LoadAction, LoadFormat, OpenConfigurationMode,
    TestOption,
};
