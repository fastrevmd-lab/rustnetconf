//! XML diff engine for comparing desired vs running config.
//!
//! ```text
//! Desired XML ──┐
//!               ├──► XmlDiff ──► Vec<DiffEntry>
//! Running XML ──┘         │
//!                         ├──► Colored terminal output
//!                         └──► JSON output
//! ```

pub mod format;
pub mod tree;

pub use format::{format_colored, format_json};
pub use tree::diff_xml;
