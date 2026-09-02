//! Regenerates `src/generated.rs` from the YANG models in `yang-models/`.
//!
//! This used to be a build script, which meant every consumer of
//! `rustnetconf-yang` compiled libyang2 — ~44 MB of build artifacts and a hard
//! `cmake` prerequisite — to produce a file that is 436 lines of ordinary Rust
//! and changes only when `yang-models/` does. The generated code is now
//! committed and included directly, so libyang2 is a maintainer's tool rather
//! than a consumer's dependency (#105).
//!
//! Run it after editing anything under `yang-models/`:
//!
//! ```sh
//! cargo run -p rustnetconf-yang --features regenerate --bin codegen
//! ```
//!
//! CI re-runs this and fails on a dirty tree, so a stale `src/generated.rs`
//! cannot merge.

use std::collections::HashSet;
use std::env;
use std::fmt::Write as FmtWrite;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use yang2::context::{Context, ContextFlags};
use yang2::schema::{DataValueType, SchemaNode, SchemaNodeKind};

/// Warn that the ABI of a system libyang is not, and cannot cheaply be,
/// verified here.
///
/// `libyang2-sys` 0.9.0 probes with a bare `probe("libyang")` and falls back to
/// `-lyang`, neither of which constrains the version, while the bindings it
/// ships target `LIBYANG_MAJOR_SOVERSION 3`. An ABI-2 libyang links cleanly and
/// then hands this generator wrong struct offsets as it walks `Context` and
/// `SchemaNode` — silent UB at codegen time rather than a link error.
///
/// Deliberately a warning and nothing more. Verifying this properly means
/// knowing which file `-lyang` actually resolves to, which depends on `-L`
/// ordering, symlink targets, and platform naming (`.so.3` vs `.3.dylib`).
/// Earlier drafts of this check got each of those wrong in turn. libyang
/// exposes no runtime soversion accessor through these bindings to settle it,
/// so any check here is a guess, and a guess that reports "OK" is worse than no
/// check: it manufactures confidence about memory-safety-relevant layout.
///
/// The honest contract is therefore: this path is opt-in, the ABI requirement
/// is documented, and the generator says out loud that it did not check. Since
/// #105 this is a maintainer-only risk — a consumer of the crate never links
/// libyang at all.
#[cfg(not(feature = "bundled"))]
fn warn_system_libyang_abi_unverified() {
    eprintln!(
        "warning: rustnetconf-yang: building against a system libyang; its ABI is NOT \
         verified. libyang2-sys ships bindings for soname 3, and an soname-2 library will \
         link successfully and then be misread during code generation. Confirm with \
         `ls $(pkg-config --variable=libdir libyang)/libyang.so.*` that you have \
         libyang.so.3 — note that `pkg-config --modversion libyang` reports the project \
         version (2.2.8 for the release vendored here), not the soname."
    );
}

/// Format the generated file in place with the same `rustfmt` that
/// `cargo fmt --all -- --check` will judge it by.
///
/// Without this the committed file is whatever the string-building below
/// happens to emit, `cargo fmt --check` fails on it in CI, and formatting it by
/// hand makes the drift check below report a spurious diff on every run.
fn format_in_place(path: &Path) {
    match Command::new("rustfmt")
        .arg("--edition")
        .arg("2021")
        .arg(path)
        .status()
    {
        Ok(status) if status.success() => {}
        Ok(status) => panic!("rustfmt failed on {} with {status}", path.display()),
        Err(e) => panic!(
            "could not run rustfmt on {} ({e}). Install it with `rustup component add rustfmt`.",
            path.display()
        ),
    }
}

fn main() {
    #[cfg(not(feature = "bundled"))]
    warn_system_libyang_abi_unverified();

    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let yang_dir = manifest_dir.join("yang-models");
    let output_file = manifest_dir.join("src").join("generated.rs");

    assert!(
        yang_dir.exists(),
        "no yang-models/ directory at {}",
        yang_dir.display()
    );

    // Collect .yang filenames (just the module names, not full paths).
    //
    // Sorted below, because `read_dir` yields in filesystem order and libyang
    // returns modules from `ctx.modules()` in the order they were loaded. Left
    // unsorted, the same models generate the same code in a different order on
    // a different filesystem, and CI's drift check fails on a checkout that is
    // in fact correct.
    let mut yang_files: Vec<(String, Option<String>)> = fs::read_dir(&yang_dir)
        .unwrap()
        .filter_map(|entry| {
            let entry = entry.ok()?;
            let path = entry.path();
            if path.extension().map(|e| e == "yang").unwrap_or(false) {
                let stem = path.file_stem()?.to_str()?.to_string();
                // Parse "module-name@revision" format
                if let Some((name, rev)) = stem.split_once('@') {
                    Some((name.to_string(), Some(rev.to_string())))
                } else {
                    Some((stem, None))
                }
            } else {
                None
            }
        })
        .collect();
    yang_files.sort();

    assert!(
        !yang_files.is_empty(),
        "no YANG models found in {}",
        yang_dir.display()
    );

    // Create libyang2 context with search path
    let mut ctx =
        Context::new(ContextFlags::NO_YANGLIBRARY).expect("failed to create libyang2 context");
    ctx.set_searchdir(&yang_dir)
        .expect("failed to set yang search directory");

    // Load each module; collect failures and hard-error at the end so users
    // never silently end up with missing generated types.
    let mut module_names = Vec::new();
    let mut load_errors: Vec<String> = Vec::new();
    for (name, revision) in &yang_files {
        match ctx.load_module(name, revision.as_deref(), &[]) {
            Ok(_module) => {
                eprintln!("Loaded YANG module: {name}");
                module_names.push(name.clone());
            }
            Err(e) => {
                let msg = format!("Failed to load YANG module '{name}': {e}");
                eprintln!("{msg}");
                load_errors.push(msg);
            }
        }
    }
    if !load_errors.is_empty() {
        panic!(
            "rustnetconf-yang: {} YANG module(s) failed to load — types were NOT generated.\n{}",
            load_errors.len(),
            load_errors.join("\n")
        );
    }

    // Generate Rust code
    let mut output = String::new();
    writeln!(output, "// Auto-generated from YANG models. Do not edit.").unwrap();
    writeln!(
        output,
        "// Regenerate with: cargo run -p rustnetconf-yang --features regenerate --bin codegen"
    )
    .unwrap();
    writeln!(output).unwrap();
    writeln!(output, "use serde::{{Serialize, Deserialize}};").unwrap();
    writeln!(output).unwrap();

    // Iterate loaded modules and generate code
    for module in ctx.modules(true) {
        let name = module.name().to_string();
        // Only generate for explicitly loaded models (skip internal/imported-only)
        if !module_names.contains(&name) {
            continue;
        }
        let namespace = module.namespace().to_string();
        let mod_name = name.replace('-', "_");

        writeln!(output, "/// Generated from YANG module `{name}`").unwrap();
        writeln!(output, "/// Namespace: `{namespace}`").unwrap();
        writeln!(output, "pub mod {mod_name} {{").unwrap();
        writeln!(output, "    #[allow(unused_imports)]").unwrap();
        writeln!(output, "    use super::*;").unwrap();
        writeln!(output, "    #[allow(unused_imports)]").unwrap();
        writeln!(output, "    use crate::serialize::*;").unwrap();
        writeln!(output).unwrap();
        writeln!(output, "    /// Namespace URI for this YANG module.").unwrap();
        writeln!(output, "    pub const NAMESPACE: &str = \"{namespace}\";").unwrap();
        writeln!(output).unwrap();

        // Generate structs for top-level data nodes
        let mut emitted = HashSet::new();
        for node in module.data() {
            generate_node(&mut output, &node, 1, true, &mut emitted);
        }

        writeln!(output, "}}").unwrap();
        writeln!(output).unwrap();
    }

    fs::write(&output_file, &output).unwrap();
    format_in_place(&output_file);
    eprintln!("Generated YANG types to {}", output_file.display());
}

/// Generate a Rust struct for a YANG container or list node.
fn generate_node(
    output: &mut String,
    node: &SchemaNode,
    indent: usize,
    is_top_level: bool,
    emitted: &mut HashSet<String>,
) {
    let ind = "    ".repeat(indent);
    let node_name = node.name().to_string();
    let rust_name = to_rust_type_name(&node_name);

    // Skip if already emitted (augmented nodes can appear in multiple modules)
    if emitted.contains(&rust_name) {
        return;
    }

    match node.kind() {
        SchemaNodeKind::Container => {
            emitted.insert(rust_name.clone());

            writeln!(output, "{ind}/// YANG container: `{node_name}`").unwrap();
            writeln!(
                output,
                "{ind}#[derive(Debug, Clone, Default, Serialize, Deserialize)]"
            )
            .unwrap();
            writeln!(output, "{ind}pub struct {rust_name} {{").unwrap();

            for child in node.children() {
                generate_field(output, &child, indent + 1);
            }

            writeln!(output, "{ind}}}").unwrap();
            writeln!(output).unwrap();

            // Generate WriteXmlFields for all containers (top-level and nested)
            generate_write_xml_fields_impl(output, node, &rust_name, indent);

            if is_top_level {
                generate_to_xml_impl(output, &rust_name, &node_name, indent);
            }

            for child in node.children() {
                if matches!(
                    child.kind(),
                    SchemaNodeKind::Container | SchemaNodeKind::List
                ) {
                    generate_node(output, &child, indent, false, emitted);
                }
            }
        }
        SchemaNodeKind::List => {
            emitted.insert(rust_name.clone());

            writeln!(output, "{ind}/// YANG list entry: `{node_name}`").unwrap();
            writeln!(
                output,
                "{ind}#[derive(Debug, Clone, Default, Serialize, Deserialize)]"
            )
            .unwrap();
            writeln!(output, "{ind}pub struct {rust_name} {{").unwrap();

            for child in node.children() {
                generate_field(output, &child, indent + 1);
            }

            writeln!(output, "{ind}}}").unwrap();
            writeln!(output).unwrap();

            // Generate WriteXmlFields for list entries so they can be embedded
            generate_write_xml_fields_impl(output, node, &rust_name, indent);

            for child in node.children() {
                if matches!(
                    child.kind(),
                    SchemaNodeKind::Container | SchemaNodeKind::List
                ) {
                    generate_node(output, &child, indent, false, emitted);
                }
            }
        }
        _ => {}
    }
}

/// Generate a struct field for a YANG child node.
fn generate_field(output: &mut String, node: &SchemaNode, indent: usize) {
    let ind = "    ".repeat(indent);
    let node_name = node.name().to_string();
    let field_name = to_rust_field_name(&node_name);

    match node.kind() {
        SchemaNodeKind::Leaf => {
            let rust_type = yang_type_to_rust(node);
            writeln!(output, "{ind}/// YANG leaf: `{node_name}`").unwrap();
            writeln!(
                output,
                "{ind}#[serde(skip_serializing_if = \"Option::is_none\")]"
            )
            .unwrap();
            writeln!(output, "{ind}pub {field_name}: Option<{rust_type}>,").unwrap();
        }
        SchemaNodeKind::LeafList => {
            let rust_type = yang_type_to_rust(node);
            writeln!(output, "{ind}/// YANG leaf-list: `{node_name}`").unwrap();
            writeln!(
                output,
                "{ind}#[serde(default, skip_serializing_if = \"Vec::is_empty\")]"
            )
            .unwrap();
            writeln!(output, "{ind}pub {field_name}: Vec<{rust_type}>,").unwrap();
        }
        SchemaNodeKind::Container => {
            let type_name = to_rust_type_name(&node_name);
            writeln!(output, "{ind}/// YANG container: `{node_name}`").unwrap();
            writeln!(
                output,
                "{ind}#[serde(skip_serializing_if = \"Option::is_none\")]"
            )
            .unwrap();
            writeln!(output, "{ind}pub {field_name}: Option<{type_name}>,").unwrap();
        }
        SchemaNodeKind::List => {
            let type_name = to_rust_type_name(&node_name);
            writeln!(output, "{ind}/// YANG list: `{node_name}`").unwrap();
            writeln!(
                output,
                "{ind}#[serde(default, skip_serializing_if = \"Vec::is_empty\")]"
            )
            .unwrap();
            writeln!(output, "{ind}pub {field_name}: Vec<{type_name}>,").unwrap();
        }
        _ => {} // Skip choice, anyxml, etc. for now
    }
}

/// Generate WriteXmlFields implementation for a container or list entry struct.
///
/// This impl writes all child fields (leaves, leaf-lists, containers, lists)
/// into a caller-supplied writer. It does not write the surrounding element tags.
fn generate_write_xml_fields_impl(
    output: &mut String,
    node: &SchemaNode,
    rust_name: &str,
    indent: usize,
) {
    let ind = "    ".repeat(indent);

    writeln!(output, "{ind}impl WriteXmlFields for {rust_name} {{").unwrap();
    writeln!(output, "{ind}    fn write_xml_fields(&self, writer: &mut Writer<Cursor<Vec<u8>>>) -> Result<(), XmlError> {{").unwrap();

    for child in node.children() {
        let child_name = child.name().to_string();
        let field = to_rust_field_name(&child_name);

        match child.kind() {
            SchemaNodeKind::Leaf => {
                writeln!(
                    output,
                    "{ind}        if let Some(ref val) = self.{field} {{"
                )
                .unwrap();
                writeln!(output, "{ind}            write_text_element(writer, \"{child_name}\", &val.to_string())?;").unwrap();
                writeln!(output, "{ind}        }}").unwrap();
            }
            SchemaNodeKind::LeafList => {
                writeln!(output, "{ind}        for val in &self.{field} {{").unwrap();
                writeln!(output, "{ind}            write_text_element(writer, \"{child_name}\", &val.to_string())?;").unwrap();
                writeln!(output, "{ind}        }}").unwrap();
            }
            SchemaNodeKind::Container => {
                writeln!(
                    output,
                    "{ind}        if let Some(ref child) = self.{field} {{"
                )
                .unwrap();
                writeln!(
                    output,
                    "{ind}            write_element_with_fields(writer, \"{child_name}\", child)?;"
                )
                .unwrap();
                writeln!(output, "{ind}        }}").unwrap();
            }
            SchemaNodeKind::List => {
                writeln!(output, "{ind}        for item in &self.{field} {{").unwrap();
                writeln!(
                    output,
                    "{ind}            write_element_with_fields(writer, \"{child_name}\", item)?;"
                )
                .unwrap();
                writeln!(output, "{ind}        }}").unwrap();
            }
            _ => {
                // Skip choice, anyxml, etc. for now
            }
        }
    }

    writeln!(output, "{ind}        Ok(())").unwrap();
    writeln!(output, "{ind}    }}").unwrap();
    writeln!(output, "{ind}}}").unwrap();
    writeln!(output).unwrap();
}

/// Generate ToNetconfXml implementation for a top-level container.
///
/// Delegates to WriteXmlFields for field serialization so containers and
/// lists at any nesting depth are serialized correctly.
fn generate_to_xml_impl(output: &mut String, rust_name: &str, node_name: &str, indent: usize) {
    let ind = "    ".repeat(indent);

    writeln!(output, "{ind}impl ToNetconfXml for {rust_name} {{").unwrap();
    writeln!(
        output,
        "{ind}    fn namespace(&self) -> &str {{ NAMESPACE }}"
    )
    .unwrap();
    writeln!(
        output,
        "{ind}    fn root_element(&self) -> &str {{ \"{node_name}\" }}"
    )
    .unwrap();
    writeln!(
        output,
        "{ind}    fn to_xml(&self) -> Result<String, XmlError> {{"
    )
    .unwrap();
    writeln!(output, "{ind}        let mut writer = new_writer();").unwrap();
    writeln!(
        output,
        "{ind}        write_start_with_ns(&mut writer, \"{node_name}\", NAMESPACE)?;"
    )
    .unwrap();
    writeln!(output, "{ind}        self.write_xml_fields(&mut writer)?;").unwrap();
    writeln!(
        output,
        "{ind}        write_end(&mut writer, \"{node_name}\")?;"
    )
    .unwrap();
    writeln!(output, "{ind}        finish_writer(writer)").unwrap();
    writeln!(output, "{ind}    }}").unwrap();
    writeln!(output, "{ind}}}").unwrap();
    writeln!(output).unwrap();
}

/// Convert YANG name to Rust PascalCase type name.
fn to_rust_type_name(yang_name: &str) -> String {
    yang_name
        .split('-')
        .map(|part| {
            let mut chars = part.chars();
            match chars.next() {
                None => String::new(),
                Some(c) => c.to_uppercase().to_string() + chars.as_str(),
            }
        })
        .collect()
}

/// Convert YANG name to Rust snake_case field name.
fn to_rust_field_name(yang_name: &str) -> String {
    let name = yang_name.replace('-', "_");
    // Full set of Rust keywords (stable + reserved) that must be escaped.
    match name.as_str() {
        "as" | "async" | "await" | "break" | "const" | "continue" | "crate" | "dyn" | "else"
        | "enum" | "extern" | "false" | "fn" | "for" | "if" | "impl" | "in" | "let" | "loop"
        | "match" | "mod" | "move" | "mut" | "pub" | "ref" | "return" | "self" | "Self"
        | "static" | "struct" | "super" | "trait" | "true" | "type" | "unsafe" | "use"
        | "where" | "while" | "abstract" | "become" | "box" | "do" | "final" | "macro"
        | "override" | "priv" | "try" | "typeof" | "unsized" | "virtual" | "yield" => {
            format!("{name}_")
        }
        _ => name,
    }
}

/// Map YANG leaf type to Rust type.
fn yang_type_to_rust(node: &SchemaNode) -> String {
    if let Some(leaf_type) = node.leaf_type() {
        match leaf_type.base_type() {
            DataValueType::String => "String",
            DataValueType::Bool => "bool",
            DataValueType::Uint8 => "u8",
            DataValueType::Uint16 => "u16",
            DataValueType::Uint32 => "u32",
            DataValueType::Uint64 => "u64",
            DataValueType::Int8 => "i8",
            DataValueType::Int16 => "i16",
            DataValueType::Int32 => "i32",
            DataValueType::Int64 => "i64",
            DataValueType::Empty => "bool",
            DataValueType::Enum => "String",
            DataValueType::Union => "String",
            DataValueType::Binary => "String",
            DataValueType::IdentityRef => "String",
            DataValueType::LeafRef => "String",
            DataValueType::Dec64 => "f64",
            DataValueType::Bits => "String",
            DataValueType::InstanceId => "String",
            _ => "String",
        }
        .to_string()
    } else {
        "String".to_string()
    }
}
