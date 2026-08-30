//! Diff output formatting — colored terminal and JSON.

use super::tree::{DiffEntry, DiffKind};
use console::style;

/// Format diff entries as colored terminal output.
pub fn format_colored(entries: &[DiffEntry], file_name: &str) -> String {
    if entries.is_empty() {
        return format!(
            "  {} {}",
            style("✓").green(),
            style(format!("{file_name}: no changes")).dim()
        );
    }

    let mut output = String::new();
    output.push_str(&format!(
        "  {} {}:\n",
        style("~").yellow(),
        style(file_name).bold()
    ));

    for entry in entries {
        match &entry.kind {
            DiffKind::Added { value } => {
                output.push_str(&format!(
                    "    {} {} = {}\n",
                    style("+").green().bold(),
                    style(&entry.path).green(),
                    style(value).green()
                ));
            }
            DiffKind::Removed { value } => {
                output.push_str(&format!(
                    "    {} {} = {}\n",
                    style("-").red().bold(),
                    style(&entry.path).red(),
                    style(value).red()
                ));
            }
            DiffKind::Modified { from, to } => {
                output.push_str(&format!(
                    "    {} {}\n",
                    style("~").yellow().bold(),
                    style(&entry.path).yellow(),
                ));
                output.push_str(&format!(
                    "      {} {}\n",
                    style("-").red(),
                    style(from).red()
                ));
                output.push_str(&format!(
                    "      {} {}\n",
                    style("+").green(),
                    style(to).green()
                ));
            }
        }
    }

    output
}

/// Format diff entries as JSON.
pub fn format_json(entries: &[DiffEntry]) -> String {
    let json_entries: Vec<serde_json::Value> = entries
        .iter()
        .map(|e| {
            let kind_str = match &e.kind {
                DiffKind::Added { value } => serde_json::json!({
                    "type": "added",
                    "value": value,
                }),
                DiffKind::Removed { value } => serde_json::json!({
                    "type": "removed",
                    "value": value,
                }),
                DiffKind::Modified { from, to } => serde_json::json!({
                    "type": "modified",
                    "from": from,
                    "to": to,
                }),
            };
            serde_json::json!({
                "path": e.path,
                "change": kind_str,
            })
        })
        .collect();

    serde_json::to_string_pretty(&json_entries).unwrap_or_else(|_| "[]".to_string())
}

/// Summary line for the diff.
pub fn summary(entries: &[DiffEntry]) -> String {
    let added = entries
        .iter()
        .filter(|e| matches!(e.kind, DiffKind::Added { .. }))
        .count();
    let removed = entries
        .iter()
        .filter(|e| matches!(e.kind, DiffKind::Removed { .. }))
        .count();
    let modified = entries
        .iter()
        .filter(|e| matches!(e.kind, DiffKind::Modified { .. }))
        .count();

    if added == 0 && removed == 0 && modified == 0 {
        return "No changes.".to_string();
    }

    let mut parts = Vec::new();
    if added > 0 {
        parts.push(format!("{} added", added));
    }
    if modified > 0 {
        parts.push(format!("{} modified", modified));
    }
    if removed > 0 {
        parts.push(format!("{} removed", removed));
    }

    format!("Plan: {}", parts.join(", "))
}

#[cfg(test)]
mod styling_tests {
    use super::*;
    use crate::diff::tree::{DiffEntry, DiffKind};

    /// The structure of the diff output, independent of colour.
    ///
    /// The escapes are stripped before asserting rather than relying on
    /// styling being off. It is off under a piped `cargo test`, which is what
    /// made the first version of this test pass -- and it fails on an
    /// interactive terminal or under `CLICOLOR_FORCE=1`, where the resets land
    /// between the sign, the path and the value. A test that only holds when
    /// the harness is redirected is not testing the thing it names.
    #[test]
    fn the_diff_lines_keep_their_shape() {
        let entries = vec![
            DiffEntry {
                path: "system/host-name".to_owned(),
                kind: DiffKind::Added {
                    value: "fw01".to_owned(),
                },
            },
            DiffEntry {
                path: "system/domain-name".to_owned(),
                kind: DiffKind::Removed {
                    value: "old.example".to_owned(),
                },
            },
            DiffEntry {
                path: "system/time-zone".to_owned(),
                kind: DiffKind::Modified {
                    from: "UTC".to_owned(),
                    to: "Europe/London".to_owned(),
                },
            },
        ];

        let styled = format_colored(&entries, "junos.conf");
        let out = console::strip_ansi_codes(&styled);
        assert!(out.contains("junos.conf:"), "{out}");
        assert!(out.contains("+ system/host-name = fw01"), "{out}");
        assert!(out.contains("- system/domain-name = old.example"), "{out}");
        assert!(out.contains("~ system/time-zone"), "{out}");
        assert!(out.contains("- UTC"), "{out}");
        assert!(out.contains("+ Europe/London"), "{out}");
    }

    /// The empty case is a distinct message, not an empty diff body.
    #[test]
    fn no_changes_says_so() {
        let styled = format_colored(&[], "junos.conf");
        let out = console::strip_ansi_codes(&styled);
        assert!(out.contains("junos.conf: no changes"), "{out}");
        assert!(!out.contains('\n'), "the empty case is one line: {out}");
    }
}
