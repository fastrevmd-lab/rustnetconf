//! Diff output formatting — colored terminal and JSON.

use colored::Colorize;
use super::tree::{DiffEntry, DiffKind};

/// Format diff entries as colored terminal output.
pub fn format_colored(entries: &[DiffEntry], file_name: &str) -> String {
    if entries.is_empty() {
        return format!("  {} {}", "✓".green(), format!("{file_name}: no changes").dimmed());
    }

    let mut output = String::new();
    output.push_str(&format!("  {} {}:\n", "~".yellow(), file_name.bold()));

    for entry in entries {
        match &entry.kind {
            DiffKind::Added { value } => {
                output.push_str(&format!(
                    "    {} {} = {}\n",
                    "+".green().bold(),
                    entry.path.green(),
                    value.green()
                ));
            }
            DiffKind::Removed { value } => {
                output.push_str(&format!(
                    "    {} {} = {}\n",
                    "-".red().bold(),
                    entry.path.red(),
                    value.red()
                ));
            }
            DiffKind::Modified { from, to } => {
                output.push_str(&format!(
                    "    {} {}\n",
                    "~".yellow().bold(),
                    entry.path.yellow(),
                ));
                output.push_str(&format!(
                    "      {} {}\n",
                    "-".red(),
                    from.red()
                ));
                output.push_str(&format!(
                    "      {} {}\n",
                    "+".green(),
                    to.green()
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
    let added = entries.iter().filter(|e| matches!(e.kind, DiffKind::Added { .. })).count();
    let removed = entries.iter().filter(|e| matches!(e.kind, DiffKind::Removed { .. })).count();
    let modified = entries.iter().filter(|e| matches!(e.kind, DiffKind::Modified { .. })).count();

    if added == 0 && removed == 0 && modified == 0 {
        return "No changes.".to_string();
    }

    let mut parts = Vec::new();
    if added > 0 { parts.push(format!("{} added", added)); }
    if modified > 0 { parts.push(format!("{} modified", modified)); }
    if removed > 0 { parts.push(format!("{} removed", removed)); }

    format!("Plan: {}", parts.join(", "))
}
