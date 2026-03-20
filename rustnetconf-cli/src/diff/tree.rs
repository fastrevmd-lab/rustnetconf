//! XML tree comparison — element-level diff engine.
//!
//! Compares two XML documents structurally, producing a list of changes.
//! List entries are matched by key elements (e.g., `<name>` for interfaces).

use quick_xml::events::Event;
use quick_xml::Reader;
use std::collections::BTreeMap;

/// A single diff entry.
#[derive(Debug, Clone, PartialEq)]
pub struct DiffEntry {
    /// XPath-like path to the changed element.
    pub path: String,
    /// The kind of change.
    pub kind: DiffKind,
}

/// The type of change detected.
#[derive(Debug, Clone, PartialEq)]
pub enum DiffKind {
    /// Element exists in desired but not in running.
    Added { value: String },
    /// Element exists in running but not in desired.
    Removed { value: String },
    /// Element exists in both but with different values.
    Modified { from: String, to: String },
}

/// A simplified XML tree node for comparison.
#[derive(Debug, Clone, PartialEq)]
enum XmlNode {
    Element {
        name: String,
        children: Vec<XmlNode>,
    },
    Text(String),
}

/// Compare two XML strings and return a list of differences.
pub fn diff_xml(desired: &str, running: &str) -> Result<Vec<DiffEntry>, String> {
    let desired_tree = parse_xml_tree(desired)?;
    let running_tree = parse_xml_tree(running)?;

    let mut entries = Vec::new();
    diff_nodes(&desired_tree, &running_tree, "", &mut entries);
    Ok(entries)
}

/// Parse an XML string into a simplified tree.
fn parse_xml_tree(xml: &str) -> Result<Vec<XmlNode>, String> {
    let mut reader = Reader::from_str(xml);
    let mut buf = Vec::new();
    let mut stack: Vec<(String, Vec<XmlNode>)> = Vec::new();
    let mut root_children: Vec<XmlNode> = Vec::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(ref tag)) => {
                let name = String::from_utf8_lossy(tag.local_name().as_ref()).to_string();
                stack.push((name, Vec::new()));
            }
            Ok(Event::End(_)) => {
                if let Some((name, children)) = stack.pop() {
                    let node = XmlNode::Element { name, children };
                    if let Some(parent) = stack.last_mut() {
                        parent.1.push(node);
                    } else {
                        root_children.push(node);
                    }
                }
            }
            Ok(Event::Text(ref text)) => {
                let value = text.unescape().unwrap_or_default().trim().to_string();
                if !value.is_empty() {
                    if let Some(parent) = stack.last_mut() {
                        parent.1.push(XmlNode::Text(value));
                    }
                }
            }
            Ok(Event::Empty(ref tag)) => {
                let name = String::from_utf8_lossy(tag.local_name().as_ref()).to_string();
                let node = XmlNode::Element {
                    name,
                    children: Vec::new(),
                };
                if let Some(parent) = stack.last_mut() {
                    parent.1.push(node);
                } else {
                    root_children.push(node);
                }
            }
            Ok(Event::Eof) => break,
            Ok(_) => {} // Skip comments, PI, etc.
            Err(e) => return Err(format!("XML parse error: {e}")),
        }
        buf.clear();
    }

    Ok(root_children)
}

/// Recursively diff two node lists.
fn diff_nodes(
    desired: &[XmlNode],
    running: &[XmlNode],
    path: &str,
    entries: &mut Vec<DiffEntry>,
) {
    // Build maps of element name → children for both sides
    let desired_map = build_element_map(desired);
    let running_map = build_element_map(running);

    // Check for added/modified elements (in desired)
    for (key, desired_nodes) in &desired_map {
        let elem_path = if path.is_empty() {
            key.clone()
        } else {
            format!("{path}/{key}")
        };

        match running_map.get(key) {
            None => {
                // Added — entire element is new
                for node in desired_nodes {
                    entries.push(DiffEntry {
                        path: elem_path.clone(),
                        kind: DiffKind::Added {
                            value: node_to_string(node),
                        },
                    });
                }
            }
            Some(running_nodes) => {
                // Both exist — compare children
                diff_matched_elements(desired_nodes, running_nodes, &elem_path, entries);
            }
        }
    }

    // Check for removed elements (in running but not desired)
    for (key, running_nodes) in &running_map {
        if !desired_map.contains_key(key) {
            let elem_path = if path.is_empty() {
                key.clone()
            } else {
                format!("{path}/{key}")
            };
            for node in running_nodes {
                entries.push(DiffEntry {
                    path: elem_path.clone(),
                    kind: DiffKind::Removed {
                        value: node_to_string(node),
                    },
                });
            }
        }
    }
}

/// Build a map of element name → list of elements with that name.
/// For list entries, appends the key value (e.g., "interface[ge-0/0/0]").
fn build_element_map(nodes: &[XmlNode]) -> BTreeMap<String, Vec<&XmlNode>> {
    let mut map: BTreeMap<String, Vec<&XmlNode>> = BTreeMap::new();

    for node in nodes {
        if let XmlNode::Element { name, children } = node {
            // Check if this element has a <name> child (list key)
            let key_value = find_key_child(children);
            let map_key = match key_value {
                Some(kv) => format!("{name}[{kv}]"),
                None => name.clone(),
            };
            map.entry(map_key).or_default().push(node);
        }
    }

    map
}

/// Find a `<name>` child element's text value (used as list key).
fn find_key_child(children: &[XmlNode]) -> Option<String> {
    for child in children {
        if let XmlNode::Element { name, children: grandchildren } = child {
            if name == "name" {
                for gc in grandchildren {
                    if let XmlNode::Text(value) = gc {
                        return Some(value.clone());
                    }
                }
            }
        }
    }
    None
}

/// Diff matched elements (same name/key, both sides exist).
fn diff_matched_elements(
    desired: &[&XmlNode],
    running: &[&XmlNode],
    path: &str,
    entries: &mut Vec<DiffEntry>,
) {
    // For simplicity, compare first desired vs first running
    if let (Some(d), Some(r)) = (desired.first(), running.first()) {
        if let (
                XmlNode::Element { children: dc, .. },
                XmlNode::Element { children: rc, .. },
            ) = (d, r) {
            // Check if these are leaf elements (contain only text)
            let d_text = extract_text(dc);
            let r_text = extract_text(rc);

            match (d_text, r_text) {
                (Some(dt), Some(rt)) if dt != rt => {
                    entries.push(DiffEntry {
                        path: path.to_string(),
                        kind: DiffKind::Modified {
                            from: rt,
                            to: dt,
                        },
                    });
                }
                (Some(_), Some(_)) => {
                    // Same value — no diff
                }
                _ => {
                    // Container elements — recurse
                    diff_nodes(dc, rc, path, entries);
                }
            }
        }
    }
}

/// Extract text content from a node's children (if it's a leaf element).
fn extract_text(children: &[XmlNode]) -> Option<String> {
    if children.len() == 1 {
        if let XmlNode::Text(text) = &children[0] {
            return Some(text.clone());
        }
    }
    None
}

/// Convert a node to a simple string representation.
fn node_to_string(node: &XmlNode) -> String {
    match node {
        XmlNode::Text(t) => t.clone(),
        XmlNode::Element { name, children } => {
            if children.is_empty() {
                format!("<{name}/>")
            } else {
                let inner: String = children.iter().map(node_to_string).collect::<Vec<_>>().join("");
                format!("<{name}>{inner}</{name}>")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identical_xml_no_diff() {
        let xml = "<interfaces><interface><name>ge-0/0/0</name><description>uplink</description></interface></interfaces>";
        let entries = diff_xml(xml, xml).unwrap();
        assert!(entries.is_empty(), "identical XML should produce no diff");
    }

    #[test]
    fn test_modified_leaf() {
        let desired = "<interfaces><interface><name>ge-0/0/0</name><description>new uplink</description></interface></interfaces>";
        let running = "<interfaces><interface><name>ge-0/0/0</name><description>old uplink</description></interface></interfaces>";
        let entries = diff_xml(desired, running).unwrap();
        assert_eq!(entries.len(), 1);
        assert!(matches!(&entries[0].kind, DiffKind::Modified { from, to }
            if from == "old uplink" && to == "new uplink"));
        assert!(entries[0].path.contains("description"));
    }

    #[test]
    fn test_added_element() {
        let desired = "<system><host-name>spine-01</host-name><location><building>DC-1</building></location></system>";
        let running = "<system><host-name>spine-01</host-name></system>";
        let entries = diff_xml(desired, running).unwrap();
        assert!(entries.iter().any(|e| matches!(&e.kind, DiffKind::Added { .. })));
    }

    #[test]
    fn test_removed_element() {
        let desired = "<system><host-name>spine-01</host-name></system>";
        let running = "<system><host-name>spine-01</host-name><location><building>DC-1</building></location></system>";
        let entries = diff_xml(desired, running).unwrap();
        assert!(entries.iter().any(|e| matches!(&e.kind, DiffKind::Removed { .. })));
    }

    #[test]
    fn test_list_entry_matching_by_name() {
        let desired = "<interfaces><interface><name>ge-0/0/0</name><description>updated</description></interface></interfaces>";
        let running = "<interfaces><interface><name>ge-0/0/0</name><description>original</description></interface></interfaces>";
        let entries = diff_xml(desired, running).unwrap();
        assert_eq!(entries.len(), 1);
        assert!(entries[0].path.contains("ge-0/0/0"));
    }

    #[test]
    fn test_added_list_entry() {
        let desired = "<interfaces><interface><name>ge-0/0/0</name></interface><interface><name>ge-0/0/1</name></interface></interfaces>";
        let running = "<interfaces><interface><name>ge-0/0/0</name></interface></interfaces>";
        let entries = diff_xml(desired, running).unwrap();
        assert!(entries.iter().any(|e|
            matches!(&e.kind, DiffKind::Added { .. }) && e.path.contains("ge-0/0/1")
        ));
    }

    #[test]
    fn test_whitespace_ignored() {
        let desired = "<system>\n  <host-name>spine-01</host-name>\n</system>";
        let running = "<system><host-name>spine-01</host-name></system>";
        let entries = diff_xml(desired, running).unwrap();
        assert!(entries.is_empty(), "whitespace differences should be ignored");
    }

    #[test]
    fn test_empty_vs_absent() {
        let desired = "<system><ntp/></system>";
        let running = "<system></system>";
        let entries = diff_xml(desired, running).unwrap();
        assert!(entries.iter().any(|e| matches!(&e.kind, DiffKind::Added { .. })));
    }
}
