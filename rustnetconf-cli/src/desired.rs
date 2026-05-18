//! Read desired state XML files from the `desired/<device>/` directory.

use rustnetconf::rpc::validate_xml_fragment;
use std::path::{Path, PathBuf};

/// A single desired config file with its content and derived subtree filter.
#[derive(Debug)]
pub struct DesiredConfig {
    /// Source file path.
    #[allow(dead_code)]
    pub path: PathBuf,
    /// File name without extension (e.g., "interfaces").
    pub name: String,
    /// Raw XML content.
    pub xml: String,
    /// Subtree filter derived from the XML root elements.
    /// Used to fetch only the matching section from the device.
    pub filter: String,
}

/// Read all .xml files from `desired/<device_name>/`.
pub fn read_desired_configs(
    project_dir: &Path,
    device_name: &str,
) -> Result<Vec<DesiredConfig>, String> {
    let desired_dir = project_dir.join("desired").join(device_name);

    if !desired_dir.exists() {
        return Err(format!(
            "desired config directory not found: {}",
            desired_dir.display()
        ));
    }

    let mut configs = Vec::new();

    let entries = std::fs::read_dir(&desired_dir)
        .map_err(|e| format!("failed to read {}: {e}", desired_dir.display()))?;

    for entry in entries {
        let entry = entry.map_err(|e| format!("directory read error: {e}"))?;
        let path = entry.path();

        if path.extension().map(|e| e == "xml").unwrap_or(false) {
            let name = path
                .file_stem()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string();

            let xml = std::fs::read_to_string(&path)
                .map_err(|e| format!("failed to read {}: {e}", path.display()))?;

            let xml_trimmed = xml.trim().to_string();
            if xml_trimmed.is_empty() {
                return Err(format!("empty XML file: {}", path.display()));
            }

            // Validate well-formedness BEFORE we connect to the device. This
            // ensures malformed XML in a desired/ file is caught locally so
            // we never lock the candidate datastore only to fail on the
            // first edit-config. (RNC-SEC-006)
            validate_xml_fragment(&xml_trimmed)
                .map_err(|e| format!("malformed XML in {}: {e}", path.display()))?;

            // Derive subtree filter from the XML content.
            // The filter uses the same root elements but with empty children
            // to tell the device "give me only this section."
            let filter = derive_subtree_filter(&xml_trimmed);

            // Filter is currently derived as a copy of the content, but
            // validate it explicitly so any future derivation logic that
            // produces malformed output is also caught here.
            validate_xml_fragment(&filter)
                .map_err(|e| format!("derived filter for {} is malformed: {e}", path.display()))?;

            configs.push(DesiredConfig {
                path,
                name,
                xml: xml_trimmed,
                filter,
            });
        }
    }

    if configs.is_empty() {
        return Err(format!("no .xml files found in {}", desired_dir.display()));
    }

    // Sort by filename for deterministic ordering
    configs.sort_by(|a, b| a.name.cmp(&b.name));

    Ok(configs)
}

/// Derive a subtree filter from desired config XML.
///
/// For a desired config like:
/// ```xml
/// <configuration>
///   <interfaces>
///     <interface>
///       <name>ge-0/0/0</name>
///       ...
///     </interface>
///   </interfaces>
/// </configuration>
/// ```
///
/// The filter is the top-level structure with empty leaves:
/// ```xml
/// <configuration><interfaces/></configuration>
/// ```
fn derive_subtree_filter(xml: &str) -> String {
    // Simple heuristic: extract top-level element structure.
    // For now, use the full XML as the filter (the device will match
    // the subtree and return the matching section).
    // A smarter version would strip leaf values and keep only structure.
    //
    // For Junos, the most reliable approach is to use the desired XML
    // as-is for the filter — the device returns the matching subtree.
    xml.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_read_desired_configs() {
        let tmp = tempdir();
        let device_dir = tmp.join("desired").join("spine-01");
        fs::create_dir_all(&device_dir).unwrap();

        fs::write(
            device_dir.join("interfaces.xml"),
            "<configuration><interfaces><interface><name>ge-0/0/0</name></interface></interfaces></configuration>",
        ).unwrap();

        fs::write(
            device_dir.join("system.xml"),
            "<configuration><system><host-name>spine-01</host-name></system></configuration>",
        )
        .unwrap();

        let configs = read_desired_configs(&tmp, "spine-01").unwrap();
        assert_eq!(configs.len(), 2);
        assert_eq!(configs[0].name, "interfaces");
        assert_eq!(configs[1].name, "system");
        assert!(configs[0].xml.contains("ge-0/0/0"));
    }

    #[test]
    fn test_missing_device_dir() {
        let tmp = tempdir();
        let result = read_desired_configs(&tmp, "nonexistent");
        assert!(result.is_err());
    }

    #[test]
    fn test_empty_dir() {
        let tmp = tempdir();
        let device_dir = tmp.join("desired").join("spine-01");
        fs::create_dir_all(&device_dir).unwrap();

        let result = read_desired_configs(&tmp, "spine-01");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("no .xml files"));
    }

    /// Malformed XML (unclosed tag) must be rejected at load time before
    /// any device connection or candidate lock. Regression guard for
    /// RNC-SEC-006.
    #[test]
    fn malformed_unclosed_tag_is_rejected_with_filename() {
        let tmp = tempdir();
        let device_dir = tmp.join("desired").join("spine-01");
        fs::create_dir_all(&device_dir).unwrap();

        fs::write(device_dir.join("broken.xml"), "<configuration><interfaces>").unwrap();

        let err = read_desired_configs(&tmp, "spine-01").unwrap_err();
        assert!(err.contains("broken.xml"), "error should name file: {err}");
        assert!(
            err.contains("malformed XML"),
            "error should say malformed: {err}"
        );
    }

    /// Mismatched closing tag must be rejected.
    #[test]
    fn malformed_mismatched_tags_is_rejected() {
        let tmp = tempdir();
        let device_dir = tmp.join("desired").join("spine-01");
        fs::create_dir_all(&device_dir).unwrap();

        fs::write(device_dir.join("bad.xml"), "<a></b>").unwrap();

        let err = read_desired_configs(&tmp, "spine-01").unwrap_err();
        assert!(err.contains("bad.xml"));
        assert!(err.contains("malformed XML"));
    }

    /// Well-formed but multi-rooted XML is still accepted (the library's
    /// validator wraps in a synthetic root so multi-sibling fragments
    /// parse as a single document). This guards against an over-eager
    /// rejection if the library validator is ever swapped out.
    #[test]
    fn multi_root_xml_is_accepted() {
        let tmp = tempdir();
        let device_dir = tmp.join("desired").join("spine-01");
        fs::create_dir_all(&device_dir).unwrap();

        fs::write(device_dir.join("multi.xml"), "<a/><b/>").unwrap();

        let configs = read_desired_configs(&tmp, "spine-01").unwrap();
        assert_eq!(configs.len(), 1);
        assert_eq!(configs[0].xml, "<a/><b/>");
    }

    fn tempdir() -> PathBuf {
        use std::sync::atomic::{AtomicU32, Ordering};
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let id = COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir =
            std::env::temp_dir().join(format!("rustnetconf-test-{}-{id}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }
}
