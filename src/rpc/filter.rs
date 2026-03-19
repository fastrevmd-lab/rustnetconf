//! Subtree and XPath filter builders for NETCONF `<get>` and `<get-config>`.

/// Builder for constructing subtree filters.
///
/// # Examples
/// ```
/// use rustnetconf::rpc::filter::SubtreeFilter;
///
/// let filter = SubtreeFilter::new()
///     .add("<interfaces/>")
///     .add("<system><hostname/></system>")
///     .build();
/// assert!(filter.contains("<interfaces/>"));
/// ```
pub struct SubtreeFilter {
    elements: Vec<String>,
}

impl SubtreeFilter {
    /// Create an empty subtree filter.
    pub fn new() -> Self {
        Self {
            elements: Vec::new(),
        }
    }

    /// Add an XML element to the filter.
    pub fn add(mut self, xml: &str) -> Self {
        self.elements.push(xml.to_string());
        self
    }

    /// Build the filter into a single XML string.
    pub fn build(&self) -> String {
        self.elements.join("\n")
    }
}

impl Default for SubtreeFilter {
    fn default() -> Self {
        Self::new()
    }
}
