//! Script grouping and categorization.
//!
//! Ported from `ghidra.app.plugin.core.script.ScriptGroup`,
//! `ScriptCategoryNode`, `RootNode`.


/// Built-in script groups shown in the script manager.
///
/// Ported from `ghidra.app.plugin.core.script.ScriptGroup`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ScriptGroup {
    /// Recently-used scripts.
    RecentScripts,
    /// All scripts.
    AllScripts,
}

impl ScriptGroup {
    /// Get the display name for this group.
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::RecentScripts => "Recent Scripts",
            Self::AllScripts => "All Scripts",
        }
    }
}

/// A node in the script category tree.
///
/// Ported from `ghidra.app.plugin.core.script.ScriptCategoryNode`.
#[derive(Debug, Clone)]
pub struct ScriptCategoryNode {
    /// Category name.
    pub name: String,
    /// Full path from root.
    pub path: String,
    /// Child categories.
    pub children: Vec<ScriptCategoryNode>,
    /// Script file names in this category.
    pub script_names: Vec<String>,
}

impl ScriptCategoryNode {
    /// Create a new category node.
    pub fn new(name: impl Into<String>, path: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            path: path.into(),
            children: Vec::new(),
            script_names: Vec::new(),
        }
    }

    /// Add a child category.
    pub fn add_child(&mut self, child: ScriptCategoryNode) {
        self.children.push(child);
    }

    /// Add a script name to this category.
    pub fn add_script(&mut self, name: impl Into<String>) {
        self.script_names.push(name.into());
    }

    /// Get the total number of scripts in this node and all children.
    pub fn total_script_count(&self) -> usize {
        self.script_names.len()
            + self
                .children
                .iter()
                .map(|c| c.total_script_count())
                .sum::<usize>()
    }

    /// Whether this node has any children.
    pub fn has_children(&self) -> bool {
        !self.children.is_empty()
    }

    /// Whether this node contains scripts directly.
    pub fn has_scripts(&self) -> bool {
        !self.script_names.is_empty()
    }

    /// Find a child category by name.
    pub fn find_child(&self, name: &str) -> Option<&ScriptCategoryNode> {
        self.children.iter().find(|c| c.name == name)
    }

    /// Find a mutable child category by name.
    pub fn find_child_mut(&mut self, name: &str) -> Option<&mut ScriptCategoryNode> {
        self.children.iter_mut().find(|c| c.name == name)
    }
}

/// The root node of the script category tree.
///
/// Ported from `ghidra.app.plugin.core.script.RootNode`.
#[derive(Debug)]
pub struct ScriptRootNode {
    /// The root category node.
    pub root: ScriptCategoryNode,
    /// Recently-used script names.
    pub recent_scripts: Vec<String>,
}

impl ScriptRootNode {
    /// Create a new root node.
    pub fn new() -> Self {
        Self {
            root: ScriptCategoryNode::new("Scripts", ""),
            recent_scripts: Vec::new(),
        }
    }

    /// Build a category tree from a list of (category_path, script_name) pairs.
    pub fn build_from_entries(&mut self, entries: &[(String, String)]) {
        for (category, script_name) in entries {
            self.insert_into_category(category, script_name);
        }
    }

    fn insert_into_category(&mut self, category: &str, script_name: &str) {
        if category.is_empty() {
            self.root.add_script(script_name);
            return;
        }
        let parts: Vec<&str> = category.split('/').collect();
        let mut current = &mut self.root;
        for part in &parts {
            let child_path = if current.path.is_empty() {
                part.to_string()
            } else {
                format!("{}/{}", current.path, part)
            };
            if current.find_child(part).is_none() {
                current.add_child(ScriptCategoryNode::new(*part, &child_path));
            }
            current = current.find_child_mut(part).unwrap();
        }
        current.add_script(script_name);
    }

    /// Get all categories as a flat list of paths.
    pub fn all_categories(&self) -> Vec<String> {
        let mut result = Vec::new();
        Self::collect_categories(&self.root, &mut result);
        result
    }

    fn collect_categories(node: &ScriptCategoryNode, result: &mut Vec<String>) {
        for child in &node.children {
            result.push(child.path.clone());
            Self::collect_categories(child, result);
        }
    }

    /// Add a script to the recent list.
    pub fn add_recent(&mut self, script_name: impl Into<String>) {
        let name = script_name.into();
        self.recent_scripts.retain(|s| s != &name);
        self.recent_scripts.insert(0, name);
        if self.recent_scripts.len() > 10 {
            self.recent_scripts.truncate(10);
        }
    }

    /// Get the recent script names.
    pub fn recent_scripts(&self) -> &[String] {
        &self.recent_scripts
    }
}

impl Default for ScriptRootNode {
    fn default() -> Self {
        Self::new()
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_script_group_display_name() {
        assert_eq!(ScriptGroup::RecentScripts.display_name(), "Recent Scripts");
        assert_eq!(ScriptGroup::AllScripts.display_name(), "All Scripts");
    }

    #[test]
    fn test_script_category_node() {
        let mut root = ScriptCategoryNode::new("Root", "");
        assert_eq!(root.name, "Root");
        assert!(!root.has_children());
        assert!(!root.has_scripts());

        root.add_script("my_script.py");
        assert!(root.has_scripts());
        assert_eq!(root.total_script_count(), 1);

        let child = ScriptCategoryNode::new("Analysis", "Analysis");
        root.add_child(child);
        assert!(root.has_children());
        assert!(root.find_child("Analysis").is_some());
        assert!(root.find_child("Missing").is_none());
    }

    #[test]
    fn test_script_category_node_nested_count() {
        let mut root = ScriptCategoryNode::new("Root", "");
        root.add_script("a.py");

        let mut child = ScriptCategoryNode::new("Sub", "Sub");
        child.add_script("b.py");
        child.add_script("c.py");

        let mut grandchild = ScriptCategoryNode::new("Deep", "Sub/Deep");
        grandchild.add_script("d.py");
        child.add_child(grandchild);

        root.add_child(child);
        assert_eq!(root.total_script_count(), 4);
    }

    #[test]
    fn test_script_root_node_build() {
        let mut root = ScriptRootNode::new();
        let entries = vec![
            ("Analysis".to_string(), "analyze.py".to_string()),
            ("Analysis/DWARF".to_string(), "dwarf.py".to_string()),
            ("Utilities".to_string(), "export.py".to_string()),
            ("".to_string(), "quick_script.py".to_string()),
        ];
        root.build_from_entries(&entries);

        assert_eq!(root.root.total_script_count(), 4);
        let cats = root.all_categories();
        assert!(cats.contains(&"Analysis".to_string()));
        assert!(cats.contains(&"Analysis/DWARF".to_string()));
        assert!(cats.contains(&"Utilities".to_string()));
    }

    #[test]
    fn test_script_root_node_recent() {
        let mut root = ScriptRootNode::new();
        root.add_recent("a.py");
        root.add_recent("b.py");
        assert_eq!(root.recent_scripts(), &["b.py", "a.py"]);

        // Moving to front
        root.add_recent("a.py");
        assert_eq!(root.recent_scripts(), &["a.py", "b.py"]);
    }

    #[test]
    fn test_script_root_node_recent_max() {
        let mut root = ScriptRootNode::new();
        for i in 0..15 {
            root.add_recent(format!("{}.py", i));
        }
        assert_eq!(root.recent_scripts().len(), 10);
        // Most recent should be 14
        assert_eq!(root.recent_scripts()[0], "14.py");
    }
}
