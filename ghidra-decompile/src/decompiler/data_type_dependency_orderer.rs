//! Data type dependency ordering for the decompiler.
//!
//! Port of Ghidra's `app.util.DataTypeDependencyOrderer`.
//! Orders data types so that dependencies are resolved before dependents,
//! ensuring correct forward-declaration and struct layout in C output.

use std::collections::{HashMap, HashSet, VecDeque};

/// A data type node in the dependency graph.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DataTypeNode {
    /// The data type name (e.g., "struct_my_type").
    pub name: String,
    /// The category path (e.g., "/my_category").
    pub category: String,
    /// Whether this is a pointer type.
    pub is_pointer: bool,
    /// Whether this type is a composite (struct/union).
    pub is_composite: bool,
}

impl DataTypeNode {
    /// Create a new data type node.
    pub fn new(name: impl Into<String>, category: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            category: category.into(),
            is_pointer: false,
            is_composite: false,
        }
    }

    /// Create a pointer type node.
    pub fn pointer(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            category: String::new(),
            is_pointer: true,
            is_composite: false,
        }
    }

    /// Create a composite type node.
    pub fn composite(name: impl Into<String>, category: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            category: category.into(),
            is_pointer: false,
            is_composite: true,
        }
    }

    /// Fully qualified name (category + name).
    pub fn qualified_name(&self) -> String {
        if self.category.is_empty() {
            self.name.clone()
        } else {
            format!("{}/{}", self.category, self.name)
        }
    }
}

/// Orders data types based on their dependencies.
///
/// Types that depend on other types appear after their dependencies in the
/// output ordering. Pointer types are special-cased since they don't require
/// the pointed-to type to be fully defined (only declared).
#[derive(Debug)]
pub struct DataTypeDependencyOrderer {
    /// Dependency graph: type name -> set of types it depends on.
    dependencies: HashMap<String, HashSet<String>>,
    /// All known types.
    types: HashMap<String, DataTypeNode>,
}

impl DataTypeDependencyOrderer {
    /// Create a new empty dependency orderer.
    pub fn new() -> Self {
        Self {
            dependencies: HashMap::new(),
            types: HashMap::new(),
        }
    }

    /// Register a data type.
    pub fn add_type(&mut self, dt: DataTypeNode) {
        self.types.insert(dt.name.clone(), dt);
    }

    /// Add a dependency: `dependent` depends on `dependency`.
    pub fn add_dependency(&mut self, dependent: &str, dependency: &str) {
        self.dependencies
            .entry(dependent.to_string())
            .or_default()
            .insert(dependency.to_string());
    }

    /// Compute a topological ordering of the types.
    ///
    /// Returns types in dependency order (dependencies first). Returns an error
    /// if there are cyclic dependencies.
    pub fn order(&self) -> Result<Vec<&DataTypeNode>, String> {
        let mut in_degree: HashMap<&str, usize> = HashMap::new();
        let mut reverse_deps: HashMap<&str, Vec<&str>> = HashMap::new();

        // Initialize in-degrees
        for (name, deps) in &self.dependencies {
            in_degree.entry(name).or_insert(0);
            for dep in deps {
                in_degree.entry(dep.as_str()).or_insert(0);
                *in_degree.entry(name).or_insert(0) += 1;
                reverse_deps.entry(dep.as_str()).or_default().push(name);
            }
        }

        // Also add types with no dependencies
        for name in self.types.keys() {
            in_degree.entry(name.as_str()).or_insert(0);
        }

        // Start with nodes that have no dependencies
        let mut queue: VecDeque<&str> = in_degree
            .iter()
            .filter(|(_, &deg)| deg == 0)
            .map(|(&name, _)| name)
            .collect();

        let mut order = Vec::new();

        while let Some(node) = queue.pop_front() {
            order.push(node);
            if let Some(dependents) = reverse_deps.get(node) {
                for &dep in dependents {
                    if let Some(deg) = in_degree.get_mut(dep) {
                        *deg -= 1;
                        if *deg == 0 {
                            queue.push_back(dep);
                        }
                    }
                }
            }
        }

        if order.len() != self.types.len() {
            return Err(format!(
                "Cyclic dependency detected: {} types ordered out of {}",
                order.len(),
                self.types.len()
            ));
        }

        Ok(order
            .iter()
            .filter_map(|name| self.types.get(*name))
            .collect())
    }

    /// Get the number of registered types.
    pub fn type_count(&self) -> usize {
        self.types.len()
    }

    /// Get the dependency count for a type.
    pub fn dependency_count(&self, name: &str) -> usize {
        self.dependencies
            .get(name)
            .map(|d| d.len())
            .unwrap_or(0)
    }

    /// Clear all types and dependencies.
    pub fn clear(&mut self) {
        self.dependencies.clear();
        self.types.clear();
    }
}

impl Default for DataTypeDependencyOrderer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_orderer_empty() {
        let orderer = DataTypeDependencyOrderer::new();
        let order = orderer.order().unwrap();
        assert!(order.is_empty());
    }

    #[test]
    fn test_orderer_simple_chain() {
        let mut orderer = DataTypeDependencyOrderer::new();
        orderer.add_type(DataTypeNode::composite("A", ""));
        orderer.add_type(DataTypeNode::composite("B", ""));
        orderer.add_type(DataTypeNode::composite("C", ""));
        orderer.add_dependency("C", "B");
        orderer.add_dependency("B", "A");

        let order = orderer.order().unwrap();
        let names: Vec<&str> = order.iter().map(|n| n.name.as_str()).collect();
        let a_pos = names.iter().position(|&n| n == "A").unwrap();
        let b_pos = names.iter().position(|&n| n == "B").unwrap();
        let c_pos = names.iter().position(|&n| n == "C").unwrap();
        assert!(a_pos < b_pos);
        assert!(b_pos < c_pos);
    }

    #[test]
    fn test_orderer_cycle_detection() {
        let mut orderer = DataTypeDependencyOrderer::new();
        orderer.add_type(DataTypeNode::new("A", ""));
        orderer.add_type(DataTypeNode::new("B", ""));
        orderer.add_dependency("A", "B");
        orderer.add_dependency("B", "A");
        assert!(orderer.order().is_err());
    }

    #[test]
    fn test_orderer_diamond() {
        let mut orderer = DataTypeDependencyOrderer::new();
        orderer.add_type(DataTypeNode::new("A", ""));
        orderer.add_type(DataTypeNode::new("B", ""));
        orderer.add_type(DataTypeNode::new("C", ""));
        orderer.add_type(DataTypeNode::new("D", ""));
        orderer.add_dependency("B", "A");
        orderer.add_dependency("C", "A");
        orderer.add_dependency("D", "B");
        orderer.add_dependency("D", "C");

        let order = orderer.order().unwrap();
        assert_eq!(order.len(), 4);
        let names: Vec<&str> = order.iter().map(|n| n.name.as_str()).collect();
        let a_pos = names.iter().position(|&n| n == "A").unwrap();
        let d_pos = names.iter().position(|&n| n == "D").unwrap();
        assert!(a_pos < d_pos);
    }

    #[test]
    fn test_data_type_node() {
        let n = DataTypeNode::composite("my_struct", "/types");
        assert!(n.is_composite);
        assert!(!n.is_pointer);
        assert_eq!(n.qualified_name(), "/types/my_struct");

        let p = DataTypeNode::pointer("char_ptr");
        assert!(p.is_pointer);
        assert_eq!(p.qualified_name(), "char_ptr");
    }

    #[test]
    fn test_orderer_dependency_count() {
        let mut orderer = DataTypeDependencyOrderer::new();
        orderer.add_type(DataTypeNode::new("A", ""));
        orderer.add_type(DataTypeNode::new("B", ""));
        orderer.add_dependency("A", "B");
        assert_eq!(orderer.dependency_count("A"), 1);
        assert_eq!(orderer.dependency_count("B"), 0);
    }

    #[test]
    fn test_orderer_clear() {
        let mut orderer = DataTypeDependencyOrderer::new();
        orderer.add_type(DataTypeNode::new("A", ""));
        assert_eq!(orderer.type_count(), 1);
        orderer.clear();
        assert_eq!(orderer.type_count(), 0);
    }
}
