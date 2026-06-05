//! JDI-specific RMI launch offers and connectors.
//!
//! Ported from Ghidra's `ghidra.dbg.jdi.rmi` package.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// A JDI connector type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum JdiConnectorType {
    /// Attach to a running JVM by port.
    Attach,
    /// Launch a new JVM.
    Launch,
    /// Listen for a JVM to connect.
    Listen,
}

/// Arguments for a JDI launch.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JdiArguments {
    /// The connector type.
    pub connector_type: JdiConnectorType,
    /// The main class or JAR to launch (for Launch connector).
    pub main_class: Option<String>,
    /// Host to attach/listen to.
    pub host: Option<String>,
    /// Port to attach/listen on.
    pub port: Option<u16>,
    /// JVM options.
    pub jvm_options: Vec<String>,
    /// Program arguments.
    pub program_args: Vec<String>,
    /// Additional connector arguments.
    pub extra: BTreeMap<String, String>,
}

impl JdiArguments {
    /// Create launch arguments.
    pub fn launch(main_class: impl Into<String>) -> Self {
        Self {
            connector_type: JdiConnectorType::Launch,
            main_class: Some(main_class.into()),
            host: None,
            port: None,
            jvm_options: Vec::new(),
            program_args: Vec::new(),
            extra: BTreeMap::new(),
        }
    }

    /// Create attach arguments.
    pub fn attach(host: impl Into<String>, port: u16) -> Self {
        Self {
            connector_type: JdiConnectorType::Attach,
            main_class: None,
            host: Some(host.into()),
            port: Some(port),
            jvm_options: Vec::new(),
            program_args: Vec::new(),
            extra: BTreeMap::new(),
        }
    }

    /// Create listen arguments.
    pub fn listen(port: u16) -> Self {
        Self {
            connector_type: JdiConnectorType::Listen,
            main_class: None,
            host: None,
            port: Some(port),
            jvm_options: Vec::new(),
            program_args: Vec::new(),
            extra: BTreeMap::new(),
        }
    }

    /// Add a JVM option.
    pub fn with_jvm_option(mut self, opt: impl Into<String>) -> Self {
        self.jvm_options.push(opt.into());
        self
    }

    /// Add a program argument.
    pub fn with_program_arg(mut self, arg: impl Into<String>) -> Self {
        self.program_args.push(arg.into());
        self
    }

    /// Add an extra connector argument.
    pub fn with_extra(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.extra.insert(key.into(), value.into());
        self
    }
}

/// A JDI architecture descriptor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JdiArch {
    /// Architecture name (e.g., "x86", "amd64", "aarch64").
    pub name: String,
    /// Pointer size in bytes.
    pub pointer_size: u32,
    /// Whether the architecture is big-endian.
    pub is_big_endian: bool,
    /// The language ID (Ghidra).
    pub language_id: Option<String>,
}

impl JdiArch {
    /// Create a new architecture descriptor.
    pub fn new(name: impl Into<String>, pointer_size: u32, is_big_endian: bool) -> Self {
        Self {
            name: name.into(),
            pointer_size,
            is_big_endian,
            language_id: None,
        }
    }

    /// The x86 architecture.
    pub fn x86() -> Self {
        let mut arch = Self::new("x86", 4, false);
        arch.language_id = Some("x86:LE:32:default".into());
        arch
    }

    /// The amd64 architecture.
    pub fn amd64() -> Self {
        let mut arch = Self::new("amd64", 8, false);
        arch.language_id = Some("x86:LE:64:default".into());
        arch
    }

    /// The aarch64 architecture.
    pub fn aarch64() -> Self {
        let mut arch = Self::new("aarch64", 8, false);
        arch.language_id = Some("AARCH64:LE:64:v8A".into());
        arch
    }
}

/// A JDI-specific RMI launch offer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JavaTraceRmiLaunchOffer {
    /// The offer name.
    pub name: String,
    /// Display label.
    pub display_label: String,
    /// The JDK home path.
    pub jdk_home: Option<String>,
    /// Launch arguments.
    pub arguments: Option<JdiArguments>,
    /// Whether the offer is available (JDK detected).
    pub available: bool,
}

impl JavaTraceRmiLaunchOffer {
    /// Create a new offer.
    pub fn new(name: impl Into<String>, display_label: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            display_label: display_label.into(),
            jdk_home: None,
            arguments: None,
            available: false,
        }
    }

    /// Set the JDK home.
    pub fn with_jdk_home(mut self, path: impl Into<String>) -> Self {
        self.jdk_home = Some(path.into());
        self
    }

    /// Set the arguments.
    pub fn with_arguments(mut self, args: JdiArguments) -> Self {
        self.arguments = Some(args);
        self
    }

    /// Set availability.
    pub fn with_available(mut self, available: bool) -> Self {
        self.available = available;
        self
    }
}

/// A JDI launch opinion.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JavaTraceRmiLaunchOpinion {
    /// The opinion name.
    pub name: String,
    /// Generated offers.
    pub offers: Vec<JavaTraceRmiLaunchOffer>,
}

impl JavaTraceRmiLaunchOpinion {
    /// Create a new opinion.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            offers: Vec::new(),
        }
    }

    /// Add an offer.
    pub fn add_offer(&mut self, offer: JavaTraceRmiLaunchOffer) {
        self.offers.push(offer);
    }

    /// Get available offers.
    pub fn available_offers(&self) -> impl Iterator<Item = &JavaTraceRmiLaunchOffer> {
        self.offers.iter().filter(|o| o.available)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jdi_arguments_launch() {
        let args = JdiArguments::launch("com.example.Main")
            .with_jvm_option("-Xmx512m")
            .with_program_arg("--debug")
            .with_extra("suspend", "true");

        assert_eq!(args.connector_type, JdiConnectorType::Launch);
        assert_eq!(args.main_class.as_deref(), Some("com.example.Main"));
        assert_eq!(args.jvm_options, vec!["-Xmx512m"]);
        assert_eq!(args.program_args, vec!["--debug"]);
        assert_eq!(args.extra["suspend"], "true");
    }

    #[test]
    fn test_jdi_arguments_attach() {
        let args = JdiArguments::attach("localhost", 5005);
        assert_eq!(args.connector_type, JdiConnectorType::Attach);
        assert_eq!(args.host.as_deref(), Some("localhost"));
        assert_eq!(args.port, Some(5005));
    }

    #[test]
    fn test_jdi_arguments_listen() {
        let args = JdiArguments::listen(8000);
        assert_eq!(args.connector_type, JdiConnectorType::Listen);
        assert_eq!(args.port, Some(8000));
    }

    #[test]
    fn test_jdi_connector_type() {
        assert_ne!(JdiConnectorType::Attach, JdiConnectorType::Launch);
        assert_ne!(JdiConnectorType::Launch, JdiConnectorType::Listen);
    }

    #[test]
    fn test_jdi_arch_x86() {
        let arch = JdiArch::x86();
        assert_eq!(arch.pointer_size, 4);
        assert!(!arch.is_big_endian);
        assert_eq!(arch.language_id.as_deref(), Some("x86:LE:32:default"));
    }

    #[test]
    fn test_jdi_arch_amd64() {
        let arch = JdiArch::amd64();
        assert_eq!(arch.pointer_size, 8);
    }

    #[test]
    fn test_jdi_arch_aarch64() {
        let arch = JdiArch::aarch64();
        assert_eq!(arch.pointer_size, 8);
        assert!(!arch.is_big_endian);
    }

    #[test]
    fn test_java_trace_rmi_launch_offer() {
        let offer = JavaTraceRmiLaunchOffer::new("java", "Java Debug")
            .with_jdk_home("/usr/lib/jvm/java-17")
            .with_available(true)
            .with_arguments(JdiArguments::launch("Main"));

        assert!(offer.available);
        assert!(offer.arguments.is_some());
    }

    #[test]
    fn test_java_trace_rmi_launch_opinion() {
        let mut opinion = JavaTraceRmiLaunchOpinion::new("java");
        opinion.add_offer(JavaTraceRmiLaunchOffer::new("java", "Java").with_available(true));
        opinion.add_offer(JavaTraceRmiLaunchOffer::new("java-pipe", "Java Pipe").with_available(false));

        let available: Vec<_> = opinion.available_offers().collect();
        assert_eq!(available.len(), 1);
    }

    #[test]
    fn test_jdi_arch_serde() {
        let arch = JdiArch::amd64();
        let json = serde_json::to_string(&arch).unwrap();
        let back: JdiArch = serde_json::from_str(&json).unwrap();
        assert_eq!(back.pointer_size, 8);
    }

    #[test]
    fn test_jdi_arguments_serde() {
        let args = JdiArguments::attach("localhost", 5005);
        let json = serde_json::to_string(&args).unwrap();
        let back: JdiArguments = serde_json::from_str(&json).unwrap();
        assert_eq!(back.port, Some(5005));
    }
}
