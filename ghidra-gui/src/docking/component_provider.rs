//! The `ComponentProvider` trait for the docking framework.
//!
//! Port of Ghidra's `docking.ComponentProvider` interface.  In Java,
//! `ComponentProvider` is the base class that every dockable view extends.
//! It carries the tool reference, the component name, and the methods
//! the framework uses to manage window lifecycle, context, and
//! actions.
//!
//! The existing [`super::component::ComponentProvider`] enum identifies
//! well-known provider *types*; this trait describes the behaviour of a
//! provider *instance*.

use std::collections::HashMap;
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};

use super::action::{DockingAction, KeyBinding, KeyBindingType, ToolBarData};
use super::action_context::DockingActionContext;
use super::component::WindowPosition;

// ---------------------------------------------------------------------------
// ComponentProviderState — mutable state for a concrete provider
// ---------------------------------------------------------------------------

/// Mutable state that a concrete `ComponentProvider` implementation can
/// embed.  Mirrors the Java `ComponentProvider` fields that are managed
/// by the framework (titles, icon, key binding, transient flag, etc.).
///
/// # Usage
///
/// ```ignore
/// use ghidra_gui::docking::component_provider::*;
/// use ghidra_gui::docking::component::ComponentProvider as ProviderType;
///
/// struct MyProvider {
///     state: ComponentProviderState,
///     // ... your fields ...
/// }
///
/// impl MyProvider {
///     fn new() -> Self {
///         Self {
///             state: ComponentProviderState::new(
///                 "MyView",
///                 "MyPlugin",
///                 ProviderType::Console,
///             ),
///         }
///     }
/// }
/// ```
#[derive(Debug)]
pub struct ComponentProviderState {
    /// Programmatic name of the provider.
    name: String,
    /// Owner (usually a plugin name).
    owner: String,
    /// The provider type enum value.
    provider_type: super::component::ComponentProvider,
    /// The current window title.
    title: String,
    /// The current sub-title.
    sub_title: String,
    /// The current tab text.
    tab_text: Option<String>,
    /// Custom title override (if set, setTitle has no effect).
    custom_title: Option<String>,
    /// Custom sub-title override.
    custom_sub_title: Option<String>,
    /// Custom tab text override.
    custom_tab_text: Option<String>,
    /// Icon identifier.
    icon: Option<String>,
    /// Whether the provider is visible.
    visible: bool,
    /// Whether the provider is in (registered with) a tool.
    in_tool: bool,
    /// Whether this is a transient provider.
    is_transient: bool,
    /// Whether the show action should appear in the toolbar.
    add_toolbar_action: bool,
    /// Default key binding for the show action.
    default_key_binding: Option<KeyBinding>,
    /// Window group for initial placement.
    window_group: String,
    /// Window menu sub-group name.
    window_sub_menu_name: Option<String>,
    /// Window menu group.
    window_menu_group: String,
    /// Default window position.
    default_position: WindowPosition,
    /// Intra-group position.
    intra_group_position: WindowPosition,
    /// Help location identifier.
    help_location: Option<String>,
    /// Unique instance ID (for layout persistence).
    instance_id: u64,
    /// Whether the instance ID has been explicitly initialized.
    instance_id_initialized: bool,
    /// Registered font ID for font size adjustments.
    registered_font_id: Option<String>,
    /// Local actions contributed by this provider.
    local_actions: Vec<DockingAction>,
}

static NEXT_INSTANCE_ID: AtomicU64 = AtomicU64::new(1);

impl ComponentProviderState {
    /// Create a new provider state with the given name, owner, and type.
    pub fn new(
        name: impl Into<String>,
        owner: impl Into<String>,
        provider_type: super::component::ComponentProvider,
    ) -> Self {
        let name = name.into();
        Self {
            title: name.clone(),
            name,
            owner: owner.into(),
            provider_type,
            sub_title: String::new(),
            tab_text: None,
            custom_title: None,
            custom_sub_title: None,
            custom_tab_text: None,
            icon: None,
            visible: false,
            in_tool: false,
            is_transient: false,
            add_toolbar_action: false,
            default_key_binding: None,
            window_group: "Default".to_owned(),
            window_sub_menu_name: None,
            window_menu_group: "Views".to_owned(),
            default_position: WindowPosition::default(),
            intra_group_position: WindowPosition::Center,
            help_location: None,
            instance_id: NEXT_INSTANCE_ID.fetch_add(1, Ordering::Relaxed),
            instance_id_initialized: false,
            registered_font_id: None,
            local_actions: Vec::new(),
        }
    }

    /// The programmatic name of the provider.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The owner (plugin name).
    pub fn owner(&self) -> &str {
        &self.owner
    }

    /// The provider type.
    pub fn provider_type(&self) -> super::component::ComponentProvider {
        self.provider_type
    }

    /// The unique instance ID.
    pub fn instance_id(&self) -> u64 {
        self.instance_id
    }

    /// Initialize the instance ID (can only be called once with a
    /// different value; subsequent calls with the same value are no-ops).
    ///
    /// Port of Ghidra's `ComponentProvider.initializeInstanceID`.
    pub fn initialize_instance_id(&mut self, new_id: u64) -> bool {
        if self.instance_id_initialized {
            if new_id != self.instance_id {
                return false; // cannot change once initialized
            }
            return true;
        }
        self.instance_id_initialized = true;
        self.instance_id = new_id;
        true
    }

    // -- Title management --

    /// The current window title.
    pub fn title(&self) -> &str {
        if let Some(ref custom) = self.custom_title {
            custom
        } else {
            &self.title
        }
    }

    /// Set the window title.  Has no effect if a custom title is set.
    ///
    /// Port of Ghidra's `ComponentProvider.setTitle`.
    pub fn set_title(&mut self, title: impl Into<String>) {
        if self.custom_title.is_some() {
            return;
        }
        self.title = title.into();
    }

    /// The current sub-title.
    pub fn sub_title(&self) -> &str {
        if let Some(ref custom) = self.custom_sub_title {
            custom
        } else {
            &self.sub_title
        }
    }

    /// Set the sub-title.  Has no effect if a custom sub-title is set.
    ///
    /// Port of Ghidra's `ComponentProvider.setSubTitle`.
    pub fn set_sub_title(&mut self, sub_title: impl Into<String>) {
        if self.custom_sub_title.is_some() {
            return;
        }
        self.sub_title = sub_title.into();
    }

    /// The current tab text.
    pub fn tab_text(&self) -> &str {
        if let Some(ref custom) = self.custom_tab_text {
            custom
        } else if let Some(ref tab) = self.tab_text {
            tab
        } else {
            self.title()
        }
    }

    /// Set the tab text.  Has no effect if a custom tab text is set.
    ///
    /// Port of Ghidra's `ComponentProvider.setTabText`.
    pub fn set_tab_text(&mut self, tab_text: impl Into<String>) {
        if self.custom_tab_text.is_some() {
            return;
        }
        self.tab_text = Some(tab_text.into());
    }

    /// Set a custom title that prevents future `set_title` calls from
    /// having any effect.
    ///
    /// Port of Ghidra's `ComponentProvider.setCustomTitle`.
    pub fn set_custom_title(&mut self, title: impl Into<String>) {
        let t = title.into();
        self.custom_title = Some(t.clone());
        self.title = t;
    }

    /// Set a custom sub-title that prevents future `set_sub_title` calls
    /// from having any effect.
    ///
    /// Port of Ghidra's `ComponentProvider.setCustomSubTitle`.
    pub fn set_custom_sub_title(&mut self, sub_title: impl Into<String>) {
        let s = sub_title.into();
        self.custom_sub_title = Some(s.clone());
        self.sub_title = s;
    }

    /// Set a custom tab text that prevents future `set_tab_text` calls
    /// from having any effect.
    ///
    /// Port of Ghidra's `ComponentProvider.setCustomTabText`.
    pub fn set_custom_tab_text(&mut self, tab_text: impl Into<String>) {
        let t = tab_text.into();
        self.custom_tab_text = Some(t.clone());
        self.tab_text = Some(t);
    }

    /// The full window title including sub-title.
    pub fn full_title(&self) -> String {
        let base = self.title().to_owned();
        let sub = self.sub_title();
        if sub.is_empty() {
            base
        } else {
            format!("{} - {}", base, sub)
        }
    }

    // -- Icon --

    /// The icon identifier.
    pub fn icon(&self) -> Option<&str> {
        self.icon.as_deref()
    }

    /// Set the icon identifier.
    ///
    /// Port of Ghidra's `ComponentProvider.setIcon`.
    pub fn set_icon(&mut self, icon: impl Into<String>) {
        self.icon = Some(icon.into());
    }

    // -- Visibility --

    /// Whether the provider is visible.
    pub fn is_visible(&self) -> bool {
        self.visible
    }

    /// Set visibility.
    pub fn set_visible(&mut self, visible: bool) {
        self.visible = visible;
    }

    // -- Tool integration --

    /// Whether the provider is registered with a tool.
    pub fn is_in_tool(&self) -> bool {
        self.in_tool
    }

    /// Mark the provider as registered with a tool.
    pub fn set_in_tool(&mut self, in_tool: bool) {
        self.in_tool = in_tool;
    }

    // -- Transient --

    /// Whether the provider is transient.
    pub fn is_transient(&self) -> bool {
        self.is_transient
    }

    /// Mark the provider as transient.
    ///
    /// Port of Ghidra's `ComponentProvider.setTransient`.
    pub fn set_transient(&mut self) {
        self.is_transient = true;
        // Transient providers cannot have toolbar actions or key bindings.
        self.add_toolbar_action = false;
        self.default_key_binding = None;
    }

    // -- Toolbar --

    /// Whether the show action should appear in the toolbar.
    pub fn add_toolbar_action(&self) -> bool {
        self.add_toolbar_action
    }

    /// Signal that the show action should appear in the toolbar.
    ///
    /// Port of Ghidra's `ComponentProvider.addToToolbar`.
    pub fn set_add_toolbar_action(&mut self, add: bool) {
        if add && self.is_transient {
            return; // transient providers cannot have toolbar actions
        }
        self.add_toolbar_action = add;
    }

    // -- Key binding --

    /// The default key binding for the show action.
    pub fn default_key_binding(&self) -> Option<&KeyBinding> {
        self.default_key_binding.as_ref()
    }

    /// Set the default key binding for the show action.
    ///
    /// Port of Ghidra's `ComponentProvider.setKeyBinding`.
    pub fn set_default_key_binding(&mut self, binding: Option<KeyBinding>) {
        if self.is_transient && binding.is_some() {
            return; // transient providers cannot have key bindings
        }
        self.default_key_binding = binding;
    }

    // -- Window group / position --

    /// The window group.
    pub fn window_group(&self) -> &str {
        &self.window_group
    }

    /// Set the window group.
    pub fn set_window_group(&mut self, group: impl Into<String>) {
        self.window_group = group.into();
    }

    /// The window sub-menu name.
    pub fn window_sub_menu_name(&self) -> Option<&str> {
        self.window_sub_menu_name.as_deref()
    }

    /// Set the window sub-menu name.
    pub fn set_window_sub_menu_name(&mut self, name: Option<String>) {
        self.window_sub_menu_name = name;
    }

    /// The window menu group.
    pub fn window_menu_group(&self) -> &str {
        &self.window_menu_group
    }

    /// Set the window menu group.
    pub fn set_window_menu_group(&mut self, group: impl Into<String>) {
        self.window_menu_group = group.into();
    }

    /// The default window position.
    pub fn default_position(&self) -> &WindowPosition {
        &self.default_position
    }

    /// Set the default window position.
    pub fn set_default_position(&mut self, position: WindowPosition) {
        self.default_position = position;
    }

    /// The intra-group position.
    pub fn intra_group_position(&self) -> &WindowPosition {
        &self.intra_group_position
    }

    /// Set the intra-group position.
    pub fn set_intra_group_position(&mut self, position: WindowPosition) {
        self.intra_group_position = position;
    }

    // -- Help --

    /// The help location identifier.
    pub fn help_location(&self) -> Option<&str> {
        self.help_location.as_deref()
    }

    /// Set the help location.
    pub fn set_help_location(&mut self, location: impl Into<String>) {
        self.help_location = Some(location.into());
    }

    // -- Font management --

    /// The registered font ID for font size adjustments.
    pub fn registered_font_id(&self) -> Option<&str> {
        self.registered_font_id.as_deref()
    }

    /// Register a font ID for automatic font size adjustments.
    ///
    /// Port of Ghidra's `ComponentProvider.registerAdjustableFontId`.
    pub fn register_adjustable_font_id(&mut self, font_id: impl Into<String>) {
        self.registered_font_id = Some(font_id.into());
    }

    // -- Local actions --

    /// All local actions registered on this provider.
    pub fn local_actions(&self) -> &[DockingAction] {
        &self.local_actions
    }

    /// Add a local action.
    ///
    /// Port of Ghidra's `ComponentProvider.addLocalAction`.
    pub fn add_local_action(&mut self, action: DockingAction) {
        if !self.local_actions.iter().any(|a| a.name == action.name) {
            self.local_actions.push(action);
        }
    }

    /// Remove a local action by name.
    ///
    /// Port of Ghidra's `ComponentProvider.removeLocalAction`.
    pub fn remove_local_action(&mut self, action_name: &str) -> Option<DockingAction> {
        let pos = self.local_actions.iter().position(|a| a.name == action_name);
        pos.map(|idx| self.local_actions.remove(idx))
    }

    /// Remove all local actions.
    ///
    /// Port of Ghidra's `ComponentProvider.removeAllLocalActions`.
    pub fn remove_all_local_actions(&mut self) -> Vec<DockingAction> {
        std::mem::take(&mut self.local_actions)
    }

    // -- Show provider action --

    /// Create the "show provider" action for this provider.
    ///
    /// Port of Ghidra's `ComponentProvider.ShowProviderAction`.
    pub fn create_show_provider_action(&self) -> DockingAction {
        let supports_key_bindings = !self.is_transient;
        let key_binding_type = if supports_key_bindings {
            KeyBindingType::Shared
        } else {
            KeyBindingType::Unsupported
        };

        let mut action = DockingAction::with_key_binding_type(
            &self.name,
            &self.owner,
            format!("Display {}", self.name),
            key_binding_type,
        )
        .with_description(format!("Display {}", self.name));

        if self.add_toolbar_action {
            if let Some(ref icon) = self.icon {
                action = action.with_tool_bar_data(ToolBarData::new(icon));
            }
        }

        if supports_key_bindings {
            if let Some(ref kb) = self.default_key_binding {
                action = action.with_key_binding(kb.clone());
            }
        }

        action
    }

    // -- Instance key --

    /// The instance key for layout persistence.
    pub fn instance_key(&self) -> (super::component::ComponentProvider, String) {
        (self.provider_type, self.name.clone())
    }

    // -- Font management (Port of Ghidra's ComponentProvider.adjustFontSize) --

    /// Adjust the font size for this provider's registered font.
    ///
    /// Port of Ghidra's `ComponentProvider.adjustFontSize(boolean)`.
    /// Returns the new font size, or `None` if no font is registered.
    pub fn adjust_font_size(&self, current_size: f32, bigger: bool) -> Option<f32> {
        if self.registered_font_id.is_none() {
            return None;
        }
        let new_size = if bigger {
            current_size + 1.0
        } else {
            (current_size - 1.0).max(3.0)
        };
        Some(new_size)
    }

    /// Whether this provider has a registered adjustable font.
    pub fn has_registered_font(&self) -> bool {
        self.registered_font_id.is_some()
    }

    // -- Show provider action with frustration detection --

    /// Create the "show provider" action with frustration detection support.
    ///
    /// Port of Ghidra's `ComponentProvider.ShowProviderAction` inner class.
    /// The action toggles visibility on click, and when the user is rapidly
    /// clicking (frustrated), it emphasizes the window instead.
    pub fn create_show_provider_action_with_frustration(&self) -> (DockingAction, ShowProviderActionState) {
        let supports_key_bindings = !self.is_transient;
        let key_binding_type = if supports_key_bindings {
            KeyBindingType::Shared
        } else {
            KeyBindingType::Unsupported
        };

        let mut action = DockingAction::with_key_binding_type(
            &self.name,
            &self.owner,
            format!("Display {}", self.name),
            key_binding_type,
        )
        .with_description(format!("Display {}", self.name));

        if self.add_toolbar_action {
            if let Some(ref icon) = self.icon {
                action = action.with_tool_bar_data(ToolBarData::new(icon));
            }
        }

        if supports_key_bindings {
            if let Some(ref kb) = self.default_key_binding {
                action = action.with_key_binding(kb.clone());
            }
        }

        let state = ShowProviderActionState::new();
        (action, state)
    }
}

// ---------------------------------------------------------------------------
// ShowProviderActionState — frustration tracking for show provider actions
// ---------------------------------------------------------------------------

/// State for tracking user frustration (rapid clicking) on a show-provider action.
///
/// Port of Ghidra's `ComponentProvider.ShowProviderAction` click tracking.
/// When the user rapidly clicks the same show-provider action, the provider
/// should be emphasized (animated) rather than toggled.
#[derive(Debug)]
pub struct ShowProviderActionState {
    /// Recent click timestamps (in milliseconds since epoch).
    click_times: Mutex<Vec<i64>>,
    /// Time window in milliseconds for tracking rapid clicks.
    time_window: i64,
    /// Click threshold to consider the user "frustrated".
    frustration_threshold: usize,
}

impl ShowProviderActionState {
    /// Create a new state with default settings.
    pub fn new() -> Self {
        Self {
            click_times: Mutex::new(Vec::new()),
            time_window: 2000,
            frustration_threshold: 2,
        }
    }

    /// Record a click at the given timestamp (milliseconds).
    ///
    /// Returns `true` if the user is considered frustrated (rapid clicking).
    pub fn record_click(&self, now_ms: i64) -> bool {
        let mut times = self.click_times.lock().unwrap();
        times.push(now_ms);
        let cutoff = now_ms - self.time_window;
        times.retain(|&t| t > cutoff);
        times.len() > self.frustration_threshold
    }

    /// Whether the user is currently frustrated (without recording a new click).
    pub fn is_frustrated(&self, now_ms: i64) -> bool {
        let times = self.click_times.lock().unwrap();
        let cutoff = now_ms - self.time_window;
        let recent_count = times.iter().filter(|&&t| t > cutoff).count();
        recent_count > self.frustration_threshold
    }

    /// Reset the click history.
    pub fn reset(&self) {
        let mut times = self.click_times.lock().unwrap();
        times.clear();
    }
}

impl Default for ShowProviderActionState {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Provider name/owner change mapping (static registry)
// ---------------------------------------------------------------------------

/// Static registry for provider name/owner changes, used during layout
/// restoration to map old provider names to new ones.
///
/// Port of Ghidra's `ComponentProvider.registerProviderNameOwnerChange`.

fn provider_name_map() -> &'static Mutex<HashMap<String, (String, String)>> {
    static MAP: OnceLock<Mutex<HashMap<String, (String, String)>>> = OnceLock::new();
    MAP.get_or_init(|| Mutex::new(HashMap::new()))
}

fn make_key(old_owner: &str, old_name: &str) -> String {
    format!("owner={}name={}", old_owner, old_name)
}

/// Register a name and/or owner change for a provider.  This allows old
/// saved layouts to correctly restore provider windows after a rename.
///
/// Port of Ghidra's `ComponentProvider.registerProviderNameOwnerChange`.
pub fn register_provider_name_owner_change(
    old_name: &str,
    old_owner: &str,
    new_name: &str,
    new_owner: &str,
) {
    let key = make_key(old_owner, old_name);
    let mut map = provider_name_map().lock().unwrap();
    map.insert(key, (new_name.to_owned(), new_owner.to_owned()));
}

/// Get the mapped owner for a given old owner/name pair.
///
/// Port of Ghidra's `ComponentProvider.getMappedOwner`.
pub fn get_mapped_owner(old_owner: &str, old_name: &str) -> Option<String> {
    let key = make_key(old_owner, old_name);
    let map = provider_name_map().lock().unwrap();
    map.get(&key).map(|(_, owner)| owner.clone())
}

/// Get the mapped name for a given old owner/name pair.
///
/// Port of Ghidra's `ComponentProvider.getMappedName`.
pub fn get_mapped_name(old_owner: &str, old_name: &str) -> Option<String> {
    let key = make_key(old_owner, old_name);
    let map = provider_name_map().lock().unwrap();
    map.get(&key).map(|(name, _)| name.clone())
}

/// The trait that every dockable component provider implements.
///
/// This mirrors Ghidra's `ComponentProvider` abstract class.  A provider
/// is responsible for:
/// - Supplying the component's title and icon.
/// - Reporting its preferred docking position and size.
/// - Contributing actions to the tool's action system.
/// - Receiving focus and context change notifications.
/// - Painting its UI (delegated to the egui layer in this Rust port).
pub trait ComponentProvider: fmt::Debug + Send + Sync {
    /// The programmatic name of the component provider.
    fn name(&self) -> &str;

    /// The window title displayed in the title bar / tab.
    fn window_title(&self) -> &str;

    /// Optional sub-title (e.g. the program name for a listing view).
    fn sub_title(&self) -> &str {
        ""
    }

    /// The full window title including sub-title.
    fn full_title(&self) -> String {
        let base = self.window_title().to_owned();
        let sub = self.sub_title();
        if sub.is_empty() {
            base
        } else {
            format!("{} - {}", base, sub)
        }
    }

    /// Icon identifier (resource name or path).
    fn icon(&self) -> Option<&str> {
        None
    }

    /// The preferred default docking position.
    fn default_position(&self) -> WindowPosition {
        WindowPosition::Center
    }

    /// The preferred default size (width, height).
    fn default_size(&self) -> (f32, f32) {
        (400.0, 300.0)
    }

    /// The tool name this provider belongs to (e.g. "CodeBrowser").
    fn tool_name(&self) -> &str {
        ""
    }

    /// An optional owner (e.g. the plugin that created this provider).
    fn owner(&self) -> &str {
        ""
    }

    /// The menu group used when this provider's items appear in the
    /// Window menu.
    fn window_menu_group(&self) -> &str {
        "Views"
    }

    /// Priority for the Window menu ordering (lower = earlier).
    fn window_menu_priority(&self) -> u32 {
        100
    }

    /// Whether the provider is currently visible.
    fn is_visible(&self) -> bool;

    /// Show the provider.
    fn show(&mut self);

    /// Hide the provider.
    fn hide(&mut self);

    /// Set visibility (convenience: show or hide).
    fn set_visible(&mut self, visible: bool) {
        if visible {
            self.show();
        } else {
            self.hide();
        }
    }

    /// Toggle visibility.
    fn toggle(&mut self) {
        if self.is_visible() {
            self.hide();
        } else {
            self.show();
        }
    }

    /// Actions contributed by this provider to the tool.
    fn actions(&self) -> Vec<DockingAction> {
        Vec::new()
    }

    /// Add a local action to this provider.
    ///
    /// Port of Ghidra's `ComponentProvider.addLocalAction`.
    fn add_local_action(&mut self, _action: DockingAction) {}

    /// Remove a local action from this provider.
    ///
    /// Port of Ghidra's `ComponentProvider.removeLocalAction`.
    fn remove_local_action(&mut self, _action_name: &str) {}

    /// Remove all local actions from this provider.
    ///
    /// Port of Ghidra's `ComponentProvider.removeAllLocalActions`.
    fn remove_all_local_actions(&mut self) {}

    /// Called when this provider gains focus.
    fn focus_gained(&self) {}

    /// Called when this provider loses focus.
    fn focus_lost(&self) {}

    /// Called when this provider becomes the active component.
    ///
    /// Port of Ghidra's `ComponentProvider.componentActivated`.
    fn component_activated(&self) {}

    /// Called when this provider is no longer the active component.
    ///
    /// Port of Ghidra's `ComponentProvider.componentDeactivated`.
    fn component_deactivated(&self) {}

    /// Called when the provider's component is being shown.
    ///
    /// Port of Ghidra's `ComponentProvider.componentShown`.
    fn component_shown(&self) {}

    /// Called when the provider's component is being hidden.
    ///
    /// Port of Ghidra's `ComponentProvider.componentHidden`.
    fn component_hidden(&self) {}

    /// Called when the action context changes.
    fn context_changed(&self, _context: &DockingActionContext) {}

    /// Whether this provider is a transient (temporary) provider.
    ///
    /// Transient providers are removed from the tool when closed,
    /// rather than merely hidden.
    ///
    /// Port of Ghidra's `ComponentProvider.isTransient`.
    fn is_transient(&self) -> bool {
        false
    }

    /// Whether this provider supports temporary (transient) windows.
    fn supports_temporary_window(&self) -> bool {
        true
    }

    /// Whether this provider handles its own focus management.
    fn manages_own_focus(&self) -> bool {
        false
    }

    /// Whether this provider has a custom context menu.
    fn has_context_menu(&self) -> bool {
        false
    }

    /// Get the action context for this provider.
    ///
    /// Port of Ghidra's `ComponentProvider.getActionContext(MouseEvent)`.
    /// Returns `None` when there is no context available.
    fn get_action_context(&self) -> Option<DockingActionContext> {
        None
    }

    /// The context class name this provider supports.
    ///
    /// Port of Ghidra's `ComponentProvider.getContextType()`.
    fn context_type(&self) -> Option<&str> {
        None
    }

    /// Whether this provider should be shown by default in new tools.
    fn is_default_provider(&self) -> bool {
        false
    }

    /// The window group this provider belongs to.
    ///
    /// Providers in the same group are stacked together when first shown.
    /// The default group is `"Default"`.
    ///
    /// Port of Ghidra's `ComponentProvider.getWindowGroup`.
    fn window_group(&self) -> &str {
        "Default"
    }

    /// The sub-menu group for the Window menu.
    ///
    /// If non-null, the provider's "Show" action appears in a sub-menu
    /// of the Window menu named by this value.
    ///
    /// Port of Ghidra's `ComponentProvider.getWindowSubMenuName`.
    fn window_sub_menu_name(&self) -> Option<&str> {
        None
    }

    /// Help location identifier for the help system.
    fn help_location(&self) -> Option<&str> {
        None
    }

    /// Whether this provider can be closed by the user.
    fn closeable(&self) -> bool {
        true
    }

    /// Whether this provider's window can be used as a parent for
    /// system dialogs.
    ///
    /// Port of Ghidra's `ComponentProvider.canBeParent`.
    fn can_be_parent(&self) -> bool {
        true
    }

    /// Whether this provider is a snapshot of a primary provider.
    ///
    /// Port of Ghidra's `ComponentProvider.isSnapshot`.
    fn is_snapshot(&self) -> bool {
        false
    }

    /// The tab text shown when stacked with other providers.
    ///
    /// Defaults to `window_title()` if not overridden.
    fn tab_text(&self) -> &str {
        self.window_title()
    }

    /// Clean up resources when the provider is disposed.
    fn dispose(&self) {}

    /// A unique instance key (used for layout persistence).
    fn instance_key(&self) -> (super::component::ComponentProvider, String);

    /// The component provider enum value for this provider.
    fn provider_type(&self) -> super::component::ComponentProvider;

    // -- Tool integration --

    /// Whether this provider is currently in (registered with) a tool.
    ///
    /// Port of Ghidra's `ComponentProvider.isInTool()`.
    fn is_in_tool(&self) -> bool {
        false
    }

    /// Add this provider to the tool.
    ///
    /// Port of Ghidra's `ComponentProvider.addToTool()`.
    fn add_to_tool(&mut self) {}

    /// Remove this provider from the tool.
    ///
    /// Port of Ghidra's `ComponentProvider.removeFromTool()`.
    fn remove_from_tool(&mut self) {}

    /// Close this component.
    ///
    /// Port of Ghidra's `ComponentProvider.closeComponent()`.  Transient
    /// providers are removed from the tool; non-transient providers are
    /// merely hidden.
    fn close_component(&mut self) {
        if self.is_transient() {
            self.remove_from_tool();
        } else {
            self.set_visible(false);
        }
    }

    /// Notify the tool that this provider's own context has changed (no args).
    ///
    /// Port of Ghidra's `ComponentProvider.contextChanged()`.
    fn notify_context_changed(&self) {}

    // -- Title management --

    /// Set the window title.
    ///
    /// Port of Ghidra's `ComponentProvider.setTitle(String)`.
    fn set_window_title(&mut self, _title: &str) {}

    /// Set the sub-title.
    ///
    /// Port of Ghidra's `ComponentProvider.setSubTitle(String)`.
    fn set_sub_title(&mut self, _sub_title: &str) {}

    /// Set the tab text.
    ///
    /// Port of Ghidra's `ComponentProvider.setTabText(String)`.
    fn set_tab_text(&mut self, _tab_text: &str) {}

    // -- Transient / toolbar --

    /// Mark this provider as transient.
    ///
    /// Port of Ghidra's `ComponentProvider.setTransient()`.
    fn set_transient(&mut self) {}

    /// Signal that this provider's show action should appear in the toolbar.
    ///
    /// Port of Ghidra's `ComponentProvider.addToToolbar()`.
    fn add_to_toolbar(&mut self) {}

    // -- Position --

    /// The intra-group position (how this provider is placed relative to
    /// other members of the same window group).
    ///
    /// Port of Ghidra's `ComponentProvider.getIntraGroupPosition()`.
    fn intra_group_position(&self) -> WindowPosition {
        WindowPosition::Center
    }

    /// Set the intra-group position.
    fn set_intra_group_position(&mut self, _position: WindowPosition) {}

    /// Set the window group.
    ///
    /// Port of Ghidra's `ComponentProvider.setWindowGroup(String)`.
    fn set_window_group(&mut self, _group: &str) {}

    /// Set the window menu group.
    ///
    /// Port of Ghidra's `ComponentProvider.setWindowMenuGroup(String)`.
    fn set_window_menu_group(&mut self, _group: &str) {}

    // -- Focus --

    /// Whether this provider is the currently focused provider.
    ///
    /// Port of Ghidra's `ComponentProvider.isFocusedProvider()`.
    fn is_focused_provider(&self) -> bool {
        false
    }

    /// Request focus for this provider.
    ///
    /// Port of Ghidra's `ComponentProvider.requestFocus()`.
    fn request_focus(&self) {}

    /// Whether the provider is currently showing (visible and displayable).
    ///
    /// Port of Ghidra's `ComponentProvider.isShowing()`.
    fn is_showing(&self) -> bool {
        self.is_visible()
    }

    /// Whether this provider is the active provider.
    ///
    /// Port of Ghidra's `ComponentProvider.isActive()`.
    fn is_active(&self) -> bool {
        false
    }

    /// Notify the provider that its component has been made displayable.
    ///
    /// Port of Ghidra's `ComponentProvider.componentMadeDisplayable()`.
    fn component_made_displayable(&self) {}

    // -- Font management --

    /// Get the registered font ID for this provider.
    ///
    /// Port of Ghidra's `ComponentProvider.registerAdjustableFontId`.
    fn registered_font_id(&self) -> Option<&str> {
        None
    }

    /// Register a font ID for automatic font size adjustments.
    ///
    /// Port of Ghidra's `ComponentProvider.registerAdjustableFontId`.
    fn register_adjustable_font_id(&mut self, _font_id: &str) {}

    /// Adjust the font size for this provider.
    ///
    /// Port of Ghidra's `ComponentProvider.adjustFontSize(boolean)`.
    /// Returns the new font size if a font is registered, `None` otherwise.
    fn adjust_font_size(&self, current_size: f32, bigger: bool) -> Option<f32> {
        if self.registered_font_id().is_none() {
            return None;
        }
        let new_size = if bigger {
            current_size + 1.0
        } else {
            (current_size - 1.0).max(3.0)
        };
        Some(new_size)
    }

    /// Whether this provider has a registered adjustable font.
    fn has_registered_font(&self) -> bool {
        self.registered_font_id().is_some()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::component::{ComponentProvider as ProviderType, SimpleComponent};

    // Test that SimpleComponent (from component.rs) doesn't conflict
    // with the new trait name.  The trait is in this module; the enum
    // is in component.rs.

    #[test]
    fn test_component_provider_trait_object() {
        // SimpleComponent implements DockingComponent and ComponentProviderInfo
        // but not the new ComponentProvider trait.  We test that the trait
        // compiles and can be used as a trait object.
        let _: Option<Box<dyn ComponentProvider>> = None;
    }

    #[test]
    fn test_full_title() {
        // Verify the default full_title logic.
        // We can't easily construct a concrete impl here without a
        // struct, so test the logic via a mock.
        #[derive(Debug)]
        struct MockProvider {
            title: String,
            sub: String,
        }
        impl ComponentProvider for MockProvider {
            fn name(&self) -> &str { "mock" }
            fn window_title(&self) -> &str { &self.title }
            fn sub_title(&self) -> &str { &self.sub }
            fn is_visible(&self) -> bool { true }
            fn show(&mut self) {}
            fn hide(&mut self) {}
            fn instance_key(&self) -> (ProviderType, String) {
                (ProviderType::Console, "mock".to_owned())
            }
            fn provider_type(&self) -> ProviderType { ProviderType::Console }
        }

        let p = MockProvider { title: "Console".into(), sub: "".into() };
        assert_eq!(p.full_title(), "Console");

        let p = MockProvider { title: "Console".into(), sub: "test.exe".into() };
        assert_eq!(p.full_title(), "Console - test.exe");
    }

    #[test]
    fn test_provider_trait_defaults() {
        #[derive(Debug)]
        struct MockProvider;
        impl ComponentProvider for MockProvider {
            fn name(&self) -> &str { "mock" }
            fn window_title(&self) -> &str { "Mock" }
            fn is_visible(&self) -> bool { false }
            fn show(&mut self) {}
            fn hide(&mut self) {}
            fn instance_key(&self) -> (ProviderType, String) {
                (ProviderType::Console, "mock".to_owned())
            }
            fn provider_type(&self) -> ProviderType { ProviderType::Console }
        }

        let p = MockProvider;
        assert_eq!(p.default_position(), WindowPosition::Center);
        assert_eq!(p.default_size(), (400.0, 300.0));
        assert_eq!(p.window_menu_group(), "Views");
        assert_eq!(p.window_menu_priority(), 100);
        assert!(p.supports_temporary_window());
        assert!(!p.manages_own_focus());
        assert!(!p.has_context_menu());
        assert!(!p.is_default_provider());
        assert!(p.help_location().is_none());
        assert!(p.closeable());
    }

    #[test]
    fn test_provider_toggle() {
        #[derive(Debug)]
        struct MockProvider { visible: bool }
        impl ComponentProvider for MockProvider {
            fn name(&self) -> &str { "mock" }
            fn window_title(&self) -> &str { "Mock" }
            fn is_visible(&self) -> bool { self.visible }
            fn show(&mut self) { self.visible = true; }
            fn hide(&mut self) { self.visible = false; }
            fn instance_key(&self) -> (ProviderType, String) {
                (ProviderType::Console, "mock".to_owned())
            }
            fn provider_type(&self) -> ProviderType { ProviderType::Console }
        }

        let mut p = MockProvider { visible: false };
        assert!(!p.is_visible());
        p.toggle();
        assert!(p.is_visible());
        p.toggle();
        assert!(!p.is_visible());
    }

    #[test]
    fn test_provider_new_defaults() {
        #[derive(Debug)]
        struct MockProvider;
        impl ComponentProvider for MockProvider {
            fn name(&self) -> &str { "mock" }
            fn window_title(&self) -> &str { "Mock" }
            fn is_visible(&self) -> bool { false }
            fn show(&mut self) {}
            fn hide(&mut self) {}
            fn instance_key(&self) -> (ProviderType, String) {
                (ProviderType::Console, "mock".to_owned())
            }
            fn provider_type(&self) -> ProviderType { ProviderType::Console }
        }

        let p = MockProvider;
        // New defaults for the Java-migrated methods.
        assert!(!p.is_transient());
        assert_eq!(p.window_group(), "Default");
        assert!(p.window_sub_menu_name().is_none());
        assert!(p.can_be_parent());
        assert!(!p.is_snapshot());
        assert!(p.sub_title().is_empty());
        assert_eq!(p.tab_text(), "Mock");
    }

    #[test]
    fn test_provider_set_visible() {
        #[derive(Debug)]
        struct MockProvider { visible: bool }
        impl ComponentProvider for MockProvider {
            fn name(&self) -> &str { "mock" }
            fn window_title(&self) -> &str { "Mock" }
            fn is_visible(&self) -> bool { self.visible }
            fn show(&mut self) { self.visible = true; }
            fn hide(&mut self) { self.visible = false; }
            fn instance_key(&self) -> (ProviderType, String) {
                (ProviderType::Console, "mock".to_owned())
            }
            fn provider_type(&self) -> ProviderType { ProviderType::Console }
        }

        let mut p = MockProvider { visible: false };
        p.set_visible(true);
        assert!(p.is_visible());
        p.set_visible(false);
        assert!(!p.is_visible());
    }

    // -- ComponentProviderState tests --

    #[test]
    fn test_provider_state_new() {
        let state = ComponentProviderState::new("MyView", "MyPlugin", ProviderType::Console);
        assert_eq!(state.name(), "MyView");
        assert_eq!(state.owner(), "MyPlugin");
        assert_eq!(state.provider_type(), ProviderType::Console);
        assert_eq!(state.title(), "MyView");
        assert!(state.sub_title().is_empty());
        assert_eq!(state.window_group(), "Default");
        assert!(!state.is_transient());
        assert!(!state.is_in_tool());
        assert!(!state.is_visible());
    }

    #[test]
    fn test_provider_state_title_management() {
        let mut state = ComponentProviderState::new("view", "plugin", ProviderType::Console);

        // Normal title change.
        state.set_title("New Title");
        assert_eq!(state.title(), "New Title");

        // Custom title overrides set_title.
        state.set_custom_title("Custom");
        assert_eq!(state.title(), "Custom");

        // set_title is ignored after custom title.
        state.set_title("Ignored");
        assert_eq!(state.title(), "Custom");
    }

    #[test]
    fn test_provider_state_sub_title_management() {
        let mut state = ComponentProviderState::new("view", "plugin", ProviderType::Console);

        state.set_sub_title("test.exe");
        assert_eq!(state.sub_title(), "test.exe");

        state.set_custom_sub_title("Custom Sub");
        assert_eq!(state.sub_title(), "Custom Sub");

        // set_sub_title is ignored after custom sub-title.
        state.set_sub_title("Ignored");
        assert_eq!(state.sub_title(), "Custom Sub");
    }

    #[test]
    fn test_provider_state_tab_text_management() {
        let mut state = ComponentProviderState::new("view", "plugin", ProviderType::Console);

        // Default tab text is the title.
        assert_eq!(state.tab_text(), "view");

        state.set_tab_text("Custom Tab");
        assert_eq!(state.tab_text(), "Custom Tab");

        state.set_custom_tab_text("Locked Tab");
        assert_eq!(state.tab_text(), "Locked Tab");

        // set_tab_text is ignored after custom tab text.
        state.set_tab_text("Ignored");
        assert_eq!(state.tab_text(), "Locked Tab");
    }

    #[test]
    fn test_provider_state_full_title() {
        let mut state = ComponentProviderState::new("Console", "plugin", ProviderType::Console);
        assert_eq!(state.full_title(), "Console");

        state.set_sub_title("test.exe");
        assert_eq!(state.full_title(), "Console - test.exe");
    }

    #[test]
    fn test_provider_state_transient() {
        let mut state = ComponentProviderState::new("view", "plugin", ProviderType::Console);
        assert!(!state.is_transient());

        state.set_add_toolbar_action(true);
        assert!(state.add_toolbar_action());

        state.set_transient();
        assert!(state.is_transient());
        // Transient clears toolbar and key binding.
        assert!(!state.add_toolbar_action());
    }

    #[test]
    fn test_provider_state_key_binding() {
        let mut state = ComponentProviderState::new("view", "plugin", ProviderType::Console);

        assert!(state.default_key_binding().is_none());

        let kb = KeyBinding::ctrl(super::super::action::Key::G);
        state.set_default_key_binding(Some(kb.clone()));
        assert!(state.default_key_binding().is_some());

        // Transient providers cannot have key bindings.
        state.set_transient();
        // The existing binding stays (set_transient already cleared it).
        assert!(state.default_key_binding().is_none());
    }

    #[test]
    fn test_provider_state_local_actions() {
        let mut state = ComponentProviderState::new("view", "plugin", ProviderType::Console);
        assert!(state.local_actions().is_empty());

        let action = DockingAction::new("action1", "Action 1");
        state.add_local_action(action);
        assert_eq!(state.local_actions().len(), 1);

        // Duplicate name is ignored.
        state.add_local_action(DockingAction::new("action1", "Duplicate"));
        assert_eq!(state.local_actions().len(), 1);

        let removed = state.remove_local_action("action1");
        assert!(removed.is_some());
        assert!(state.local_actions().is_empty());
    }

    #[test]
    fn test_provider_state_remove_all_local_actions() {
        let mut state = ComponentProviderState::new("view", "plugin", ProviderType::Console);
        state.add_local_action(DockingAction::new("a", "A"));
        state.add_local_action(DockingAction::new("b", "B"));

        let removed = state.remove_all_local_actions();
        assert_eq!(removed.len(), 2);
        assert!(state.local_actions().is_empty());
    }

    #[test]
    fn test_provider_state_show_action() {
        let mut state = ComponentProviderState::new("MyView", "MyPlugin", ProviderType::Console);
        state.set_icon("icon/myview.png");
        state.set_add_toolbar_action(true);

        let action = state.create_show_provider_action();
        assert_eq!(action.name, "MyView");
        assert_eq!(action.owner, "MyPlugin");
        assert_eq!(action.display_name, "Display MyView");
        assert!(action.tool_bar_data.is_some());
        assert_eq!(action.tool_bar_data.unwrap().icon, "icon/myview.png");
    }

    #[test]
    fn test_provider_state_show_action_transient_no_toolbar() {
        let mut state = ComponentProviderState::new("temp", "plugin", ProviderType::Console);
        state.set_transient();

        let action = state.create_show_provider_action();
        assert!(action.tool_bar_data.is_none());
        assert_eq!(action.key_binding_type, KeyBindingType::Unsupported);
    }

    #[test]
    fn test_provider_state_instance_id() {
        let mut state1 = ComponentProviderState::new("a", "p", ProviderType::Console);
        let mut state2 = ComponentProviderState::new("b", "p", ProviderType::Console);

        // Each state gets a unique instance ID.
        assert_ne!(state1.instance_id(), state2.instance_id());

        // Can initialize once.
        assert!(state1.initialize_instance_id(42));
        assert_eq!(state1.instance_id(), 42);

        // Cannot change to a different value.
        assert!(!state1.initialize_instance_id(99));
        assert_eq!(state1.instance_id(), 42);

        // Same value is fine.
        assert!(state1.initialize_instance_id(42));
    }

    #[test]
    fn test_provider_state_instance_key() {
        let state = ComponentProviderState::new("MyView", "plugin", ProviderType::DecompilerView);
        let (ptype, name) = state.instance_key();
        assert_eq!(ptype, ProviderType::DecompilerView);
        assert_eq!(name, "MyView");
    }

    #[test]
    fn test_provider_state_font_id() {
        let mut state = ComponentProviderState::new("view", "plugin", ProviderType::Console);
        assert!(state.registered_font_id().is_none());

        state.register_adjustable_font_id("font.listing");
        assert_eq!(state.registered_font_id(), Some("font.listing"));
    }

    #[test]
    fn test_provider_state_window_group_position() {
        let mut state = ComponentProviderState::new("view", "plugin", ProviderType::Console);

        state.set_window_group("Analysis");
        assert_eq!(state.window_group(), "Analysis");

        state.set_window_sub_menu_name(Some("Advanced".to_owned()));
        assert_eq!(state.window_sub_menu_name(), Some("Advanced"));

        state.set_window_menu_group("Tools");
        assert_eq!(state.window_menu_group(), "Tools");

        state.set_default_position(WindowPosition::Right);
        assert_eq!(state.default_position(), &WindowPosition::Right);

        state.set_intra_group_position(WindowPosition::Bottom);
        assert_eq!(state.intra_group_position(), &WindowPosition::Bottom);
    }

    // -- Provider name/owner mapping tests --

    #[test]
    fn test_provider_name_owner_change_mapping() {
        // Clean up any prior registrations for this key.
        let key_old = "OldOwner";
        let key_old_name = "OldName";

        register_provider_name_owner_change(
            key_old_name,
            key_old,
            "NewName",
            "NewOwner",
        );

        assert_eq!(
            get_mapped_owner(key_old, key_old_name),
            Some("NewOwner".to_owned())
        );
        assert_eq!(
            get_mapped_name(key_old, key_old_name),
            Some("NewName".to_owned())
        );

        // Non-existent key returns None.
        assert!(get_mapped_owner("nope", "nope").is_none());
        assert!(get_mapped_name("nope", "nope").is_none());
    }

    // -- ShowProviderActionState tests --

    #[test]
    fn test_show_provider_action_state() {
        let state = ShowProviderActionState::new();
        assert!(!state.is_frustrated(0));

        // First click - not frustrated (1 click).
        assert!(!state.record_click(1000));
        // Second click - not frustrated (2 clicks).
        assert!(!state.record_click(1100));
        // Third click - now frustrated (3 clicks > threshold of 2).
        assert!(state.record_click(1200));
    }

    #[test]
    fn test_show_provider_action_state_reset() {
        let state = ShowProviderActionState::new();
        state.record_click(1000);
        state.record_click(1100);
        state.reset();
        assert!(!state.is_frustrated(1200));
    }

    #[test]
    fn test_show_provider_action_state_time_window() {
        let state = ShowProviderActionState::new();
        // Clicks outside the time window should not count.
        assert!(!state.record_click(1000));
        assert!(!state.record_click(1100));
        // Old clicks should expire.
        assert!(!state.is_frustrated(5000));
    }

    // -- Font management on ComponentProviderState tests --

    #[test]
    fn test_provider_state_adjust_font_size() {
        let state = ComponentProviderState::new("view", "plugin", ProviderType::Console);
        // No registered font -> returns None.
        assert!(state.adjust_font_size(12.0, true).is_none());
    }

    #[test]
    fn test_provider_state_adjust_font_size_registered() {
        let mut state = ComponentProviderState::new("view", "plugin", ProviderType::Console);
        state.register_adjustable_font_id("font.listing");
        assert!(state.has_registered_font());

        let new_size = state.adjust_font_size(12.0, true);
        assert_eq!(new_size, Some(13.0));

        let new_size = state.adjust_font_size(12.0, false);
        assert_eq!(new_size, Some(11.0));

        // Minimum font size is 3.
        let new_size = state.adjust_font_size(3.0, false);
        assert_eq!(new_size, Some(3.0));
    }

    // -- Show provider action with frustration tests --

    #[test]
    fn test_provider_state_show_action_with_frustration() {
        let mut state = ComponentProviderState::new("MyView", "MyPlugin", ProviderType::Console);
        state.set_icon("icon/myview.png");
        state.set_add_toolbar_action(true);

        let (action, frustration_state) = state.create_show_provider_action_with_frustration();
        assert_eq!(action.name, "MyView");
        assert!(action.tool_bar_data.is_some());
        assert!(!frustration_state.is_frustrated(0));
    }

    // -- ComponentProvider trait new method tests --

    #[test]
    fn test_provider_trait_font_methods() {
        #[derive(Debug)]
        struct MockProvider;
        impl ComponentProvider for MockProvider {
            fn name(&self) -> &str { "mock" }
            fn window_title(&self) -> &str { "Mock" }
            fn is_visible(&self) -> bool { false }
            fn show(&mut self) {}
            fn hide(&mut self) {}
            fn instance_key(&self) -> (ProviderType, String) {
                (ProviderType::Console, "mock".to_owned())
            }
            fn provider_type(&self) -> ProviderType { ProviderType::Console }
        }

        let p = MockProvider;
        assert!(!p.has_registered_font());
        assert!(p.adjust_font_size(12.0, true).is_none());
        assert!(p.registered_font_id().is_none());
        assert!(p.get_action_context().is_none());
    }
}
