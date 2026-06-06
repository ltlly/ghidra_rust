//! Integration tests for the GUI theme and options framework.
//!
//! Covers: theme values, theme value map, options types, preference state,
//! and resource management.

use ghidra_gui::theme::*;
use ghidra_gui::options::*;
use ghidra_gui::resources::*;
use ghidra_gui::resources::multi_icon::{BuiltinIcon, IconId, IconOverlay, Quadrant};
use ghidra_gui::gui_util::web_colors::RgbaColor;
use ghidra_gui::gui_util::HelpLocation;
use ghidra_gui::util::image::{ImageBuffer, RgbaPixel};

// ============================================================================
// Theme value types
// ============================================================================

#[test]
fn test_color_value_new() {
    let cv = ColorValue::new("my.color", RgbaColor::new(255, 0, 0));
    assert_eq!(cv.id(), "my.color");
    assert_eq!(cv.raw_value(), Some(RgbaColor::new(255, 0, 0)));
    assert!(!cv.is_indirect());
}

#[test]
fn test_color_value_indirect() {
    let cv = ColorValue::with_ref("my.color", "base.color");
    assert_eq!(cv.id(), "my.color");
    assert!(cv.is_indirect());
    assert_eq!(cv.reference_id(), Some("base.color"));
    assert!(cv.raw_value().is_none());
}

#[test]
fn test_font_value_new() {
    let fd = ghidra_gui::options::option_value::FontDescriptor::plain("Monospaced", 12.0);
    let fv = FontValue::new("my.font", fd);
    assert_eq!(fv.id(), "my.font");
    assert!(!fv.is_indirect());
    let raw = fv.raw_value().unwrap();
    assert_eq!(raw.family, "Monospaced");
    assert_eq!(raw.size, 12.0);
}

#[test]
fn test_font_value_indirect() {
    let fv = FontValue::with_ref("my.font", "base.font");
    assert_eq!(fv.id(), "my.font");
    assert!(fv.is_indirect());
}

#[test]
fn test_icon_value_new() {
    let icon = ghidra_gui::theme::icon_value::IconPath::new("/path/to/icon.png");
    let iv = IconValue::new("my.icon", icon);
    assert_eq!(iv.id(), "my.icon");
    assert!(!iv.is_indirect());
}

#[test]
fn test_icon_value_indirect() {
    let iv = IconValue::with_ref("my.icon", "base.icon");
    assert!(iv.is_indirect());
    assert_eq!(iv.reference_id(), Some("base.icon"));
}

// ============================================================================
// ThemeValue generic base
// ============================================================================

#[test]
fn test_theme_value_with_value() {
    let tv = ThemeValue::with_value("color.bg", RgbaColor::new(0, 0, 0));
    assert_eq!(tv.id(), "color.bg");
    assert!(tv.has_direct_value());
    assert!(!tv.is_indirect());
    assert_eq!(*tv.raw_value().unwrap(), RgbaColor::new(0, 0, 0));
}

#[test]
fn test_theme_value_with_reference() {
    let tv = ThemeValue::<RgbaColor>::with_reference("color.bg", "color.base");
    assert_eq!(tv.id(), "color.bg");
    assert!(!tv.has_direct_value());
    assert!(tv.is_indirect());
    assert_eq!(tv.reference_id(), Some("color.base"));
}

#[test]
fn test_theme_value_resolve_direct() {
    let tv = ThemeValue::with_value("c", 42i32);
    let resolved = tv.resolve(&|_| None);
    assert_eq!(resolved, Some(42));
}

#[test]
fn test_theme_value_resolve_indirect() {
    let base = ThemeValue::with_value("base", 100i32);
    let ref_tv = ThemeValue::<i32>::with_reference("ref", "base");
    let resolved = ref_tv.resolve(&|id| {
        if id == "base" { Some(base.clone()) } else { None }
    });
    assert_eq!(resolved, Some(100));
}

#[test]
fn test_theme_value_resolve_circular() {
    let tv = ThemeValue::<i32>::with_reference("a", "b");
    let resolved = tv.resolve(&|id| {
        if id == "b" { Some(ThemeValue::<i32>::with_reference("b", "a")) } else { None }
    });
    assert_eq!(resolved, None);
}

#[test]
fn test_theme_value_resolve_missing() {
    let tv = ThemeValue::<i32>::with_reference("a", "nonexistent");
    let resolved = tv.resolve(&|_| None);
    assert_eq!(resolved, None);
}

// ============================================================================
// Theme value map
// ============================================================================

#[test]
fn test_theme_value_map_new() {
    let map = GThemeValueMap::new();
    assert!(map.get_color_ids().is_empty());
    assert!(map.get_font_ids().is_empty());
    assert!(map.get_icon_ids().is_empty());
}

#[test]
fn test_theme_value_map_add_and_get_color() {
    let mut map = GThemeValueMap::new();
    let cv = ColorValue::new("my.color", RgbaColor::new(255, 0, 0));
    map.add_color(cv);
    let got = map.get_color("my.color").unwrap();
    assert_eq!(got.raw_value(), Some(RgbaColor::new(255, 0, 0)));
}

#[test]
fn test_theme_value_map_add_and_get_font() {
    let mut map = GThemeValueMap::new();
    let fd = ghidra_gui::options::option_value::FontDescriptor::plain("Arial", 14.0);
    let fv = FontValue::new("my.font", fd);
    map.add_font(fv);
    let got = map.get_font("my.font").unwrap();
    assert_eq!(got.raw_value().unwrap().family, "Arial");
}

#[test]
fn test_theme_value_map_add_and_get_icon() {
    let mut map = GThemeValueMap::new();
    let icon = ghidra_gui::theme::icon_value::IconPath::new("/path/to/icon.png");
    let iv = IconValue::new("my.icon", icon);
    map.add_icon(iv);
    let got = map.get_icon("my.icon").unwrap();
    assert_eq!(got.raw_value().unwrap().path(), "/path/to/icon.png");
}

#[test]
fn test_theme_value_map_remove_color() {
    let mut map = GThemeValueMap::new();
    map.add_color(ColorValue::new("c", RgbaColor::new(0, 0, 0)));
    let removed = map.remove_color("c");
    assert!(removed.is_some());
    assert!(map.get_color("c").is_none());
}

#[test]
fn test_theme_value_map_override() {
    let mut map = GThemeValueMap::new();
    map.add_color(ColorValue::new("c", RgbaColor::new(255, 0, 0)));
    map.add_color(ColorValue::new("c", RgbaColor::new(0, 255, 0)));
    let got = map.get_color("c").unwrap();
    assert_eq!(got.raw_value(), Some(RgbaColor::new(0, 255, 0)));
}

#[test]
fn test_theme_value_map_load() {
    let mut map1 = GThemeValueMap::new();
    map1.add_color(ColorValue::new("a", RgbaColor::new(255, 0, 0)));
    let mut map2 = GThemeValueMap::new();
    map2.add_color(ColorValue::new("b", RgbaColor::new(0, 255, 0)));
    map2.load(&map1);
    assert!(map2.get_color("a").is_some());
    assert!(map2.get_color("b").is_some());
}

#[test]
fn test_theme_value_map_changed_values() {
    let mut base = GThemeValueMap::new();
    base.add_color(ColorValue::new("c", RgbaColor::new(255, 0, 0)));
    let mut current = GThemeValueMap::new();
    current.add_color(ColorValue::new("c", RgbaColor::new(0, 255, 0)));
    let changed = current.get_changed_values(&base);
    assert!(changed.get_color("c").is_some());
}

#[test]
fn test_theme_value_map_resolve_color() {
    let mut map = GThemeValueMap::new();
    map.add_color(ColorValue::new("base", RgbaColor::new(100, 100, 100)));
    map.add_color(ColorValue::with_ref("ref", "base"));
    let resolved = map.get_resolved_color("ref");
    assert_eq!(resolved, Some(RgbaColor::new(100, 100, 100)));
}

// ============================================================================
// Options types
// ============================================================================

#[test]
fn test_option_type_properties() {
    assert!(OptionType::BooleanType.is_primitive());
    assert!(OptionType::IntType.is_primitive());
    assert!(OptionType::LongType.is_primitive());
}

#[test]
fn test_tool_options_new() {
    let opts = ToolOptions::new("Analysis");
    assert_eq!(opts.name(), "Analysis");
}

#[test]
fn test_tool_options_put_and_get() {
    let mut opts = ToolOptions::new("Test");
    opts.put_object("debug", OptionValue::Boolean(true), OptionType::BooleanType);
    let entry = opts.get_option("debug");
    assert!(entry.is_some());
}

#[test]
fn test_tool_options_category_help() {
    let mut opts = ToolOptions::new("Test");
    let help = HelpLocation::new("TestHelp", "analysis_options");
    opts.set_category_help_location("Analysis", help);
    let got = opts.get_category_help_location("Analysis");
    assert!(got.is_some());
}

#[test]
fn test_preference_state_new() {
    let state = PreferenceState::new();
    assert!(state.is_empty());
    assert_eq!(state.len(), 0);
}

#[test]
fn test_preference_state_put_and_get() {
    let mut state = PreferenceState::new();
    state.put("width", OptionValue::Int(800));
    state.put("height", OptionValue::Int(600));
    assert_eq!(state.len(), 2);
    assert!(!state.is_empty());
}

#[test]
fn test_preference_state_contains() {
    let mut state = PreferenceState::new();
    assert!(!state.contains("x"));
    state.put("x", OptionValue::Int(1));
    assert!(state.contains("x"));
}

#[test]
fn test_preference_state_remove() {
    let mut state = PreferenceState::new();
    state.put("x", OptionValue::Int(1));
    let removed = state.remove("x");
    assert!(removed.is_some());
    assert!(!state.contains("x"));
}

#[test]
fn test_preference_state_keys() {
    let mut state = PreferenceState::new();
    state.put("a", OptionValue::Int(1));
    state.put("b", OptionValue::Int(2));
    let mut keys: Vec<&str> = state.keys();
    keys.sort();
    assert_eq!(keys, vec!["a", "b"]);
}

#[test]
fn test_preference_state_with_name() {
    let state = PreferenceState::with_name("TestState");
    assert_eq!(state.name(), "TestState");
}

#[test]
fn test_option_value_display() {
    let v = OptionValue::Boolean(true);
    assert_eq!(v.to_display_string(), "true");
    let v = OptionValue::Int(42);
    assert_eq!(v.to_display_string(), "42");
}

#[test]
fn test_option_value_type() {
    assert_eq!(OptionValue::Boolean(true).option_type(), OptionType::BooleanType);
    assert_eq!(OptionValue::Int(0).option_type(), OptionType::IntType);
    assert_eq!(OptionValue::String("".into()).option_type(), OptionType::StringType);
}

#[test]
fn test_key_stroke_new() {
    let ks = ghidra_gui::options::option_value::KeyStroke::new("Ctrl+S");
    let _ = ks;
}

#[test]
fn test_action_trigger_parse() {
    let trigger = ActionTrigger::parse("Ctrl+S");
    assert!(trigger.is_some());
}

#[test]
fn test_font_descriptor_plain() {
    let fd = ghidra_gui::options::option_value::FontDescriptor::plain("Monospaced", 12.0);
    assert_eq!(fd.family, "Monospaced");
    assert_eq!(fd.size, 12.0);
    assert!(!fd.is_bold());
    assert!(!fd.is_italic());
}

#[test]
fn test_font_descriptor_bold() {
    let fd = ghidra_gui::options::option_value::FontDescriptor::bold("Arial", 14.0);
    assert!(fd.is_bold());
    assert!(!fd.is_italic());
}

#[test]
fn test_font_descriptor_derive_size() {
    let fd = ghidra_gui::options::option_value::FontDescriptor::plain("Arial", 12.0);
    let fd2 = fd.derive_size(24.0);
    assert_eq!(fd2.size, 24.0);
    assert_eq!(fd2.family, "Arial");
}

// ============================================================================
// Help location
// ============================================================================

#[test]
fn test_help_location_new() {
    let help = HelpLocation::new("MyPlugin", "topic1");
    let _ = help;
}

// ============================================================================
// Resource types
// ============================================================================

#[test]
fn test_empty_icon() {
    let icon = EmptyIcon::new(32, 32);
    assert_eq!(icon.width, 32);
    assert_eq!(icon.height, 32);
}

#[test]
fn test_color_icon() {
    let icon = ColorIcon::new(RgbaPixel::rgb(255, 0, 0), 16, 16);
    assert_eq!(icon.width, 16);
    assert_eq!(icon.height, 16);
}

#[test]
fn test_color_icon3d() {
    let icon = ColorIcon3D::new(RgbaPixel::rgb(0, 255, 0), 20, 20);
    assert_eq!(icon.width, 20);
    assert_eq!(icon.height, 20);
}

#[test]
fn test_scaled_image_icon() {
    let source = ImageBuffer::transparent(16, 16);
    let icon = ScaledImageIcon::new(source, 32, 32);
    assert_eq!(icon.target_width, 32);
    assert_eq!(icon.target_height, 32);
}

#[test]
fn test_multi_icon() {
    let base = IconId::Name("base_icon".into());
    let icon = MultiIcon::new(base);
    assert_eq!(icon.overlay_count(), 0);
    assert!(!icon.has_overlays());
    assert_eq!(icon.width, 16);
    assert_eq!(icon.height, 16);
}

#[test]
fn test_multi_icon_builder() {
    let base = IconId::Name("base_icon".into());
    let overlay_id = IconId::Builtin(BuiltinIcon::Check);
    let icon = MultiIconBuilder::new(base)
        .overlay(overlay_id, Quadrant::TopLeft)
        .build();
    assert_eq!(icon.overlay_count(), 1);
    assert!(icon.has_overlays());
}

#[test]
fn test_multi_icon_builder_multiple_overlays() {
    let base = IconId::Name("base_icon".into());
    let icon = MultiIconBuilder::new(base)
        .overlay(IconId::Builtin(BuiltinIcon::Check), Quadrant::TopLeft)
        .overlay(IconId::Builtin(BuiltinIcon::Error), Quadrant::BottomRight)
        .build();
    assert_eq!(icon.overlay_count(), 2);
}

#[test]
fn test_multi_icon_add_overlay() {
    let base = IconId::Name("base_icon".into());
    let mut icon = MultiIcon::new(base);
    let overlay = IconOverlay::new(IconId::Builtin(BuiltinIcon::Warning), Quadrant::TopRight);
    icon.add_overlay(overlay);
    assert_eq!(icon.overlay_count(), 1);
}

#[test]
fn test_multi_icon_set_size() {
    let base = IconId::Name("base_icon".into());
    let mut icon = MultiIcon::new(base);
    icon.set_size(32, 32);
    assert_eq!(icon.width, 32);
    assert_eq!(icon.height, 32);
}

#[test]
fn test_quadrant_variants() {
    let q = Quadrant::TopLeft;
    assert_eq!(q as u8, Quadrant::TopLeft as u8);
    let q2 = Quadrant::BottomRight;
    assert_ne!(q as u8, q2 as u8);
}

#[test]
fn test_icon_overlay() {
    let overlay = IconOverlay::new(
        IconId::Builtin(BuiltinIcon::Check),
        Quadrant::TopRight,
    );
    assert_eq!(overlay.position, Quadrant::TopRight);
    assert_eq!(overlay.scale, 0.5);
}

#[test]
fn test_icon_overlay_with_scale() {
    let overlay = IconOverlay::new(
        IconId::Builtin(BuiltinIcon::Check),
        Quadrant::TopRight,
    ).with_scale(0.8);
    assert!((overlay.scale - 0.8).abs() < f32::EPSILON);
}

#[test]
fn test_icon_id_variants() {
    let name = IconId::Name("test".into());
    let path = IconId::Path("/path/to/icon.png".into());
    let builtin = IconId::Builtin(BuiltinIcon::Info);
    assert_ne!(name, path);
    assert_ne!(path, builtin);
}

#[test]
fn test_builtin_icon_variants() {
    let icons = [
        BuiltinIcon::Check,
        BuiltinIcon::Error,
        BuiltinIcon::Warning,
        BuiltinIcon::Info,
        BuiltinIcon::Lock,
        BuiltinIcon::Add,
        BuiltinIcon::Remove,
    ];
    assert_eq!(icons.len(), 7);
    for i in 0..icons.len() {
        for j in (i + 1)..icons.len() {
            assert_ne!(icons[i], icons[j]);
        }
    }
}

#[test]
fn test_icon_resource() {
    let icon = Icon::new("icons/test.png");
    assert_eq!(icon.path, "icons/test.png");
    assert_eq!(icon.width, 0);
    assert_eq!(icon.height, 0);
}

#[test]
fn test_icon_with_size() {
    let icon = Icon::with_size("icons/test.png", 32, 32);
    assert_eq!(icon.width, 32);
    assert_eq!(icon.height, 32);
}

#[test]
fn test_icon_with_description() {
    let icon = Icon::new("test.png").with_description("Test icon");
    assert_eq!(icon.description.as_deref(), Some("Test icon"));
}
