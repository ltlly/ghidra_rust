//! Menu bar for the Ghidra GUI.
//!
//! Implements the top menu bar with File, Edit, Analysis, Tools, Window,
//! and Help menus. Each menu contains standard Ghidra actions.

use egui::{Context, Ui};

/// Actions that can be triggered from the menu bar.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MenuAction {
    // File menu
    NewProject,
    OpenProject,
    OpenFile,
    Save,
    SaveAs,
    Export,
    ExportProgram,
    Close,
    CloseAll,
    Quit,
    Exit,
    // Edit menu
    Undo,
    Redo,
    Cut,
    Copy,
    Paste,
    Delete,
    SelectAll,
    Find,
    FindNext,
    Replace,
    Preferences,
    GoTo,
    // Analysis menu
    AutoAnalyze,
    AnalyzeOneShot,
    ClearAnalysis,
    AnalysisOptions,
    ConfigureAnalyzers,
    // Navigation menu
    NavigateGoTo,
    NavigateBack,
    NavigateForward,
    NavigateNextFunction,
    NavigatePreviousFunction,
    NavigateNextInstruction,
    NavigatePreviousInstruction,
    NavigateNextLabel,
    NavigateNextReference,
    NavigateEntryPoint,
    // Listing-level actions (accessible via keyboard)
    RenameLabel,
    Disassemble,
    ClearCodeBytes,
    CreateFunction,
    CreateLabel,
    SetComment,
    DefineDataType,
    CreatePointer,
    CreateArray,
    CreateData,
    CreateStructure,
    PatchInstruction,
    // Tools menu
    ProgramDifferences,
    FunctionGraph,
    DataTypeManager,
    MemoryMap,
    RegisterManager,
    ScriptManager,
    // Window menu
    ResetLayout,
    DefaultLayout,
    ToggleListing,
    ToggleDecompiler,
    ToggleSymbolTree,
    ToggleConsole,
    ToggleBytesView,
    ToggleDataTypes,
    ToggleFunctionGraph,
    // Help menu
    About,
    Documentation,
    KeyBindings,
    CheckForUpdates,
    None,
}

/// Keyboard shortcut manager.
#[derive(Debug, Clone)]
pub struct KeyBindings {
    pub bindings: Vec<(String, MenuAction)>,
}

impl KeyBindings {
    pub fn new() -> Self {
        Self {
            bindings: Vec::new(),
        }
    }

    pub fn add(&mut self, key: impl Into<String>, action: MenuAction) {
        self.bindings.push((key.into(), action));
    }

    pub fn default_bindings() -> Self {
        let mut kb = Self::new();
        kb.add("Ctrl+N", MenuAction::NewProject);
        kb.add("Ctrl+O", MenuAction::OpenFile);
        kb.add("Ctrl+S", MenuAction::Save);
        kb.add("Ctrl+Shift+S", MenuAction::SaveAs);
        kb.add("Ctrl+E", MenuAction::ExportProgram);
        kb.add("Ctrl+W", MenuAction::Close);
        kb.add("Ctrl+Q", MenuAction::Quit);
        kb.add("Ctrl+Z", MenuAction::Undo);
        kb.add("Ctrl+Y", MenuAction::Redo);
        kb.add("Ctrl+Shift+Z", MenuAction::Redo);
        kb.add("Ctrl+X", MenuAction::Cut);
        kb.add("Ctrl+C", MenuAction::Copy);
        kb.add("Ctrl+V", MenuAction::Paste);
        kb.add("Delete", MenuAction::Delete);
        kb.add("Ctrl+A", MenuAction::SelectAll);
        kb.add("Ctrl+F", MenuAction::Find);
        kb.add("Ctrl+H", MenuAction::Replace);
        kb.add("F3", MenuAction::FindNext);
        kb.add("G", MenuAction::NavigateGoTo);
        kb.add("Ctrl+G", MenuAction::NavigateGoTo);
        kb.add("Escape", MenuAction::NavigateBack);
        kb.add("Alt+Left", MenuAction::NavigateBack);
        kb.add("Alt+Right", MenuAction::NavigateForward);
        kb.add("Ctrl+Down", MenuAction::NavigateNextFunction);
        kb.add("Ctrl+Up", MenuAction::NavigatePreviousFunction);
        kb.add("F2", MenuAction::RenameLabel);
        // Ghidra listing shortcuts (not menu actions, handled at listing level)
        kb.add("D", MenuAction::Disassemble);
        kb.add("C", MenuAction::ClearCodeBytes);
        kb.add("F", MenuAction::CreateFunction);
        kb.add("L", MenuAction::CreateLabel);
        kb.add(";", MenuAction::SetComment);
        kb.add("T", MenuAction::DefineDataType);
        kb.add("P", MenuAction::CreatePointer);
        kb.add("[", MenuAction::CreateArray);
        kb.add("*", MenuAction::CreateData);
        kb.add("Shift+[", MenuAction::CreateStructure);
        kb.add("Ctrl+Shift+G", MenuAction::PatchInstruction);
        kb.add("Ctrl+Alt+A", MenuAction::AutoAnalyze);
        kb
    }

    /// Get the action for a key combination.
    pub fn action_for(&self, key: &str) -> Option<MenuAction> {
        self.bindings
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, a)| a.clone())
    }
}

impl Default for KeyBindings {
    fn default() -> Self {
        Self::default_bindings()
    }
}

/// Render the top menu bar and return any triggered action.
pub fn render_menu_bar(_ctx: &Context, ui: &mut Ui) -> MenuAction {
    let mut action = MenuAction::None;

    egui::menu::bar(ui, |ui| {
        // ---- File menu ----
        ui.menu_button("File", |ui| {
            if ui.button("New Project...  Ctrl+N").clicked() {
                action = MenuAction::NewProject;
                ui.close_menu();
            }
            if ui.button("Open Project...").clicked() {
                action = MenuAction::OpenProject;
                ui.close_menu();
            }
            if ui.button("Open File...  Ctrl+O").clicked() {
                action = MenuAction::OpenFile;
                ui.close_menu();
            }
            ui.separator();
            if ui.button("Save  Ctrl+S").clicked() {
                action = MenuAction::Save;
                ui.close_menu();
            }
            if ui.button("Save As...  Ctrl+Shift+S").clicked() {
                action = MenuAction::SaveAs;
                ui.close_menu();
            }
            ui.separator();
            if ui.button("Export Program...  Ctrl+E").clicked() {
                action = MenuAction::ExportProgram;
                ui.close_menu();
            }
            if ui.button("Export...").clicked() {
                action = MenuAction::Export;
                ui.close_menu();
            }
            ui.separator();
            if ui.button("Close  Ctrl+W").clicked() {
                action = MenuAction::Close;
                ui.close_menu();
            }
            if ui.button("Close All").clicked() {
                action = MenuAction::CloseAll;
                ui.close_menu();
            }
            ui.separator();
            if ui.button("Quit  Ctrl+Q").clicked() {
                action = MenuAction::Quit;
                ui.close_menu();
            }
            if ui.button("Exit").clicked() {
                action = MenuAction::Exit;
                ui.close_menu();
            }
        });

        // ---- Edit menu ----
        ui.menu_button("Edit", |ui| {
            if ui.button("Undo  Ctrl+Z").clicked() {
                action = MenuAction::Undo;
                ui.close_menu();
            }
            if ui.button("Redo  Ctrl+Y").clicked() {
                action = MenuAction::Redo;
                ui.close_menu();
            }
            ui.separator();
            if ui.button("Cut  Ctrl+X").clicked() {
                action = MenuAction::Cut;
                ui.close_menu();
            }
            if ui.button("Copy  Ctrl+C").clicked() {
                action = MenuAction::Copy;
                ui.close_menu();
            }
            if ui.button("Paste  Ctrl+V").clicked() {
                action = MenuAction::Paste;
                ui.close_menu();
            }
            if ui.button("Delete  Del").clicked() {
                action = MenuAction::Delete;
                ui.close_menu();
            }
            ui.separator();
            if ui.button("Select All  Ctrl+A").clicked() {
                action = MenuAction::SelectAll;
                ui.close_menu();
            }
            ui.separator();
            if ui.button("Find...  Ctrl+F").clicked() {
                action = MenuAction::Find;
                ui.close_menu();
            }
            if ui.button("Find Next  F3").clicked() {
                action = MenuAction::FindNext;
                ui.close_menu();
            }
            if ui.button("Replace...  Ctrl+H").clicked() {
                action = MenuAction::Replace;
                ui.close_menu();
            }
            ui.separator();
            if ui.button("Preferences...").clicked() {
                action = MenuAction::Preferences;
                ui.close_menu();
            }
        });

        // ---- Analysis menu ----
        ui.menu_button("Analysis", |ui| {
            if ui.button("Auto Analyze...  Ctrl+Alt+A").clicked() {
                action = MenuAction::AutoAnalyze;
                ui.close_menu();
            }
            if ui.button("One-Shot Analysis...").clicked() {
                action = MenuAction::AnalyzeOneShot;
                ui.close_menu();
            }
            ui.separator();
            if ui.button("Clear Analysis...").clicked() {
                action = MenuAction::ClearAnalysis;
                ui.close_menu();
            }
            ui.separator();
            if ui.button("Analysis Options...").clicked() {
                action = MenuAction::AnalysisOptions;
                ui.close_menu();
            }
        });

        // ---- Navigation menu ----
        ui.menu_button("Navigation", |ui| {
            if ui.button("Go To...  G").clicked() {
                action = MenuAction::NavigateGoTo;
                ui.close_menu();
            }
            ui.separator();
            if ui.button("Back  Esc").clicked() {
                action = MenuAction::NavigateBack;
                ui.close_menu();
            }
            if ui.button("Forward  Alt+Right").clicked() {
                action = MenuAction::NavigateForward;
                ui.close_menu();
            }
            ui.separator();
            if ui.button("Next Function  Ctrl+Down").clicked() {
                action = MenuAction::NavigateNextFunction;
                ui.close_menu();
            }
            if ui.button("Previous Function  Ctrl+Up").clicked() {
                action = MenuAction::NavigatePreviousFunction;
                ui.close_menu();
            }
            ui.separator();
            if ui.button("Next Instruction").clicked() {
                action = MenuAction::NavigateNextInstruction;
                ui.close_menu();
            }
            if ui.button("Previous Instruction").clicked() {
                action = MenuAction::NavigatePreviousInstruction;
                ui.close_menu();
            }
            ui.separator();
            if ui.button("Next Label").clicked() {
                action = MenuAction::NavigateNextLabel;
                ui.close_menu();
            }
            if ui.button("Next Reference").clicked() {
                action = MenuAction::NavigateNextReference;
                ui.close_menu();
            }
            ui.separator();
            if ui.button("Entry Point").clicked() {
                action = MenuAction::NavigateEntryPoint;
                ui.close_menu();
            }
        });

        // ---- Tools menu ----
        ui.menu_button("Tools", |ui| {
            if ui.button("Program Differences...").clicked() {
                action = MenuAction::ProgramDifferences;
                ui.close_menu();
            }
            if ui.button("Function Graph").clicked() {
                action = MenuAction::FunctionGraph;
                ui.close_menu();
            }
            ui.separator();
            if ui.button("Data Type Manager").clicked() {
                action = MenuAction::DataTypeManager;
                ui.close_menu();
            }
            if ui.button("Memory Map").clicked() {
                action = MenuAction::MemoryMap;
                ui.close_menu();
            }
            if ui.button("Register Manager").clicked() {
                action = MenuAction::RegisterManager;
                ui.close_menu();
            }
            ui.separator();
            if ui.button("Script Manager").clicked() {
                action = MenuAction::ScriptManager;
                ui.close_menu();
            }
        });

        // ---- Window menu ----
        ui.menu_button("Window", |ui| {
            if ui.button("Reset Layout").clicked() {
                action = MenuAction::ResetLayout;
                ui.close_menu();
            }
            if ui.button("Default Layout").clicked() {
                action = MenuAction::DefaultLayout;
                ui.close_menu();
            }
            ui.separator();
            ui.menu_button("Toggle Panels", |ui| {
                if ui.button("Listing View").clicked() {
                    action = MenuAction::ToggleListing;
                    ui.close_menu();
                }
                if ui.button("Decompiler View").clicked() {
                    action = MenuAction::ToggleDecompiler;
                    ui.close_menu();
                }
                if ui.button("Symbol Tree").clicked() {
                    action = MenuAction::ToggleSymbolTree;
                    ui.close_menu();
                }
                if ui.button("Console").clicked() {
                    action = MenuAction::ToggleConsole;
                    ui.close_menu();
                }
                if ui.button("Bytes View").clicked() {
                    action = MenuAction::ToggleBytesView;
                    ui.close_menu();
                }
                if ui.button("Data Types").clicked() {
                    action = MenuAction::ToggleDataTypes;
                    ui.close_menu();
                }
                if ui.button("Function Graph").clicked() {
                    action = MenuAction::ToggleFunctionGraph;
                    ui.close_menu();
                }
            });
        });

        // ---- Help menu ----
        ui.menu_button("Help", |ui| {
            if ui.button("About Ghidra Rust").clicked() {
                action = MenuAction::About;
                ui.close_menu();
            }
            if ui.button("Documentation").clicked() {
                action = MenuAction::Documentation;
                ui.close_menu();
            }
            ui.separator();
            if ui.button("Key Bindings...").clicked() {
                action = MenuAction::KeyBindings;
                ui.close_menu();
            }
            ui.separator();
            if ui.button("Check for Updates").clicked() {
                action = MenuAction::CheckForUpdates;
                ui.close_menu();
            }
        });
    });

    action
}

/// Process global keyboard shortcuts and return corresponding actions.
pub fn process_keyboard_shortcuts(ctx: &Context, bindings: &KeyBindings) -> MenuAction {
    let input = ctx.input(|i| i.clone());

    // Check for modifier+key combinations
    let _mod_ctrl = input.modifiers.ctrl;
    let _mod_shift = input.modifiers.shift;

    // Iterate through recently pressed keys
    for event in &input.events {
        match event {
            egui::Event::Key {
                key,
                pressed: true,
                modifiers,
                ..
            } => {
                let key_str =
                    format_key_combo(*key, modifiers.ctrl, modifiers.shift, modifiers.alt);
                if let Some(action) = bindings.action_for(&key_str) {
                    return action;
                }
            }
            _ => {}
        }
    }

    MenuAction::None
}

/// Format a key combination as a human-readable string.
fn format_key_combo(key: egui::Key, ctrl: bool, shift: bool, alt: bool) -> String {
    let mut parts = Vec::new();
    if ctrl {
        parts.push("Ctrl");
    }
    if shift {
        parts.push("Shift");
    }
    if alt {
        parts.push("Alt");
    }
    let key_name = match key {
        egui::Key::A => "A",
        egui::Key::B => "B",
        egui::Key::C => "C",
        egui::Key::D => "D",
        egui::Key::E => "E",
        egui::Key::F => "F",
        egui::Key::G => "G",
        egui::Key::H => "H",
        egui::Key::I => "I",
        egui::Key::J => "J",
        egui::Key::K => "K",
        egui::Key::L => "L",
        egui::Key::M => "M",
        egui::Key::N => "N",
        egui::Key::O => "O",
        egui::Key::P => "P",
        egui::Key::Q => "Q",
        egui::Key::R => "R",
        egui::Key::S => "S",
        egui::Key::T => "T",
        egui::Key::U => "U",
        egui::Key::V => "V",
        egui::Key::W => "W",
        egui::Key::X => "X",
        egui::Key::Y => "Y",
        egui::Key::Z => "Z",
        egui::Key::Num0 => "0",
        egui::Key::Num1 => "1",
        egui::Key::Num2 => "2",
        egui::Key::Num3 => "3",
        egui::Key::Num4 => "4",
        egui::Key::Num5 => "5",
        egui::Key::Num6 => "6",
        egui::Key::Num7 => "7",
        egui::Key::Num8 => "8",
        egui::Key::Num9 => "9",
        egui::Key::Escape => "Escape",
        egui::Key::Tab => "Tab",
        egui::Key::Backspace => "Backspace",
        egui::Key::Enter => "Enter",
        egui::Key::Space => "Space",
        egui::Key::Delete => "Delete",
        egui::Key::ArrowUp => "Up",
        egui::Key::ArrowDown => "Down",
        egui::Key::ArrowLeft => "Left",
        egui::Key::ArrowRight => "Right",
        egui::Key::F1 => "F1",
        egui::Key::F2 => "F2",
        egui::Key::F3 => "F3",
        egui::Key::F4 => "F4",
        egui::Key::F5 => "F5",
        egui::Key::F6 => "F6",
        egui::Key::F7 => "F7",
        egui::Key::F8 => "F8",
        egui::Key::F9 => "F9",
        egui::Key::F10 => "F10",
        egui::Key::F11 => "F11",
        egui::Key::F12 => "F12",
        _ => "?",
    };
    parts.push(key_name);
    parts.join("+")
}
