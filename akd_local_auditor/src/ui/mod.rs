// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! A user-interface for the local auditor service for easy usage

// TODO list:
// 1. Breadcrumbs
// 2. Epoch drill-down

use std::sync::Arc;

use iced::alignment;
use iced::event::{self, Event};
use iced::theme::Theme;
use iced::widget::{button, column, container, horizontal_rule, text, Row};
use iced::{keyboard, subscription, window};
use iced::{Application, Command, Element, Length, Settings, Subscription};

type Storage = Arc<Box<dyn crate::storage::AuditProofStorage>>;
use settings::StorageSettings;

mod auditor;
mod logstream;
mod settings;

pub const AUDITOR_INTERFACE_TAB: usize = 0;
pub const SETTINGS_INTERFACE_TAB: usize = 1;
pub const LOG_INTERFACE_TAB: usize = 2;

pub const DEFAULT_SPACING: u16 = 15;
pub const DEFAULT_FONT_SIZE: u16 = 20;

/*
================= Helpers =================
*/

pub trait AuditorTab {
    fn tab_title(&self) -> String;

    fn view(&self) -> Element<Message>;
}

pub fn empty_action_message(msg: Message) -> Command<Message> {
    Command::perform(async {}, |_| msg)
}

pub fn empty_message<'a>(message: &str, theme: &'a iced::Theme) -> Element<'a, Message> {
    container(
        text(message)
            .width(Length::Fill)
            .size(30)
            .horizontal_alignment(alignment::Horizontal::Center)
            .style(theme.extended_palette().secondary.weak.text),
    )
    .width(Length::Fill)
    .height(Length::Units(200))
    .center_y()
    .into()
}

/*
================= User Interface =================
*/

pub(crate) struct UserInterface {
    should_exit: bool,
    active_tab: usize,
    settings: StorageSettings,
    auditor: auditor::Auditor,
    logs: logstream::LogStream,
    theme: Theme,
}

impl UserInterface {
    pub(crate) fn execute(processor: Option<Storage>) -> anyhow::Result<()> {
        let theme = Theme::Dark;

        let mut settings = Settings::with_flags((theme, processor));
        settings.window = window::Settings {
            size: (800, 800),
            ..window::Settings::default()
        };
        Self::run(settings)
            .map_err(|err| anyhow::anyhow!("Some user-interface error occurred {}", err))
    }
}

#[derive(Debug, Clone)]
pub enum Message {
    Exit,

    Auditor(auditor::AuditorMessage),
    Settings(settings::SettingsMessage),
    SettingsUpdated,
    Logs(logstream::LoggerMessage),

    TabSelected(usize),
    UnhandledKeyboardEvent(keyboard::Event),
}
impl Application for UserInterface {
    type Message = Message;
    type Theme = Theme;
    type Executor = iced::executor::Default;
    type Flags = (Theme, Option<Storage>);

    fn new((theme, optional_settings): Self::Flags) -> (Self, Command<Message>) {
        let active_tab = if optional_settings.is_some() {
            AUDITOR_INTERFACE_TAB
        } else {
            SETTINGS_INTERFACE_TAB
        };
        (
            Self {
                auditor: auditor::Auditor::new(optional_settings, theme.clone()),
                should_exit: false,
                active_tab,
                settings: StorageSettings::new(theme.clone()),
                logs: logstream::LogStream::new(theme.clone()),
                theme,
            },
            // try and load the previous state
            Command::perform(settings::SpecificStorageSettings::load(), |r| {
                Message::Settings(settings::SettingsMessage::Loaded(r))
            }),
        )
    }

    fn title(&self) -> String {
        "AKD Auditor".to_string()
    }

    fn update(&mut self, message: Message) -> Command<Message> {
        match message {
            Message::Exit => {
                self.should_exit = true;
                Command::none()
            }
            Message::Settings(settings_msg) => self.settings.update(settings_msg),
            Message::Auditor(audit_msg) => self.auditor.update(audit_msg),
            Message::Logs(log_msg) => self.logs.update(log_msg),
            Message::TabSelected(tab_index) => {
                self.active_tab = tab_index;
                Command::none()
            }
            Message::SettingsUpdated => {
                self.auditor.settings_updated(&self.settings);
                self.active_tab = AUDITOR_INTERFACE_TAB;
                empty_action_message(Message::Auditor(auditor::AuditorMessage::RefreshEpochs))
            }
            Message::UnhandledKeyboardEvent(evt) => {
                match evt {
                    // F5 to refresh on the main auditor page
                    keyboard::Event::KeyPressed {
                        key_code: keyboard::KeyCode::F5,
                        ..
                    } if self.active_tab == AUDITOR_INTERFACE_TAB => empty_action_message(
                        Message::Auditor(auditor::AuditorMessage::RefreshEpochs),
                    ),
                    // check CTRL-S on the settings page
                    keyboard::Event::KeyPressed {
                        key_code: keyboard::KeyCode::S,
                        modifiers,
                    } if self.active_tab == SETTINGS_INTERFACE_TAB => {
                        // Returns true if a "command key" is pressed in the [`Modifiers`].
                        //
                        // The "command key" is the main modifier key used to issue commands in the
                        // current platform. Specifically:
                        //
                        // - It is the `logo` or command key (⌘) on macOS
                        // - It is the `control` key on other platforms
                        if modifiers.command() {
                            empty_action_message(Message::Settings(
                                settings::SettingsMessage::SaveSettings,
                            ))
                        } else {
                            Command::none()
                        }
                    }
                    // CTRL-X exits the app
                    keyboard::Event::KeyPressed {
                        key_code: keyboard::KeyCode::X,
                        modifiers,
                    } => {
                        if modifiers.command() {
                            empty_action_message(Message::Exit)
                        } else {
                            Command::none()
                        }
                    }
                    // Tabbing around the interface should toggle focuses
                    keyboard::Event::KeyPressed {
                        key_code: keyboard::KeyCode::Tab,
                        modifiers,
                    } => {
                        if modifiers.shift() {
                            iced::widget::focus_previous()
                        } else {
                            iced::widget::focus_next()
                        }
                    }
                    _ => Command::none(),
                }
            }
        }
    }

    fn should_exit(&self) -> bool {
        self.should_exit
    }

    fn view(&self) -> Element<Message> {
        let tabs: Vec<Box<&dyn AuditorTab>> = vec![
            Box::new(&self.auditor),
            Box::new(&self.settings),
            Box::new(&self.logs),
        ];

        let mut tab_bar = Row::new();
        for (i, tab) in tabs.iter().enumerate() {
            tab_bar = tab_bar.push(
                button(text(tab.tab_title()).size(14))
                    .width(Length::Shrink)
                    .padding(DEFAULT_SPACING)
                    .style(iced::theme::Button::Secondary)
                    .on_press(Message::TabSelected(i)),
            );
            if i < tabs.len() - 1 {
                tab_bar = tab_bar.push(iced::widget::horizontal_space(Length::Fill));
            }
        }

        tab_bar = tab_bar.push(
            button(text("Exit").size(14))
                .width(Length::Shrink)
                .padding(DEFAULT_SPACING)
                .style(iced::theme::Button::Destructive)
                .on_press(Message::Exit),
        );
        tab_bar = tab_bar
            .width(Length::Fill)
            .padding(DEFAULT_SPACING)
            .spacing(DEFAULT_SPACING);

        column![
            tab_bar,
            horizontal_rule(10),
            tabs.get(self.active_tab).unwrap().view()
        ]
        .into()
    }

    fn subscription(&self) -> Subscription<Message> {
        subscription::events_with(|event, status| match (event, status) {
            (Event::Keyboard(keyboard_evt), event::Status::Ignored) => {
                Some(Message::UnhandledKeyboardEvent(keyboard_evt))
            }
            _ => None,
        })
    }

    fn theme(&self) -> Self::Theme {
        self.theme.clone()
    }
}
