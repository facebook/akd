// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! A log-stream interface for the auditor process

use super::{AuditorTab, Message, DEFAULT_SPACING};

use chrono::prelude::*;
use iced::widget::{container, scrollable, text, Column};
use iced::{Command, Element, Length};

#[derive(Debug, Clone)]
pub struct LogEntry {
    level: log::Level,
    time: DateTime<Local>,
    message: String,
}

impl std::fmt::Display for LogEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "[{}] {}  {}",
            self.time,
            self.level.as_str(),
            self.message
        )
    }
}

impl LogEntry {
    fn get_color(&self) -> iced::Color {
        match self.level {
            log::Level::Error => iced::Color::from_rgb8(123, 36, 28),
            log::Level::Warn => iced::Color::from_rgb8(212, 172, 13),
            log::Level::Info => iced::Color::from_rgb8(31, 97, 141),
            _ => iced::Color::BLACK,
        }
    }
}

/* ======== Logger call utility functions ======== */
pub fn log(message: String, level: log::Level) -> Command<Message> {
    Command::perform(async {}, move |_| {
        Message::Logs(LoggerMessage::Push(LogEntry {
            message,
            time: Local::now(),
            level,
        }))
    })
}
pub fn error(message: String) -> Command<Message> {
    log(message, log::Level::Error)
}
pub fn warn(message: String) -> Command<Message> {
    log(message, log::Level::Warn)
}
pub fn info(message: String) -> Command<Message> {
    log(message, log::Level::Info)
}
pub fn debug(message: String) -> Command<Message> {
    log(message, log::Level::Debug)
}

pub struct LogStream {
    messages: Vec<LogEntry>,
}

#[derive(Debug, Clone)]
pub enum LoggerMessage {
    Push(LogEntry),
    Clear,
}

impl LogStream {
    pub fn new() -> Self {
        Self { messages: vec![] }
    }

    pub fn push(&mut self, msg: LogEntry) {
        self.messages.push(msg)
    }

    pub fn clear(&mut self) {
        self.messages.clear();
    }
}

impl LogStream {
    pub fn update(&mut self, msg: LoggerMessage) -> Command<Message> {
        match msg {
            LoggerMessage::Push(s) => self.push(s),
            LoggerMessage::Clear => self.clear(),
        }
        Command::none()
    }
}

impl AuditorTab for LogStream {
    fn tab_title(&self) -> String {
        "Auditor Logs".to_string()
    }

    fn view(&self) -> Element<Message> {
        let data_column = Column::with_children(
            self.messages
                .iter()
                .map(|msg| text(msg.to_string()).size(16).style(msg.get_color()))
                .map(Element::from)
                .collect(),
        );
        scrollable(
            container(data_column)
                .width(Length::Fill)
                .padding(DEFAULT_SPACING),
        )
        .into()
    }
}
