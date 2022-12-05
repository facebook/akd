// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! Breadcrumb management

// TODO:
// 1. filter to only show a few breadcrumbs (i.e. 5)

use super::super::Message;
use super::AuditorMessage;

use std::fmt::{Debug, Display};

use iced::widget::{button, container, horizontal_space, scrollable, text, Row};
use iced::{Alignment, Command, Element, Length};

const DEFAULT_FONT_SIZE: u16 = 12;
const DEFAULT_SPACING: u16 = 5;

pub struct Breadcrumbs<T: Display + Debug + Clone> {
    crumbs: Vec<T>,
    current: usize,
    theme: iced::Theme
}

#[derive(Debug, Clone)]
pub enum BreadcrumbMessage<T> {
    Select(usize),
    Increment,
    Decrement,
    First,
    Last,
    Push(T),
}

impl<T: Display + Debug + Clone> Breadcrumbs<T> {
    pub fn new(theme: iced::Theme) -> Self {
        Self {
            crumbs: vec![],
            current: 0,
            theme,
        }
    }

    pub fn increment(&mut self) {
        if self.can_increment() {
            self.current += 1;
        } else {
            self.current = self.crumbs.len() - 1;
        }
    }

    pub fn decrement(&mut self) {
        if self.can_decrement() {
            self.current -= 1;
        } else {
            self.current = 0;
        }
    }

    pub fn goto_last(&mut self) {
        if !self.crumbs.is_empty() {
            self.current = self.crumbs.len() - 1;
        } else {
            self.current = 0;
        }
    }

    pub fn goto_first(&mut self) {
        self.current = 0;
    }

    pub fn clear(&mut self) {
        self.crumbs.clear();
        self.current = 0;
    }

    pub fn push(&mut self, t: T) {
        self.crumbs = self
            .crumbs
            .iter()
            .take(self.current + 1)
            .cloned()
            .collect::<Vec<_>>();

        self.crumbs.push(t);
        self.goto_last();
    }

    pub fn reset(&mut self, crumb: T) {
        self.clear();
        self.push(crumb);
    }

    pub fn can_increment(&self) -> bool {
        !self.crumbs.is_empty() && self.current < self.crumbs.len() - 1
    }

    pub fn can_decrement(&self) -> bool {
        !self.crumbs.is_empty() && self.current > 0
    }

    pub fn in_view(&self) -> Option<T> {
        self.crumbs.get(self.current).cloned()
    }

    pub fn view(&self) -> Element<Message> {
        let mut the_row = Row::new();
        the_row = the_row.push(
            button("First")
                .style(iced::theme::Button::Text)
                .padding(10)
                .on_press(Message::Auditor(AuditorMessage::Breadcrumb(
                    BreadcrumbMessage::First,
                ))),
        );

        // for now, a hack is to make the middle scrollable
        let scroll = scrollable(container(
            Row::with_children(
                self.crumbs
                    .iter()
                    .enumerate()
                    .map(|(crumb_id, crumb)| {
                        let mut crumb_text = text(crumb.to_string()).size(DEFAULT_FONT_SIZE);
                        if crumb_id == self.current {
                            // color the selected item RED
                            crumb_text = crumb_text.style(self.theme.palette().primary.clone());
                        } else {
                            crumb_text =
                                crumb_text.style(self.theme.palette().text.clone());
                        }
                        let mut crumb_set = Row::with_children(vec![button(crumb_text)
                            .style(iced::theme::Button::Text)
                            .padding(DEFAULT_SPACING)
                            .on_press(Message::Auditor(AuditorMessage::Breadcrumb(
                                BreadcrumbMessage::Select(crumb_id),
                            )))
                            .into()]);
                        if crumb_id != self.crumbs.len() - 1 {
                            // use a no-op button to just be the same size so we get proper spacing between the ">"s
                            crumb_set = crumb_set.push(
                                button(text(">").size(DEFAULT_FONT_SIZE))
                                    .style(iced::theme::Button::Text)
                                    .padding(DEFAULT_SPACING),
                            );
                        }
                        crumb_set.into()
                    })
                    .collect(),
            )
            .width(Length::Fill)
            .padding(DEFAULT_SPACING)
            .height(Length::Fill),
        ));
        the_row = the_row.align_items(Alignment::Center).push(scroll);

        the_row = the_row.push(horizontal_space(Length::Fill));
        the_row = the_row.push(
            button("Last")
                .style(iced::theme::Button::Text)
                .padding(DEFAULT_SPACING)
                .on_press(Message::Auditor(AuditorMessage::Breadcrumb(
                    BreadcrumbMessage::Last,
                ))),
        );

        the_row.width(Length::Fill).into()
    }

    pub fn update(&mut self, message: BreadcrumbMessage<T>) -> Command<Message> {
        match message {
            BreadcrumbMessage::Select(crumb_id) => {
                self.current = crumb_id;
            }
            BreadcrumbMessage::Increment => self.increment(),
            BreadcrumbMessage::Decrement => self.decrement(),
            BreadcrumbMessage::First => {
                self.goto_first();
            }
            BreadcrumbMessage::Last => {
                self.goto_last();
            }
            BreadcrumbMessage::Push(item) => {
                self.push(item);
            }
        }
        Command::none()
    }
}
