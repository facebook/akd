// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! Settings page for the AKD local auditor application

use super::{empty_action_message, Message, DEFAULT_FONT_SIZE, DEFAULT_SPACING};
use crate::storage::{
    dynamodb::DynamoDbClapSettings, s3::S3ClapSettings, CommonStorageClapSettings,
};

use iced::widget::{
    button, column, horizontal_space, radio, row, text, text_input, Checkbox, Column, Row,
    TextInput,
};
use iced::{Command, Element, Length};
use std::sync::Arc;

mod saved_state;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum StorageType {
    S3,
    DynamoDb,
}

impl std::fmt::Display for StorageType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::S3 => write!(f, "S3"),
            Self::DynamoDb => write!(f, "Dynamo DB"),
        }
    }
}

pub struct StorageSettings {
    theme: iced::Theme,
    pub(crate) settings: SpecificStorageSettings,
    is_saving: bool,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum SpecificStorageSettings {
    /// Amazon S3 compatible storage
    S3(S3ClapSettings),

    /// DynamoDB
    DynamoDb(DynamoDbClapSettings),
}

impl SpecificStorageSettings {
    /// Dynamo specific call
    pub(crate) fn set_table(&mut self, v: String) {
        match self {
            Self::S3(_) => {}
            Self::DynamoDb(settings) => {
                settings.table = v;
            }
        }
    }

    pub(crate) fn set_dynamo_endpoint(&mut self, v: Option<String>) {
        match self {
            Self::S3(_) => {}
            Self::DynamoDb(settings) => {
                settings.dynamo_endpoint = v;
            }
        }
    }

    pub fn toggle(&self, ty: StorageType) -> Self {
        match ty {
            StorageType::S3 => Self::S3(S3ClapSettings {
                access_key: self.access_key(),
                bucket: self.bucket(),
                endpoint: self.s3_endpoint(),
                region: self.region(),
                secret_key: self.secret_key(),
            }),
            StorageType::DynamoDb => Self::DynamoDb(DynamoDbClapSettings {
                table: "".to_string(),
                access_key: self.access_key(),
                bucket: self.bucket(),
                dynamo_endpoint: None,
                region: self.region(),
                s3_endpoint: self.s3_endpoint(),
                secret_key: self.secret_key(),
            }),
        }
    }
}

impl CommonStorageClapSettings for SpecificStorageSettings {
    fn bucket(&self) -> String {
        match self {
            Self::S3(settings) => settings.bucket(),
            Self::DynamoDb(settings) => settings.bucket(),
        }
    }

    fn region(&self) -> String {
        match self {
            Self::S3(settings) => settings.region(),
            Self::DynamoDb(settings) => settings.region(),
        }
    }

    fn s3_endpoint(&self) -> Option<String> {
        match self {
            Self::S3(settings) => settings.s3_endpoint(),
            Self::DynamoDb(settings) => settings.s3_endpoint(),
        }
    }

    fn access_key(&self) -> Option<String> {
        match self {
            Self::S3(settings) => settings.access_key(),
            Self::DynamoDb(settings) => settings.access_key(),
        }
    }

    fn secret_key(&self) -> Option<String> {
        match self {
            Self::S3(settings) => settings.secret_key(),
            Self::DynamoDb(settings) => settings.secret_key(),
        }
    }

    fn set_bucket(&mut self, v: String) {
        match self {
            Self::S3(settings) => settings.set_bucket(v),
            Self::DynamoDb(settings) => settings.set_bucket(v),
        }
    }

    fn set_region(&mut self, v: String) {
        match self {
            Self::S3(settings) => settings.set_region(v),
            Self::DynamoDb(settings) => settings.set_region(v),
        }
    }

    fn set_s3_endpoint(&mut self, v: Option<String>) {
        match self {
            Self::S3(settings) => settings.set_s3_endpoint(v),
            Self::DynamoDb(settings) => settings.set_s3_endpoint(v),
        }
    }

    fn set_access_key(&mut self, v: Option<String>) {
        match self {
            Self::S3(settings) => settings.set_access_key(v),
            Self::DynamoDb(settings) => settings.set_access_key(v),
        }
    }

    fn set_secret_key(&mut self, v: Option<String>) {
        match self {
            Self::S3(settings) => settings.set_secret_key(v),
            Self::DynamoDb(settings) => settings.set_secret_key(v),
        }
    }
}

impl StorageSettings {
    pub fn new(theme: iced::Theme) -> Self {
        Self {
            theme,
            settings: SpecificStorageSettings::S3(S3ClapSettings {
                bucket: "bucket".to_string(),
                region: "us-east-2".to_string(),
                endpoint: None,
                access_key: None,
                secret_key: None,
            }),
            is_saving: false,
        }
    }
}

#[derive(Debug, Clone)]
pub enum SettingsMessage {
    CancelSettings,
    SaveSettings,

    Loaded(Result<SpecificStorageSettings, saved_state::LoadError>),
    Saved(Result<(), saved_state::SaveError>),

    // The storage type (s3 or dynamo)
    ChangeStorageType(StorageType),

    // common settings shared in s3 + dynamo
    BucketChanged(String),
    RegionChanged(String),
    S3EndpointChanged((bool, String)),
    AccessKeyChanged((bool, String)),
    SecretKeyChanged((bool, String)),

    // dynamo-specific settings (a no-op in s3 mode)
    DynamoTableChanged(String),
    DynamoEndpointChanged((bool, String)),
}

impl StorageSettings {
    pub fn update(&mut self, settings_msg: SettingsMessage) -> Command<Message> {
        match settings_msg {
            SettingsMessage::ChangeStorageType(ty) => {
                self.settings = self.settings.toggle(ty);
                Command::none()
            }
            SettingsMessage::BucketChanged(bucket) => {
                self.settings.set_bucket(bucket);
                Command::none()
            }
            SettingsMessage::RegionChanged(region) => {
                self.settings.set_region(region);
                Command::none()
            }
            SettingsMessage::CancelSettings => {
                // switch the tab back to the auditor interface
                empty_action_message(Message::TabSelected(super::AUDITOR_INTERFACE_TAB))
            }
            SettingsMessage::S3EndpointChanged((endpoint, endpoint_value)) => {
                if endpoint {
                    self.settings.set_s3_endpoint(Some(endpoint_value));
                } else {
                    self.settings.set_s3_endpoint(None);
                }
                Command::none()
            }
            SettingsMessage::AccessKeyChanged((key, key_value)) => {
                if key {
                    self.settings.set_access_key(Some(key_value));
                } else {
                    self.settings.set_access_key(None);
                }
                Command::none()
            }
            SettingsMessage::SecretKeyChanged((key, key_value)) => {
                if key {
                    self.settings.set_secret_key(Some(key_value));
                } else {
                    self.settings.set_secret_key(None);
                }
                Command::none()
            }
            SettingsMessage::DynamoTableChanged(new_table) => {
                self.settings.set_table(new_table);
                Command::none()
            }
            SettingsMessage::DynamoEndpointChanged((endpoint, endpoint_value)) => {
                if endpoint {
                    self.settings.set_dynamo_endpoint(Some(endpoint_value));
                } else {
                    self.settings.set_dynamo_endpoint(None);
                }
                Command::none()
            }
            SettingsMessage::SaveSettings => {
                self.is_saving = true;
                let self_clone = self.settings.clone();
                Command::perform(async move { self_clone.save().await }, |out| {
                    Message::Settings(SettingsMessage::Saved(out))
                })
            }
            SettingsMessage::Saved(save_result) => {
                self.is_saving = false;
                match save_result {
                    Ok(_) => {
                        log::info!("Settings saved.");
                        Command::batch([
                            empty_action_message(Message::SettingsUpdated),
                            crate::ui::logstream::debug("Settings saved.".to_string()),
                        ])
                    }
                    Err(err) => {
                        log::error!("Failed to save settings: {:?}", err);
                        crate::ui::logstream::warn(format!("Failed to save settings: {:?}", err))
                    }
                }
            }
            SettingsMessage::Loaded(load_result) => match load_result {
                Ok(set) => {
                    log::info!("Settings loaded.");
                    self.settings = set;
                    Command::batch([
                        empty_action_message(Message::SettingsUpdated),
                        crate::ui::logstream::debug("Settings loaded.".to_string()),
                    ])
                }
                Err(err) => {
                    log::error!("Failed to load settings: {:?}", err);
                    crate::ui::logstream::warn(format!("Failed to load settings: {:?}", err))
                }
            },
        }
    }

    fn optional_string_setting<'a, TMsgBuilder>(
        the_setting: Option<String>,
        label: &'static str,
        hint: &'static str,
        msg_builder: TMsgBuilder,
    ) -> Element<'a, Message>
    where
        TMsgBuilder: 'a + Fn(bool, String) -> Message,
    {
        let clone_1 = the_setting.clone();
        let clone_2 = the_setting.clone();
        let clone_3 = the_setting.clone();
        let fn_arc = Arc::new(msg_builder);
        let fn_clone = fn_arc.clone();

        let mut row = Row::new().push(Checkbox::new(
            the_setting.is_some(),
            label,
            move |is_checked| {
                let setting = clone_1.clone();
                fn_arc(is_checked, setting.unwrap_or_default())
            },
        ));

        if the_setting.is_some() {
            row = row.push(TextInput::new(
                hint,
                &clone_2.unwrap_or_default(),
                move |new_setting| fn_clone(clone_3.is_some(), new_setting),
            ));
        }

        row.spacing(DEFAULT_SPACING).padding(DEFAULT_SPACING).into()
    }

    fn common_view(
        common: &dyn crate::storage::CommonStorageClapSettings,
    ) -> Vec<Element<Message>> {
        let s3_endpoint_setting = Self::optional_string_setting(
            common.s3_endpoint(),
            "S3 endpoint",
            "URI",
            |is_checked, value| {
                Message::Settings(SettingsMessage::S3EndpointChanged((is_checked, value)))
            },
        );
        let access_key_setting = Self::optional_string_setting(
            common.access_key(),
            "Access key",
            "Value",
            |is_checked, value| {
                Message::Settings(SettingsMessage::AccessKeyChanged((is_checked, value)))
            },
        );
        let secret_key_setting = Self::optional_string_setting(
            common.secret_key(),
            "Secret key",
            "Value",
            |is_checked, value| {
                Message::Settings(SettingsMessage::SecretKeyChanged((is_checked, value)))
            },
        );

        vec![
            row![
                text("Bucket").size(DEFAULT_FONT_SIZE),
                text_input("Bucket name", &common.bucket(), |new_bucket| {
                    Message::Settings(SettingsMessage::BucketChanged(new_bucket))
                })
            ]
            .spacing(DEFAULT_SPACING)
            .padding(DEFAULT_SPACING)
            .into(),
            row![
                text("Region").size(DEFAULT_FONT_SIZE),
                text_input("Region identifier", &common.region(), |new_region| {
                    Message::Settings(SettingsMessage::RegionChanged(new_region))
                })
            ]
            .spacing(DEFAULT_SPACING)
            .padding(DEFAULT_SPACING)
            .into(),
            s3_endpoint_setting,
            access_key_setting,
            secret_key_setting,
        ]
    }

    pub fn s3_view(s3: &crate::storage::s3::S3ClapSettings) -> Element<Message> {
        let items = Self::common_view(s3);
        // add specific items
        Column::with_children(items).into()
    }

    pub fn dynamo_view(
        dynamo: &crate::storage::dynamodb::DynamoDbClapSettings,
    ) -> Element<Message> {
        let mut items = Self::common_view(dynamo);
        // add specific items
        items.push(
            row![
                text("Table").size(DEFAULT_FONT_SIZE),
                text_input("Table name", &dynamo.table, |new_table| {
                    Message::Settings(SettingsMessage::DynamoTableChanged(new_table))
                })
            ]
            .spacing(DEFAULT_SPACING)
            .padding(DEFAULT_SPACING)
            .into(),
        );

        items.push(Self::optional_string_setting(
            dynamo.dynamo_endpoint.clone(),
            "DynamoDB endpoint",
            "URI",
            |is_checked, value| {
                Message::Settings(SettingsMessage::DynamoEndpointChanged((is_checked, value)))
            },
        ));

        Column::with_children(items).spacing(10).into()
    }
}

impl super::AuditorTab for StorageSettings {
    fn tab_title(&self) -> String {
        "Settings".to_string()
    }

    fn view(&self) -> Element<Message> {
        if self.is_saving {
            return super::empty_message("Saving...", &self.theme);
        }

        let settings_view = match &self.settings {
            SpecificStorageSettings::S3(s3_settings) => Self::s3_view(s3_settings),
            SpecificStorageSettings::DynamoDb(dynamo_settings) => {
                Self::dynamo_view(dynamo_settings)
            }
        };

        let choose_storage_type: Row<Message> =
            [StorageType::S3, StorageType::DynamoDb].iter().fold(
                row![text("Storage Type: ")].spacing(DEFAULT_SPACING),
                |row, ty| {
                    row.push(radio(
                        format!("{}", ty),
                        *ty,
                        Some(match self.settings {
                            SpecificStorageSettings::S3(_) => StorageType::S3,
                            SpecificStorageSettings::DynamoDb(_) => StorageType::DynamoDb,
                        }),
                        |ty| Message::Settings(SettingsMessage::ChangeStorageType(ty)),
                    ))
                },
            );

        column![
            choose_storage_type,
            settings_view,
            row![
                button("Cancel")
                    .width(Length::Shrink)
                    .padding(DEFAULT_SPACING)
                    .on_press(Message::Settings(SettingsMessage::CancelSettings))
                    .style(iced::theme::Button::Destructive),
                horizontal_space(Length::Fill),
                button("Save")
                    .width(Length::Shrink)
                    .padding(DEFAULT_SPACING)
                    .on_press(Message::Settings(SettingsMessage::SaveSettings))
                    .style(iced::theme::Button::Positive),
            ]
            .width(Length::Fill)
            .padding(DEFAULT_SPACING)
            .spacing(DEFAULT_SPACING)
        ]
        .into()
    }
}
