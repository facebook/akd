// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! The main interface for doing audit operations

use self::breadcrumb::{BreadcrumbMessage, Breadcrumbs};

use super::{Message, Storage, DEFAULT_FONT_SIZE, DEFAULT_SPACING};
use crate::storage;
use crate::storage::EpochSummary;

use iced::alignment;
use iced::widget::{
    button, column, container, horizontal_rule, horizontal_space, qr_code, row, scrollable, text,
    Column, Row,
};
use iced::{Alignment, Command, Element, Length};
use std::collections::HashMap;

mod breadcrumb;

const CRUMB_SUMMARY_CUTOFF: usize = 10;
const CRUMB_SUMMARY_COLUMNS: usize = 3;

fn empty_message<'a>(message: &str, theme: &'a iced::Theme) -> Element<'a, Message> {
    container(
        text(message)
            .width(Length::Fill)
            .size(30)
            .horizontal_alignment(alignment::Horizontal::Center)
            .style(theme.extended_palette().secondary.weak.text.clone()),
    )
    .width(Length::Fill)
    .height(Length::Units(200))
    .center_y()
    .into()
}

enum ProcessingMode {
    None,
    Refreshing,
    Auditing,
}

pub struct Auditor {
    proofs: Vec<EpochSummary>,
    storage: Option<Storage>,
    qr_codes: HashMap<EpochSummary, Result<qr_code::State, String>>,
    crumbs: Breadcrumbs<BreadcrumbValue>,
    processing_mode: ProcessingMode,
    theme: iced::Theme,
}

#[derive(Clone, Debug)]
pub struct BreadcrumbValue {
    pub low: u64,
    pub high: u64,
}

impl std::fmt::Display for BreadcrumbValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}..{}", self.low, self.high)
    }
}

#[derive(Debug, Clone)]
pub enum AuditorMessage {
    Breadcrumb(BreadcrumbMessage<BreadcrumbValue>),

    RefreshEpochs,
    RefreshComplete(Result<Vec<EpochSummary>, String>),

    AuditEpoch(EpochSummary),
    AuditComplete((EpochSummary, Result<Vec<u8>, String>)),
}

impl From<AuditorMessage> for Message {
    fn from(a: AuditorMessage) -> Self {
        Message::Auditor(a)
    }
}

impl Auditor {
    pub fn settings_updated(&mut self, settings: &super::settings::StorageSettings) {
        let storage: Box<dyn storage::AuditProofStorage> = match &settings {
            super::settings::StorageSettings::S3(s3_settings) => {
                let imp: storage::s3::S3AuditStorage = s3_settings.into();
                Box::new(imp)
            }
            super::settings::StorageSettings::DynamoDb(dynamo_settings) => {
                let imp: storage::dynamodb::DynamoDbAuditStorage = dynamo_settings.into();
                Box::new(imp)
            }
        };

        self.storage = Some(std::sync::Arc::new(storage));
    }

    pub fn new(storage: Option<Storage>, theme: iced::Theme) -> Self {
        Self {
            storage,
            crumbs: Breadcrumbs::new(theme.clone()),
            proofs: vec![],
            // qr: None,
            qr_codes: HashMap::new(),
            processing_mode: ProcessingMode::None,
            theme,
        }
    }

    async fn refresh_epochs(maybe_storage: Option<Storage>) -> Result<Vec<EpochSummary>, String> {
        if let Some(storage) = maybe_storage {
            storage
                .list_proofs(crate::storage::ProofIndexCacheOption::NoCache)
                .await
                .map_err(|e| e.to_string())
        } else {
            Err("No storage is available!".to_string())
        }
    }

    async fn audit_epoch(
        maybe_storage: Option<Storage>,
        epoch_summary: EpochSummary,
    ) -> Result<Vec<u8>, String> {
        if let Some(storage) = maybe_storage {
            // download the proof
            let blob = storage
                .get_proof(&epoch_summary)
                .await
                .map_err(|err| format!("Error downloading proof {}", err))?;
            // decode the proof
            let (epoch, p_hash, c_hash, proof) = blob
                .decode()
                .map_err(|err| format!("Error decodeing proof {:?}", err))?;
            // audit the proof
            akd::auditor::audit_verify(
                vec![p_hash, c_hash],
                akd::AppendOnlyProof {
                    proofs: vec![proof],
                    epochs: vec![epoch],
                },
            )
            .await
            .map_err(|err| format!("Error auditing proof {}", err))?;

            let qr_data = crate::auditor::format_qr_record(p_hash, c_hash, epoch);
            Ok(qr_data)
        } else {
            Err("No storage is available!".to_string())
        }
    }

    pub fn update(&mut self, message: AuditorMessage) -> Command<Message> {
        match message {
            AuditorMessage::RefreshEpochs => {
                self.processing_mode = ProcessingMode::Refreshing;

                Command::perform(Self::refresh_epochs(self.storage.clone()), |args| {
                    Message::Auditor(AuditorMessage::RefreshComplete(args))
                })
            }
            AuditorMessage::RefreshComplete(data) => {
                self.processing_mode = ProcessingMode::None;

                match data {
                    Ok(mut epochs) => {
                        log::info!("Received {} epochs", epochs.len());
                        epochs.sort_unstable_by(|a, b| a.name.epoch.cmp(&b.name.epoch));

                        // reset the crumbs
                        let crumb = BreadcrumbValue {
                            low: epochs.first().unwrap().name.epoch,
                            high: epochs.last().unwrap().name.epoch,
                        };
                        self.crumbs.reset(crumb);

                        self.proofs = epochs;
                        super::logstream::info(format!("Received {} epochs", self.proofs.len()))
                    }
                    Err(err) => {
                        let c = super::logstream::error(format!(
                            "Error downloading epoch information {}",
                            err
                        ));
                        log::error!("Error downloading epoch infomation {}", err);
                        c
                    }
                }
            }

            AuditorMessage::AuditEpoch(epoch) => {
                self.processing_mode = ProcessingMode::Auditing;
                let epoch_clone = epoch.clone();
                Command::perform(
                    Self::audit_epoch(self.storage.clone(), epoch),
                    |args: Result<Vec<u8>, String>| {
                        Message::Auditor(AuditorMessage::AuditComplete((epoch_clone, args)))
                    },
                )
            }
            AuditorMessage::AuditComplete((epoch_summary, result)) => {
                self.processing_mode = ProcessingMode::None;
                match result {
                    Ok(msg) => {
                        let command = super::logstream::info(format!(
                            "Audit succeeded for epoch {}. Generating qr code...",
                            epoch_summary.name.epoch
                        ));
                        log::info!("Audit succeeded! Generating QR code...");
                        if let Ok(state) = qr_code::State::new(msg) {
                            self.qr_codes.insert(epoch_summary, Ok(state));
                            command
                        } else {
                            log::warn!("Failed to generate auditor verification QR code");
                            Command::batch([
                                command,
                                super::logstream::warn(format!("Failed to generate auditor verification QR code, but audit was successful for epoch {}", epoch_summary.name.epoch))
                            ])
                        }
                    }
                    Err(err) => {
                        let command = super::logstream::error(format!(
                            "Audit of epoch {} failed with error {}",
                            epoch_summary.name.epoch, err
                        ));
                        log::error!(
                            "Audit of epoch {} failed with error {}",
                            epoch_summary.name.epoch,
                            err
                        );

                        self.qr_codes
                            .insert(epoch_summary, Err(format!("Audit failed! {}", err)));
                        command
                    }
                }
            }

            AuditorMessage::Breadcrumb(crumb_msg) => self.crumbs.update(crumb_msg),
        }
    }

    fn is_summary_view(&self) -> bool {
        if let Some(current) = self.crumbs.in_view() {
            current.high - current.low > (CRUMB_SUMMARY_CUTOFF as u64)
        } else {
            false
        }
    }

    fn generate_summary_view(&self) -> Element<Message> {
        let current_range = self.crumbs.in_view().unwrap();
        let chunk_size = ((current_range.high - current_range.low + 1) as f64
            / (CRUMB_SUMMARY_CUTOFF as f64).floor()) as usize;
        let summaries = (current_range.low..=current_range.high)
            .collect::<Vec<_>>()
            .chunks(chunk_size)
            .map(|chunk| (*chunk.first().unwrap(), *chunk.last().unwrap()))
            .collect::<Vec<_>>();

        // Create CRUMB_SUMMARY_COLUMNS column layouts (rows), each with
        // an equal number of row layouts (columns)
        Column::with_children(
            summaries
                .chunks(CRUMB_SUMMARY_COLUMNS)
                .map(|row_batch| {
                    Row::with_children(
                        row_batch
                            .iter()
                            .map(|(start, end)| {
                                let txt =
                                    text(format!("{}..{}", start, end)).size(DEFAULT_FONT_SIZE);
                                button(txt)
                                    .padding(DEFAULT_SPACING)
                                    .width(Length::FillPortion(1))
                                    .on_press(Message::Auditor(AuditorMessage::Breadcrumb(
                                        BreadcrumbMessage::Push(BreadcrumbValue {
                                            low: *start,
                                            high: *end,
                                        }),
                                    )))
                                    .style(iced::theme::Button::Secondary)
                                    .into()
                            })
                            .collect(),
                    )
                    .align_items(Alignment::Center)
                    .padding(DEFAULT_SPACING)
                    .spacing(DEFAULT_SPACING)
                    .into()
                })
                .collect(),
        )
        .into()
    }

    fn generate_regular_view(&self) -> Element<Message> {
        match self.processing_mode {
            ProcessingMode::Auditing => {
                return empty_message("Processing audit...", &self.theme);
            }
            ProcessingMode::Refreshing => {
                return empty_message("Refreshing epochs...", &self.theme);
            }
            _ => {}
        }

        if let Some(BreadcrumbValue { low, high }) = self.crumbs.in_view() {
            let skip = low as usize;
            let len = (high - low + 1) as usize;
            let filtered_proofs = self
                .proofs
                .iter()
                .skip(skip)
                .take(len)
                .cloned()
                .collect::<Vec<_>>();

            let epochs = Column::with_children(
                filtered_proofs
                    .iter()
                    .map(|proof| {
                        let mut data_row = row![
                            text(format!(
                                "Epoch {} -> {}:",
                                proof.name.epoch,
                                proof.name.epoch + 1
                            ))
                            .style(self.theme.palette().primary.clone()),
                            button("Verify")
                                .width(Length::Shrink)
                                .padding(DEFAULT_SPACING)
                                .on_press(Message::Auditor(AuditorMessage::AuditEpoch(
                                    proof.clone()
                                )))
                                .style(iced::theme::Button::Primary),
                            horizontal_space(Length::Fill),
                        ];

                        match self.qr_codes.get(proof) {
                            Some(Ok(qr_state)) => {
                                let qr = qr_code::QRCode::new(qr_state).cell_size(2);
                                data_row = data_row.push(qr);
                            }
                            Some(Err(audit_failure)) => {
                                let msg = text(audit_failure)
                                    .size(16)
                                    .horizontal_alignment(alignment::Horizontal::Center);
                                data_row = data_row.push(msg);
                            }
                            _ => {}
                        }

                        data_row
                            .padding(DEFAULT_SPACING)
                            .spacing(DEFAULT_SPACING)
                            .width(Length::Fill)
                            .align_items(Alignment::Center)
                    })
                    .map(Element::from)
                    .collect(),
            );

            scrollable(
                container(epochs)
                    .width(Length::Fill)
                    .padding(DEFAULT_SPACING)
                    .center_x(),
            )
            .into()
        } else {
            column![].into()
        }
    }

    fn generate_view_header(&self) -> Element<Message> {
        row![
            button(text("Refresh epochs").size(16))
                .width(Length::Shrink)
                .on_press(Message::Auditor(AuditorMessage::RefreshEpochs)),
            self.crumbs.view(),
        ]
        .align_items(alignment::Alignment::Center)
        .width(Length::Fill)
        .into()
    }
}

impl super::AuditorTab for Auditor {
    fn tab_title(&self) -> String {
        "Auditor".to_string()
    }

    fn view(&self) -> Element<Message> {
        let content = if self.is_summary_view() {
            self.generate_summary_view()
        } else {
            self.generate_regular_view()
        };

        column![self.generate_view_header(), horizontal_rule(20), content,]
            .spacing(DEFAULT_SPACING)
            .width(Length::Fill)
            .height(Length::Fill)
            .into()
    }
}
