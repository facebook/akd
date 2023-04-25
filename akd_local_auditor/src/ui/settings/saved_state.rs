// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed licenses.

//! Backing storage implementation for a saved state
//!
//! Test state
//! s3 --bucket populatetestbucket --region us-east-2 --endpoint http://127.0.0.1:9000 --access-key test --secret-key someLongAccessKey

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::SpecificStorageSettings as StorageSettings;

#[derive(Debug, Clone)]
pub enum LoadError {
    File,
    Format,
}

#[derive(Debug, Clone)]
pub enum SaveError {
    File,
    Write,
    Format,
}

#[cfg(not(target_arch = "wasm32"))]
impl StorageSettings {
    pub fn path() -> std::path::PathBuf {
        let mut path = if let Some(project_dirs) =
            directories_next::ProjectDirs::from("rs", "Akd", "LocalAuditor")
        {
            project_dirs.data_dir().into()
        } else {
            std::env::current_dir().unwrap_or_default()
        };

        path.push("auditor.json");

        path
    }

    pub async fn load() -> Result<Self, LoadError> {
        let mut contents = String::new();

        let mut file = tokio::fs::File::open(Self::path())
            .await
            .map_err(|_| LoadError::File)?;

        file.read_to_string(&mut contents)
            .await
            .map_err(|_| LoadError::File)?;

        serde_json::from_str(&contents).map_err(|_| LoadError::Format)
    }

    pub async fn save(self) -> Result<(), SaveError> {
        let json = serde_json::to_string_pretty(&self).map_err(|_| SaveError::Format)?;

        let path = Self::path();

        if let Some(dir) = path.parent() {
            tokio::fs::create_dir_all(dir)
                .await
                .map_err(|_| SaveError::File)?;
        }

        let mut file = tokio::fs::File::create(path)
            .await
            .map_err(|_| SaveError::File)?;

        file.write_all(json.as_bytes())
            .await
            .map_err(|_| SaveError::Write)?;

        // This is a simple way to save at most once every couple seconds
        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

        Ok(())
    }
}

#[cfg(target_arch = "wasm32")]
impl StorageSettings {
    fn storage() -> Option<web_sys::Storage> {
        let window = web_sys::window()?;

        window.local_storage().ok()?
    }

    async fn load() -> Result<Self, LoadError> {
        let storage = Self::storage().ok_or(LoadError::File)?;

        let contents = storage
            .get_item("state")
            .map_err(|_| LoadError::File)?
            .ok_or(LoadError::File)?;

        serde_json::from_str(&contents).map_err(|_| LoadError::Format)
    }

    async fn save(self) -> Result<(), SaveError> {
        let storage = Self::storage().ok_or(SaveError::File)?;

        let json = serde_json::to_string_pretty(&self).map_err(|_| SaveError::Format)?;

        storage
            .set_item("state", &json)
            .map_err(|_| SaveError::Write)?;

        let _ = wasm_timer::Delay::new(std::time::Duration::from_secs(2)).await;

        Ok(())
    }
}
