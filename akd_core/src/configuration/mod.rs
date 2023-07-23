// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed licenses.

//! Defines the configuration trait and implementations for various configurations

mod traits;
pub use traits::{Configuration, DomainLabel, ExampleLabel};

#[cfg(feature = "public_tests")]
pub use traits::NamedConfiguration;

// Note(new_config): Update this when adding a new configuration

#[cfg(feature = "whatsapp_v1")]
pub(crate) mod whatsapp_v1;
#[cfg(feature = "whatsapp_v1")]
pub use whatsapp_v1::WhatsAppV1Configuration;

#[cfg(feature = "experimental")]
pub(crate) mod experimental;
#[cfg(feature = "experimental")]
pub use experimental::ExperimentalConfiguration;
