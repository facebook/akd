// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed licenses.

pub mod fixture_generator;

pub mod test_suites;

#[cfg(test)]
#[macro_export]
// NOTE(new_config): Add new configurations here
macro_rules! test_config {
    ( $x:ident ) => {
        paste::paste! {
            #[tokio::test]
            async fn [<$x _ whatsapp_v1_config>]() {
                $x::<akd::WhatsAppV1Configuration>().await
            }

            #[tokio::test]
            async fn [<$x _ experimental_config>]() {
                $x::<akd::ExperimentalConfiguration>().await
            }
        }
    };
}
