// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed licenses.

// 1. Create a hashmap of all prefixes of all elements of the node set
// 2. For each node in current_nodes set, check if each child is in prefix hashmap
// 3. If so, add child label to batch set

// Creates a byte array of 32 bytes from a u64
// Note that this representation is big-endian, and
// places the bits to the front of the output byte_array.
#[cfg(any(test, feature = "public_tests"))]
pub(crate) fn byte_arr_from_u64(input_int: u64) -> [u8; 32] {
    let mut output_arr = [0u8; 32];
    let input_arr = input_int.to_be_bytes();
    output_arr[..8].clone_from_slice(&input_arr[..8]);
    output_arr
}

#[allow(unused)]
#[cfg(any(test, feature = "public_tests"))]
pub(crate) fn random_label(rng: &mut impl rand::Rng) -> crate::NodeLabel {
    crate::NodeLabel {
        label_val: rng.gen::<[u8; 32]>(),
        label_len: 256,
    }
}

/// NOTE(new_config): Add a new configuration here

/// Macro used for running tests with different configurations
#[cfg(any(test, feature = "public_tests"))]
#[macro_export]
macro_rules! test_config {
    ( $x:ident ) => {
        paste::paste! {
            #[cfg(feature = "whatsapp_v1")]
            #[tokio::test]
            async fn [<$x _ whatsapp_v1_config>]() -> Result<(), AkdError> {
                $x::<$crate::WhatsAppV1Configuration>().await
            }

            #[cfg(feature = "experimental")]
            #[tokio::test]
            async fn [<$x _ experimental_config>]() -> Result<(), AkdError> {
                $x::<$crate::ExperimentalConfiguration<$crate::ExampleLabel>>().await
            }
        }
    };
}
