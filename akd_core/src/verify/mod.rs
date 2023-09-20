// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed licenses.

//! This module contains verification calls for different proofs contained in the AKD crate

pub mod base;
pub mod history;
pub mod lookup;

#[cfg(feature = "nostd")]
use alloc::format;
#[cfg(feature = "nostd")]
use alloc::string::String;
#[cfg(feature = "nostd")]
use alloc::string::ToString;

/// Proof verification error types
#[derive(Debug, Eq, PartialEq)]
pub enum VerificationError {
    /// Error verifying a membership proof
    MembershipProof(String),
    /// Error verifying a non-membership proof
    NonMembershipProof(String),
    /// Error verifying a lookup proof
    LookupProof(String),
    /// Error verifying a history proof
    HistoryProof(String),
    /// Error verifying a VRF proof
    #[cfg(feature = "vrf")]
    Vrf(crate::ecvrf::VrfError),
    /// Error converting protobuf types during verification
    #[cfg(feature = "protobuf")]
    Serialization(crate::proto::ConversionError),
}

impl core::fmt::Display for VerificationError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let code = match &self {
            VerificationError::MembershipProof(err) => format!("(Membership proof) - {err}"),
            VerificationError::NonMembershipProof(err) => {
                format!("(Non-membership proof) - {err}")
            }
            VerificationError::LookupProof(err) => format!("(Lookup proof) - {err}"),
            VerificationError::HistoryProof(err) => format!("(History proof) - {err}"),
            #[cfg(feature = "vrf")]
            VerificationError::Vrf(vrf) => vrf.to_string(),
            #[cfg(feature = "protobuf")]
            VerificationError::Serialization(proto) => proto.to_string(),
        };
        write!(f, "Verification error {code}")
    }
}

#[cfg(feature = "vrf")]
impl From<crate::ecvrf::VrfError> for VerificationError {
    fn from(input: crate::ecvrf::VrfError) -> Self {
        VerificationError::Vrf(input)
    }
}

#[cfg(feature = "protobuf")]
impl From<crate::proto::ConversionError> for VerificationError {
    fn from(input: crate::proto::ConversionError) -> Self {
        VerificationError::Serialization(input)
    }
}

#[cfg(feature = "protobuf")]
impl From<protobuf::Error> for VerificationError {
    fn from(input: protobuf::Error) -> Self {
        let conv: crate::proto::ConversionError = input.into();
        conv.into()
    }
}

// Re-export the necessary verification functions

#[cfg(feature = "public_tests")]
pub use base::{verify_membership_for_tests_only, verify_nonmembership_for_tests_only};

pub use history::{key_history_verify, HistoryVerificationParams};
pub use lookup::lookup_verify;
