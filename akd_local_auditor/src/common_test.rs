// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! This module implements some common test functionality (i.e. proof generation and whatnot)
//! for use in test infra
use crate::{Digest, Hasher};
use akd::directory::Directory;
use akd::ecvrf::HardCodedAkdVRF;
use akd::storage::memory::AsyncInMemoryDatabase;
use akd::AkdLabel;
use akd::AkdValue;

/// Generate a aws-safe bucket/table name from the test function name
///
/// So these are for S3 storage bucket names.
/// To guarantee parallel tests don't conflict with each other,
/// each test uses a different bucket for its tests which is
/// derived from the function name. However buckets cannot
/// contain the "_" char and must be capped @ 63 chars.
/// It's only for generating independent test cases
macro_rules! alphanumeric_function_name {
    () => {{
        fn f() {}
        fn type_name_of<T>(_: T) -> &'static str {
            std::any::type_name::<T>()
        }
        let name = type_name_of(f);
        name[..name.len() - 3]
            .trim_end_matches("::{{closure}}")
            .split("::")
            .last()
            .unwrap()
            .replace("_", "")
            .chars()
            .take(63)
            .collect::<String>()
    }};
}

// Re-export the macro for cross-module use
pub(crate) use alphanumeric_function_name;

pub struct AuditInformation {
    pub proof: akd::proof_structs::AppendOnlyProof<Hasher>,
    pub phash: Digest,
    pub chash: Digest,
}

/// Generate N audit proofs from a new tree
///
/// n: number of proofs to generate
/// expensive: This flag denotes if we should have many or just a single update in each iteration. If true, makes the audit's very large (100K updates)
pub async fn generate_audit_proofs(
    n: usize,
    expensive: bool,
) -> Result<Vec<AuditInformation>, akd::errors::AkdError> {
    let db = AsyncInMemoryDatabase::new();
    let vrf = HardCodedAkdVRF {};
    let akd = Directory::<_, _>::new::<Hasher>(&db, &vrf, false).await?;
    let mut proofs = vec![];
    // gather the hash + azks for epoch "0" (init)
    let mut azks = akd.retrieve_current_azks().await?;
    let mut phash = akd.get_root_hash::<Hasher>(&azks).await?;

    for _epoch in 1..=n {
        if expensive {
            // generate (n) epochs of updates on many users
            let data = (1..100000)
                .map(|item| {
                    let user = format!("user{}", item);
                    let value = format!("value{}_{}", _epoch, item);
                    (
                        AkdLabel::from_utf8_str(&user),
                        AkdValue::from_utf8_str(&value),
                    )
                })
                .collect::<Vec<(AkdLabel, AkdValue)>>();
            akd.publish::<Hasher>(data).await?;
        } else {
            // generate (n) epochs of updates on the same user
            let t_value = format!("certificate{}", _epoch);
            akd.publish::<Hasher>(vec![(
                AkdLabel::from_utf8_str("user"),
                AkdValue::from_utf8_str(&t_value),
            )])
            .await?;
        }
        // generate the append-only proof
        let proof = akd
            .audit::<Hasher>((_epoch - 1) as u64, _epoch as u64)
            .await?;
        // update the azks + retrieve the updated hash
        azks = akd.retrieve_current_azks().await?;
        let chash = akd.get_root_hash::<Hasher>(&azks).await?;

        // we have everything we need, pass it along
        let info = AuditInformation {
            phash,
            chash,
            proof,
        };
        proofs.push(info);

        // reset the "previous" hash for the next iteration
        phash = chash;
    }
    Ok(proofs)
}
