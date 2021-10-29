// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

use rand::{prelude::ThreadRng, thread_rng, RngCore};
use seemless::{
    append_only_zks::Azks, node_state::NodeLabel,
    storage::memory::r#async::AsyncInMemoryDbWithCache,
};
use winter_crypto::{hashers::Blake3_256, Hasher};
use winter_math::fields::f128::BaseElement;

type Blake3 = Blake3_256<BaseElement>;

#[tokio::main]
async fn main() {
    let num_nodes = 200;

    let mut rng: ThreadRng = thread_rng();

    let db = AsyncInMemoryDbWithCache::new();
    let mut azks1 = Azks::<Blake3, AsyncInMemoryDbWithCache>::new(&db, &mut rng)
        .await
        .unwrap();

    for _ in 0..num_nodes {
        let node = NodeLabel::random(&mut rng);
        let mut input = [0u8; 32];
        rng.fill_bytes(&mut input);
        let val = Blake3::hash(&input);
        azks1.insert_leaf(&db, node, val).await.unwrap();
    }

    let node = NodeLabel::random(&mut rng);
    let mut input = [0u8; 32];
    rng.fill_bytes(&mut input);
    let val = Blake3::hash(&input);

    // Start measurement
    db.clear_stats();
    azks1.insert_leaf(&db, node, val).await.unwrap();

    db.print_hashmap_distribution();
    db.print_stats();
}
