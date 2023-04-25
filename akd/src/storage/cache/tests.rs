// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed licenses.

//! Caching tests

use super::*;
use std::time::Duration;

use crate::storage::types::{ValueState, ValueStateKey};
use crate::storage::DbRecord;
use crate::{AkdLabel, AkdValue, NodeLabel};

#[tokio::test]
async fn test_cache_put_and_expires() {
    let cache = TimedCache::new(
        Some(Duration::from_millis(10)),
        None,
        Some(Duration::from_millis(50)),
    );

    let value_state = DbRecord::ValueState(ValueState {
        epoch: 1,
        version: 1,
        label: NodeLabel {
            label_len: 1,
            label_val: [0u8; 32],
        },
        value: AkdValue::from("some value"),
        username: AkdLabel::from("user"),
    });
    let key = ValueStateKey(AkdLabel::from("user").0.to_vec(), 1);
    cache.put(&value_state).await;

    let got = cache.hit_test::<ValueState>(&key).await;
    assert!(got.is_some());
    assert_eq!(Some(value_state), got);

    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    let got = cache.hit_test::<ValueState>(&key).await;
    assert_eq!(None, got);
}

#[tokio::test]
async fn test_cache_overwrite() {
    let cache = TimedCache::new(Some(Duration::from_millis(1000)), None, None);

    let value_state = ValueState {
        epoch: 1,
        version: 1,
        label: NodeLabel {
            label_len: 1,
            label_val: [0u8; 32],
        },
        value: AkdValue::from("some value"),
        username: AkdLabel::from("user"),
    };
    let key = ValueStateKey(AkdLabel::from("user").0.to_vec(), 1);

    let value_state_2 = ValueState {
        epoch: 1,
        version: 2,
        label: NodeLabel {
            label_len: 2,
            label_val: [0u8; 32],
        },
        value: AkdValue::from("some value"),
        username: AkdLabel::from("user"),
    };
    cache.put(&DbRecord::ValueState(value_state)).await;
    cache
        .put(&DbRecord::ValueState(value_state_2.clone()))
        .await;

    let got = cache.hit_test::<ValueState>(&key).await;
    assert_eq!(Some(DbRecord::ValueState(value_state_2)), got);
}

#[tokio::test]
async fn test_cache_memory_pressure() {
    let cache = TimedCache::new(
        Some(Duration::from_millis(1000)),
        Some(10),
        Some(Duration::from_millis(50)),
    );

    let value_state = DbRecord::ValueState(ValueState {
        epoch: 1,
        version: 1,
        label: NodeLabel {
            label_len: 1,
            label_val: [0u8; 32],
        },
        value: AkdValue::from("some value"),
        username: AkdLabel::from("user"),
    });
    let key = ValueStateKey(AkdLabel::from("user").0.to_vec(), 1);
    cache.put(&value_state).await;

    // we only do an "automated" clean every 50ms in test, which is when memory pressure is evaluated.
    // 100ms will make sure the clean op will run on the next `hit_test` op
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    // This get should return none, even though the cache expiration time is 1s. This is because
    // we should exceed 10 bytes of storage utilization so the cache should clean the item.
    let got = cache.hit_test::<ValueState>(&key).await;
    assert_eq!(None, got);
}

#[tokio::test]
async fn test_many_memory_pressure() {
    let cache = TimedCache::new(
        Some(Duration::from_millis(1000)),
        Some(1024 * 5),
        Some(Duration::from_millis(50)),
    );

    let value_states = (1..100)
        .map(|i| ValueState {
            epoch: i as u64,
            version: i as u64,
            label: NodeLabel {
                label_len: 1,
                label_val: [0u8; 32],
            },
            value: AkdValue::from("test"),
            username: AkdLabel::from("user"),
        })
        .map(DbRecord::ValueState)
        .collect::<Vec<_>>();

    cache.batch_put(&value_states).await;

    // we only do an "automated" clean every 50ms in test, which is when memory pressure is evaluated.
    // 100ms will make sure the clean op will run on the next `hit_test` op
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    let all = cache.get_all().await;
    assert!(all.len() < 99);
}
