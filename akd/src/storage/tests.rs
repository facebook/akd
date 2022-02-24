// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! Test utilities of storage layers implementing the storage primatives for AKD

use crate::errors::StorageError;
use crate::history_tree_node::*;
use crate::node_state::*;
use crate::storage::types::*;
use crate::storage::Storage;
use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use tokio::time::{Duration, Instant};

type Azks = crate::append_only_zks::Azks;
type HistoryTreeNode = crate::history_tree_node::HistoryTreeNode;

// *** Tests *** //

#[cfg(test)]
mod memory_storage_tests {
    use crate::storage::memory::AsyncInMemoryDatabase;
    use serial_test::serial;

    #[tokio::test]
    #[serial]
    async fn test_v2_in_memory_db_with_caching() {
        let mut db = crate::storage::memory::AsyncInMemoryDbWithCache::new();
        crate::storage::tests::run_test_cases_for_storage_impl(&mut db).await;
    }

    #[tokio::test]
    #[serial]
    async fn test_v2_in_memory_db() {
        let mut db = AsyncInMemoryDatabase::new();
        crate::storage::tests::run_test_cases_for_storage_impl(&mut db).await;
    }
}

// *** Run the test cases for a given data-layer impl *** //
/// Run the storage-layer test suite for a given storage implementation.
/// This is public because it can be used by other implemented storage layers
/// for consistency checks (e.g. mysql, memcached, etc)
pub async fn run_test_cases_for_storage_impl<S: Storage + Sync + Send>(db: &mut S) {
    test_get_and_set_item(db).await;
    test_user_data(db).await;
    test_transactions(db).await;
    test_batch_get_items(db).await;
}

// *** New Test Helper Functions *** //
async fn test_get_and_set_item<Ns: Storage>(storage: &Ns) {
    // === Azks storage === //
    let azks = Azks {
        latest_epoch: 34,
        num_nodes: 10,
    };

    let set_result = storage.set(DbRecord::Azks(azks.clone())).await;
    assert_eq!(Ok(()), set_result);

    let get_result = storage
        .get::<Azks>(crate::append_only_zks::DEFAULT_AZKS_KEY)
        .await;
    if let Ok(DbRecord::Azks(got_azks)) = get_result {
        assert_eq!(got_azks.latest_epoch, azks.latest_epoch);
        assert_eq!(got_azks.num_nodes, azks.num_nodes);
    } else {
        panic!("Failed to retrieve AZKS");
    }

    // === HistoryTreeNode storage === //

    let node = HistoryTreeNode {
        label: NodeLabel::new(byte_arr_from_u64(13), 4),
        birth_epoch: 123,
        last_epoch: 234,
        parent: NodeLabel::new(byte_arr_from_u64(1), 1),
        node_type: NodeType::Leaf,
    };
    let mut node2 = node.clone();
    node2.label = NodeLabel::new(byte_arr_from_u64(16), 4);

    let key = NodeKey(NodeLabel::new(byte_arr_from_u64(13), 4));
    let key2 = NodeKey(NodeLabel::new(byte_arr_from_u64(16), 4));

    let set_result = storage.set(DbRecord::HistoryTreeNode(node.clone())).await;
    assert_eq!(Ok(()), set_result);

    let set_result = storage.set(DbRecord::HistoryTreeNode(node2.clone())).await;
    assert_eq!(Ok(()), set_result);

    let get_result = storage.get::<HistoryTreeNode>(key).await;
    if let Ok(DbRecord::HistoryTreeNode(got_node)) = get_result {
        assert_eq!(got_node.label, node.label);
        assert_eq!(got_node.parent, node.parent);
        assert_eq!(got_node.node_type, node.node_type);
        assert_eq!(got_node.birth_epoch, node.birth_epoch);
        assert_eq!(got_node.last_epoch, node.last_epoch);
    } else {
        panic!("Failed to retrieve History Tree Node");
    }

    let get_result = storage.get::<HistoryTreeNode>(key2).await;
    if let Err(err) = get_result {
        panic!("Failed to retrieve history tree node (2) {:?}", err)
    }

    // === HistoryNodeState storage === //
    let key = NodeStateKey(NodeLabel::new(byte_arr_from_u64(1), 1), 1);
    let node_state = HistoryNodeState {
        value: vec![],
        child_states: [None, None],
        key,
    };
    let set_result = storage
        .set(DbRecord::HistoryNodeState(node_state.clone()))
        .await;
    assert_eq!(Ok(()), set_result);

    let get_result = storage.get::<HistoryNodeState>(key).await;
    if let Ok(DbRecord::HistoryNodeState(got_state)) = get_result {
        assert_eq!(got_state.value, node_state.value);
        assert_eq!(got_state.child_states, node_state.child_states);
        assert_eq!(got_state.key, node_state.key);
    } else {
        panic!("Failed to retrieve history node state");
    }

    // === ValueState storage === //
    let key = ValueStateKey("test".to_string(), 1);
    let value = ValueState {
        username: AkdLabel("test".to_string()),
        epoch: 1,
        label: NodeLabel::new(byte_arr_from_u64(1), 1),
        version: 1,
        plaintext_val: AkdValue("abc123".to_string()),
    };
    let set_result = storage.set(DbRecord::ValueState(value.clone())).await;
    assert_eq!(Ok(()), set_result);

    let get_result = storage.get::<ValueState>(key).await;
    if let Ok(DbRecord::ValueState(got_state)) = get_result {
        assert_eq!(got_state.username, value.username);
        assert_eq!(got_state.epoch, value.epoch);
        assert_eq!(got_state.label, value.label);
        assert_eq!(got_state.plaintext_val, value.plaintext_val);
        assert_eq!(got_state.version, value.version);
    } else {
        panic!("Failed to retrieve history node state");
    }
}

async fn test_batch_get_items<Ns: Storage>(storage: &Ns) {
    let mut rand_users: Vec<String> = vec![];
    for _ in 0..20 {
        rand_users.push(
            thread_rng()
                .sample_iter(&Alphanumeric)
                .take(30)
                .map(char::from)
                .collect(),
        );
    }

    let mut data = Vec::new();

    let mut epoch = 1;
    for value in rand_users.iter() {
        for user in rand_users.iter() {
            data.push(DbRecord::ValueState(ValueState {
                plaintext_val: AkdValue(value.clone()),
                version: epoch,
                label: NodeLabel {
                    val: byte_arr_from_u64(1),
                    len: 1u32,
                },
                epoch,
                username: AkdLabel(user.clone()),
            }));
        }
        epoch += 1;
    }

    let tic = Instant::now();
    assert_eq!(Ok(()), storage.batch_set(data.clone()).await);
    let toc: Duration = Instant::now() - tic;
    println!("Storage batch op: {} ms", toc.as_millis());
    let got = storage
        .get::<ValueState>(ValueStateKey(rand_users[0].clone(), 10))
        .await;
    if got.is_err() {
        panic!("Failed to retrieve a user after batch insert");
    }

    let keys: Vec<ValueStateKey> = rand_users
        .iter()
        .map(|user| ValueStateKey(user.clone(), 1))
        .collect();
    let got_all = storage.batch_get::<ValueState>(keys).await;
    match got_all {
        Err(_) => panic!("Failed to retrieve batch of user at specific epochs"),
        Ok(lst) if lst.len() != rand_users.len() => {
            panic!(
                "Retrieved list length does not match input length {} != {}",
                lst.len(),
                rand_users.len()
            );
        }
        Ok(results) => {
            // correct length, now check the values
            for result in results.into_iter() {
                // find the initial record with the same username & epoch
                let initial_record = data
                    .iter()
                    .find(|&x| {
                        if let DbRecord::ValueState(value_state) = &x {
                            if let DbRecord::ValueState(retrieved_state) = &result {
                                return value_state.username == retrieved_state.username
                                    && value_state.epoch == retrieved_state.epoch;
                            }
                        }
                        false
                    })
                    .cloned();
                // assert it matches what was given matches what was retrieved
                assert_eq!(Some(result), initial_record);
            }
        }
    }

    let user_keys: Vec<_> = rand_users
        .iter()
        .map(|user| AkdLabel(user.clone()))
        .collect();
    let got_all_min_states = storage
        .get_user_state_versions(&user_keys, ValueStateRetrievalFlag::MinEpoch)
        .await;
    // should be the same thing as the previous get
    match got_all_min_states {
        Err(err) => panic!("Failed to retrieve batch of user at min epochs: {:?}", err),
        Ok(lst) if lst.len() != rand_users.len() => {
            panic!(
                "Retrieved list length does not match input length {} != {}",
                lst.len(),
                rand_users.len()
            );
        }
        Ok(results) => {
            // correct length, now check the values
            for result in results.into_iter() {
                // find the initial record with the same username & epoch
                let initial_record = data
                    .iter()
                    .find(|&x| {
                        if let DbRecord::ValueState(value_state) = &x {
                            return value_state.username == result.0
                                && value_state.version == result.1;
                        }
                        false
                    })
                    .cloned()
                    .map(|item| {
                        if let DbRecord::ValueState(value_state) = &item {
                            value_state.version
                        } else {
                            0u64
                        }
                    });

                // assert it matches what was given matches what was retrieved
                assert_eq!(Some(result.1), initial_record);
            }
        }
    }

    let got_all_max_states = storage
        .get_user_state_versions(&user_keys, ValueStateRetrievalFlag::MaxEpoch)
        .await;
    // should be the same thing as the previous get
    match got_all_max_states {
        Err(err) => panic!("Failed to retrieve batch of user at min epochs: {:?}", err),
        Ok(lst) if lst.len() != rand_users.len() => {
            panic!(
                "Retrieved list length does not match input length {} != {}",
                lst.len(),
                rand_users.len()
            );
        }
        Ok(results) => {
            // correct length, now check the values
            for result in results.into_iter() {
                // find the initial record with the same username & epoch
                let initial_record = data
                    .iter()
                    .find(|&x| {
                        if let DbRecord::ValueState(value_state) = &x {
                            return value_state.username == result.0
                                && value_state.version == result.1;
                        }
                        false
                    })
                    .cloned()
                    .map(|item| {
                        if let DbRecord::ValueState(value_state) = &item {
                            value_state.version
                        } else {
                            0u64
                        }
                    });
                // assert it matches what was given matches what was retrieved
                assert_eq!(Some(result.1), initial_record);
            }
        }
    }
}

async fn test_transactions<S: Storage + Sync + Send>(storage: &mut S) {
    let mut rand_users: Vec<String> = vec![];
    for _ in 0..20 {
        rand_users.push(
            thread_rng()
                .sample_iter(&Alphanumeric)
                .take(30)
                .map(char::from)
                .collect(),
        );
    }

    let mut data = Vec::new();

    let mut epoch = 1;
    for value in rand_users.iter() {
        for user in rand_users.iter() {
            data.push(DbRecord::ValueState(ValueState {
                plaintext_val: AkdValue(value.clone()),
                version: 1u64,
                label: NodeLabel {
                    val: byte_arr_from_u64(1),
                    len: 1u32,
                },
                epoch,
                username: AkdLabel(user.clone()),
            }));
        }
        epoch += 1;
    }

    let new_data = data
        .iter()
        .map(|item| {
            let new_item = item.clone();
            if let DbRecord::ValueState(new_state) = &item {
                let mut copied_state = new_state.clone();
                copied_state.epoch += 10000;
                DbRecord::ValueState(copied_state)
            } else {
                new_item
            }
        })
        .collect();

    let tic = Instant::now();
    assert_eq!(Ok(()), storage.batch_set(data).await);
    let toc: Duration = Instant::now() - tic;
    println!("Storage batch op: {} ms", toc.as_millis());
    let got = storage
        .get::<ValueState>(ValueStateKey(rand_users[0].clone(), 10))
        .await;
    if got.is_err() {
        panic!("Failed to retrieve a user after batch insert");
    }

    let tic = Instant::now();
    assert!(storage.begin_transaction().await);
    assert_eq!(Ok(()), storage.batch_set(new_data).await);
    assert_eq!(Ok(()), storage.commit_transaction().await);
    let toc: Duration = Instant::now() - tic;
    println!("Transactional storage batch op: {} ms", toc.as_millis());

    let got = storage
        .get::<ValueState>(ValueStateKey(rand_users[0].clone(), 10 + 10000))
        .await;
    if got.is_err() {
        panic!("Failed to retrieve a user after batch insert");
    }
}

async fn test_user_data<S: Storage + Sync + Send>(storage: &S) {
    let rand_user: String = thread_rng()
        .sample_iter(&Alphanumeric)
        .take(30)
        .map(char::from)
        .collect();
    let rand_value: String = thread_rng()
        .sample_iter(&Alphanumeric)
        .take(1028)
        .map(char::from)
        .collect();
    let mut sample_state = ValueState {
        plaintext_val: AkdValue(rand_value.clone()),
        version: 1u64,
        label: NodeLabel {
            val: byte_arr_from_u64(1),
            len: 1u32,
        },
        epoch: 1u64,
        username: AkdLabel(rand_user),
    };
    let mut sample_state_2 = sample_state.clone();
    sample_state_2.username = AkdLabel("test_user".to_string());

    let result = storage
        .set(DbRecord::ValueState(sample_state.clone()))
        .await;
    assert_eq!(Ok(()), result);

    sample_state.version = 2u64;
    sample_state.epoch = 123u64;
    let result = storage
        .set(DbRecord::ValueState(sample_state.clone()))
        .await;
    assert_eq!(Ok(()), result);

    sample_state.version = 3u64;
    sample_state.epoch = 456u64;
    let result = storage
        .set(DbRecord::ValueState(sample_state.clone()))
        .await;
    assert_eq!(Ok(()), result);

    let data = storage.get_user_data(&sample_state.username).await.unwrap();
    assert_eq!(3, data.states.len());

    let versions = data
        .states
        .into_iter()
        .map(|state| state.version)
        .collect::<Vec<_>>();
    assert_eq!(vec![1, 2, 3], versions);

    // At this point the DB has structure (for MySQL):
    /*
    mysql> USE default;
    Reading table information for completion of table and column names
    You can turn off this feature to get a quicker startup with -A

    Database changed
    mysql> SHOW TABLES;
    +-------------------+
    | Tables_in_default |
    +-------------------+
    | data              |
    | user_data         |
    +-------------------+
    2 rows in set (0.00 sec)

    mysql> SELECT * FROM user_data;
    +--------------------------------+-------+---------+----------------+----------------+-------------------+
    | username                       | epoch | version | node_label_val | node_label_len | data              |
    +--------------------------------+-------+---------+----------------+----------------+-------------------+
    | do3zfiXa0IUKznscp06jtc6KfHJudy |     1 |       1 |              1 |              1 | 8owmLSoZi...B9pu8 |
    | do3zfiXa0IUKznscp06jtc6KfHJudy |   123 |       2 |              1 |              1 | 8owmLSoZi...B9pu8 |
    | do3zfiXa0IUKznscp06jtc6KfHJudy |   456 |       3 |              1 |              1 | 8owmLSoZi...B9pu8 |
    +--------------------------------+-------+---------+----------------+----------------+-------------------+
    3 rows in set (0.00 sec)
    */

    let specific_result = storage
        .get_user_state(
            &sample_state.username,
            ValueStateRetrievalFlag::SpecificVersion(2),
        )
        .await;
    assert_eq!(
        Ok(ValueState {
            epoch: 123,
            version: 2,
            label: NodeLabel::new(byte_arr_from_u64(1), 1),
            plaintext_val: AkdValue(rand_value.clone()),
            username: sample_state.username.clone(),
        }),
        specific_result
    );

    let specifc_result = storage
        .get::<ValueState>(ValueStateKey(sample_state.username.0.clone(), 123))
        .await;
    if let Ok(DbRecord::ValueState(state)) = specifc_result {
        assert_eq!(
            ValueState {
                epoch: 123,
                version: 2,
                label: NodeLabel::new(byte_arr_from_u64(1), 1),
                plaintext_val: AkdValue(rand_value.clone()),
                username: sample_state.username.clone(),
            },
            state
        );
    } else {
        panic!("Unable to retrieve user state object");
    }

    let missing_result = storage
        .get_user_state(
            &sample_state.username,
            ValueStateRetrievalFlag::SpecificVersion(100),
        )
        .await;
    assert!(matches!(missing_result, Err(StorageError::GetData(_)),));

    let specific_result = storage
        .get_user_state(
            &sample_state.username,
            ValueStateRetrievalFlag::SpecificEpoch(123),
        )
        .await;
    assert_eq!(
        Ok(ValueState {
            epoch: 123,
            version: 2,
            label: NodeLabel::new(byte_arr_from_u64(1), 1),
            plaintext_val: AkdValue(rand_value.clone()),
            username: sample_state.username.clone(),
        }),
        specific_result
    );

    let specific_result = storage
        .get_user_state(&sample_state.username, ValueStateRetrievalFlag::MinEpoch)
        .await;
    assert_eq!(
        Ok(ValueState {
            epoch: 1,
            version: 1,
            label: NodeLabel::new(byte_arr_from_u64(1), 1),
            plaintext_val: AkdValue(rand_value.clone()),
            username: sample_state.username.clone(),
        }),
        specific_result
    );

    let specific_result = storage
        .get_user_state(&sample_state.username, ValueStateRetrievalFlag::MaxEpoch)
        .await;
    assert_eq!(
        Ok(ValueState {
            epoch: 456,
            version: 3,
            label: NodeLabel::new(byte_arr_from_u64(1), 1),
            plaintext_val: AkdValue(rand_value.clone()),
            username: sample_state.username.clone(),
        }),
        specific_result
    );

    // Vector operations

    let mut vector_of_states = vec![sample_state_2.clone()];
    sample_state_2.version = 2;
    sample_state_2.epoch = 234;
    vector_of_states.push(sample_state_2.clone());

    sample_state_2.version = 3;
    sample_state_2.epoch = 345;
    vector_of_states.push(sample_state_2.clone());
    sample_state_2.version = 4;
    sample_state_2.epoch = 456;
    vector_of_states.push(sample_state_2.clone());

    let records = vector_of_states
        .into_iter()
        .map(DbRecord::ValueState)
        .collect::<Vec<_>>();
    let result = storage.batch_set(records).await;
    assert_eq!(Ok(()), result);

    let data = storage.get_user_data(&sample_state_2.username).await;
    assert_eq!(4, data.unwrap().states.len());
}
