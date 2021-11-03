#![cfg(test)]
// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use serial_test::serial;

use crate::errors::StorageError;
use crate::node_state::NodeLabel;
use crate::storage::memory::{AsyncInMemoryDatabase, AsyncInMemoryDbWithCache};
use crate::storage::mysql::AsyncMySqlDatabase;
use crate::storage::types::*;
use crate::storage::{V1Storage, V2Storage};

use std::marker::PhantomData;
use winter_crypto::hashers::Blake3_256;
use winter_math::fields::f128::BaseElement;

type Blake3 = Blake3_256<BaseElement>;
type Azks = crate::append_only_zks::Azks<Blake3>;
type HistoryTreeNode = crate::history_tree_node::HistoryTreeNode<Blake3>;

// *** Tests *** //

#[actix_rt::test]
async fn async_test_basic_database() {
    let db = AsyncInMemoryDatabase::new();
    async_test_get_and_set_item(&db).await;
    async_test_user_data(&db).await;

    let db = AsyncInMemoryDbWithCache::new();
    async_test_get_and_set_item(&db).await;
    async_test_user_data(&db).await;
}

#[actix_rt::test]
async fn async_test_new_basic_database() {
    let db = crate::storage::V2FromV1StorageWrapper::new(AsyncInMemoryDatabase::new());
    async_test_new_get_and_set_item(&db).await;
    async_test_new_user_data(&db).await;

    let db = crate::storage::V2FromV1StorageWrapper::new(AsyncInMemoryDbWithCache::new());
    async_test_new_get_and_set_item(&db).await;
    async_test_new_user_data(&db).await;
}

#[actix_rt::test]
#[serial]
async fn test_async_mysql_new_db() {
    if AsyncMySqlDatabase::test_guard() {
        let mysql_db = AsyncMySqlDatabase::new(
            "localhost",
            "default",
            Option::from("root"),
            Option::from("example"),
            Option::from(8001),
        )
        .await;

        if let Err(error) = mysql_db.delete_data().await {
            println!("Error cleaning mysql prior to test suite: {}", error);
        }

        // The test cases
        async_test_new_get_and_set_item(&mysql_db).await;
        async_test_new_user_data(&mysql_db).await;

        // clean the test infra
        if let Err(mysql_async::Error::Server(error)) = mysql_db.test_cleanup().await {
            println!(
                "ERROR: Failed to clean MySQL test database with error {}",
                error
            );
        }
    } else {
        println!("WARN: Skipping MySQL test due to test guard noting that the docker container appears to not be running.");
    }
}

// *** New Test Helper Functions *** //
async fn async_test_new_get_and_set_item<Ns: V2Storage>(storage: &Ns) {
    // === Azks storage === //
    let azks = Azks {
        root: 3,
        latest_epoch: 34,
        num_nodes: 10,
        _h: PhantomData,
    };

    let set_result = storage.set::<Blake3>(DbRecord::Azks(azks.clone())).await;
    assert_eq!(Ok(()), set_result);

    let get_result = storage
        .get::<Blake3, Azks>(crate::append_only_zks::DEFAULT_AZKS_KEY)
        .await;
    if let Ok(DbRecord::Azks(got_azks)) = get_result {
        assert_eq!(got_azks.root, azks.root);
        assert_eq!(got_azks.latest_epoch, azks.latest_epoch);
        assert_eq!(got_azks.num_nodes, azks.num_nodes);
    } else {
        panic!("Failed to retrieve AZKS");
    }

    // === HistoryTreeNode storage === //

    let node = HistoryTreeNode {
        label: crate::node_state::NodeLabel { val: 13, len: 1 },
        location: 234,
        epochs: vec![123u64, 234u64, 345u64],
        parent: 1,
        node_type: crate::history_tree_node::NodeType::Leaf,
        _h: PhantomData,
    };
    let mut node2 = node.clone();
    node2.location = 123;

    let key = crate::history_tree_node::NodeKey(234);

    let set_result = storage
        .set::<Blake3>(DbRecord::HistoryTreeNode(node.clone()))
        .await;
    assert_eq!(Ok(()), set_result);

    let set_result = storage
        .set::<Blake3>(DbRecord::HistoryTreeNode(node2.clone()))
        .await;
    assert_eq!(Ok(()), set_result);

    let get_result = storage.get::<Blake3, HistoryTreeNode>(key).await;
    if let Ok(DbRecord::HistoryTreeNode(got_node)) = get_result {
        assert_eq!(got_node.label, node.label);
        assert_eq!(got_node.location, node.location);
        assert_eq!(got_node.parent, node.parent);
        assert_eq!(got_node.node_type, node.node_type);
        assert_eq!(got_node.epochs, node.epochs);
    } else {
        panic!("Failed to retrieve History Tree Node");
    }

    let get_result = storage.get_all::<Blake3, HistoryTreeNode>(None).await;
    if let Ok(nodes) = get_result {
        assert_eq!(nodes.len(), 2);
    } else {
        panic!("Failed to retrieve history tree nodes from database");
    }

    // === HistoryNodeState storage === //
    // TODO: test the history node state storage

    // === UserState storage === //
    // TODO: test with this format of user storage
}

async fn async_test_new_user_data<S: V2Storage + Sync + Send>(storage: &S) {
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
    let mut sample_state = UserState {
        plaintext_val: Values(rand_value.clone()),
        version: 1u64,
        label: NodeLabel {
            val: 1u64,
            len: 1u32,
        },
        epoch: 1u64,
        username: Username(rand_user),
    };
    let mut sample_state_2 = sample_state.clone();
    sample_state_2.username = Username("test_user".to_string());

    let result = storage.append_user_state::<Blake3>(&sample_state).await;
    assert_eq!(Ok(()), result);

    sample_state.version = 2u64;
    sample_state.epoch = 123u64;
    let result = storage.append_user_state::<Blake3>(&sample_state).await;
    assert_eq!(Ok(()), result);

    sample_state.version = 3u64;
    sample_state.epoch = 456u64;
    let result = storage.append_user_state::<Blake3>(&sample_state).await;
    assert_eq!(Ok(()), result);

    let data = storage
        .get_user_data::<Blake3>(&sample_state.username)
        .await
        .unwrap();
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
        .get_user_state::<Blake3>(
            &sample_state.username,
            UserStateRetrievalFlag::SpecificVersion(2),
        )
        .await;
    assert_eq!(
        Ok(UserState {
            epoch: 123,
            version: 2,
            label: NodeLabel { val: 1, len: 1 },
            plaintext_val: Values(rand_value.clone()),
            username: sample_state.username.clone(),
        }),
        specific_result
    );

    let specifc_result = storage
        .get::<Blake3, crate::storage::types::UserState>(crate::storage::types::UserStateKey(
            sample_state.username.0.clone(),
            123,
        ))
        .await;
    if let Ok(DbRecord::UserState(state)) = specifc_result {
        assert_eq!(
            UserState {
                epoch: 123,
                version: 2,
                label: NodeLabel { val: 1, len: 1 },
                plaintext_val: Values(rand_value.clone()),
                username: sample_state.username.clone(),
            },
            state
        );
    } else {
        panic!("Unable to retrieve user state object");
    }

    let missing_result = storage
        .get_user_state::<Blake3>(
            &sample_state.username,
            UserStateRetrievalFlag::SpecificVersion(100),
        )
        .await;
    assert_eq!(
        Err(StorageError::GetError(String::from("Not found"))),
        missing_result
    );

    let specific_result = storage
        .get_user_state::<Blake3>(
            &sample_state.username,
            UserStateRetrievalFlag::SpecificEpoch(123),
        )
        .await;
    assert_eq!(
        Ok(UserState {
            epoch: 123,
            version: 2,
            label: NodeLabel { val: 1, len: 1 },
            plaintext_val: Values(rand_value.clone()),
            username: sample_state.username.clone(),
        }),
        specific_result
    );

    let specific_result = storage
        .get_user_state::<Blake3>(&sample_state.username, UserStateRetrievalFlag::MinEpoch)
        .await;
    assert_eq!(
        Ok(UserState {
            epoch: 1,
            version: 1,
            label: NodeLabel { val: 1, len: 1 },
            plaintext_val: Values(rand_value.clone()),
            username: sample_state.username.clone(),
        }),
        specific_result
    );
    let specific_result = storage
        .get_user_state::<Blake3>(&sample_state.username, UserStateRetrievalFlag::MinVersion)
        .await;
    assert_eq!(
        Ok(UserState {
            epoch: 1,
            version: 1,
            label: NodeLabel { val: 1, len: 1 },
            plaintext_val: Values(rand_value.clone()),
            username: sample_state.username.clone(),
        }),
        specific_result
    );

    let specific_result = storage
        .get_user_state::<Blake3>(&sample_state.username, UserStateRetrievalFlag::MaxEpoch)
        .await;
    assert_eq!(
        Ok(UserState {
            epoch: 456,
            version: 3,
            label: NodeLabel { val: 1, len: 1 },
            plaintext_val: Values(rand_value.clone()),
            username: sample_state.username.clone(),
        }),
        specific_result
    );
    let specific_result = storage
        .get_user_state::<Blake3>(&sample_state.username, UserStateRetrievalFlag::MaxVersion)
        .await;
    assert_eq!(
        Ok(UserState {
            epoch: 456,
            version: 3,
            label: NodeLabel { val: 1, len: 1 },
            plaintext_val: Values(rand_value.clone()),
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

    let result = storage.append_user_states::<Blake3>(vector_of_states).await;
    assert_eq!(Ok(()), result);

    let data = storage
        .get_user_data::<Blake3>(&sample_state_2.username)
        .await
        .unwrap();
    assert_eq!(4, data.states.len());
}

// *** Helper Functions *** //

async fn async_test_get_and_set_item<S: V1Storage>(storage: &S) {
    let rand_string: String = thread_rng()
        .sample_iter(&Alphanumeric)
        .take(30)
        .map(char::from)
        .collect();
    let value: Vec<u8> = thread_rng()
        .sample_iter(&Alphanumeric)
        .take(30)
        .map(char::from)
        .collect::<String>()
        .as_bytes()
        .to_vec();

    let set_result = storage
        .set(rand_string.clone(), StorageType::Azks, &value)
        .await;
    assert_eq!(Ok(()), set_result);

    let storage_bytes = storage.get(rand_string, StorageType::Azks).await;
    assert_eq!(Ok(value), storage_bytes);

    let fake_key = "abc123".to_owned();
    let missing = storage.get(fake_key, StorageType::Azks).await;
    assert_eq!(
        Err(StorageError::GetError(String::from("Not found"))),
        missing
    );

    let all_azks = storage.get_all(StorageType::Azks, None).await;
    assert_eq!(1, all_azks.unwrap().len());
}

async fn async_test_user_data<S: V1Storage>(storage: &S) {
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
    let mut sample_state = UserState {
        plaintext_val: Values(rand_value.clone()),
        version: 1u64,
        label: NodeLabel {
            val: 1u64,
            len: 1u32,
        },
        epoch: 1u64,
        username: Username(rand_user.clone()),
    };
    let mut sample_state_2 = sample_state.clone();
    let username = Username(rand_user);
    let username_2 = Username("test_user".to_string());
    sample_state_2.username = username_2.clone();

    let result = storage.append_user_state(&username, &sample_state).await;
    assert_eq!(Ok(()), result);

    sample_state.version = 2u64;
    sample_state.epoch = 123u64;
    let result = storage.append_user_state(&username, &sample_state).await;
    assert_eq!(Ok(()), result);

    sample_state.version = 3u64;
    sample_state.epoch = 456u64;
    let result = storage.append_user_state(&username, &sample_state).await;
    assert_eq!(Ok(()), result);

    let data = storage.get_user_data(&username).await.unwrap();
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
        .get_user_state(&username, UserStateRetrievalFlag::SpecificVersion(2))
        .await;
    assert_eq!(
        Ok(UserState {
            epoch: 123,
            version: 2,
            label: NodeLabel { val: 1, len: 1 },
            plaintext_val: Values(rand_value.clone()),
            username: username.clone(),
        }),
        specific_result
    );

    let missing_result = storage
        .get_user_state(&username, UserStateRetrievalFlag::SpecificVersion(100))
        .await;
    assert_eq!(
        Err(StorageError::GetError(String::from("Not found"))),
        missing_result
    );

    let specific_result = storage
        .get_user_state(&username, UserStateRetrievalFlag::SpecificEpoch(123))
        .await;
    assert_eq!(
        Ok(UserState {
            epoch: 123,
            version: 2,
            label: NodeLabel { val: 1, len: 1 },
            plaintext_val: Values(rand_value.clone()),
            username: username.clone(),
        }),
        specific_result
    );

    let specific_result = storage
        .get_user_state(&username, UserStateRetrievalFlag::MinEpoch)
        .await;
    assert_eq!(
        Ok(UserState {
            epoch: 1,
            version: 1,
            label: NodeLabel { val: 1, len: 1 },
            plaintext_val: Values(rand_value.clone()),
            username: username.clone(),
        }),
        specific_result
    );
    let specific_result = storage
        .get_user_state(&username, UserStateRetrievalFlag::MinVersion)
        .await;
    assert_eq!(
        Ok(UserState {
            epoch: 1,
            version: 1,
            label: NodeLabel { val: 1, len: 1 },
            plaintext_val: Values(rand_value.clone()),
            username: username.clone(),
        }),
        specific_result
    );

    let specific_result = storage
        .get_user_state(&username, UserStateRetrievalFlag::MaxEpoch)
        .await;
    assert_eq!(
        Ok(UserState {
            epoch: 456,
            version: 3,
            label: NodeLabel { val: 1, len: 1 },
            plaintext_val: Values(rand_value.clone()),
            username: username.clone(),
        }),
        specific_result
    );
    let specific_result = storage
        .get_user_state(&username, UserStateRetrievalFlag::MaxVersion)
        .await;
    assert_eq!(
        Ok(UserState {
            epoch: 456,
            version: 3,
            label: NodeLabel { val: 1, len: 1 },
            plaintext_val: Values(rand_value.clone()),
            username: username.clone(),
        }),
        specific_result
    );

    // Vector operations

    let mut vector_of_states = vec![(username_2.clone(), sample_state_2.clone())];
    sample_state_2.version = 2;
    sample_state_2.epoch = 234;
    vector_of_states.push((username_2.clone(), sample_state_2.clone()));

    sample_state_2.version = 3;
    sample_state_2.epoch = 345;
    vector_of_states.push((username_2.clone(), sample_state_2.clone()));
    sample_state_2.version = 4;
    sample_state_2.epoch = 456;
    vector_of_states.push((username_2.clone(), sample_state_2.clone()));

    let result = storage.append_user_states(vector_of_states).await;
    assert_eq!(Ok(()), result);

    let data = storage.get_user_data(&username_2).await.unwrap();
    assert_eq!(4, data.states.len());
}
