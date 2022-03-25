// Copyright (c) Aptos
// SPDX-License-Identifier: Apache-2.0

use crate::account_state::AccountState;
use crate::{account_state_blob::AccountStateBlob, proof::SparseMerkleRangeProof};
use aptos_crypto::{
    hash::{CryptoHash, CryptoHasher},
    HashValue,
};
use aptos_crypto_derive::CryptoHasher;
use move_core_types::account_address::AccountAddress;
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;

const ACCOUNT_ADDRESS_KEY_PREFIX: &str = "acc_blb_|";

#[derive(
    Clone, Debug, CryptoHasher, Eq, PartialEq, Serialize, Deserialize, Ord, PartialOrd, Hash,
)]
pub enum StateStoreKey {
    AccountAddressKey(AccountAddress),
}

#[derive(Clone, Debug, CryptoHasher, Eq, PartialEq, Serialize, Deserialize)]
pub struct StateStoreValue {
    pub bytes: Vec<u8>,
}

struct RawStateKey {
    bytes: Vec<u8>,
}

impl From<&StateStoreKey> for RawStateKey {
    fn from(key: &StateStoreKey) -> Self {
        match key {
            StateStoreKey::AccountAddressKey(account_address) => {
                let mut account_address_prefix = ACCOUNT_ADDRESS_KEY_PREFIX.as_bytes().to_vec();
                account_address_prefix.extend(account_address.to_vec());
                RawStateKey {
                    bytes: account_address_prefix,
                }
            }
        }
    }
}

impl CryptoHash for StateStoreKey {
    type Hasher = StateStoreKeyHasher;

    fn hash(&self) -> HashValue {
        let mut state = Self::Hasher::default();
        state.update(RawStateKey::from(self).bytes.as_ref());
        state.finish()
    }
}

impl CryptoHash for StateStoreValue {
    type Hasher = StateStoreValueHasher;

    fn hash(&self) -> HashValue {
        let mut state = Self::Hasher::default();
        state.update(self.bytes.as_ref());
        state.finish()
    }
}

/// TODO(joshlind): add a proof implementation (e.g., verify()) and unit tests
/// for these once we start supporting them.
///
/// A single chunk of all state values at a specific version.
/// Note: this is similar to `StateSnapshotChunk` but all data is included
/// in the struct itself and not behind pointers/handles to file locations.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RawStateValueChunkWithProof {
    pub first_index: u64,     // The first account index in chunk
    pub last_index: u64,      // The last account index in chunk
    pub first_key: HashValue, // The first account key in chunk
    pub last_key: HashValue,  // The last account key in chunk
    pub raw_values: Vec<(HashValue, StateStoreValue)>, // The account blobs in the chunk
    pub proof: SparseMerkleRangeProof, // The proof to ensure the chunk is in the account states
    pub root_hash: HashValue, // The root hash of the sparse merkle tree for this chunk
}
