// Copyright (c) Aptos
// SPDX-License-Identifier: Apache-2.0

use crate::{
    account_address::HashAccountAddress,
    account_state_blob::AccountStateBlob,
    ledger_info::LedgerInfo,
    proof::{ResourceValueProof, SparseMerkleRangeProof},
    transaction::Version,
};
use anyhow::ensure;
use aptos_crypto::{
    hash::{CryptoHash, CryptoHasher},
    HashValue,
};
use aptos_crypto_derive::CryptoHasher;
use move_core_types::account_address::AccountAddress;
use proptest_derive::Arbitrary;
use serde::{Deserialize, Deserializer, Serialize};

const ACCOUNT_ADDRESS_KEY_PREFIX: &str = "acc_blb_|";

#[derive(
    Arbitrary,
    Clone,
    Debug,
    CryptoHasher,
    Eq,
    PartialEq,
    Serialize,
    Deserialize,
    Ord,
    PartialOrd,
    Hash,
)]
pub enum ResourceKey {
    AccountAddressKey(AccountAddress),
}

#[derive(Arbitrary, Clone, Default, Debug, CryptoHasher, Eq, PartialEq, Serialize, Deserialize)]
pub struct ResourceValue {
    pub bytes: Vec<u8>,
}

struct RawStateKey {
    bytes: Vec<u8>,
}

impl From<&ResourceKey> for RawStateKey {
    fn from(key: &ResourceKey) -> Self {
        match key {
            ResourceKey::AccountAddressKey(account_address) => {
                let mut account_address_prefix = ACCOUNT_ADDRESS_KEY_PREFIX.as_bytes().to_vec();
                account_address_prefix.extend(account_address.to_vec());
                RawStateKey {
                    bytes: account_address_prefix,
                }
            }
        }
    }
}

impl From<AccountStateBlob> for ResourceValue {
    fn from(account_state_blob: AccountStateBlob) -> Self {
        ResourceValue {
            bytes: account_state_blob.blob,
        }
    }
}

impl CryptoHash for ResourceKey {
    type Hasher = ResourceKeyHasher;

    fn hash(&self) -> HashValue {
        let mut state = Self::Hasher::default();
        state.update(RawStateKey::from(self).bytes.as_ref());
        state.finish()
    }
}

impl CryptoHash for ResourceValue {
    type Hasher = ResourceValueHasher;

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
pub struct ResourceValueChunkWithProof {
    pub first_index: u64,     // The first account index in chunk
    pub last_index: u64,      // The last account index in chunk
    pub first_key: HashValue, // The first account key in chunk
    pub last_key: HashValue,  // The last account key in chunk
    pub raw_values: Vec<(HashValue, ResourceValue)>, // The account blobs in the chunk
    pub proof: SparseMerkleRangeProof, // The proof to ensure the chunk is in the account states
    pub root_hash: HashValue, // The root hash of the sparse merkle tree for this chunk
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(any(test, feature = "fuzzing"), derive(Arbitrary))]
pub struct ResourceValueWithProof {
    /// The transaction version at which this account state is seen.
    pub version: Version,
    /// Value represents the value in state store. If this field is not set, it
    /// means the key does not exist.
    pub value: Option<ResourceValue>,
    /// The proof the client can use to authenticate the value.
    pub proof: ResourceValueProof,
}

impl ResourceValueWithProof {
    /// Constructor.
    pub fn new(version: Version, value: Option<ResourceValue>, proof: ResourceValueProof) -> Self {
        Self {
            version,
            value,
            proof,
        }
    }

    /// Verifies the state store value with the proof, both carried by `self`.
    ///
    /// Two things are ensured if no error is raised:
    ///   1. This value exists in the ledger represented by `ledger_info`.
    ///   2. It belongs to state_store_key and is seen at the time the transaction at version
    /// `state_version` is just committed. To make sure this is the latest state, pass in
    /// `ledger_info.version()` as `state_version`.
    pub fn verify(
        &self,
        ledger_info: &LedgerInfo,
        version: Version,
        state_store_key: ResourceKey,
    ) -> anyhow::Result<()> {
        ensure!(
            self.version == version,
            "State version ({}) is not expected ({}).",
            self.version,
            version,
        );

        self.proof.verify(
            ledger_info,
            version,
            state_store_key.hash(),
            self.value.as_ref(),
        )
    }
}
