// Copyright (c) Aptos
// SPDX-License-Identifier: Apache-2.0

use crate::DbReader;
use anyhow::{format_err, Result};
use aptos_crypto::{
    hash::{CryptoHash, SPARSE_MERKLE_PLACEHOLDER_HASH},
    HashValue,
};
use aptos_state_view::{StateView, StateViewId};
use aptos_types::{
    access_path::AccessPath,
    account_state::AccountState,
    proof::SparseMerkleProof,
    state_store_key::{ResourceKey, ResourceValue},
    transaction::{Version, PRE_GENESIS_VERSION},
};
use parking_lot::RwLock;
use scratchpad::{FrozenSparseMerkleTree, SparseMerkleTree, StateStoreStatus};
use std::{collections::HashMap, convert::TryFrom, sync::Arc};

/// `VerifiedStateView` is like a snapshot of the global state comprised of state view at two
/// levels, persistent storage and memory.
pub struct VerifiedStateView {
    /// For logging and debugging purpose, identifies what this view is for.
    id: StateViewId,

    /// A gateway implementing persistent storage interface, which can be a RPC client or direct
    /// accessor.
    reader: Arc<dyn DbReader>,

    /// The most recent version in persistent storage.
    latest_persistent_version: Option<Version>,

    /// The most recent state root hash in persistent storage.
    latest_persistent_state_root: HashValue,

    /// The in-momery version of sparse Merkle tree of which the states haven't been committed.
    speculative_state: FrozenSparseMerkleTree<ResourceValue>,

    /// The cache of verified account states from `reader` and `speculative_state_view`,
    /// represented by a hashmap with an account address as key and a pair of an ordered
    /// account state map and an an optional account state proof as value. When the VM queries an
    /// `access_path`, this cache will first check whether `reader_cache` is hit. If hit, it
    /// will return the corresponding value of that `access_path`; otherwise, the account state
    /// will be loaded into the cache from scratchpad or persistent storage in order as a
    /// deserialized ordered map and then be returned. If the VM queries this account again,
    /// the cached data can be read directly without bothering storage layer. The proofs in
    /// cache are needed by ScratchPad after VM execution to construct an in-memory sparse Merkle
    /// tree.
    /// ```text
    ///                      +----------------------------+
    ///                      | In-memory SparseMerkleTree <------+
    ///                      +-------------^--------------+      |
    ///                                    |                     |
    ///                                write sets                |
    ///                                    |          cached account state map
    ///                            +-------+-------+           proof
    ///                            |      V M      |             |
    ///                            +-------^-------+             |
    ///                                    |                     |
    ///                      value of `account_address/path`     |
    ///                                    |                     |
    ///        +---------------------------+---------------------+-------+
    ///        | +-------------------------+---------------------+-----+ |
    ///        | |           state_cache,     account_to_proof_cache   | |
    ///        | +---------------^---------------------------^---------+ |
    ///        |                 |                           |           |
    ///        |     state store values only        account state blob   |
    ///        |                 |                         proof         |
    ///        |                 |                           |           |
    ///        | +---------------+--------------+ +----------+---------+ |
    ///        | |      speculative_state       | |       reader       | |
    ///        | +------------------------------+ +--------------------+ |
    ///        +---------------------------------------------------------+
    /// ```
    state_cache: RwLock<HashMap<ResourceKey, ResourceValue>>,
    /// TODO(skedia): This is very account related logic, that needs to be moved out of storage layer.
    /// Will be addressed in a follow up diff.
    state_proof_cache: RwLock<HashMap<HashValue, SparseMerkleProof<ResourceValue>>>,
}

impl VerifiedStateView {
    /// Constructs a [`VerifiedStateView`] with persistent state view represented by
    /// `latest_persistent_state_root` plus a storage reader, and the in-memory speculative state
    /// on top of it represented by `speculative_state`.
    pub fn new(
        id: StateViewId,
        reader: Arc<dyn DbReader>,
        latest_persistent_version: Option<Version>,
        latest_persistent_state_root: HashValue,
        speculative_state: SparseMerkleTree<ResourceValue>,
    ) -> Self {
        // Hack: When there's no transaction in the db but state tree root hash is not the
        // placeholder hash, it implies that there's pre-genesis state present.
        let latest_persistent_version = latest_persistent_version.or_else(|| {
            if latest_persistent_state_root != *SPARSE_MERKLE_PLACEHOLDER_HASH {
                Some(PRE_GENESIS_VERSION)
            } else {
                None
            }
        });
        Self {
            id,
            reader,
            latest_persistent_version,
            latest_persistent_state_root,
            speculative_state: speculative_state.freeze(),
            state_cache: RwLock::new(HashMap::new()),
            state_proof_cache: RwLock::new(HashMap::new()),
        }
    }

    pub fn into_state_cache(self) -> StateCache {
        StateCache {
            frozen_base: self.speculative_state,
            state: self.state_cache.into_inner(),
            proofs: self.state_proof_cache.into_inner(),
        }
    }
}

pub struct StateCache {
    pub frozen_base: FrozenSparseMerkleTree<ResourceValue>,
    pub state: HashMap<ResourceKey, ResourceValue>,
    pub proofs: HashMap<HashValue, SparseMerkleProof<ResourceValue>>,
}

impl StateView for VerifiedStateView {
    fn id(&self) -> StateViewId {
        self.id
    }

    fn get(&self, access_path: &AccessPath) -> Result<Option<Vec<u8>>> {
        let address = access_path.address;
        let path = &access_path.path;
        let state_store_key = ResourceKey::AccountAddressKey(address);

        // Lock for read first:
        if let Some(content) = self
            .state_cache
            .read()
            .get(&ResourceKey::AccountAddressKey(address))
        {
            return Ok(AccountState::try_from(content)
                .unwrap_or_default()
                .get(path)
                .cloned());
        }

        // Do most of the work outside the write lock.
        let key_hash = state_store_key.hash();
        let state_store_value_option = match self.speculative_state.get(key_hash) {
            StateStoreStatus::ExistsInScratchPad(blob) => Some(blob),
            StateStoreStatus::DoesNotExist => None,
            // No matter it is in db or unknown, we have to query from db since even the
            // former case, we don't have the blob data but only its hash.
            StateStoreStatus::ExistsInDB | StateStoreStatus::Unknown => {
                let (state_store_value, proof) = match self.latest_persistent_version {
                    Some(version) => self
                        .reader
                        .get_value_with_proof_by_version(state_store_key.clone(), version)?,
                    None => (None, SparseMerkleProof::new(None, vec![])),
                };
                proof
                    .verify(
                        self.latest_persistent_state_root,
                        key_hash,
                        state_store_value.as_ref(),
                    )
                    .map_err(|err| {
                        format_err!(
                            "Proof is invalid for address {:?} with state root hash {:?}: {}",
                            address,
                            self.latest_persistent_state_root,
                            err
                        )
                    })?;

                // multiple threads may enter this code, and another thread might add
                // an address before this one. Thus the insertion might return a None here.
                self.state_proof_cache.write().insert(key_hash, proof);

                state_store_value
            }
        };

        let mut state_cache = self.state_cache.write();
        let state_store_value = state_cache
            .entry(state_store_key)
            .or_insert_with(|| state_store_value_option.unwrap_or_default());
        Ok(AccountState::try_from(&*state_store_value)
            .unwrap_or_default()
            .get(path)
            .cloned())
    }

    fn is_genesis(&self) -> bool {
        self.latest_persistent_version.is_none()
    }
}
