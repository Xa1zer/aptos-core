// Copyright (c) Aptos
// SPDX-License-Identifier: Apache-2.0

//! This file defines state store APIs that are related account state Merkle tree.
use move_core_types::account_address::AccountAddress;

const ACCOUNT_ADDRESS_PREFIX: &str = "acc_blb_|";

#[derive(Clone, Debug)]
pub enum StateStoreKey {
    AccountStateKey(AccountAddress),
}

#[derive(Clone, Debug, PartialEq)]
pub struct RawStateStoreKey(Vec<u8>);

impl From<StateStoreKey> for RawStateStoreKey {
    fn from(key: StateStoreKey) -> Self {
        match key {
            StateStoreKey::AccountStateKey(account_address) => {
                let mut account_address_prefix = ACCOUNT_ADDRESS_PREFIX.as_bytes().to_vec();
                account_address_prefix.extend(account_address.to_vec());
                RawStateStoreKey(account_address_prefix)
            }
        }
    }
}
