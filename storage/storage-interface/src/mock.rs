// Copyright (c) Aptos
// SPDX-License-Identifier: Apache-2.0

//! This module provides mock dbreader for tests.

use crate::{DbReader, DbWriter};
use anyhow::Result;
use aptos_types::{
    account_address::AccountAddress,
    account_config::AccountResource,
    account_state::AccountState,
    account_state_blob::AccountStateBlob,
    state_store::{state_store_key::StateStoreKey, state_store_value::StateStoreValue},
};
use move_core_types::move_resource::MoveResource;
use std::convert::TryFrom;

/// This is a mock of the DbReaderWriter in tests.
pub struct MockDbReaderWriter;

impl DbReader for MockDbReaderWriter {
    fn get_latest_value(&self, _resource_key: StateStoreKey) -> Result<Option<StateStoreValue>> {
        Ok(Some(get_mock_account_state_blob()))
    }
}

fn get_mock_account_state_blob() -> StateStoreValue {
    let account_resource = AccountResource::new(0, vec![], AccountAddress::random());

    let mut account_state = AccountState::default();
    account_state.insert(
        AccountResource::resource_path(),
        bcs::to_bytes(&account_resource).unwrap(),
    );

    StateStoreValue::from(AccountStateBlob::try_from(&account_state).unwrap())
}

impl DbWriter for MockDbReaderWriter {}
