// Copyright (c) Aptos
// SPDX-License-Identifier: Apache-2.0

#![forbid(unsafe_code)]

//! This crate provides [`AptosDB`] which represents physical storage of the core Diem data
//! structures.
//!
//! It relays read/write operations on the physical storage via [`schemadb`] to the underlying
//! Key-Value storage system, and implements diem data structures on top of it.

#[cfg(any(feature = "aptossum"))]
pub mod aptossum;
// Used in this and other crates for testing.
#[cfg(any(test, feature = "fuzzing"))]
pub mod test_helper;

pub mod backup;
pub mod errors;
pub mod metrics;
pub mod schema;

mod change_set;
mod event_store;
mod ledger_counters;
mod ledger_store;
mod pruner;
mod state_store;
mod system_store;
mod transaction_store;

#[cfg(any(test, feature = "fuzzing"))]
#[allow(dead_code)]
mod aptosdb_test;

#[cfg(feature = "fuzzing")]
pub use aptosdb_test::test_save_blocks_impl;

use crate::{
    backup::{backup_handler::BackupHandler, restore_handler::RestoreHandler},
    change_set::{ChangeSet, SealedChangeSet},
    errors::AptosDbError,
    event_store::EventStore,
    ledger_counters::LedgerCounters,
    ledger_store::LedgerStore,
    metrics::{
        DIEM_STORAGE_API_LATENCY_SECONDS, DIEM_STORAGE_COMMITTED_TXNS,
        DIEM_STORAGE_LATEST_ACCOUNT_COUNT, DIEM_STORAGE_LATEST_TXN_VERSION,
        DIEM_STORAGE_LEDGER_VERSION, DIEM_STORAGE_NEXT_BLOCK_EPOCH,
        DIEM_STORAGE_OTHER_TIMERS_SECONDS, DIEM_STORAGE_ROCKSDB_PROPERTIES,
    },
    pruner::Pruner,
    schema::*,
    state_store::StateStore,
    system_store::SystemStore,
    transaction_store::TransactionStore,
};
use anyhow::{ensure, format_err, Result};
use aptos_config::config::{RocksdbConfig, StoragePrunerConfig, NO_OP_STORAGE_PRUNER_CONFIG};
use aptos_crypto::hash::{HashValue, SPARSE_MERKLE_PLACEHOLDER_HASH};
use aptos_logger::prelude::*;
use aptos_types::{
    account_address::AccountAddress,
    account_state::AccountState,
    account_state_blob::AccountStateBlob,
    contract_event::{ContractEvent, EventByVersionWithProof, EventWithProof},
    epoch_change::EpochChangeProof,
    event::EventKey,
    ledger_info::LedgerInfoWithSignatures,
    proof::{
        AccumulatorConsistencyProof, EventProof, ResourceValueProof, SparseMerkleProof,
        TransactionInfoListWithProof,
    },
    state_proof::StateProof,
    state_store_key::{
        ResourceKey, ResourceValue, ResourceValueChunkWithProof, ResourceValueWithProof,
    },
    transaction::{
        AccountTransactionsWithProof, TransactionInfo, TransactionListWithProof, TransactionOutput,
        TransactionOutputListWithProof, TransactionToCommit, TransactionWithProof, Version,
        PRE_GENESIS_VERSION,
    },
};
use itertools::zip_eq;
use move_core_types::{
    language_storage::{ModuleId, StructTag},
    resolver::{ModuleResolver, ResourceResolver},
};
use once_cell::sync::Lazy;
use schemadb::{ColumnFamilyName, Options, DB, DEFAULT_CF_NAME};
use std::{
    collections::HashMap,
    convert::TryFrom,
    iter::Iterator,
    path::Path,
    sync::{mpsc, Arc, Mutex},
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};
use storage_interface::{
    DbReader, DbWriter, MoveDbReader, Order, StartupInfo, StateSnapshotReceiver, TreeState,
};

const MAX_LIMIT: u64 = 5000;

// TODO: Either implement an iteration API to allow a very old client to loop through a long history
// or guarantee that there is always a recent enough waypoint and client knows to boot from there.
const MAX_NUM_EPOCH_ENDING_LEDGER_INFO: usize = 100;
static ROCKSDB_PROPERTY_MAP: Lazy<HashMap<&str, String>> = Lazy::new(|| {
    [
        "rocksdb.num-immutable-mem-table",
        "rocksdb.mem-table-flush-pending",
        "rocksdb.compaction-pending",
        "rocksdb.background-errors",
        "rocksdb.cur-size-active-mem-table",
        "rocksdb.cur-size-all-mem-tables",
        "rocksdb.size-all-mem-tables",
        "rocksdb.num-entries-active-mem-table",
        "rocksdb.num-entries-imm-mem-tables",
        "rocksdb.num-deletes-active-mem-table",
        "rocksdb.num-deletes-imm-mem-tables",
        "rocksdb.estimate-num-keys",
        "rocksdb.estimate-table-readers-mem",
        "rocksdb.is-file-deletions-enabled",
        "rocksdb.num-snapshots",
        "rocksdb.oldest-snapshot-time",
        "rocksdb.num-live-versions",
        "rocksdb.current-super-version-number",
        "rocksdb.estimate-live-data-size",
        "rocksdb.min-log-number-to-keep",
        "rocksdb.min-obsolete-sst-number-to-keep",
        "rocksdb.total-sst-files-size",
        "rocksdb.live-sst-files-size",
        "rocksdb.base-level",
        "rocksdb.estimate-pending-compaction-bytes",
        "rocksdb.num-running-compactions",
        "rocksdb.num-running-flushes",
        "rocksdb.actual-delayed-write-rate",
        "rocksdb.is-write-stopped",
        "rocksdb.block-cache-capacity",
        "rocksdb.block-cache-usage",
        "rocksdb.block-cache-pinned-usage",
    ]
    .iter()
    .map(|x| (*x, format!("aptos_{}", x.replace(".", "_"))))
    .collect()
});

fn error_if_too_many_requested(num_requested: u64, max_allowed: u64) -> Result<()> {
    if num_requested > max_allowed {
        Err(AptosDbError::TooManyRequested(num_requested, max_allowed).into())
    } else {
        Ok(())
    }
}

fn gen_rocksdb_options(config: &RocksdbConfig) -> Options {
    let mut db_opts = Options::default();
    db_opts.set_max_open_files(config.max_open_files);
    db_opts.set_max_total_wal_size(config.max_total_wal_size);
    db_opts
}

fn update_rocksdb_properties(db: &DB) -> Result<()> {
    let _timer = DIEM_STORAGE_OTHER_TIMERS_SECONDS
        .with_label_values(&["update_rocksdb_properties"])
        .start_timer();
    for cf_name in AptosDB::column_families() {
        for (rockdb_property_name, aptos_rocksdb_property_name) in &*ROCKSDB_PROPERTY_MAP {
            DIEM_STORAGE_ROCKSDB_PROPERTIES
                .with_label_values(&[cf_name, aptos_rocksdb_property_name])
                .set(db.get_property(cf_name, rockdb_property_name)? as i64);
        }
    }
    Ok(())
}

#[derive(Debug)]
struct RocksdbPropertyReporter {
    sender: Mutex<mpsc::Sender<()>>,
    join_handle: Option<JoinHandle<()>>,
}

impl RocksdbPropertyReporter {
    fn new(db: Arc<DB>) -> Self {
        let (send, recv) = mpsc::channel();
        let join_handle = Some(thread::spawn(move || loop {
            if let Err(e) = update_rocksdb_properties(&db) {
                warn!(
                    error = ?e,
                    "Updating rocksdb property failed."
                );
            }
            // report rocksdb properties each 10 seconds
            match recv.recv_timeout(Duration::from_secs(10)) {
                Ok(_) => break,
                Err(mpsc::RecvTimeoutError::Timeout) => (),
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            }
        }));
        Self {
            sender: Mutex::new(send),
            join_handle,
        }
    }
}

impl Drop for RocksdbPropertyReporter {
    fn drop(&mut self) {
        // Notify the property reporting thread to exit
        self.sender.lock().unwrap().send(()).unwrap();
        self.join_handle
            .take()
            .expect("Rocksdb property reporting thread must exist.")
            .join()
            .expect("Rocksdb property reporting thread should join peacefully.");
    }
}

/// This holds a handle to the underlying DB responsible for physical storage and provides APIs for
/// access to the core Diem data structures.
#[derive(Debug)]
pub struct AptosDB {
    db: Arc<DB>,
    ledger_store: Arc<LedgerStore>,
    transaction_store: Arc<TransactionStore>,
    state_store: Arc<StateStore>,
    event_store: Arc<EventStore>,
    system_store: Arc<SystemStore>,
    rocksdb_property_reporter: RocksdbPropertyReporter,
    pruner: Option<Pruner>,
}

impl AptosDB {
    fn column_families() -> Vec<ColumnFamilyName> {
        vec![
            /* LedgerInfo CF = */ DEFAULT_CF_NAME,
            EPOCH_BY_VERSION_CF_NAME,
            EVENT_ACCUMULATOR_CF_NAME,
            EVENT_BY_KEY_CF_NAME,
            EVENT_BY_VERSION_CF_NAME,
            EVENT_CF_NAME,
            JELLYFISH_MERKLE_NODE_CF_NAME,
            LEDGER_COUNTERS_CF_NAME,
            STALE_NODE_INDEX_CF_NAME,
            TRANSACTION_CF_NAME,
            TRANSACTION_ACCUMULATOR_CF_NAME,
            TRANSACTION_BY_ACCOUNT_CF_NAME,
            TRANSACTION_BY_HASH_CF_NAME,
            TRANSACTION_INFO_CF_NAME,
            WRITE_SET_CF_NAME,
        ]
    }

    fn new_with_db(db: DB, storage_pruner_config: StoragePrunerConfig) -> Self {
        let db = Arc::new(db);
        let transaction_store = Arc::new(TransactionStore::new(Arc::clone(&db)));
        let event_store = Arc::new(EventStore::new(Arc::clone(&db)));
        let ledger_store = Arc::new(LedgerStore::new(Arc::clone(&db)));
        let system_store = Arc::new(SystemStore::new(Arc::clone(&db)));

        AptosDB {
            db: Arc::clone(&db),
            event_store: Arc::clone(&event_store),
            ledger_store: Arc::clone(&ledger_store),
            state_store: Arc::new(StateStore::new(Arc::clone(&db))),
            transaction_store: Arc::clone(&transaction_store),
            system_store: Arc::clone(&system_store),
            rocksdb_property_reporter: RocksdbPropertyReporter::new(Arc::clone(&db)),
            pruner: match storage_pruner_config {
                NO_OP_STORAGE_PRUNER_CONFIG => None,
                _ => Some(Pruner::new(
                    Arc::clone(&db),
                    storage_pruner_config,
                    transaction_store,
                    ledger_store,
                    event_store,
                )),
            },
        }
    }

    pub fn open<P: AsRef<Path> + Clone>(
        db_root_path: P,
        readonly: bool,
        storage_pruner_config: StoragePrunerConfig,
        rocksdb_config: RocksdbConfig,
    ) -> Result<Self> {
        ensure!(
            storage_pruner_config.eq(&NO_OP_STORAGE_PRUNER_CONFIG) || !readonly,
            "Do not set prune_window when opening readonly.",
        );

        let path = db_root_path.as_ref().join("aptosdb");
        let instant = Instant::now();

        let mut rocksdb_opts = gen_rocksdb_options(&rocksdb_config);

        let db = if readonly {
            DB::open_readonly(
                path.clone(),
                "aptosdb_ro",
                Self::column_families(),
                &rocksdb_opts,
            )?
        } else {
            rocksdb_opts.create_if_missing(true);
            rocksdb_opts.create_missing_column_families(true);
            DB::open(
                path.clone(),
                "aptosdb",
                Self::column_families(),
                &rocksdb_opts,
            )?
        };

        let ret = Self::new_with_db(db, storage_pruner_config);
        info!(
            path = path,
            time_ms = %instant.elapsed().as_millis(),
            "Opened AptosDB.",
        );
        Ok(ret)
    }

    pub fn open_as_secondary<P: AsRef<Path> + Clone>(
        db_root_path: P,
        secondary_path: P,
        mut rocksdb_config: RocksdbConfig,
    ) -> Result<Self> {
        let primary_path = db_root_path.as_ref().join("aptosdb");
        let secondary_path = secondary_path.as_ref().to_path_buf();
        // Secondary needs `max_open_files = -1` per https://github.com/facebook/rocksdb/wiki/Secondary-instance
        rocksdb_config.max_open_files = -1;
        let rocksdb_opts = gen_rocksdb_options(&rocksdb_config);

        Ok(Self::new_with_db(
            DB::open_as_secondary(
                primary_path,
                secondary_path,
                "aptosdb_sec",
                Self::column_families(),
                &rocksdb_opts,
            )?,
            NO_OP_STORAGE_PRUNER_CONFIG,
        ))
    }

    /// This opens db in non-readonly mode, without the pruner.
    #[cfg(any(test, feature = "fuzzing"))]
    pub fn new_for_test<P: AsRef<Path> + Clone>(db_root_path: P) -> Self {
        Self::open(
            db_root_path,
            false,                       /* readonly */
            NO_OP_STORAGE_PRUNER_CONFIG, /* pruner */
            RocksdbConfig::default(),
        )
        .expect("Unable to open AptosDB")
    }

    /// This force the db to update rocksdb properties immediately.
    pub fn update_rocksdb_properties(&self) -> Result<()> {
        update_rocksdb_properties(&self.db)
    }

    /// Returns ledger infos reflecting epoch bumps starting with the given epoch. If there are no
    /// more than `MAX_NUM_EPOCH_ENDING_LEDGER_INFO` results, this function returns all of them,
    /// otherwise the first `MAX_NUM_EPOCH_ENDING_LEDGER_INFO` results are returned and a flag
    /// (when true) will be used to indicate the fact that there is more.
    fn get_epoch_ending_ledger_infos(
        &self,
        start_epoch: u64,
        end_epoch: u64,
    ) -> Result<(Vec<LedgerInfoWithSignatures>, bool)> {
        self.get_epoch_ending_ledger_infos_impl(
            start_epoch,
            end_epoch,
            MAX_NUM_EPOCH_ENDING_LEDGER_INFO,
        )
    }

    fn get_epoch_ending_ledger_infos_impl(
        &self,
        start_epoch: u64,
        end_epoch: u64,
        limit: usize,
    ) -> Result<(Vec<LedgerInfoWithSignatures>, bool)> {
        ensure!(
            start_epoch <= end_epoch,
            "Bad epoch range [{}, {})",
            start_epoch,
            end_epoch,
        );
        // Note that the latest epoch can be the same with the current epoch (in most cases), or
        // current_epoch + 1 (when the latest ledger_info carries next validator set)
        let latest_epoch = self
            .ledger_store
            .get_latest_ledger_info()?
            .ledger_info()
            .next_block_epoch();
        ensure!(
            end_epoch <= latest_epoch,
            "Unable to provide epoch change ledger info for still open epoch. asked upper bound: {}, last sealed epoch: {}",
            end_epoch,
            latest_epoch - 1,  // okay to -1 because genesis LedgerInfo has .next_block_epoch() == 1
        );

        let (paging_epoch, more) = if end_epoch - start_epoch > limit as u64 {
            (start_epoch + limit as u64, true)
        } else {
            (end_epoch, false)
        };

        let lis = self
            .ledger_store
            .get_epoch_ending_ledger_info_iter(start_epoch, paging_epoch)?
            .collect::<Result<Vec<_>>>()?;
        ensure!(
            lis.len() == (paging_epoch - start_epoch) as usize,
            "DB corruption: missing epoch ending ledger info for epoch {}",
            lis.last()
                .map(|li| li.ledger_info().next_block_epoch())
                .unwrap_or(start_epoch),
        );
        Ok((lis, more))
    }

    fn get_transaction_with_proof(
        &self,
        version: Version,
        ledger_version: Version,
        fetch_events: bool,
    ) -> Result<TransactionWithProof> {
        let proof = self
            .ledger_store
            .get_transaction_info_with_proof(version, ledger_version)?;
        let transaction = self.transaction_store.get_transaction(version)?;

        // If events were requested, also fetch those.
        let events = if fetch_events {
            Some(self.event_store.get_events_by_version(version)?)
        } else {
            None
        };

        Ok(TransactionWithProof {
            version,
            transaction,
            events,
            proof,
        })
    }

    // ================================== Backup APIs ===================================

    /// Gets an instance of `BackupHandler` for data backup purpose.
    pub fn get_backup_handler(&self) -> BackupHandler {
        BackupHandler::new(
            Arc::clone(&self.ledger_store),
            Arc::clone(&self.transaction_store),
            Arc::clone(&self.state_store),
            Arc::clone(&self.event_store),
        )
    }

    /// Creates new physical DB checkpoint in directory specified by `path`.
    pub fn create_checkpoint<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let start = Instant::now();
        self.db.create_checkpoint(&path).map(|_| {
            info!(
                path = path.as_ref(),
                time_ms = %start.elapsed().as_millis(),
                "Made AptosDB checkpoint."
            );
        })
    }

    // ================================== Private APIs ==================================
    fn get_events_with_proof_by_event_key(
        &self,
        event_key: &EventKey,
        start_seq_num: u64,
        order: Order,
        limit: u64,
        ledger_version: Version,
    ) -> Result<Vec<EventWithProof>> {
        error_if_too_many_requested(limit, MAX_LIMIT)?;
        let get_latest = order == Order::Descending && start_seq_num == u64::max_value();

        let cursor = if get_latest {
            // Caller wants the latest, figure out the latest seq_num.
            // In the case of no events on that path, use 0 and expect empty result below.
            self.event_store
                .get_latest_sequence_number(ledger_version, event_key)?
                .unwrap_or(0)
        } else {
            start_seq_num
        };

        // Convert requested range and order to a range in ascending order.
        let (first_seq, real_limit) = get_first_seq_num_and_limit(order, cursor, limit)?;

        // Query the index.
        let mut event_indices = self.event_store.lookup_events_by_key(
            event_key,
            first_seq,
            real_limit,
            ledger_version,
        )?;

        // When descending, it's possible that user is asking for something beyond the latest
        // sequence number, in which case we will consider it a bad request and return an empty
        // list.
        // For example, if the latest sequence number is 100, and the caller is asking for 110 to
        // 90, we will get 90 to 100 from the index lookup above. Seeing that the last item
        // is 100 instead of 110 tells us 110 is out of bound.
        if order == Order::Descending {
            if let Some((seq_num, _, _)) = event_indices.last() {
                if *seq_num < cursor {
                    event_indices = Vec::new();
                }
            }
        }

        let mut events_with_proof = event_indices
            .into_iter()
            .map(|(seq, ver, idx)| {
                let (event, event_proof) = self
                    .event_store
                    .get_event_with_proof_by_version_and_index(ver, idx)?;
                ensure!(
                    seq == event.sequence_number(),
                    "Index broken, expected seq:{}, actual:{}",
                    seq,
                    event.sequence_number()
                );
                let txn_info_with_proof = self
                    .ledger_store
                    .get_transaction_info_with_proof(ver, ledger_version)?;
                let proof = EventProof::new(txn_info_with_proof, event_proof);
                Ok(EventWithProof::new(ver, idx, event, proof))
            })
            .collect::<Result<Vec<_>>>()?;
        if order == Order::Descending {
            events_with_proof.reverse();
        }

        Ok(events_with_proof)
    }

    /// Convert a `ChangeSet` to `SealedChangeSet`.
    ///
    /// Specifically, counter increases are added to current counter values and converted to DB
    /// alternations.
    fn seal_change_set(
        &self,
        first_version: Version,
        num_txns: Version,
        mut cs: ChangeSet,
    ) -> Result<(SealedChangeSet, Option<LedgerCounters>)> {
        // Avoid reading base counter values when not necessary.
        let counters = if num_txns > 0 {
            Some(self.system_store.bump_ledger_counters(
                first_version,
                first_version + num_txns - 1,
                &mut cs,
            )?)
        } else {
            None
        };

        Ok((SealedChangeSet { batch: cs.batch }, counters))
    }

    fn save_transactions_impl(
        &self,
        txns_to_commit: &[TransactionToCommit],
        first_version: u64,
        mut cs: &mut ChangeSet,
    ) -> Result<HashValue> {
        let last_version = first_version + txns_to_commit.len() as u64 - 1;

        // Account state updates. Gather account state root hashes
        {
            let _timer = DIEM_STORAGE_OTHER_TIMERS_SECONDS
                .with_label_values(&["save_transactions_state"])
                .start_timer();

            let account_state_sets = txns_to_commit
                .iter()
                .map(|txn_to_commit| txn_to_commit.state_store_value_set())
                .collect::<Vec<_>>();

            let node_hashes = txns_to_commit
                .iter()
                .map(|txn_to_commit| txn_to_commit.jf_node_hashes())
                .collect::<Option<Vec<_>>>();
            self.state_store.put_value_sets(
                account_state_sets,
                node_hashes,
                first_version,
                &mut cs,
            )?;
        }

        // Event updates. Gather event accumulator root hashes.
        {
            let _timer = DIEM_STORAGE_OTHER_TIMERS_SECONDS
                .with_label_values(&["save_transactions_events"])
                .start_timer();
            zip_eq(first_version..=last_version, txns_to_commit)
                .map(|(ver, txn_to_commit)| {
                    self.event_store
                        .put_events(ver, txn_to_commit.events(), &mut cs)
                })
                .collect::<Result<Vec<_>>>()?;
        }

        let new_root_hash = {
            let _timer = DIEM_STORAGE_OTHER_TIMERS_SECONDS
                .with_label_values(&["save_transactions_txn_infos"])
                .start_timer();
            zip_eq(first_version..=last_version, txns_to_commit).try_for_each(
                |(ver, txn_to_commit)| {
                    // Transaction updates. Gather transaction hashes.
                    self.transaction_store.put_transaction(
                        ver,
                        txn_to_commit.transaction(),
                        &mut cs,
                    )?;
                    self.transaction_store
                        .put_write_set(ver, txn_to_commit.write_set(), &mut cs)
                },
            )?;
            // Transaction accumulator updates. Get result root hash.
            let txn_infos: Vec<_> = txns_to_commit
                .iter()
                .map(|t| t.transaction_info())
                .cloned()
                .collect();
            self.ledger_store
                .put_transaction_infos(first_version, &txn_infos, &mut cs)?
        };

        Ok(new_root_hash)
    }

    /// Write the whole schema batch including all data necessary to mutate the ledger
    /// state of some transaction by leveraging rocksdb atomicity support. Also committed are the
    /// LedgerCounters.
    fn commit(&self, sealed_cs: SealedChangeSet) -> Result<()> {
        self.db.write_schemas(sealed_cs.batch)?;

        Ok(())
    }

    fn wake_pruner(&self, latest_version: Version) {
        if let Some(pruner) = self.pruner.as_ref() {
            pruner.wake(latest_version)
        }
    }
}

impl DbReader for AptosDB {
    fn get_epoch_ending_ledger_infos(
        &self,
        start_epoch: u64,
        end_epoch: u64,
    ) -> Result<EpochChangeProof> {
        gauged_api("get_epoch_ending_ledger_infos", || {
            let (ledger_info_with_sigs, more) =
                Self::get_epoch_ending_ledger_infos(self, start_epoch, end_epoch)?;
            Ok(EpochChangeProof::new(ledger_info_with_sigs, more))
        })
    }

    fn get_latest_value(&self, state_store_key: ResourceKey) -> Result<Option<ResourceValue>> {
        gauged_api("get_latest_value", || {
            let ledger_info_with_sigs = self.ledger_store.get_latest_ledger_info()?;
            let version = ledger_info_with_sigs.ledger_info().version();
            let (blob, _proof) = self
                .state_store
                .get_value_with_proof_by_version(state_store_key, version)?;
            Ok(blob)
        })
    }

    fn get_latest_ledger_info(&self) -> Result<LedgerInfoWithSignatures> {
        gauged_api("get_latest_ledger_info", || {
            self.ledger_store.get_latest_ledger_info()
        })
    }

    fn get_account_transaction(
        &self,
        address: AccountAddress,
        seq_num: u64,
        include_events: bool,
        ledger_version: Version,
    ) -> Result<Option<TransactionWithProof>> {
        gauged_api("get_account_transaction", || {
            self.transaction_store
                .get_account_transaction_version(address, seq_num, ledger_version)?
                .map(|txn_version| {
                    self.get_transaction_with_proof(txn_version, ledger_version, include_events)
                })
                .transpose()
        })
    }

    fn get_account_transactions(
        &self,
        address: AccountAddress,
        start_seq_num: u64,
        limit: u64,
        include_events: bool,
        ledger_version: Version,
    ) -> Result<AccountTransactionsWithProof> {
        gauged_api("get_account_transactions", || {
            error_if_too_many_requested(limit, MAX_LIMIT)?;

            let txns_with_proofs = self
                .transaction_store
                .get_account_transaction_version_iter(
                    address,
                    start_seq_num,
                    limit,
                    ledger_version,
                )?
                .map(|result| {
                    let (_seq_num, txn_version) = result?;
                    self.get_transaction_with_proof(txn_version, ledger_version, include_events)
                })
                .collect::<Result<Vec<_>>>()?;

            Ok(AccountTransactionsWithProof::new(txns_with_proofs))
        })
    }

    /// This API is best-effort in that it CANNOT provide absense proof.
    fn get_transaction_by_hash(
        &self,
        hash: HashValue,
        ledger_version: Version,
        fetch_events: bool,
    ) -> Result<Option<TransactionWithProof>> {
        self.transaction_store
            .get_transaction_version_by_hash(&hash, ledger_version)?
            .map(|v| self.get_transaction_with_proof(v, ledger_version, fetch_events))
            .transpose()
    }

    /// Get transaction by version, delegates to `AptosDB::get_transaction_by_hash`
    fn get_transaction_by_version(
        &self,
        version: Version,
        ledger_version: Version,
        fetch_events: bool,
    ) -> Result<TransactionWithProof> {
        self.get_transaction_with_proof(version, ledger_version, fetch_events)
    }

    // ======================= State Synchronizer Internal APIs ===================================
    /// Gets a batch of transactions for the purpose of synchronizing state to another node.
    ///
    /// This is used by the State Synchronizer module internally.
    fn get_transactions(
        &self,
        start_version: Version,
        limit: u64,
        ledger_version: Version,
        fetch_events: bool,
    ) -> Result<TransactionListWithProof> {
        gauged_api("get_transactions", || {
            error_if_too_many_requested(limit, MAX_LIMIT)?;

            if start_version > ledger_version || limit == 0 {
                return Ok(TransactionListWithProof::new_empty());
            }

            let limit = std::cmp::min(limit, ledger_version - start_version + 1);

            let txns = (start_version..start_version + limit)
                .map(|version| self.transaction_store.get_transaction(version))
                .collect::<Result<Vec<_>>>()?;
            let txn_infos = (start_version..start_version + limit)
                .map(|version| self.ledger_store.get_transaction_info(version))
                .collect::<Result<Vec<_>>>()?;
            let events = if fetch_events {
                Some(
                    (start_version..start_version + limit)
                        .map(|version| self.event_store.get_events_by_version(version))
                        .collect::<Result<Vec<_>>>()?,
                )
            } else {
                None
            };
            let proof = TransactionInfoListWithProof::new(
                self.ledger_store.get_transaction_range_proof(
                    Some(start_version),
                    limit,
                    ledger_version,
                )?,
                txn_infos,
            );

            Ok(TransactionListWithProof::new(
                txns,
                events,
                Some(start_version),
                proof,
            ))
        })
    }

    /// Get the first version that txn starts existent.
    fn get_first_txn_version(&self) -> Result<Option<Version>> {
        self.transaction_store.get_first_txn_version()
    }

    /// Get the first version that write set starts existent.
    fn get_first_write_set_version(&self) -> Result<Option<Version>> {
        self.transaction_store.get_first_write_set_version()
    }

    /// Gets a batch of transactions for the purpose of synchronizing state to another node.
    ///
    /// This is used by the State Synchronizer module internally.
    fn get_transaction_outputs(
        &self,
        start_version: Version,
        limit: u64,
        ledger_version: Version,
    ) -> Result<TransactionOutputListWithProof> {
        gauged_api("get_transactions_outputs", || {
            error_if_too_many_requested(limit, MAX_LIMIT)?;

            if start_version > ledger_version || limit == 0 {
                return Ok(TransactionOutputListWithProof::new_empty());
            }

            let limit = std::cmp::min(limit, ledger_version - start_version + 1);

            let (txn_infos, txns_and_outputs) = (start_version..start_version + limit)
                .map(|version| {
                    let txn_info = self.ledger_store.get_transaction_info(version)?;
                    let events = self.event_store.get_events_by_version(version)?;
                    let write_set = self.transaction_store.get_write_set(version)?;
                    let txn = self.transaction_store.get_transaction(version)?;
                    let txn_output = TransactionOutput::new(
                        write_set,
                        events,
                        txn_info.gas_used(),
                        txn_info.status().clone().into(),
                    );
                    Ok((txn_info, (txn, txn_output)))
                })
                .collect::<Result<Vec<_>>>()?
                .into_iter()
                .unzip();
            let proof = TransactionInfoListWithProof::new(
                self.ledger_store.get_transaction_range_proof(
                    Some(start_version),
                    limit,
                    ledger_version,
                )?,
                txn_infos,
            );

            Ok(TransactionOutputListWithProof::new(
                txns_and_outputs,
                Some(start_version),
                proof,
            ))
        })
    }

    fn get_events(
        &self,
        event_key: &EventKey,
        start: u64,
        order: Order,
        limit: u64,
    ) -> Result<Vec<(u64, ContractEvent)>> {
        gauged_api("get_events", || {
            let events_with_proofs =
                self.get_events_with_proofs(event_key, start, order, limit, None)?;
            let events = events_with_proofs
                .into_iter()
                .map(|e| (e.transaction_version, e.event))
                .collect();
            Ok(events)
        })
    }

    fn get_events_with_proofs(
        &self,
        event_key: &EventKey,
        start: u64,
        order: Order,
        limit: u64,
        known_version: Option<u64>,
    ) -> Result<Vec<EventWithProof>> {
        gauged_api("get_events_with_proofs", || {
            let version = match known_version {
                Some(version) => version,
                None => self.get_latest_version()?,
            };
            let events =
                self.get_events_with_proof_by_event_key(event_key, start, order, limit, version)?;
            Ok(events)
        })
    }

    /// Gets ledger info at specified version and ensures it's an epoch ending.
    fn get_epoch_ending_ledger_info(&self, version: u64) -> Result<LedgerInfoWithSignatures> {
        gauged_api("get_epoch_ending_ledger_info", || {
            self.ledger_store.get_epoch_ending_ledger_info(version)
        })
    }

    fn get_state_proof_with_ledger_info(
        &self,
        known_version: u64,
        ledger_info_with_sigs: LedgerInfoWithSignatures,
    ) -> Result<StateProof> {
        gauged_api("get_state_proof_with_ledger_info", || {
            let ledger_info = ledger_info_with_sigs.ledger_info();
            ensure!(
                known_version <= ledger_info.version(),
                "Client known_version {} larger than ledger version {}.",
                known_version,
                ledger_info.version(),
            );
            let known_epoch = self.ledger_store.get_epoch(known_version)?;
            let end_epoch = ledger_info.next_block_epoch();
            let epoch_change_proof = if known_epoch < end_epoch {
                let (ledger_infos_with_sigs, more) =
                    self.get_epoch_ending_ledger_infos(known_epoch, end_epoch)?;
                EpochChangeProof::new(ledger_infos_with_sigs, more)
            } else {
                EpochChangeProof::new(vec![], /* more = */ false)
            };

            // Only return a consistency proof up to the verifiable end LI. If a
            // client still needs to sync more epoch change LI's, then they cannot
            // verify the latest LI nor verify a consistency proof up to the latest
            // LI. If the client needs more epochs, we just return the consistency
            // proof up to the last epoch change LI.
            let verifiable_li = if epoch_change_proof.more {
                epoch_change_proof
                    .ledger_info_with_sigs
                    .last()
                    .ok_or_else(|| format_err!(
                        "No epoch changes despite claiming the client needs to sync more epochs: known_epoch={}, end_epoch={}",
                        known_epoch, end_epoch,
                    ))?
                    .ledger_info()
            } else {
                ledger_info
            };

            let consistency_proof = self
                .ledger_store
                .get_consistency_proof(Some(known_version), verifiable_li.version())?;
            Ok(StateProof::new(
                ledger_info_with_sigs,
                epoch_change_proof,
                consistency_proof,
            ))
        })
    }

    fn get_state_proof(&self, known_version: u64) -> Result<StateProof> {
        gauged_api("get_state_proof", || {
            let ledger_info_with_sigs = self.ledger_store.get_latest_ledger_info()?;
            self.get_state_proof_with_ledger_info(known_version, ledger_info_with_sigs)
        })
    }

    fn get_value_with_proof(
        &self,
        state_store_key: ResourceKey,
        version: Version,
        ledger_version: Version,
    ) -> Result<ResourceValueWithProof> {
        gauged_api("get_account_state_with_proof", || {
            ensure!(
                version <= ledger_version,
                "The queried version {} should be equal to or older than ledger version {}.",
                version,
                ledger_version
            );
            {
                let latest_version = self.get_latest_version()?;
                ensure!(
                    ledger_version <= latest_version,
                    "ledger_version specified {} is greater than committed version {}.",
                    ledger_version,
                    latest_version
                );
            }

            let txn_info_with_proof = self
                .ledger_store
                .get_transaction_info_with_proof(version, ledger_version)?;
            let (state_store_value, sparse_merkle_proof) = self
                .state_store
                .get_value_with_proof_by_version(state_store_key, version)?;
            Ok(ResourceValueWithProof::new(
                version,
                state_store_value,
                ResourceValueProof::new(txn_info_with_proof, sparse_merkle_proof),
            ))
        })
    }

    fn get_startup_info(&self) -> Result<Option<StartupInfo>> {
        gauged_api("get_startup_info", || self.ledger_store.get_startup_info())
    }

    fn get_value_with_proof_by_version(
        &self,
        state_store_key: ResourceKey,
        version: Version,
    ) -> Result<(Option<ResourceValue>, SparseMerkleProof<ResourceValue>)> {
        gauged_api("get_account_state_with_proof_by_version", || {
            self.state_store
                .get_value_with_proof_by_version(state_store_key, version)
        })
    }

    fn get_latest_tree_state(&self) -> Result<TreeState> {
        gauged_api("get_latest_tree_state", || {
            let tree_state = match self.ledger_store.get_latest_transaction_info_option()? {
                Some((version, txn_info)) => {
                    self.ledger_store.get_tree_state(version + 1, txn_info)?
                }
                None => TreeState::new(
                    0,
                    vec![],
                    self.state_store
                        .get_root_hash_option(PRE_GENESIS_VERSION)?
                        .unwrap_or(*SPARSE_MERKLE_PLACEHOLDER_HASH),
                ),
            };

            info!(
                num_transactions = tree_state.num_transactions,
                state_root_hash = %tree_state.account_state_root_hash,
                description = tree_state.describe(),
                "Got latest TreeState."
            );

            Ok(tree_state)
        })
    }

    fn get_block_timestamp(&self, version: u64) -> Result<u64> {
        gauged_api("get_block_timestamp", || {
            let ts = match self.transaction_store.get_block_metadata(version)? {
                Some((_v, block_meta)) => block_meta.into_inner().1,
                // genesis timestamp is 0
                None => 0,
            };
            Ok(ts)
        })
    }

    fn get_event_by_version_with_proof(
        &self,
        event_key: &EventKey,
        event_version: u64,
        proof_version: u64,
    ) -> Result<EventByVersionWithProof> {
        gauged_api("get_event_by_version_with_proof", || {
            let latest_version = self.get_latest_version()?;
            ensure!(
                proof_version <= latest_version,
                "cannot construct proofs for a version that doesn't exist yet: proof_version: {}, latest_version: {}",
                proof_version, latest_version,
            );
            ensure!(
                event_version <= proof_version,
                "event_version {} must be <= proof_version {}",
                event_version,
                proof_version,
            );

            // Get the latest sequence number of an event at or before the
            // requested event_version.
            let maybe_seq_num = self
                .event_store
                .get_latest_sequence_number(event_version, event_key)?;

            let (lower_bound_incl, upper_bound_excl) = if let Some(seq_num) = maybe_seq_num {
                // We need to request the surrounding events (surrounding
                // as in E_i.version <= event_version < E_{i+1}.version) in order
                // to prove that there are no intermediate events, i.e.,
                // E_j, where E_i.version < E_j.version <= event_version.
                //
                // This limit also works for the case where `event_version` is
                // after the latest event, since the upper bound will just be None.
                let limit = 2;

                let events = self.get_events_with_proof_by_event_key(
                    event_key,
                    seq_num,
                    Order::Ascending,
                    limit,
                    proof_version,
                )?;

                let mut events_iter = events.into_iter();
                let lower_bound_incl = events_iter.next();
                let upper_bound_excl = events_iter.next();
                assert_eq!(events_iter.len(), 0);

                (lower_bound_incl, upper_bound_excl)
            } else {
                // Since there is no event at or before `event_version`, we need to
                // show that either (1.) there are no events or (2.) events start
                // at some later version.
                let seq_num = 0;
                let limit = 1;

                let events = self.get_events_with_proof_by_event_key(
                    event_key,
                    seq_num,
                    Order::Ascending,
                    limit,
                    proof_version,
                )?;

                let mut events_iter = events.into_iter();
                let upper_bound_excl = events_iter.next();
                assert_eq!(events_iter.len(), 0);

                (None, upper_bound_excl)
            };

            Ok(EventByVersionWithProof::new(
                lower_bound_incl,
                upper_bound_excl,
            ))
        })
    }

    fn get_last_version_before_timestamp(
        &self,
        timestamp: u64,
        ledger_version: Version,
    ) -> Result<Version> {
        gauged_api("get_last_version_before_timestamp", || {
            self.event_store
                .get_last_version_before_timestamp(timestamp, ledger_version)
        })
    }

    fn get_latest_transaction_info_option(&self) -> Result<Option<(Version, TransactionInfo)>> {
        gauged_api("get_latest_transaction_info_option", || {
            self.ledger_store.get_latest_transaction_info_option()
        })
    }

    fn get_accumulator_root_hash(&self, version: Version) -> Result<HashValue> {
        gauged_api("get_accumulator_root_hash", || {
            self.ledger_store.get_root_hash(version)
        })
    }

    fn get_accumulator_consistency_proof(
        &self,
        client_known_version: Option<Version>,
        ledger_version: Version,
    ) -> Result<AccumulatorConsistencyProof> {
        gauged_api("get_accumulator_consistency_proof", || {
            self.ledger_store
                .get_consistency_proof(client_known_version, ledger_version)
        })
    }

    fn get_account_count(&self, version: Version) -> Result<usize> {
        gauged_api("get_account_count", || {
            self.state_store.get_leaf_count(version)
        })
    }

    fn get_account_chunk_with_proof(
        &self,
        version: Version,
        first_index: usize,
        chunk_size: usize,
    ) -> Result<ResourceValueChunkWithProof> {
        gauged_api("get_account_chunk_with_proof", || {
            self.state_store
                .get_value_chunk_with_proof(version, first_index, chunk_size)
        })
    }

    fn get_state_prune_window(&self) -> Option<usize> {
        self.pruner
            .as_ref()
            .map(|x| x.get_state_store_pruner_window() as usize)
    }
}

impl ModuleResolver for AptosDB {
    type Error = anyhow::Error;

    fn get_module(&self, module_id: &ModuleId) -> Result<Option<Vec<u8>>> {
        let (resource_value_with_proof, _) = self.get_value_with_proof_by_version(
            ResourceKey::AccountAddressKey(*module_id.address()),
            self.get_latest_version()?,
        )?;
        if let Some(account_state_blob) = resource_value_with_proof {
            let account_state = AccountState::try_from(&account_state_blob)?;
            Ok(account_state.get(&module_id.access_vector()).cloned())
        } else {
            Ok(None)
        }
    }
}

impl ResourceResolver for AptosDB {
    type Error = anyhow::Error;

    fn get_resource(&self, address: &AccountAddress, tag: &StructTag) -> Result<Option<Vec<u8>>> {
        let (resource_value_with_proof, _) = self.get_value_with_proof_by_version(
            ResourceKey::AccountAddressKey(*address),
            self.get_latest_version()?,
        )?;
        if let Some(account_state_blob) = resource_value_with_proof {
            let account_state = AccountState::try_from(&account_state_blob)?;
            Ok(account_state.get(&tag.access_vector()).cloned())
        } else {
            Ok(None)
        }
    }
}

impl MoveDbReader for AptosDB {}

impl DbWriter for AptosDB {
    /// `first_version` is the version of the first transaction in `txns_to_commit`.
    /// When `ledger_info_with_sigs` is provided, verify that the transaction accumulator root hash
    /// it carries is generated after the `txns_to_commit` are applied.
    /// Note that even if `txns_to_commit` is empty, `frist_version` is checked to be
    /// `ledger_info_with_sigs.ledger_info.version + 1` if `ledger_info_with_sigs` is not `None`.
    fn save_transactions(
        &self,
        txns_to_commit: &[TransactionToCommit],
        first_version: Version,
        ledger_info_with_sigs: Option<&LedgerInfoWithSignatures>,
    ) -> Result<()> {
        gauged_api("save_transactions", || {
            let num_txns = txns_to_commit.len() as u64;
            // ledger_info_with_sigs could be None if we are doing state synchronization. In this case
            // txns_to_commit should not be empty. Otherwise it is okay to commit empty blocks.
            ensure!(
                ledger_info_with_sigs.is_some() || num_txns > 0,
                "txns_to_commit is empty while ledger_info_with_sigs is None.",
            );

            if let Some(x) = ledger_info_with_sigs {
                let claimed_last_version = x.ledger_info().version();
                ensure!(
                    claimed_last_version + 1 == first_version + num_txns,
                    "Transaction batch not applicable: first_version {}, num_txns {}, last_version {}",
                    first_version,
                    num_txns,
                    claimed_last_version,
                );
            }

            // Gather db mutations to `batch`.
            let mut cs = ChangeSet::new();

            let new_root_hash =
                self.save_transactions_impl(txns_to_commit, first_version, &mut cs)?;

            // If expected ledger info is provided, verify result root hash and save the ledger info.
            if let Some(x) = ledger_info_with_sigs {
                let expected_root_hash = x.ledger_info().transaction_accumulator_hash();
                ensure!(
                    new_root_hash == expected_root_hash,
                    "Root hash calculated doesn't match expected. {:?} vs {:?}",
                    new_root_hash,
                    expected_root_hash,
                );

                self.ledger_store.put_ledger_info(x, &mut cs)?;
            }

            // Persist.
            let (sealed_cs, counters) = self.seal_change_set(first_version, num_txns, cs)?;
            {
                let _timer = DIEM_STORAGE_OTHER_TIMERS_SECONDS
                    .with_label_values(&["save_transactions_commit"])
                    .start_timer();
                self.commit(sealed_cs)?;
            }

            // Once everything is successfully persisted, update the latest in-memory ledger info.
            if let Some(x) = ledger_info_with_sigs {
                self.ledger_store.set_latest_ledger_info(x.clone());

                DIEM_STORAGE_LEDGER_VERSION.set(x.ledger_info().version() as i64);
                DIEM_STORAGE_NEXT_BLOCK_EPOCH.set(x.ledger_info().next_block_epoch() as i64);
            }

            // Only increment counter if commit succeeds and there are at least one transaction written
            // to the storage. That's also when we'd inform the pruner thread to work.
            if num_txns > 0 {
                let last_version = first_version + num_txns - 1;
                DIEM_STORAGE_COMMITTED_TXNS.inc_by(num_txns);
                DIEM_STORAGE_LATEST_TXN_VERSION.set(last_version as i64);
                counters
                    .expect("Counters should be bumped with transactions being saved.")
                    .bump_op_counters();
                // -1 for "not fully migrated", -2 for "error on get_account_count()"
                DIEM_STORAGE_LATEST_ACCOUNT_COUNT.set(
                    self.state_store
                        .get_leaf_count(last_version)
                        .map_or(-1, |c| c as i64),
                );

                self.wake_pruner(last_version);
            }

            Ok(())
        })
    }

    fn get_state_snapshot_receiver(
        &self,
        version: Version,
        expected_root_hash: HashValue,
    ) -> Result<Box<dyn StateSnapshotReceiver<ResourceValue>>> {
        gauged_api("get_state_snapshot_receiver", || {
            self.state_store
                .get_snapshot_receiver(version, expected_root_hash)
        })
    }
}

// Convert requested range and order to a range in ascending order.
fn get_first_seq_num_and_limit(order: Order, cursor: u64, limit: u64) -> Result<(u64, u64)> {
    ensure!(limit > 0, "limit should > 0, got {}", limit);

    Ok(if order == Order::Ascending {
        (cursor, limit)
    } else if limit <= cursor {
        (cursor - limit + 1, limit)
    } else {
        (0, cursor + 1)
    })
}

pub trait GetRestoreHandler {
    /// Gets an instance of `RestoreHandler` for data restore purpose.
    fn get_restore_handler(&self) -> RestoreHandler;
}

impl GetRestoreHandler for Arc<AptosDB> {
    fn get_restore_handler(&self) -> RestoreHandler {
        RestoreHandler::new(
            Arc::clone(&self.db),
            Arc::clone(self),
            Arc::clone(&self.ledger_store),
            Arc::clone(&self.transaction_store),
            Arc::clone(&self.state_store),
            Arc::clone(&self.event_store),
        )
    }
}

fn gauged_api<T, F>(api_name: &'static str, api_impl: F) -> Result<T>
where
    F: FnOnce() -> Result<T>,
{
    let timer = Instant::now();

    let res = api_impl();

    let res_type = match &res {
        Ok(_) => "Ok",
        Err(e) => {
            warn!(
                api_name = api_name,
                error = ?e,
                "AptosDB API returned error."
            );
            "Err"
        }
    };
    DIEM_STORAGE_API_LATENCY_SECONDS
        .with_label_values(&[api_name, res_type])
        .observe(timer.elapsed().as_secs_f64());

    res
}
