// Copyright (c) Aptos
// SPDX-License-Identifier: Apache-2.0

use aptos_crypto::{
    ed25519::{Ed25519PrivateKey, Ed25519PublicKey},
    PrivateKey, SigningKey, Uniform,
};
use aptos_logger::info;
use aptos_sdk::transaction_builder::TransactionFactory;
use aptos_types::{
    account_address::AccountAddress,
    account_config::aptos_root_address,
    account_config::AccountResource,
    account_state_blob::AccountStateBlob,
    chain_id::ChainId,
    state_store::state_store_key::StateStoreKey,
    transaction::{RawTransaction, SignedTransaction, Transaction, Version},
};
use chrono::Local;
use indicatif::{ProgressBar, ProgressStyle};
use rand::{rngs::StdRng, SeedableRng};
use serde::{Deserialize, Serialize};
use std::{
    convert::TryFrom,
    fs::File,
    io::{Read, Write},
    path::Path,
    sync::mpsc,
    time::Instant,
};
use storage_interface::DbReader;

const META_FILENAME: &str = "metadata.toml";
const MAX_ACCOUNTS_INVOLVED_IN_P2P: usize = 1_000_000;

fn get_progress_bar(num_accounts: usize) -> ProgressBar {
    let bar = ProgressBar::new(num_accounts as u64);
    bar.set_style(
        ProgressStyle::default_bar()
            .template("[{elapsed_precise}] {bar:100.cyan/blue} {percent}% ETA {eta_precise}"),
    );
    bar
}

macro_rules! now_fmt {
    () => {
        Local::now().format("%m-%d %H:%M:%S")
    };
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "type", content = "args")]
enum TestCase {
    P2p(P2pTestCase),
}

#[derive(Serialize, Deserialize)]
struct P2pTestCase {
    num_accounts: usize,
}

// TODO: use LocalAccount instead
#[derive(Deserialize, Serialize)]
struct AccountData {
    private_key: Ed25519PrivateKey,
    public_key: Ed25519PublicKey,
    address: AccountAddress,
    sequence_number: u64,
}

pub struct TransactionGenerator {
    /// The current state of the accounts. The main purpose is to keep track of the sequence number
    /// so generated transactions are guaranteed to be successfully executed.
    accounts_cache: Vec<AccountData>,

    /// Total number of accounts in the DB
    num_accounts: usize,

    /// Used to mint accounts.
    genesis_key: Ed25519PrivateKey,

    /// Record the number of txns generated.
    version: Version,

    /// For deterministic transaction generation.
    rng: StdRng,

    /// Each generated block of transactions are sent to this channel. Using `SyncSender` to make
    /// sure if execution is slow to consume the transactions, we do not run out of memory.
    block_sender: Option<mpsc::SyncSender<Vec<Transaction>>>,
}

impl TransactionGenerator {
    pub fn new(genesis_key: Ed25519PrivateKey, num_accounts: usize) -> Self {
        Self::new_impl(genesis_key, num_accounts, None)
    }

    pub fn new_with_sender(
        genesis_key: Ed25519PrivateKey,
        num_accounts: usize,
        block_sender: mpsc::SyncSender<Vec<Transaction>>,
    ) -> Self {
        Self::new_impl(genesis_key, num_accounts, Some(block_sender))
    }

    fn new_impl(
        genesis_key: Ed25519PrivateKey,
        num_accounts: usize,
        block_sender: Option<mpsc::SyncSender<Vec<Transaction>>>,
    ) -> Self {
        let seed = [1u8; 32];
        let rng = StdRng::from_seed(seed);
        Self {
            accounts_cache: Self::gen_account_cache(num_accounts),
            num_accounts,
            genesis_key,
            version: 0,
            rng,
            block_sender,
        }
    }

    fn gen_account_cache(num_accounts: usize) -> Vec<AccountData> {
        let start = Instant::now();
        let seed = [1u8; 32];
        let mut rng = StdRng::from_seed(seed);

        let mut accounts = Vec::with_capacity(num_accounts);
        println!("[{}] Generating {} accounts.", now_fmt!(), num_accounts);
        let bar = get_progress_bar(num_accounts);
        for _i in 0..num_accounts {
            let private_key = Ed25519PrivateKey::generate(&mut rng);
            let public_key = private_key.public_key();
            let address = aptos_types::account_address::from_public_key(&public_key);
            let account = AccountData {
                private_key,
                public_key,
                address,
                sequence_number: 0,
            };
            accounts.push(account);
            bar.inc(1);
        }
        bar.finish();
        println!("[{}] done.", now_fmt!());

        info!(
            num_accounts_generated = num_accounts,
            time_ms = %start.elapsed().as_millis(),
            "Account cache generation finished.",
        );
        accounts
    }

    pub fn new_with_metafile<P: AsRef<Path>>(
        genesis_key: Ed25519PrivateKey,
        block_sender: mpsc::SyncSender<Vec<Transaction>>,
        db_dir: P,
    ) -> Self {
        let path = db_dir.as_ref().join(META_FILENAME);
        let mut file = File::open(&path).unwrap();
        let mut contents = vec![];
        file.read_to_end(&mut contents).unwrap();
        let test_case: TestCase = toml::from_slice(&contents).expect("Must exist.");
        let num_accounts = match test_case {
            TestCase::P2p(P2pTestCase { num_accounts }) => num_accounts,
        };

        let seed = [1u8; 32];
        let rng = StdRng::from_seed(seed);
        Self {
            accounts_cache: Self::gen_account_cache(std::cmp::min(
                num_accounts,
                MAX_ACCOUNTS_INVOLVED_IN_P2P,
            )),
            num_accounts,
            genesis_key,
            version: 2 * num_accounts as Version,
            rng,
            block_sender: Some(block_sender),
        }
    }

    // Write metadata
    pub fn write_meta<P: AsRef<Path>>(self, path: &P) {
        let metadata = TestCase::P2p(P2pTestCase {
            num_accounts: self.num_accounts,
        });
        let serialized = toml::to_vec(&metadata).unwrap();
        let meta_file = path.as_ref().join(META_FILENAME);
        let mut file = File::create(meta_file).unwrap();
        file.write_all(&serialized).unwrap();
    }

    pub fn version(&self) -> Version {
        self.version
    }

    pub fn run_mint(&mut self, init_account_balance: u64, block_size: usize) {
        assert!(self.block_sender.is_some());
        self.gen_account_creations(block_size);
        self.gen_mint_transactions(init_account_balance, block_size);
    }

    pub fn run_transfer(&mut self, block_size: usize, num_transfer_blocks: usize) {
        assert!(self.block_sender.is_some());
        self.gen_transfer_transactions(block_size, num_transfer_blocks);
    }

    pub fn transaction_factory() -> TransactionFactory {
        TransactionFactory::new(ChainId::test())
            .with_transaction_expiration_time(300)
            .with_gas_unit_price(1)
            .with_max_gas_amount(1000)
    }

    pub fn gen_account_creations(&mut self, block_size: usize) -> Vec<Vec<Transaction>> {
        let root_address = aptos_root_address();
        let mut txn_block = vec![];

        println!(
            "[{}] Generating {} account creation txns.",
            now_fmt!(),
            self.accounts_cache.len(),
        );
        let bar = get_progress_bar(self.accounts_cache.len());
        for (i, block) in self.accounts_cache.chunks(block_size).enumerate() {
            let mut transactions = Vec::with_capacity(block_size);
            for (j, account) in block.iter().enumerate() {
                let txn = create_transaction(
                    &self.genesis_key,
                    self.genesis_key.public_key(),
                    Self::transaction_factory()
                        .create_user_account(&account.public_key)
                        .sender(root_address)
                        .sequence_number((i * block_size + j) as u64)
                        .build(),
                );
                transactions.push(txn);
            }
            self.version += transactions.len() as Version;
            if let Some(sender) = &self.block_sender {
                sender.send(transactions).unwrap();
            } else {
                txn_block.push(transactions);
            }
            bar.inc(block_size as u64);
        }
        bar.finish();
        println!("[{}] done.", now_fmt!());
        txn_block
    }

    /// Generates transactions that allocate `init_account_balance` to every account.
    pub fn gen_mint_transactions(
        &mut self,
        init_account_balance: u64,
        block_size: usize,
    ) -> Vec<Vec<Transaction>> {
        let root_address = aptos_root_address();
        let mut txn_block = vec![];

        let total_accounts = self.accounts_cache.len();
        println!("[{}] Generating {} mint txns.", now_fmt!(), total_accounts,);
        let bar = get_progress_bar(total_accounts);
        for (i, block) in self.accounts_cache.chunks(block_size).enumerate() {
            let mut transactions = Vec::with_capacity(block_size);
            for (j, account) in block.iter().enumerate() {
                let txn = create_transaction(
                    &self.genesis_key,
                    self.genesis_key.public_key(),
                    Self::transaction_factory()
                        .mint(account.address, init_account_balance)
                        .sender(root_address)
                        .sequence_number((total_accounts + i * block_size + j) as u64)
                        .build(),
                );
                transactions.push(txn);
            }
            self.version += transactions.len() as Version;

            if let Some(sender) = &self.block_sender {
                sender.send(transactions).unwrap();
            } else {
                txn_block.push(transactions);
            }
            bar.inc(block.len() as u64)
        }
        bar.finish();
        println!("[{}] done.", now_fmt!());
        txn_block
    }

    /// Generates transactions for random pairs of accounts.
    pub fn gen_transfer_transactions(
        &mut self,
        block_size: usize,
        num_blocks: usize,
    ) -> Vec<Vec<Transaction>> {
        let mut txn_block = vec![];

        for _i in 0..num_blocks {
            let mut transactions = Vec::with_capacity(block_size);
            for _j in 0..block_size {
                let indices = rand::seq::index::sample(&mut self.rng, self.accounts_cache.len(), 2);
                let sender_idx = indices.index(0);
                let receiver_idx = indices.index(1);

                let sender = &self.accounts_cache[sender_idx];
                let receiver = &self.accounts_cache[receiver_idx];
                let txn = create_transaction(
                    &sender.private_key,
                    sender.public_key.clone(),
                    Self::transaction_factory()
                        .transfer(receiver.address, 1)
                        .sender(sender.address)
                        .sequence_number(sender.sequence_number)
                        .build(),
                );
                transactions.push(txn);
                self.accounts_cache[sender_idx].sequence_number += 1;
            }
            self.version += transactions.len() as Version;

            if let Some(sender) = &self.block_sender {
                sender.send(transactions).unwrap();
            } else {
                txn_block.push(transactions);
            }
        }
        txn_block
    }

    /// Verifies the sequence numbers in storage match what we have locally.
    pub fn verify_sequence_number(&self, db: &dyn DbReader) {
        println!(
            "[{}] verify {} account sequence numbers.",
            now_fmt!(),
            self.accounts_cache.len(),
        );
        let bar = get_progress_bar(self.accounts_cache.len());
        for account in &self.accounts_cache {
            let address = account.address;
            let state_store_value = db
                .get_latest_value(StateStoreKey::AccountAddressKey(address))
                .expect("Failed to query storage.")
                .expect("Account must exist.");
            let account_resource =
                AccountResource::try_from(&AccountStateBlob::from(state_store_value)).unwrap();
            assert_eq!(account_resource.sequence_number(), account.sequence_number);
            bar.inc(1);
        }
        bar.finish();
        println!("[{}] done.", now_fmt!());
    }

    /// Drops the sender to notify the receiving end of the channel.
    pub fn drop_sender(&mut self) {
        self.block_sender.take().unwrap();
    }
}

fn create_transaction(
    private_key: &Ed25519PrivateKey,
    public_key: Ed25519PublicKey,
    raw_txn: RawTransaction,
) -> Transaction {
    let signature = private_key.sign(&raw_txn);
    let signed_txn = SignedTransaction::new(raw_txn, public_key, signature);
    Transaction::UserTransaction(signed_txn)
}
