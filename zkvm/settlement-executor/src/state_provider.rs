//! Read-only access to on-chain state, as REVM needs it via `revm::DatabaseRef`.
//!
//! A real implementation would anchor to the settlement chain's own consensus (e.g. via a light
//! client) and check each account/slot with a cryptographic proof against a verified state root.
//! [`MockChainStateProvider`] below is an in-memory stand-in for local development and tests only;
//! it verifies nothing and must never be used outside tests.

use revm::bytecode::Bytecode;
use revm::database::DatabaseRef;
use revm::primitives::{Address, B256, U256};
use revm::state::AccountInfo;
use std::collections::HashMap;

/// Cryptographically verified read access to on-chain state. A real implementation backs this
/// with a consensus-anchored light client (see module docs); it is not merely an RPC passthrough.
pub trait VerifiedChainStateProvider: DatabaseRef {}

impl<T: DatabaseRef> VerifiedChainStateProvider for T {}

/// Test-only stand-in for the real light-client-backed provider. Answers every query from an
/// in-memory map and performs **no verification whatsoever**. Never use outside tests/local dev.
#[derive(Debug, Default, Clone, serde::Serialize, serde::Deserialize)]
pub struct MockChainStateProvider {
    accounts: HashMap<Address, AccountInfo>,
    storage: HashMap<(Address, U256), U256>,
    code: HashMap<B256, Bytecode>,
}

impl MockChainStateProvider {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_account(&mut self, address: Address, info: AccountInfo) {
        self.accounts.insert(address, info);
    }

    pub fn set_storage(&mut self, address: Address, index: U256, value: U256) {
        self.storage.insert((address, index), value);
    }

    pub fn set_code(&mut self, hash: B256, code: Bytecode) {
        self.code.insert(hash, code);
    }
}

impl DatabaseRef for MockChainStateProvider {
    type Error = core::convert::Infallible;

    fn basic_ref(&self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        Ok(self.accounts.get(&address).cloned())
    }

    fn code_by_hash_ref(&self, code_hash: B256) -> Result<Bytecode, Self::Error> {
        Ok(self.code.get(&code_hash).cloned().unwrap_or_default())
    }

    fn storage_ref(&self, address: Address, index: U256) -> Result<U256, Self::Error> {
        Ok(self
            .storage
            .get(&(address, index))
            .copied()
            .unwrap_or_default())
    }

    fn block_hash_ref(&self, _number: u64) -> Result<B256, Self::Error> {
        Ok(B256::ZERO)
    }
}
