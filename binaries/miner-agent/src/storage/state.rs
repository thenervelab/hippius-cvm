//! The storage set the agent runs with right now, shared by the launch
//! gates, destroy, the heartbeat report and the `storage-config` route.
//!
//! It is the applied remote document when there is one
//! ([`super::remote`]), else the local `[[storage.pools]]` /
//! `[[storage.dedicated_disks]]`, else the implicit `default`. An applied
//! `storage-config` replaces it whole; every reader takes one snapshot
//! per decision, so a decision never mixes two sets.

use std::sync::{Arc, RwLock};

use crate::config::DedicatedDiskConfig;

use super::registry::PoolBindings;
use super::StoragePools;

/// One storage set.
#[derive(Debug, Clone)]
pub struct EffectiveStorage {
    pub pools: Arc<StoragePools>,
    pub dedicated: Vec<DedicatedDiskConfig>,
    /// The applied `storage-config` revision, `0` for the local set.
    pub revision: u64,
    /// The filesystem each pool is bound to ([`super::registry`]).
    pub bindings: PoolBindings,
}

impl EffectiveStorage {
    /// A set from the local config (revision `0`).
    pub fn local(
        pools: Arc<StoragePools>,
        dedicated: Vec<DedicatedDiskConfig>,
        bindings: PoolBindings,
    ) -> Self {
        Self {
            pools,
            dedicated,
            revision: 0,
            bindings,
        }
    }
}

/// The current [`EffectiveStorage`], swapped whole.
#[derive(Debug)]
pub struct StorageState {
    current: RwLock<Arc<EffectiveStorage>>,
}

impl StorageState {
    pub fn new(effective: EffectiveStorage) -> Self {
        Self {
            current: RwLock::new(Arc::new(effective)),
        }
    }

    /// A set holding only `pools`: no dedicated disk, no binding.
    pub fn with_pools(pools: StoragePools) -> Self {
        Self::new(EffectiveStorage::local(
            Arc::new(pools),
            Vec::new(),
            PoolBindings::default(),
        ))
    }

    /// The set right now. A poisoned lock still holds a whole set (it is
    /// only ever replaced, never edited in place).
    pub fn current(&self) -> Arc<EffectiveStorage> {
        Arc::clone(
            &self
                .current
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        )
    }

    /// The pools right now.
    pub fn pools(&self) -> Arc<StoragePools> {
        Arc::clone(&self.current().pools)
    }

    pub fn replace(&self, effective: EffectiveStorage) {
        *self
            .current
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Arc::new(effective);
    }
}
