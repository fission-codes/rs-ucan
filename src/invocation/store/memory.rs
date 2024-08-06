use super::Store;
use crate::{crypto::varsig, did::Did, invocation::Invocation};
use libipld_core::{cid::Cid, codec::Codec};
use std::sync::{Arc, Mutex, MutexGuard};
use std::{collections::BTreeMap, convert::Infallible};

#[derive(Debug, Clone)]
pub struct MemoryStore<
    T = crate::ability::preset::Preset,
    DID: crate::did::Did = crate::did::preset::Verifier,
    V: varsig::Header<C> = varsig::header::Preset,
    C: Codec = varsig::encoding::Preset,
> {
    inner: Arc<Mutex<MemoryStoreInner<T, DID, V, C>>>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct MemoryStoreInner<
    T = crate::ability::preset::Preset,
    DID: crate::did::Did = crate::did::preset::Verifier,
    V: varsig::Header<C> = varsig::header::Preset,
    C: Codec = varsig::encoding::Preset,
> {
    store: BTreeMap<Cid, Arc<Invocation<T, DID, V, C>>>,
}

impl<T, DID: Did, V: varsig::Header<Enc>, Enc: Codec> MemoryStore<T, DID, V, Enc> {
    fn lock(&self) -> MutexGuard<'_, MemoryStoreInner<T, DID, V, Enc>> {
        match self.inner.lock() {
            Ok(guard) => guard,
            Err(poison) => {
                // There's no logic errors through lock poisoning in our case
                poison.into_inner()
            }
        }
    }
}

impl<T, DID: Did, V: varsig::Header<Enc>, Enc: Codec> Default for MemoryStore<T, DID, V, Enc> {
    fn default() -> Self {
        Self {
            inner: Arc::new(Mutex::new(MemoryStoreInner {
                store: BTreeMap::new(),
            })),
        }
    }
}

impl<T, DID: Did, V: varsig::Header<Enc>, Enc: Codec> Store<T, DID, V, Enc>
    for MemoryStore<T, DID, V, Enc>
{
    type Error = Infallible;

    fn get(&self, cid: Cid) -> Result<Option<Arc<Invocation<T, DID, V, Enc>>>, Self::Error> {
        Ok(self.lock().store.get(&cid).cloned())
    }

    fn put(&self, cid: Cid, invocation: Invocation<T, DID, V, Enc>) -> Result<(), Self::Error> {
        self.lock().store.insert(cid, Arc::new(invocation));
        Ok(())
    }
}
