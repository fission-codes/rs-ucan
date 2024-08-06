use crate::{crypto::varsig, did::Did, invocation::Invocation};
use libipld_core::{cid::Cid, codec::Codec};
use std::{fmt::Debug, sync::Arc};

pub trait Store<T, DID: Did, V: varsig::Header<C>, C: Codec> {
    type Error: Debug;

    fn get(&self, cid: Cid) -> Result<Option<Arc<Invocation<T, DID, V, C>>>, Self::Error>;

    fn put(&self, cid: Cid, invocation: Invocation<T, DID, V, C>) -> Result<(), Self::Error>;

    fn has(&self, cid: Cid) -> Result<bool, Self::Error> {
        Ok(self.get(cid).is_ok())
    }
}

impl<S: Store<T, DID, V, C>, T, DID: Did, V: varsig::Header<C>, C: Codec> Store<T, DID, V, C>
    for &S
{
    type Error = <S as Store<T, DID, V, C>>::Error;

    fn get(&self, cid: Cid) -> Result<Option<Arc<Invocation<T, DID, V, C>>>, Self::Error> {
        (**self).get(cid)
    }

    fn put(&self, cid: Cid, invocation: Invocation<T, DID, V, C>) -> Result<(), Self::Error> {
        (**self).put(cid, invocation)
    }
}
