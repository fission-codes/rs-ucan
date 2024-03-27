use crate::{
    ability::arguments::Named,
    crypto::signature::Envelope,
    crypto::varsig,
    delegation::payload::Payload,
    delegation::{policy::Predicate, Delegation},
    did::Did,
};
use libipld_core::codec::Encode;
use libipld_core::ipld::Ipld;
use libipld_core::{cid::Cid, codec::Codec};
use nonempty::NonEmpty;
use std::{fmt::Debug, sync::Arc};
use thiserror::Error;
use web_time::SystemTime;

pub trait Store<DID: Did + Clone, V: varsig::Header<C> + Clone, C: Codec>
where
    Ipld: Encode<C>,
    Payload<DID>: TryFrom<Named<Ipld>>,
    Named<Ipld>: From<Payload<DID>>,
{
    type DelegationStoreError: Debug;

    fn get(
        &self,
        cid: &Cid,
    ) -> Result<Option<Arc<Delegation<DID, V, C>>>, Self::DelegationStoreError>;

    fn insert(
        &self,
        delegation: Delegation<DID, V, C>,
    ) -> Result<(), CannotCidOr<Self::DelegationStoreError>> {
        self.insert_keyed(delegation.cid()?, delegation)
            .map_err(CannotCidOr::StoreError)
    }

    fn insert_keyed(
        &self,
        cid: Cid,
        delegation: Delegation<DID, V, C>,
    ) -> Result<(), Self::DelegationStoreError>;

    // FIXME validate invocation
    // store invocation
    // just... move to invocation
    fn revoke(&self, cid: Cid) -> Result<(), Self::DelegationStoreError>;

    fn get_chain(
        &self,
        audience: &DID,
        subject: &DID,
        command: &str,
        policy: Vec<Predicate>,
        now: SystemTime,
    ) -> Result<Option<NonEmpty<(Cid, Arc<Delegation<DID, V, C>>)>>, Self::DelegationStoreError>;

    fn get_chain_cids(
        &self,
        audience: &DID,
        subject: &DID,
        command: &str,
        policy: Vec<Predicate>,
        now: SystemTime,
    ) -> Result<Option<NonEmpty<Cid>>, Self::DelegationStoreError> {
        self.get_chain(audience, subject, command, policy, now)
            .map(|chain| chain.map(|chain| chain.map(|(cid, _)| cid)))
    }

    fn can_delegate(
        &self,
        issuer: DID,
        audience: &DID,
        command: &str,
        policy: Vec<Predicate>,
        now: SystemTime,
    ) -> Result<bool, Self::DelegationStoreError> {
        self.get_chain(audience, &issuer, command, policy, now)
            .map(|chain| chain.is_some())
    }

    fn get_many(
        &self,
        cids: &[Cid],
    ) -> Result<Vec<Option<Arc<Delegation<DID, V, C>>>>, Self::DelegationStoreError> {
        cids.iter()
            .map(|cid| self.get(cid))
            .collect::<Result<_, Self::DelegationStoreError>>()
    }
}

impl<T: Store<DID, V, C>, DID: Did + Clone, V: varsig::Header<C> + Clone, C: Codec> Store<DID, V, C>
    for &T
where
    Ipld: Encode<C>,
    Payload<DID>: TryFrom<Named<Ipld>>,
    Named<Ipld>: From<Payload<DID>>,
{
    type DelegationStoreError = <T as Store<DID, V, C>>::DelegationStoreError;

    fn get(
        &self,
        cid: &Cid,
    ) -> Result<Option<Arc<Delegation<DID, V, C>>>, Self::DelegationStoreError> {
        (**self).get(cid)
    }

    fn insert_keyed(
        &self,
        cid: Cid,
        delegation: Delegation<DID, V, C>,
    ) -> Result<(), Self::DelegationStoreError> {
        (**self).insert_keyed(cid, delegation)
    }

    fn revoke(&self, cid: Cid) -> Result<(), Self::DelegationStoreError> {
        (**self).revoke(cid)
    }

    fn get_chain(
        &self,
        audience: &DID,
        subject: &DID,
        command: &str,
        policy: Vec<Predicate>,
        now: SystemTime,
    ) -> Result<Option<NonEmpty<(Cid, Arc<Delegation<DID, V, C>>)>>, Self::DelegationStoreError>
    {
        (**self).get_chain(audience, subject, command, policy, now)
    }
}

#[derive(Debug, Error)]
pub enum CannotCidOr<E> {
    #[error("Cannot make CID from delegation based on supplied Varsig")]
    CannotMakeCid(#[from] libipld_core::error::Error),

    #[error("Store error: {0}")]
    StoreError(E),
}
