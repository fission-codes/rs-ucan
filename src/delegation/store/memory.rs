use super::Store;
use crate::{
    crypto::varsig,
    delegation::{policy::Predicate, Delegation},
    did::{self, Did},
};
use libipld_core::{cid::Cid, codec::Codec};
use nonempty::NonEmpty;
use std::{
    collections::{BTreeMap, BTreeSet},
    ops::ControlFlow,
};
use web_time::SystemTime;

#[cfg_attr(doc, aquamarine::aquamarine)]
/// A simple in-memory store for delegations.
///
/// The store is laid out as follows:
///
/// `{Subject => {Audience => {Cid => Delegation}}}`
///
/// ```mermaid
/// flowchart LR
/// subgraph Subjects
///     direction TB
///
///     Akiko
///     Boris
///     Carol
///
///     subgraph aud[Boris's Audiences]
///         direction TB
///
///         Denzel
///         Erin
///         Frida
///         Georgia
///         Hugo
///
///         subgraph cid[Frida's CIDs]
///             direction LR
///
///             CID1 --> Delegation1
///             CID2 --> Delegation2
///             CID3 --> Delegation3
///         end
///     end
/// end
///
/// Akiko ~~~ Hugo
/// Carol ~~~ Hugo
/// Boris --> Frida --> CID2
///
/// Boris -.-> Denzel
/// Boris -.-> Erin
/// Boris -.-> Georgia
/// Boris -.-> Hugo
///
/// Frida -.-> CID1
/// Frida -.-> CID3
///
/// style Boris stroke:orange;
/// style Frida stroke:orange;
/// style CID2 stroke:orange;
/// style Delegation2 stroke:orange;
///
/// linkStyle 5 stroke:orange;
/// linkStyle 6 stroke:orange;
/// linkStyle 1 stroke:orange;
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct MemoryStore<
    DID: did::Did + Ord = did::preset::Verifier,
    V: varsig::Header<C> = varsig::header::Preset,
    C: Codec + TryFrom<u64> + Into<u64> = varsig::encoding::Preset,
> {
    ucans: BTreeMap<Cid, Delegation<DID, V, C>>,
    index: BTreeMap<Option<DID>, BTreeMap<DID, BTreeSet<Cid>>>,
    revocations: BTreeSet<Cid>,
}

impl MemoryStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_empty(&self) -> bool {
        self.ucans.is_empty() // FIXME acocunt for revocations?
    }
}

impl<DID: Did + Ord, V: varsig::Header<C>, C: Codec + TryFrom<u64> + Into<u64>> Default
    for MemoryStore<DID, V, C>
{
    fn default() -> Self {
        MemoryStore {
            ucans: BTreeMap::new(),
            index: BTreeMap::new(),
            revocations: BTreeSet::new(),
        }
    }
}

// FIXME check that UCAN is valid
impl<DID: Did + Ord + Clone, V: varsig::Header<Enc>, Enc: Codec + TryFrom<u64> + Into<u64>>
    Store<DID, V, Enc> for MemoryStore<DID, V, Enc>
{
    type DelegationStoreError = (); // FIXME misisng

    fn get(&self, cid: &Cid) -> Result<&Delegation<DID, V, Enc>, Self::DelegationStoreError> {
        self.ucans.get(cid).ok_or(())
    }

    fn insert(
        &mut self,
        cid: Cid,
        delegation: Delegation<DID, V, Enc>,
    ) -> Result<(), Self::DelegationStoreError> {
        self.index
            .entry(delegation.subject().clone())
            .or_default()
            .entry(delegation.audience().clone())
            .or_default()
            .insert(cid);

        self.ucans.insert(cid.clone(), delegation);
        Ok(())
    }

    fn revoke(&mut self, cid: Cid) -> Result<(), Self::DelegationStoreError> {
        self.revocations.insert(cid);
        Ok(())
    }

    fn get_chain(
        &self,
        aud: &DID,
        subject: &Option<DID>,
        policy: Vec<Predicate>, // FIXME
        now: SystemTime,
    ) -> Result<Option<NonEmpty<(Cid, &Delegation<DID, V, Enc>)>>, Self::DelegationStoreError> {
        match self
            .index
            .get(subject) // FIXME probably need to rework this after last minbute chanegs
            .and_then(|aud_map| aud_map.get(aud))
        {
            None => Ok(None),
            Some(delegation_subtree) => {
                #[derive(PartialEq)]
                enum Status {
                    Complete,
                    Looking,
                    NoPath,
                }

                let mut status = Status::Looking;
                let mut target_aud = aud;
                let mut chain = vec![];

                while status == Status::Looking {
                    let found = delegation_subtree.iter().try_for_each(|cid| {
                        if let Some(d) = self.ucans.get(cid) {
                            if self.revocations.contains(cid) {
                                return ControlFlow::Continue(());
                            }

                            if d.check_time(now).is_err() {
                                return ControlFlow::Continue(());
                            }

                            target_aud = &d.audience();

                            chain.push((*cid, d));

                            if let Some(ref subject) = subject {
                                if d.issuer() == subject {
                                    status = Status::Complete;
                                }
                            } else {
                                status = Status::Complete;
                            }

                            ControlFlow::Break(())
                        } else {
                            ControlFlow::Continue(())
                        }
                    });

                    if found.is_continue() {
                        status = Status::NoPath;
                    }
                }

                match status {
                    Status::Complete => Ok(NonEmpty::from_vec(chain)),
                    _ => Ok(None),
                }
            }
        }
    }
}
