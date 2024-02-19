use super::Store;
use crate::{
    ability::arguments,
    crypto::varsig,
    delegation::{condition::Condition, Delegation},
    did::Did,
    proof::{checkable::Checkable, prove::Prove},
};
use libipld_core::{cid::Cid, codec::Codec, ipld::Ipld};
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
    H,
    C: Condition,
    DID: Did + Ord,
    V: varsig::Header<Enc>,
    Enc: Codec + TryFrom<u32> + Into<u32>,
> {
    ucans: BTreeMap<Cid, Delegation<H, C, DID, V, Enc>>,
    index: BTreeMap<DID, BTreeMap<DID, BTreeSet<Cid>>>,
    revocations: BTreeSet<Cid>,
}

// FIXME check that UCAN is valid
impl<
        B: Checkable + Clone,
        C: Condition + PartialEq,
        DID: Did + Ord + Clone,
        V: varsig::Header<Enc>,
        Enc: Codec + TryFrom<u32> + Into<u32>,
    > Store<B, C, DID, V, Enc> for MemoryStore<B::Hierarchy, C, DID, V, Enc>
where
    B::Hierarchy: Into<arguments::Named<Ipld>> + Clone,
{
    type DelegationStoreError = (); // FIXME misisng

    fn get(
        &self,
        cid: &Cid,
    ) -> Result<&Delegation<B::Hierarchy, C, DID, V, Enc>, Self::DelegationStoreError> {
        self.ucans.get(cid).ok_or(())
    }

    fn insert(
        &mut self,
        cid: Cid,
        delegation: Delegation<B, C, DID, V, Enc>,
    ) -> Result<(), Self::DelegationStoreError> {
        self.index
            .entry(delegation.subject().clone())
            .or_default()
            .entry(delegation.audience().clone())
            .or_default()
            .insert(cid);

        let hierarchy: Delegation<B::Hierarchy, C, DID, V, Enc> =
            delegation.map_ability_builder(Into::into);

        self.ucans.insert(cid.clone(), hierarchy);
        Ok(())
    }

    fn revoke(&mut self, cid: Cid) -> Result<(), Self::DelegationStoreError> {
        self.revocations.insert(cid);
        Ok(())
    }

    fn get_chain(
        &self,
        aud: &DID,
        subject: &DID,
        builder: &B,
        conditions: Vec<C>,
        now: SystemTime,
    ) -> Result<
        Option<NonEmpty<(Cid, &Delegation<B::Hierarchy, C, DID, V, Enc>)>>,
        Self::DelegationStoreError,
    > {
        match self.index.get(subject).and_then(|aud_map| aud_map.get(aud)) {
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
                let mut args = &B::Hierarchy::from(builder.clone());
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

                            if args.check(&d.ability_builder()).is_ok() {
                                args = &d.ability_builder();
                            } else {
                                return ControlFlow::Continue(());
                            }

                            for condition in &conditions {
                                if !condition.validate(&d.ability_builder().clone().into()) {
                                    return ControlFlow::Continue(());
                                }
                            }

                            chain.push((*cid, d));

                            if d.issuer() == subject {
                                status = Status::Complete;
                            } else {
                                target_aud = &d.issuer();
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
