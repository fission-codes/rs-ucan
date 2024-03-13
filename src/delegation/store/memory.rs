use super::Store;
use crate::crypto::signature::Envelope;
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

use crate::delegation;
use libipld_core::codec::Encode;
use libipld_core::ipld::Ipld;

// FIXME check that UCAN is valid
impl<
        DID: Did + Ord + Clone,
        V: varsig::Header<Enc> + Clone,
        Enc: Codec + TryFrom<u64> + Into<u64>,
    > Store<DID, V, Enc> for MemoryStore<DID, V, Enc>
where
    Ipld: From<delegation::Payload<DID>>,
    delegation::Payload<DID>: TryFrom<Ipld>,
    Delegation<DID, V, Enc>: Encode<Enc>,
{
    type DelegationStoreError = String; // FIXME misisng

    fn get(&self, cid: &Cid) -> Result<&Delegation<DID, V, Enc>, Self::DelegationStoreError> {
        self.ucans.get(cid).ok_or("nope".into()) // FIXME
    }

    fn insert(
        &mut self,
        cid: Cid,
        delegation: Delegation<DID, V, Enc>,
    ) -> Result<(), Self::DelegationStoreError> {
        dbg!(&cid.to_string());
        self.index
            .entry(delegation.subject().clone())
            .or_default()
            .entry(delegation.audience().clone())
            .or_default()
            .insert(cid);

        self.ucans.insert(cid.clone(), delegation);

        dbg!(self.ucans.len());
        dbg!(self.index.len());
        for (sub, inner) in self.index.clone() {
            dbg!(sub.clone().map(|x| x.to_string()));
            for (aud, cids) in inner {
                dbg!(aud.to_string());
                dbg!(cids.len());
            }
        }
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
        command: String,
        policy: Vec<Predicate>, // FIXME
        now: SystemTime,
    ) -> Result<Option<NonEmpty<(Cid, &Delegation<DID, V, Enc>)>>, Self::DelegationStoreError> {
        let blank_set = BTreeSet::new();
        let blank_map = BTreeMap::new();

        let all_powerlines = self.index.get(&None).unwrap_or(&blank_map);
        let all_aud_for_subject = self.index.get(subject).unwrap_or(&blank_map);
        let powerline_candidates = all_powerlines.get(aud).unwrap_or(&blank_set);
        let sub_candidates = all_aud_for_subject.get(aud).unwrap_or(&blank_set);

        let mut parent_candidate_stack = vec![];
        let mut hypothesis_chain = vec![];

        let corrected_target_command = if command.ends_with('/') {
            command
        } else {
            format!("{}/", command)
        };

        parent_candidate_stack.push(sub_candidates.iter().chain(powerline_candidates.iter()));
        let mut next = None;

        'outer: loop {
            if let Some(parent_cid_candidates) = parent_candidate_stack.last_mut() {
                if parent_cid_candidates.clone().collect::<Vec<_>>().is_empty() {
                    parent_candidate_stack.pop();
                    hypothesis_chain.pop();
                    break 'outer;
                }

                'inner: for cid in parent_cid_candidates {
                    if self.revocations.contains(cid) {
                        continue;
                    }

                    if let Some(delegation) = self.ucans.get(cid) {
                        if delegation.check_time(now).is_err() {
                            continue;
                        }

                        // FIXME extract
                        let corrected_delegation_command =
                            if delegation.payload.command.ends_with('/') {
                                delegation.payload.command.clone()
                            } else {
                                format!("{}/", delegation.payload.command)
                            };

                        if !corrected_delegation_command.starts_with(&corrected_target_command) {
                            continue;
                        }

                        for target_pred in policy.iter() {
                            for delegate_pred in delegation.payload.policy.iter() {
                                let comparison =
                                    target_pred.harmonize(delegate_pred, vec![], vec![]);

                                if comparison.is_conflict() || comparison.is_lhs_weaker() {
                                    continue 'inner;
                                }
                            }
                        }

                        hypothesis_chain.push((cid.clone(), delegation));

                        let issuer = delegation.issuer().clone();

                        // Hit a root delegation, AKA base case
                        if &Some(issuer.clone()) == delegation.subject() {
                            break 'outer;
                        }

                        let new_aud_candidates =
                            all_aud_for_subject.get(&issuer).unwrap_or(&blank_set);

                        let new_powerline_candidates =
                            all_powerlines.get(&issuer).unwrap_or(&blank_set);

                        if !new_aud_candidates.is_empty() || !new_powerline_candidates.is_empty() {
                            next = Some(
                                new_aud_candidates
                                    .iter()
                                    .chain(new_powerline_candidates.iter()),
                            );

                            break 'inner;
                        }
                    }
                }

                if let Some(ref n) = next {
                    parent_candidate_stack.push(n.clone());
                    next = None;
                } else {
                    // Didn't find a match
                    break 'outer;
                }
            } else {
                parent_candidate_stack.pop();
                hypothesis_chain.pop();
            }
        }

        Ok(NonEmpty::from_vec(hypothesis_chain))
    }
}

#[cfg(test)]
mod tests {
    use crate::ability::arguments;
    use crate::ability::command::Command;
    use crate::ability::crud::Crud;
    use crate::crypto::signature::Envelope;
    use crate::delegation::store::Store;
    use crate::invocation::promise::{self, Resolvable};
    use crate::invocation::Agent;
    use crate::ipld;
    use libipld::json::DagJsonCodec;
    use libipld_core::codec::Codec;
    use libipld_core::ipld::Ipld;
    use libipld_core::serde::Serializer;
    use rand::thread_rng;
    use testresult::TestResult;

    fn generate_did() -> (crate::did::preset::Signer, crate::did::preset::Verifier) {
        let sk = ed25519_dalek::SigningKey::generate(&mut thread_rng());
        let signer = crate::did::preset::Signer::Key(crate::did::key::Signer::EdDsa(sk.clone()));

        let verifier =
            crate::did::preset::Verifier::Key(crate::did::key::Verifier::EdDsa(sk.verifying_key()));

        (signer, verifier)
    }

    #[test_log::test]
    fn test_powerbox_ucan_resource() -> TestResult {
        let (server_signer, server) = generate_did();
        let (account_signer, account) = generate_did();
        let (dnslink_signer, dnslink) = generate_did();
        let (device_signer, device) = generate_did();

        // FIXME perhaps add this back upstream as a named const
        let varsig_header = crate::crypto::varsig::header::Preset::EdDsa(
            crate::crypto::varsig::header::EdDsaHeader {
                codec: crate::crypto::varsig::encoding::Preset::DagCbor,
            },
        );

        // 1.               account -*-> server
        // 2.                            server -a-> device
        // 3.  dnslink -d-> account
        // 4. [dnslink -d-> account -*-> server -a-> device]

        // 1.               account -*-> server
        let account_pbox = crate::Delegation::try_sign(
            &account_signer,
            varsig_header.clone(),
            crate::delegation::PayloadBuilder::default()
                .subject(None)
                .issuer(account.clone())
                .audience(server.clone())
                .command("/".into())
                .expiration(crate::time::Timestamp::five_years_from_now())
                .build()?,
        )?;

        // 2.                            server -a-> device
        let account_device_ucan = crate::Delegation::try_sign(
            &server_signer,
            varsig_header.clone(), // FIXME can also put this on a builder
            crate::delegation::PayloadBuilder::default()
                .subject(None) // FIXME needs a sibject when we figure out powerbox
                .issuer(server.clone())
                .audience(device.clone())
                .command("/".into())
                .expiration(crate::time::Timestamp::five_years_from_now())
                .build()?, // I don't love this is now failable
        )?;

        // 3.  dnslink -d-> account
        let dnslink_ucan = crate::Delegation::try_sign(
            &dnslink_signer,
            varsig_header.clone(),
            crate::delegation::PayloadBuilder::default()
                .subject(Some(dnslink.clone()))
                .issuer(dnslink.clone())
                .audience(account.clone())
                .command("/".into())
                .expiration(crate::time::Timestamp::five_years_from_now())
                .build()?,
        )?;

        #[derive(Debug, Clone, PartialEq)]
        pub struct AccountManage;

        impl Command for AccountManage {
            const COMMAND: &'static str = "/account/info";
        }

        impl TryFrom<Ipld> for AccountManage {
            type Error = ();

            fn try_from(ipld: Ipld) -> Result<Self, Self::Error> {
                match ipld {
                    Ipld::String(s) => match s.as_ref() {
                        "account/info" => Ok(AccountManage),
                        _ => Err(()),
                    },
                    _ => Err(()),
                }
            }
        }

        impl From<AccountManage> for Ipld {
            fn from(info: AccountManage) -> Self {
                match info {
                    AccountManage => Ipld::String("account/info".to_string()),
                }
            }
        }

        impl promise::Resolvable for AccountManage {
            type Promised = AccountManage;
        }

        impl From<arguments::Named<libipld::Ipld>> for AccountManage {
            fn from(_: arguments::Named<libipld::Ipld>) -> Self {
                AccountManage
            }
        }

        // named::Named<libipld::Ipld>: From<AccountManage>
        impl Into<arguments::Named<libipld::Ipld>> for AccountManage {
            fn into(self) -> arguments::Named<libipld::Ipld> {
                arguments::Named::new()
            }
        }

        impl From<arguments::Named<ipld::Promised>> for AccountManage {
            fn from(_: arguments::Named<ipld::Promised>) -> Self {
                AccountManage
            }
        }

        impl From<AccountManage> for arguments::Named<ipld::Promised> {
            fn from(_: AccountManage) -> Self {
                arguments::Named::new()
            }
        }

        // #[derive(Debug, Clone, PartialEq)]
        // pub struct DnsLinkUpdate {
        //     pub cid: Cid,
        // }

        // impl From<Ipld> for DnsLinkUpdate {
        //     fn from(_: Ipld) -> Self {
        //         todo!()
        //     }
        // }

        // 4. [dnslink -d-> account -*-> server -a-> device]
        let account_invocation = crate::Invocation::try_sign(
            &device_signer,
            varsig_header,
            crate::invocation::PayloadBuilder::default()
                .subject(account.clone())
                .issuer(device.clone())
                .audience(Some(server.clone()))
                .ability(AccountManage)
                .proofs(vec![]) // FIXME
                .build()?,
        )?;

        // FIXME reenable
        // let dnslink_invocation = crate::Invocation::try_sign(
        //     &device,
        //     varsig_header,
        //     crate::invocation::PayloadBuilder::default()
        //         .subject(dnslink)
        //         .issuer(device)
        //         .audience(Some(server))
        //         .ability(DnsLinkUpdate { cid: todo!() })
        //         .build()
        //         .expect("FIXME"),
        // )
        // .expect("FIXME");

        use crate::crypto::varsig;

        let mut store: crate::delegation::store::MemoryStore<
            crate::did::preset::Verifier,
            varsig::header::Preset,
            varsig::encoding::Preset,
        > = Default::default();

        let agent = crate::delegation::Agent::new(&server, &server_signer, &mut store);

        let _ = store.insert(
            account_device_ucan.cid().expect("FIXME"),
            account_device_ucan.clone(),
        );

        let _ = store.insert(account_pbox.cid().expect("FIXME"), account_pbox.clone());

        let _ = store.insert(dnslink_ucan.cid().expect("FIXME"), dnslink_ucan.clone());

        use std::time::SystemTime;

        dbg!(device.to_string().clone());
        dbg!(server.to_string().clone());
        dbg!(account.to_string().clone());
        dbg!(dnslink.to_string().clone());

        let chain_for_powerline = store
            .get_chain(&device, &None, "/".into(), vec![], SystemTime::now())?
            .expect("to find a valid powerline chain");

        let chain_for_dnslink = store
            .get_chain(
                &device,
                &Some(dnslink),
                "/".into(),
                vec![],
                SystemTime::now(),
            )?
            .expect("to find a valid dnslink chain");

        assert_eq!((chain_for_powerline.len(), chain_for_dnslink.len()), (3, 3));

        let mut server_agent = Agent::<AccountManage, _, _, _, _, _, _>::new(
            &server,
            &server_signer,
            &mut crate::invocation::store::MemoryStore::default(),
            &mut store,
            &mut crate::invocation::promise::store::MemoryStore::default(),
        );

        server_agent.receive(account_invocation, &SystemTime::now());

        Ok(())
    }
}
