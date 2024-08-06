//! A [`Delegation`] is the way to grant someone else the use of [`Ability`][crate::ability].
//!
//! ## Data
//!
//! - [`Delegation`] is the top-level, signed data struture.
//! - [`Payload`] is the fields unique to an invocation.
//! - [`Preset`] is an [`Delegation`] preloaded with this library's [preset abilities](crate::ability::preset::Ready).
//! - [`Predicate`]s are syntactically-driven validation rules for [`Delegation`]s.
//!
//! ## Stateful Helpers
//!
//! - [`Agent`] is a high-level interface for sessions that will involve more than one invoctaion.
//! - [`store`] is an interface for caching [`Delegation`]s.

pub mod policy;
pub mod store;

mod agent;
mod payload;

pub use agent::Agent;
pub use payload::*;

use crate::{
    ability::arguments::Named,
    capsule::Capsule,
    crypto::{signature::Envelope, varsig, Nonce},
    did::{self, Did},
    time::{TimeBoundError, Timestamp},
};
use core::str::FromStr;
use libipld_core::{
    codec::{Codec, Encode},
    ipld::Ipld,
    link::Link,
};
use policy::Predicate;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::marker::PhantomData;
use web_time::SystemTime;

/// A [`Delegation`] is a signed delegation [`Payload`]
///
/// A [`Payload`] on its own is not a valid [`Delegation`], as it must be signed by the issuer.
#[derive(Clone, Debug, PartialEq)]
pub struct Delegation<
    DID: Did = did::preset::Verifier,
    V: varsig::Header<C> = varsig::header::Preset,
    C: Codec = varsig::encoding::Preset,
> {
    pub varsig_header: V,
    pub payload: Payload<DID>,
    pub signature: DID::Signature,
    _marker: PhantomData<C>,
}

pub struct DelegationRequired<
    DID: Did = did::preset::Verifier,
    V: varsig::Header<C> = varsig::header::Preset,
    C: Codec = varsig::encoding::Preset,
> {
    pub subject: Subject<DID>,
    pub issuer: DID,
    pub audience: DID,
    pub command: String,

    pub codec: PhantomData<C>,
    pub varsig_header: V,
    pub signer: DID::Signer,
}

pub struct DelegationBuilder<
    DID: Did = did::preset::Verifier,
    V: varsig::Header<C> = varsig::header::Preset,
    C: Codec = varsig::encoding::Preset,
> {
    subject: Subject<DID>,
    issuer: DID,
    audience: DID,
    command: String,

    codec: PhantomData<C>,
    varsig_header: V,
    signer: DID::Signer,

    via: Option<DID>,
    policy: Vec<Predicate>,
    metadata: BTreeMap<String, Ipld>,
    nonce: Option<Nonce>,
    expiration: Option<Timestamp>,
    not_before: Option<Timestamp>,
}

impl<DID: Did + Clone, V: varsig::Header<C> + Clone, C: Codec> DelegationRequired<DID, V, C>
where
    Ipld: Encode<C>,
{
    pub fn into_builder(self) -> DelegationBuilder<DID, V, C> {
        DelegationBuilder {
            subject: self.subject,
            issuer: self.issuer,
            audience: self.audience,
            command: self.command,

            codec: self.codec,
            varsig_header: self.varsig_header,
            signer: self.signer,

            via: None,
            policy: vec![],
            metadata: Default::default(),
            nonce: None,
            expiration: None,
            not_before: None,
        }
    }
}

impl<DID: Did + Clone, V: varsig::Header<C> + Clone, C: Codec> DelegationBuilder<DID, V, C>
where
    Ipld: Encode<C>,
{
    pub fn try_sign(self) -> Result<Delegation<DID, V, C>, crate::crypto::signature::SignError>
    where
        <DID as FromStr>::Err: std::fmt::Debug,
    {
        let payload = Payload {
            subject: self.subject,
            issuer: self.issuer,
            audience: self.audience,
            via: self.via,

            command: self.command,
            policy: self.policy,

            nonce: self.nonce.unwrap_or(Nonce::generate_16()),
            metadata: self.metadata,

            expiration: self.expiration,
            not_before: self.not_before,
        };

        Delegation::try_sign(&self.signer, self.varsig_header, payload)
    }

    pub fn via(mut self, via: DID) -> DelegationBuilder<DID, V, C> {
        self.via = Some(via);
        self
    }

    pub fn policy(mut self, policy: Vec<Predicate>) -> DelegationBuilder<DID, V, C> {
        self.policy = policy;
        self
    }

    pub fn nonce(mut self, nonce: Nonce) -> DelegationBuilder<DID, V, C> {
        self.nonce = Some(nonce);
        self
    }

    pub fn metadata(mut self, metadata: BTreeMap<String, Ipld>) -> DelegationBuilder<DID, V, C> {
        self.metadata = metadata;
        self
    }

    pub fn expiration(mut self, expiration: Timestamp) -> DelegationBuilder<DID, V, C> {
        self.expiration = Some(expiration);
        self
    }

    pub fn not_before(mut self, not_before: Timestamp) -> DelegationBuilder<DID, V, C> {
        self.not_before = Some(not_before);
        self
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Proof<
    DID: Did = did::preset::Verifier,
    V: varsig::Header<C> = varsig::header::Preset,
    C: Codec = varsig::encoding::Preset,
> {
    pub prf: Vec<Link<Delegation<DID, V, C>>>,
}

impl<DID: Did, V: varsig::Header<C>, C: Codec> Capsule for Proof<DID, V, C> {
    const TAG: &'static str = "ucan/prf";
}

impl<DID: Did, V: varsig::Header<C>, C: Codec> Delegation<DID, V, C> {
    pub fn new(
        varsig_header: V,
        signature: DID::Signature,
        payload: Payload<DID>,
    ) -> Delegation<DID, V, C> {
        Delegation {
            varsig_header,
            payload,
            signature,
            _marker: PhantomData,
        }
    }

    /// Retrive the `issuer` of a [`Delegation`]
    pub fn issuer(&self) -> &DID {
        &self.payload.issuer
    }

    /// Retrive the `subject` of a [`Delegation`]
    pub fn subject(&self) -> &Subject<DID> {
        &self.payload.subject
    }

    /// Retrive the `audience` of a [`Delegation`]
    pub fn audience(&self) -> &DID {
        &self.payload.audience
    }

    /// Retrieve the `via` of a [`Delegation`]
    pub fn via(&self) -> Option<&DID> {
        self.payload.via.as_ref()
    }

    /// Retrieve the `command` of a [`Delegation`]
    pub fn command(&self) -> &String {
        &self.payload.command
    }

    /// Retrive the `policy` of a [`Delegation`]
    pub fn policy(&self) -> &Vec<Predicate> {
        &self.payload.policy
    }

    /// Retrive the `metadata` of a [`Delegation`]
    pub fn metadata(&self) -> &BTreeMap<String, Ipld> {
        &self.payload.metadata
    }

    /// Retrive the `nonce` of a [`Delegation`]
    pub fn nonce(&self) -> &Nonce {
        &self.payload.nonce
    }

    /// Retrive the `not_before` of a [`Delegation`]
    pub fn not_before(&self) -> Option<&Timestamp> {
        self.payload.not_before.as_ref()
    }

    /// Retrive the `expiration` of a [`Delegation`]
    pub fn expiration(&self) -> Option<&Timestamp> {
        self.payload.expiration.as_ref()
    }

    pub fn check_time(&self, now: SystemTime) -> Result<(), TimeBoundError> {
        self.payload.check_time(now)
    }
}

impl<DID: Did + Clone, V: varsig::Header<C> + Clone, C: Codec> Envelope for Delegation<DID, V, C>
where
    Payload<DID>: TryFrom<Named<Ipld>>,
    Named<Ipld>: From<Payload<DID>>,
{
    type DID = DID;
    type Payload = Payload<DID>;
    type VarsigHeader = V;
    type Encoder = C;

    fn construct(
        varsig_header: V,
        signature: DID::Signature,
        payload: Payload<DID>,
    ) -> Delegation<DID, V, C> {
        Delegation {
            varsig_header,
            payload,
            signature,
            _marker: PhantomData,
        }
    }

    fn varsig_header(&self) -> &V {
        &self.varsig_header
    }

    fn payload(&self) -> &Payload<DID> {
        &self.payload
    }

    fn signature(&self) -> &DID::Signature {
        &self.signature
    }

    fn verifier(&self) -> &DID {
        &self.payload.issuer
    }
}

impl<DID: Did + Clone, V: varsig::Header<C> + Clone, C: Codec> Serialize for Delegation<DID, V, C>
where
    Payload<DID>: TryFrom<Named<Ipld>>,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.to_ipld_envelope().serialize(serializer)
    }
}

impl<'de, DID: Did + Clone, V: varsig::Header<C> + Clone, C: Codec> Deserialize<'de>
    for Delegation<DID, V, C>
where
    Payload<DID>: TryFrom<Named<Ipld>>,
    <Payload<DID> as TryFrom<Named<Ipld>>>::Error: std::fmt::Display,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let ipld = Ipld::deserialize(deserializer)?;
        Self::try_from_ipld_envelope(ipld).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::varsig::{encoding, header};
    use assert_matches::assert_matches;
    use rand::thread_rng;
    use std::collections::BTreeMap;
    use testresult::TestResult;

    fn gen_did() -> (crate::did::preset::Verifier, crate::did::preset::Signer) {
        let sk = ed25519_dalek::SigningKey::generate(&mut thread_rng());
        let verifier =
            crate::did::preset::Verifier::Key(crate::did::key::Verifier::EdDsa(sk.verifying_key()));
        let signer = crate::did::preset::Signer::Key(crate::did::key::Signer::EdDsa(sk));

        (verifier, signer)
    }

    mod required {
        use super::*;

        fn fixture() -> DelegationRequired {
            let (alice, alice_signer) = gen_did();
            let (bob, _bob_signer) = gen_did();
            let (carol, _carol_signer) = gen_did();

            DelegationRequired {
                subject: Subject::Any,
                issuer: alice,
                audience: bob,
                command: "/".to_string(),

                signer: alice_signer,
                codec: PhantomData,
                varsig_header: header::Preset::EdDsa(header::EdDsaHeader {
                    codec: encoding::Preset::DagCbor,
                }),
            }
        }

        #[test_log::test]
        fn test_sign() -> TestResult {
            let delegation = fixture().into_builder().try_sign();
            assert_matches!(delegation, Ok(_));
            Ok(())
        }

        #[test_log::test]
        fn test_sign_with_metadata() -> TestResult {
            let meta = BTreeMap::from_iter([("foo".into(), 123.into())]);
            let delegation = fixture().into_builder().metadata(meta.clone()).try_sign()?;

            assert_eq!(delegation.metadata(), &meta);
            Ok(())
        }

        #[test_log::test]
        fn test_sign_with_via() -> TestResult {
            let (alice, _) = gen_did();
            let delegation = fixture().into_builder().via(alice.clone()).try_sign()?;
            assert_eq!(delegation.via(), Some(alice).as_ref());
            Ok(())
        }

        #[test_log::test]
        fn test_sign_with_policy() -> TestResult {
            let pred = Predicate::Equal(FromStr::from_str(".foo")?, 123.into());
            let delegation = fixture()
                .into_builder()
                .policy(vec![pred.clone()])
                .try_sign()?;

            assert_eq!(delegation.policy(), &vec![pred]);
            Ok(())
        }

        #[test_log::test]
        fn test_sign_with_expiration() -> TestResult {
            let exp = Timestamp::now();
            let delegation = fixture()
                .into_builder()
                .expiration(exp.clone())
                .try_sign()?;

            assert_eq!(delegation.expiration(), Some(&exp));
            Ok(())
        }

        #[test_log::test]
        fn test_sign_with_not_before() -> TestResult {
            let nbf = Timestamp::now();
            let delegation = fixture()
                .into_builder()
                .not_before(nbf.clone())
                .try_sign()?;

            assert_eq!(delegation.not_before(), Some(&nbf));
            Ok(())
        }
    }

    mod builder {
        use super::*;

        fn fixture() -> Result<Delegation, crate::crypto::signature::SignError> {
            let (alice, alice_signer) = gen_did();
            let (bob, bob_signer) = gen_did();
            let (carol, carol_signer) = gen_did();

            DelegationRequired {
                subject: Subject::Any,
                issuer: alice,
                audience: bob,
                command: "/".to_string(),

                signer: alice_signer,
                codec: PhantomData,
                varsig_header: header::Preset::EdDsa(header::EdDsaHeader {
                    codec: encoding::Preset::DagCbor,
                }),
            }
            .into_builder()
            .via(carol)
            .policy(vec![])
            .metadata(BTreeMap::from_iter([("foo".into(), 123.into())]))
            .try_sign()
        }

        #[test_log::test]
        fn test_full_builder() -> TestResult {
            let delegation = fixture();
            assert_matches!(delegation, Ok(_));
            Ok(())
        }
    }
}
