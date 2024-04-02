use crate::ability::arguments::Named;
use crate::crypto::varsig::Header;
use crate::{capsule::Capsule, crypto::varsig, did::Did};
use libipld_core::{
    cid::Cid,
    codec::{Codec, Encode},
    error::Result,
    ipld::Ipld,
    multihash::{Code, MultihashDigest},
};
use signature::SignatureEncoding;
use signature::Verifier;
use std::collections::BTreeMap;
use std::io::Write;
use thiserror::Error;

pub trait Envelope: Sized {
    type DID: Did;
    type Payload: Clone + Capsule + TryFrom<Named<Ipld>> + Into<Named<Ipld>>;
    type VarsigHeader: varsig::Header<Self::Encoder> + Clone;
    type Encoder: Codec;

    fn varsig_header(&self) -> &Self::VarsigHeader;
    fn signature(&self) -> &<Self::DID as Did>::Signature;
    fn payload(&self) -> &Self::Payload;
    fn verifier(&self) -> &Self::DID;

    fn construct(
        varsig_header: Self::VarsigHeader,
        signature: <Self::DID as Did>::Signature,
        payload: Self::Payload,
    ) -> Self;

    fn to_ipld_envelope(&self) -> Ipld {
        let wrapped_payload = Self::wrap_payload(self.payload().clone());
        let header_bytes: Vec<u8> = self.varsig_header().clone().into();
        let header: Ipld = vec![header_bytes.into(), wrapped_payload].into();
        let sig_bytes: Ipld = self.signature().to_vec().into();

        vec![sig_bytes.into(), header].into()
    }

    fn wrap_payload(payload: Self::Payload) -> Ipld {
        let inner_args: Named<Ipld> = payload.into();
        let inner_ipld: Ipld = inner_args.into();
        BTreeMap::from_iter([(Self::Payload::TAG.into(), inner_ipld)]).into()
    }

    fn try_from_ipld_envelope(
        ipld: Ipld,
    ) -> Result<Self, FromIpldError<<Self::Payload as TryFrom<Named<Ipld>>>::Error>> {
        let Ipld::List(list) = ipld else {
            return Err(FromIpldError::InvalidSignatureContainer);
        };

        let [Ipld::Bytes(sig), Ipld::List(inner)] = list.as_slice() else {
            return Err(FromIpldError::InvalidSignatureContainer);
        };

        let [Ipld::Bytes(varsig_header), Ipld::Map(btree)] = inner.as_slice() else {
            return Err(FromIpldError::InvalidVarsigContainer);
        };

        let (1, Some(Ipld::Map(inner))) = (
            btree.len(),
            btree.get(<Self::Payload as Capsule>::TAG.into()),
        ) else {
            return Err(FromIpldError::InvalidPayloadCapsule);
        };

        let payload = Self::Payload::try_from(Named(inner.clone()))
            .map_err(FromIpldError::CannotParsePayload)?;

        let varsig_header = Self::VarsigHeader::try_from(varsig_header.as_slice())
            .map_err(|_| FromIpldError::CannotParseVarsigHeader)?;

        let signature = <Self::DID as Did>::Signature::try_from(sig.as_slice())
            .map_err(|_| FromIpldError::CannotParseSignature)?;

        Ok(Self::construct(varsig_header, signature, payload))
    }

    fn varsig_encode<W: Write>(&self, mut w: W) -> Result<W, libipld_core::error::Error>
    where
        Ipld: Encode<Self::Encoder>,
    {
        let codec = self.varsig_header().codec().clone();
        self.to_ipld_envelope().encode(codec, &mut w)?;
        Ok(w)
    }

    /// Attempt to sign some payload with a given signer and specific codec.
    ///
    /// # Arguments
    ///
    /// * `signer` - The signer to use to sign the payload.
    /// * `codec` - The codec to use to encode the payload.
    /// * `payload` - The payload to sign.
    ///
    /// # Errors
    ///
    /// * [`SignError`] - the payload can't be encoded or the signature fails.
    ///
    /// # Example
    ///
    fn try_sign(
        signer: &<Self::DID as Did>::Signer,
        varsig_header: Self::VarsigHeader,
        payload: Self::Payload,
    ) -> Result<Self, SignError>
    where
        Ipld: Encode<Self::Encoder>,
        Named<Ipld>: From<Self::Payload>,
    {
        let ipld = Self::wrap_payload(payload.clone());
        let mut buffer = vec![];
        ipld.encode(*varsig_header.codec(), &mut buffer)
            .map_err(SignError::PayloadEncodingError)?;

        let signature =
            signature::Signer::try_sign(signer, &buffer).map_err(SignError::SignatureError)?;

        Ok(Self::construct(varsig_header, signature, payload))
    }

    /// Attempt to validate a signature.
    ///
    /// # Arguments
    ///
    /// * `self` - The envelope to validate.
    ///
    /// # Errors
    ///
    /// * [`ValidateError`] - the payload can't be encoded or the signature fails.
    ///
    /// # Exmaples
    ///
    /// FIXME
    fn validate_signature(&self) -> Result<(), ValidateError>
    where
        Ipld: Encode<Self::Encoder>,
        Named<Ipld>: From<Self::Payload>,
    {
        let mut encoded = vec![];
        let ipld: Ipld = BTreeMap::from_iter([(
            Self::Payload::TAG.to_string(),
            Named::<Ipld>::from(self.payload().clone()).into(),
        )])
        .into();

        ipld.encode(
            *varsig::header::Header::codec(self.varsig_header()),
            &mut encoded,
        )
        .map_err(ValidateError::PayloadEncodingError)?;

        self.verifier()
            .verify(&encoded, &self.signature())
            .map_err(ValidateError::VerifyError)
    }

    fn cid(&self) -> Result<Cid, libipld_core::error::Error>
    where
        Ipld: Encode<Self::Encoder>,
    {
        let encoded = self.varsig_encode(Vec::new())?;
        let multihash = Code::Sha2_256.digest(&encoded);

        Ok(Cid::new_v1(
            varsig::header::Header::codec(self.varsig_header())
                .clone()
                .into(),
            multihash,
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Error)]
pub enum FromIpldError<E> {
    #[error("Invalid signature container")]
    InvalidSignatureContainer,

    #[error("Invalid varsig container")]
    InvalidVarsigContainer,

    #[error("Cannot parse payload: {0}")]
    CannotParsePayload(#[from] E),

    #[error("Cannot parse varsig header")]
    CannotParseVarsigHeader,

    #[error("Cannot parse signature")]
    CannotParseSignature,

    #[error("Invalid payload capsule")]
    InvalidPayloadCapsule,
}

/// Errors that can occur when signing a [`siganture::Envelope`][Envelope].
#[derive(Debug, Error)]
pub enum SignError {
    /// Unable to encode the payload.
    #[error("Unable to encode payload")]
    PayloadEncodingError(#[from] libipld_core::error::Error),

    /// Error while signing.
    #[error("Signature error: {0}")]
    SignatureError(#[from] signature::Error),
}

/// Errors that can occur when validating a [`signature::Envelope`][Envelope].
#[derive(Debug, Error)]
pub enum ValidateError {
    /// Unable to encode the payload.
    #[error("Unable to encode payload")]
    PayloadEncodingError(#[from] libipld_core::error::Error),

    /// Error while verifying the signature.
    #[error("Signature verification failed: {0}")]
    VerifyError(#[from] signature::Error),
}
