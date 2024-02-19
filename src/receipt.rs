//! A [`Receipt`] is the (optional) response from an [`Invocation`][`crate::invocation::Invocation`].
//!
//! - [`Receipt`]s are the result of an [`Invocation`][`crate::invocation::Invocation`].
//! - [`Payload`] contains the pimary semantic information for a [`Receipt`].
//! - [`Store`] is the storage interface for [`Receipt`]s.
//! - [`Responds`] associates the response success type to an [Ability][crate::ability].

mod payload;
mod responds;

pub mod store;

pub use payload::Payload;
pub use responds::Responds;
pub use store::Store;

use crate::{
    ability,
    crypto::{signature, varsig},
    did,
};
use libipld_core::codec::Codec;

/// The complete, signed receipt of an [`Invocation`][`crate::invocation::Invocation`].
#[derive(Clone, Debug, PartialEq)]
pub struct Receipt<
    T: Responds,
    DID: did::Did,
    V: varsig::Header<C>,
    C: Codec + Into<u32> + TryFrom<u32>,
>(pub signature::Envelope<Payload<T, DID>, DID, V, C>);

/// An alias for the [`Receipt`] type with the library preset
/// [`Did`](crate::did)s and [Abilities](crate::ability).
pub type Preset = Receipt<
    ability::preset::Ready,
    did::preset::Verifier,
    varsig::header::Preset,
    varsig::encoding::Preset,
>;

impl<T: Responds, DID: did::Did, V: varsig::Header<C>, C: Codec + Into<u32> + TryFrom<u32>>
    Receipt<T, DID, V, C>
{
    /// Returns the [`Payload`] of the [`Receipt`].
    pub fn payload(&self) -> &Payload<T, DID> {
        &self.0.payload
    }

    /// Returns the [`signature::Envelope`] of the [`Receipt`].
    pub fn signature(&self) -> &DID::Signature {
        &self.0.signature
    }
}
