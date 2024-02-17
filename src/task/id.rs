use libipld_core::{cid::Cid, error::SerdeError, ipld::Ipld, serde as ipld_serde};
use serde_derive::{Deserialize, Serialize};
use std::fmt::Debug;

/// The unique identifier for a [`Task`][super::Task].
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Id {
    /// The CID of the [`Task`][super::Task].
    ///
    /// This acts as a unique identifier for the task.
    pub cid: Cid,
}

impl TryFrom<Ipld> for Id {
    type Error = SerdeError;

    fn try_from(ipld: Ipld) -> Result<Self, Self::Error> {
        ipld_serde::from_ipld(ipld)
    }
}

impl From<Id> for Ipld {
    fn from(id: Id) -> Self {
        id.cid.into()
    }
}
