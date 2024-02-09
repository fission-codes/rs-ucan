//! "Any" CRUD ability (superclass of all CRUD abilities)

use super::error::PathError;
use crate::{
    ability::command::Command,
    proof::{parentless::NoParents, same::CheckSame},
};
use libipld_core::{error::SerdeError, ipld::Ipld, serde as ipld_serde};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[cfg_attr(doc, aquamarine::aquamarine)]
/// The superclass of all other CRUD abilities.
///
/// For example, the [`crud::Create`][super::create::Create] ability may
/// be proven by the [`crud::Any`][Any] ability in a delegation chain.
///
/// It may not be invoked directly, but rather is used as a delegaton proof
/// for other CRUD abilities (see the diagram below).
///
/// # Delegation Hierarchy
///
/// The hierarchy of CRUD abilities is as follows:
///
/// ```mermaid
/// flowchart TB
///     top("*")
///
///     subgraph Message Abilities
///       any("crud/*")
///
///       mutate("crud/mutate")
///
///       subgraph Invokable
///         read("crud/read")
///         create("crud/create")
///         update("crud/update")
///         destroy("crud/destroy")
///       end
///     end
///
///     readrun{{"invoke"}}
///     createrun{{"invoke"}}
///     updaterun{{"invoke"}}
///     destroyrun{{"invoke"}}
///
///     top --> any
///             any --> read -.-> readrun
///             any --> mutate
///                     mutate --> create -.-> createrun
///                     mutate --> update -.-> updaterun
///                     mutate --> destroy -.-> destroyrun
///
///     style any stroke:orange;
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Any {
    /// A an optional path relative to the actor's root.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<PathBuf>,
}

impl Command for Any {
    const COMMAND: &'static str = "crud/*";
}

impl NoParents for Any {}

impl CheckSame for Any {
    type Error = PathError;

    fn check_same(&self, proof: &Self) -> Result<(), Self::Error> {
        if let Some(path) = &self.path {
            let proof_path = proof.path.as_ref().ok_or(PathError::Missing)?;
            if path != proof_path {
                return Err(PathError::Mismatch);
            }
        }

        Ok(())
    }
}

impl TryFrom<Ipld> for Any {
    type Error = SerdeError;

    fn try_from(ipld: Ipld) -> Result<Self, Self::Error> {
        ipld_serde::from_ipld(ipld)
    }
}

impl From<Any> for Ipld {
    fn from(builder: Any) -> Self {
        builder.into()
    }
}
