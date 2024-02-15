//! Flat types for parent checking.
//!
//! Types here turn recursive checking into a since union to check.
//! This only needs to handle "inner" delegation types, not the topmost `*`
//! ability, or the invocable leaves of a delegation hierarchy.

use super::error::ParentError;
use crate::{
    ability::{
        arguments,
        command::{ParseAbility, ParseAbilityError, ToCommand},
    },
    proof::{parents::CheckParents, same::CheckSame},
};
use libipld_core::ipld::Ipld;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[cfg_attr(doc, aquamarine::aquamarine)]
/// The union of mutable parents.
///
/// This is helpful as a flat type to put in [`CheckParents::Parents`].
///
/// # Delegation Hierarchy
///
/// The parents captured here are highlted in the following diagram:
///
/// ```mermaid
/// flowchart TB
///     top("*")
///
///     subgraph CRUD Abilities
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
///     style any    stroke:orange;
///     style mutate stroke:orange;
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, untagged)]
pub enum MutableParents {
    /// The `crud/*` ability.
    Any(super::Any),

    /// The `crud/mutate` ability.
    Mutate(super::Mutate),
}

impl ToCommand for MutableParents {
    fn to_command(&self) -> String {
        match self {
            MutableParents::Any(any) => any.to_command(),
            MutableParents::Mutate(mutate) => mutate.to_command(),
        }
    }
}

#[derive(Debug, Clone, Error)]
pub enum ParseError {
    #[error("Invalid `crud/*` arguments: {0}")]
    InvalidAnyArgs(#[source] <super::Any as ParseAbility>::Error),

    #[error("Invalid `crud/mutate` arguments: {0}")]
    InvalidMutateArgs(#[source] <super::Mutate as ParseAbility>::Error),
}

impl ParseAbility for MutableParents {
    type Error = ParseAbilityError<ParseError>;

    fn try_parse(cmd: &str, args: &arguments::Named<Ipld>) -> Result<Self, Self::Error> {
        super::Any::try_parse(cmd, args)
            .map(MutableParents::Any)
            .map_err(ParseError::InvalidAnyArgs)
            .map_err(ParseAbilityError::InvalidArgs)?;

        super::Mutate::try_parse(cmd, args)
            .map(MutableParents::Mutate)
            .map_err(ParseError::InvalidMutateArgs)
            .map_err(ParseAbilityError::InvalidArgs)?;

        Err(ParseAbilityError::UnknownCommand)
    }
}

impl CheckSame for MutableParents {
    type Error = ParentError;

    fn check_same(&self, proof: &Self) -> Result<(), Self::Error> {
        match self {
            MutableParents::Mutate(mutate) => match proof {
                MutableParents::Mutate(proof_mutate) => mutate
                    .check_same(proof_mutate)
                    .map_err(ParentError::InvalidMutateProof),

                MutableParents::Any(proof_any) => mutate
                    .check_parent(proof_any)
                    .map_err(ParentError::InvalidMutateParent),
            },

            MutableParents::Any(any) => match proof {
                MutableParents::Mutate(_) => Err(ParentError::CommandEscelation),
                MutableParents::Any(proof_any) => any
                    .check_same(proof_any)
                    .map_err(ParentError::InvalidAnyProof),
            },
        }
    }
}
