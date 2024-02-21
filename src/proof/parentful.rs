//! Utilities for working with abilties that *do* have a delegation hirarchy.

use super::{
    internal::Checker,
    parents::CheckParents,
    prove::{Prove, Success},
    same::CheckSame,
};
use crate::ability::arguments;
use libipld_core::{error::SerdeError, ipld::Ipld, serde as ipld_serde};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use thiserror::Error;

/// The possible cases for an [ability][crate::ability]'s
/// [Delegation][crate::delegation::Delegation] chain when
/// it has parent abilities (a hierarchy).
///
/// This type is generally not used directly, but rather is
/// called in the plumbing of the library.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Parentful<T: CheckParents> {
    /// The "top" ability (`*`)
    Any,

    /// All possible parents for the ability.
    Parents(T::Parents),

    /// The (invokable) ability itself.
    This(T),
}

impl<T> From<T> for Parentful<T>
where
    T: CheckParents,
{
    fn from(this: T) -> Self {
        Parentful::This(this)
    }
}

/// Error cases when checking proofs (including parents)
#[derive(Debug, Error, PartialEq)]
pub enum ParentfulError<ArgErr, PrfErr, ParErr> {
    /// The `cmd` field was more powerful than the proof.
    ///
    /// i.e. it behaves like moving "down" the delegation chain not "up"
    #[error("The `cmd` field was more powerful than the proof")]
    CommandEscelation,

    /// The `args` field was more powerful than the proof.
    #[error("The `args` field was more powerful than the proof: {0}")]
    ArgumentEscelation(ArgErr),

    /// The parents do not prove the ability.
    #[error("The parents do not prove the ability: {0}")]
    InvalidProofChain(PrfErr),

    /// Comparing parents in a delegation chain failed.
    ///
    /// The specific comparison error is captured in the `ParErr`.
    #[error("Comparing parents in a delegation chain failed: {0}")]
    InvalidParents(ParErr), // FIXME seems kinda broken -- better naming at least
}

impl<T: CheckParents> From<Parentful<T>> for arguments::Named<Ipld>
where
    arguments::Named<Ipld>: From<T> + From<T::Parents>,
{
    fn from(parentful: Parentful<T>) -> Self {
        match parentful {
            Parentful::Any => arguments::Named::new(),
            Parentful::Parents(parents) => parents.into(),
            Parentful::This(this) => this.into(),
        }
    }
}

impl<T: CheckParents> From<Parentful<T>> for Ipld
where
    Ipld: From<T>,
{
    fn from(parentful: Parentful<T>) -> Self {
        parentful.into()
    }
}

impl<T: TryFrom<Ipld> + DeserializeOwned + CheckParents> TryFrom<Ipld> for Parentful<T>
where
    <T as CheckParents>::Parents: DeserializeOwned,
{
    type Error = SerdeError;

    fn try_from(ipld: Ipld) -> Result<Self, Self::Error> {
        ipld_serde::from_ipld(ipld)
    }
}

impl<T: CheckParents> CheckSame for Parentful<T>
where
    T::Parents: CheckSame,
{
    type Error = ParentfulError<T::Error, T::ParentError, <T::Parents as CheckSame>::Error>; // FIXME

    fn check_same(&self, proof: &Self) -> Result<(), Self::Error> {
        match proof {
            Parentful::Any => Ok(()),
            Parentful::Parents(their_parents) => match self {
                Parentful::Any => Err(ParentfulError::CommandEscelation),
                Parentful::Parents(parents) => parents
                    .check_same(their_parents)
                    .map_err(ParentfulError::InvalidParents),
                Parentful::This(this) => this
                    .check_parent(their_parents)
                    .map_err(ParentfulError::InvalidProofChain),
            },
            Parentful::This(that) => match self {
                Parentful::Any => Err(ParentfulError::CommandEscelation),
                Parentful::Parents(_) => Err(ParentfulError::CommandEscelation),
                Parentful::This(this) => this
                    .check_same(that)
                    .map_err(ParentfulError::ArgumentEscelation),
            },
        }
    }
}

impl<T: CheckParents> CheckParents for Parentful<T>
where
    T::Parents: CheckSame,
{
    type Parents = Parentful<T>;
    type ParentError = ParentfulError<T::Error, T::ParentError, <T::Parents as CheckSame>::Error>;

    fn check_parent(&self, proof: &Parentful<T>) -> Result<(), Self::ParentError> {
        match proof {
            Parentful::Any => Ok(()),
            Parentful::Parents(their_parents) => match self {
                Parentful::Any => Err(ParentfulError::CommandEscelation),
                Parentful::Parents(parents) => parents
                    .check_same(their_parents)
                    .map_err(ParentfulError::InvalidParents),
                Parentful::This(this) => this
                    .check_parent(their_parents)
                    .map_err(ParentfulError::InvalidProofChain),
            },
            Parentful::This(that) => match self {
                Parentful::Any => Err(ParentfulError::CommandEscelation),
                Parentful::Parents(_) => Err(ParentfulError::CommandEscelation),
                Parentful::This(this) => this
                    .check_same(that)
                    .map_err(ParentfulError::ArgumentEscelation),
            },
        }
    }
}

impl<T: CheckParents> Checker for Parentful<T> {}

impl<T: CheckParents> Prove for Parentful<T>
where
    T::Parents: CheckSame,
{
    type Error = ParentfulError<T::Error, T::ParentError, <T::Parents as CheckSame>::Error>;

    fn check(&self, proof: &Parentful<T>) -> Result<Success, Self::Error> {
        match proof {
            Parentful::Any => Ok(Success::ProvenByAny),
            Parentful::Parents(their_parents) => match self {
                Parentful::Any => Err(ParentfulError::CommandEscelation),
                Parentful::Parents(parents) => match parents.check_same(their_parents) {
                    Ok(()) => Ok(Success::Proven),
                    Err(e) => Err(ParentfulError::InvalidParents(e)),
                },
                Parentful::This(this) => match this.check_parent(their_parents) {
                    Ok(()) => Ok(Success::Proven),
                    Err(e) => Err(ParentfulError::InvalidProofChain(e)),
                },
            },
            Parentful::This(that) => match self {
                Parentful::Any => Err(ParentfulError::CommandEscelation),
                Parentful::Parents(_) => Err(ParentfulError::CommandEscelation),
                Parentful::This(this) => match this.check_same(that) {
                    Ok(()) => Ok(Success::Proven),
                    Err(e) => Err(ParentfulError::ArgumentEscelation(e)),
                },
            },
        }
    }
}
