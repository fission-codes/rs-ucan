//! This module is for dynamic abilities, especially for FFI and Wasm support

use super::{arguments::Arguments, command::ToCommand};
use crate::{ipld, proof::same::CheckSame};
use js_sys;
use libipld_core::{error::SerdeError, ipld::Ipld, serde as ipld_serde};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, fmt::Debug};
use wasm_bindgen::prelude::*;

// NOTE the lack of checking functions!
// This is meant to be embedded inside of structs that have e.g. FFI bindings to
// a validation function, such as a &js_sys::Function, Ruby magnus::function!, etc etc
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)] // FIXME serialize / deserilaize?
pub struct Dynamic {
    pub cmd: String,
    pub args: Arguments,
}

impl ToCommand for Dynamic {
    fn to_command(&self) -> String {
        self.cmd.clone()
    }
}

impl From<Dynamic> for Arguments {
    fn from(dynamic: Dynamic) -> Self {
        dynamic.args
    }
}

#[cfg(target_arch = "wasm32")]
impl From<Dynamic> for js_sys::Map {
    fn from(ability: Dynamic) -> Self {
        let args = js_sys::Map::new();
        for (k, v) in ability.args.0 {
            args.set(&k.into(), &ipld::Newtype(v).into());
        }

        let map = js_sys::Map::new();
        map.set(&"args".into(), &js_sys::Object::from(args).into());
        map.set(&"cmd".into(), &ability.cmd.into());
        map
    }
}

#[cfg(target_arch = "wasm32")]
impl TryFrom<js_sys::Map> for Dynamic {
    type Error = JsValue;

    fn try_from(map: js_sys::Map) -> Result<Self, Self::Error> {
        if let (Some(cmd), js_args) = (
            map.get(&("cmd".into())).as_string(),
            &map.get(&("args".into())),
        ) {
            let obj_args = js_sys::Object::try_from(js_args).ok_or(wasm_bindgen::JsValue::NULL)?;
            let keys = js_sys::Object::keys(obj_args);
            let values = js_sys::Object::values(obj_args);

            let mut btree = BTreeMap::new();
            for (k, v) in keys.iter().zip(values) {
                if let Some(k) = k.as_string() {
                    btree.insert(k, ipld::Newtype::try_from(v).expect("FIXME").0);
                } else {
                    return Err(k);
                }
            }

            Ok(Dynamic {
                cmd,
                args: Arguments(btree), // FIXME kill clone
            })
        } else {
            Err(JsValue::NULL) // FIXME
        }
    }
}

impl CheckSame for Dynamic {
    type Error = String; // FIXME better err

    fn check_same(&self, proof: &Self) -> Result<(), Self::Error> {
        if self.cmd != proof.cmd {
            return Err("Command mismatch".into());
        }

        self.args.0.iter().try_for_each(|(k, v)| {
            if let Some(proof_v) = proof.args.0.get(k) {
                if v != proof_v {
                    return Err("Arguments mismatch".into());
                }
            } else {
                return Err("Arguments mismatch".into());
            }

            Ok(())
        })
    }
}

impl From<Dynamic> for Ipld {
    fn from(dynamic: Dynamic) -> Self {
        dynamic.into()
    }
}

impl TryFrom<Ipld> for Dynamic {
    type Error = SerdeError;

    fn try_from(ipld: Ipld) -> Result<Self, Self::Error> {
        ipld_serde::from_ipld(ipld)
    }
}
