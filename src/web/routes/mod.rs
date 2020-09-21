// Gotham-city
//
// Copyright 2018 by Kzen Networks (kzencorp.com)
// Gotham city is free software: you can redistribute
// it and/or modify it under the terms of the GNU General Public
// License as published by the Free Software Foundation, either
// version 3 of the License, or (at your option) any later version.
//

pub mod ping;
pub mod vault;
pub mod keygen;
pub mod sign;
pub mod wallet;
pub mod token;


#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct RequestMessage {
    pub uuid: String,
    pub message: String,
}

#[derive(Debug)]
pub enum VaultStruct {
    VaultWalletIDs,
    VaultData,
    VaultWalletNetwork,
}

use super::storage::*;

impl db::MPCStruct for VaultStruct {
    fn to_string(&self) -> String {
        format!("{:?}", self)
    }
}