

use bitcoin::util::psbt::*;
extern crate serde_json;
// use std::collections::HashMap;

#[derive(Serialize, Deserialize)]
pub struct WalletProfile {
    pub id: String,
    pub name: String,
    pub threshold: u32,
    pub parties: u32,
}

#[derive(Serialize, Deserialize)]
pub struct WalletNetwork {
    pub server: String,
    pub jwt_token: String,
}

#[derive(Serialize, Deserialize)]
pub struct Wallet {
    pub profile: WalletProfile,
    pub network: WalletNetwork,
}

impl Clone for WalletProfile {
    fn clone(&self) -> WalletProfile {
        WalletProfile{
            id: self.id.clone(),
            name: self.name.clone(),
            threshold: self.threshold.clone(),
            parties: self.parties.clone()
        }
    }
}

impl Clone for WalletNetwork {
    fn clone(&self) -> WalletNetwork {
        WalletNetwork {
            server: self.server.clone(),
            jwt_token: self.jwt_token.clone(),
        }
    }
}

impl Wallet {
    
    pub fn new(profile: &WalletProfile, network: &WalletNetwork) -> Self {

        // serde_json::from_str(&config).unwrap();
        Wallet{
            profile: profile.clone(),
            network: network.clone(),
        }
    }

    pub fn from(server: String, json: String) -> Self {
        let mut wallet: Wallet = serde_json::from_str(&json).unwrap();
        wallet.network.server = server;
        wallet
    }

    pub fn parse_psbt(data: &[u8]) -> Option<PartiallySignedTransaction> {
        return None
    }

    pub fn sign(mut psbt: &PartiallySignedTransaction) -> Option<PartiallySignedTransaction> {
        return None
    }
}