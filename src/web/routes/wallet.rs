//use uuid::Uuid;
use super::super::Result;
use rocket::State;
use rocket_contrib::json::Json;
//use std::collections::HashMap;
//use std::sync::RwLock;
use super::super::auth::jwt::Claims;
use super::super::storage::db;
use super::super::Config;
use super::*;

//use crypto::aead::AeadDecryptor;
//use crypto::aead::AeadEncryptor;
//use crypto::aes::KeySize::KeySize256;
//use crypto::aes_gcm::AesGcm;

//use curv::arithmetic::traits::Converter;
//use curv::cryptographic_primitives::proofs::sigma_dlog::DLogProof;
use curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;
//use curv::elliptic::curves::traits::*;
//use curv::BigInt;
//use curv::{FE, GE};
use curv::{GE};
use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2018::party_i::*;
use paillier::EncryptionKey;
// use std::iter::repeat;

// use std::{time};



#[get("/wallet/default")]
pub fn get_default(
    state: State<Config>,
    // db_mtx: State<RwLock<HashMap<String, String>>>,
    claim: Claims,
) -> Result<Json<(String, String, String, String)>> {

    let vault_wallet_ids_id = String::from("vault_wallet_ids_id");
    let result: Vec<String> = db::get(&state.db, &claim.sub, &vault_wallet_ids_id, &VaultStruct::VaultWalletIDs)?
    .ok_or(format_err!("No data for such identifier {}", vault_wallet_ids_id))?;
    let wallet_id = result.first().unwrap();

    let wallet_data: String =db::get(&state.db, &claim.sub, &wallet_id, &VaultStruct::VaultData)?
    .ok_or(format_err!("No data for such identifier {}", wallet_id))?;
    

    let (uuid, network, _party_keys, _shared_keys, _party_id, mut _vss_scheme_vec, _paillier_key_vector, y_sum, _chaincode): (
        String,
        String,
        Keys,
        SharedKeys,
        u32,
        Vec<VerifiableSS>,
        Vec<EncryptionKey>,
        GE,
        String,
    ) = serde_json::from_str(&wallet_data)?;

    // let xpubstr = "0488b21e010a2683ed00000000d970c5e49aa52f3e074c2dc1f8eb4f08fd12c594cbde161dffc722ae0b7bafcf0212b55b9431515c7185355f15b48c5e1a1bbfa31af61429fa2bb8709de722f420767a344a";
    // let data = hex::decode(&xpubstr).unwrap();
    // let b58 = bitcoin::util::base58::encode_slice(&data);
    // let xpub = super::super::super::util::address::zpub_from(&y_sum, &chaincode);

    let btcnw = network.parse::<bitcoin::network::constants::Network>()?;
    let xpub = String::new();
    let addr = super::super::super::util::address::pubkey_to_address(&y_sum, &btcnw);
    let mut path = String::from("m/84'/0'/0'");
    if btcnw == bitcoin::network::constants::Network::Testnet {
        path = String::from("m/84'/1'/0'");
    }
    Ok(Json((uuid, addr, path, xpub)))
}