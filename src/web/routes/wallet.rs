use uuid::Uuid;
use super::super::Result;
use rocket::State;
use rocket_contrib::json::Json;
use std::collections::HashMap;
use std::sync::RwLock;
use super::super::auth::jwt::Claims;
use super::super::storage::db;
use super::super::Config;
use super::*;

use crypto::aead::AeadDecryptor;
use crypto::aead::AeadEncryptor;
use crypto::aes::KeySize::KeySize256;
use crypto::aes_gcm::AesGcm;

use curv::arithmetic::traits::Converter;
use curv::cryptographic_primitives::proofs::sigma_dlog::DLogProof;
use curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;
use curv::elliptic::curves::traits::*;
use curv::BigInt;
use curv::{FE, GE};
use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2018::party_i::*;
use paillier::EncryptionKey;
use std::iter::repeat;
// use std::{time};



#[get("/wallet/default")]
pub fn get_default(
    state: State<Config>,
    db_mtx: State<RwLock<HashMap<String, String>>>,
    claim: Claims,
) -> Result<Json<(String, String, String)>> {

    let vault_wallet_ids_id = String::from("vault_wallet_ids_id");
    let result: Vec<String> = db::get(&state.db, &claim.sub, &vault_wallet_ids_id, &VaultStruct::VaultWalletIDs)?
    .ok_or(format_err!("No data for such identifier {}", vault_wallet_ids_id))?;
    let wallet_id = result.first().unwrap();

    let wallet_data: String =db::get(&state.db, &claim.sub, &wallet_id, &VaultStruct::VaultData)?
    .ok_or(format_err!("No data for such identifier {}", wallet_id))?;
    

    let (uuid, _party_keys, _shared_keys, _party_id, mut _vss_scheme_vec, _paillier_key_vector, y_sum, _chaincode): (
        String,
        Keys,
        SharedKeys,
        u32,
        Vec<VerifiableSS>,
        Vec<EncryptionKey>,
        GE,
        String,
    ) = serde_json::from_str(&wallet_data)?;
    let addr = super::super::super::util::address::pubkey_to_address(&y_sum);
    Ok(Json((uuid, addr, String::from("m/84'/0'/0'"))))
}