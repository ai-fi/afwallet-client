
#![feature(map_first_last)]

// iOS bindings

use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int, c_void};


#[macro_use] 
extern crate  failure;
#[macro_use]
extern crate serde_derive;
pub mod ecdsa;
pub mod util;
pub mod sdk;

#[derive(Copy, PartialEq, Eq, Clone, Debug)]
pub enum Error {
    InvalidKey,
    InvalidSS,
    InvalidCom,
    InvalidSig,
}



pub fn error_to_c_string(e: failure::Error) -> *mut c_char {
    CString::new(format!("Error: {}", e.to_string())).unwrap().into_raw()
}

pub fn parse_address_path(path: &str) -> Option<Vec<i32>> {

    if !path.starts_with("m") {
        return None
    }

    let new_path = path.replace("'", "").replace("m/", "");


    let components: Vec<&str> = new_path.split("/").collect();
    let mut res: Vec<i32> = Vec::new();
    for component in components.iter() {
        let num = component.parse::<i32>().unwrap();
        res.push(num);
    }

    return Some(res);
}

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
// use std::{time};


#[no_mangle]
pub extern "C" fn get_master_address(c_wallet_json: *const c_char, c_network: *const c_char, c_error: *mut c_int) -> *mut c_char {

    let raw_wallet_json = unsafe { CStr::from_ptr(c_wallet_json) };
    if raw_wallet_json.to_str().is_err() {
        unsafe {
            *c_error = -1
        };
        let null: *const c_char = std::ptr::null();
        let mutnull: *mut c_char = null.clone() as *mut c_char;
        return mutnull;
    }
    let wallet_json = raw_wallet_json.to_str().unwrap();

    let raw_network = unsafe { CStr::from_ptr(c_network) };
    if raw_network.to_str().is_err() {
        unsafe {
            *c_error = -1
        };
        let null: *const c_char = std::ptr::null();
        let mutnull: *mut c_char = null.clone() as *mut c_char;
        return mutnull;
    }
    let network_str = raw_network.to_str().unwrap();

    let network = network_str.parse::<bitcoin::network::constants::Network>().unwrap();

    let (_uuid, _party_keys, _shared_keys, _party_id, mut _vss_scheme_vec, _paillier_key_vector, y_sum, _chaincode): (
        String,
        Keys,
        SharedKeys,
        u32,
        Vec<VerifiableSS>,
        Vec<EncryptionKey>,
        GE,
        String,
    ) = serde_json::from_str(&wallet_json).unwrap();
    unsafe {
        *c_error = 0;
    };
    let addr = util::address::pubkey_to_address(&y_sum, &network);

    CString::new(addr).unwrap().into_raw()
}

#[no_mangle]
pub extern "C" fn ecdsa_keygen(c_connstr: *const c_char, pcb: sdk::keygen::KeyGenProgress, c_user_data: *mut c_void, c_error: *mut c_int) -> *mut c_char {
    
    let raw_connstr = unsafe { CStr::from_ptr(c_connstr) };
    if raw_connstr.to_str().is_err() {
        unsafe {
            *c_error = -1
        };
        let null: *const c_char = std::ptr::null();
        let mutnull: *mut c_char = null.clone() as *mut c_char;
        return mutnull;
    }

    let connstr = raw_connstr.to_str().unwrap();
    let nc = sdk::network::NetworkClient::new(connstr);
    
    let result = sdk::keygen::keygen(&nc, pcb, c_user_data);
    if result.is_err() {
        unsafe {
            *c_error = -2
        };
        let null: *const c_char = std::ptr::null();
        let mutnull: *mut c_char = null.clone() as *mut c_char;
        return mutnull;
    }

    let keygen_json = serde_json::to_string(&result.unwrap());
    CString::new(keygen_json.unwrap()).unwrap().into_raw()
}

#[no_mangle]
pub fn ecdsa_sign(c_connstr: *const c_char, c_wallet_str: *const c_char, c_network: *const c_char, c_psbt_str: *const c_char, pcb: sdk::sign::SignProgress, c_user_data: *mut c_void, c_error: *mut c_int)  -> *mut c_char {
    let raw_connstr = unsafe { CStr::from_ptr(c_connstr) };
    let opt_connstr = raw_connstr.to_str();
    if opt_connstr.is_err() {
        unsafe {
            *c_error = -1
        };
        let null: *const c_char = std::ptr::null();
        let mutnull: *mut c_char = null.clone() as *mut c_char;
        return mutnull;
    }
    let connstr = opt_connstr.unwrap();

    let raw_wallet_str = unsafe { CStr::from_ptr(c_wallet_str) };
    let opt_wallet_str = raw_wallet_str.to_str();
    if opt_wallet_str.is_err() {
        unsafe {
            *c_error = -1
        };
        let null: *const c_char = std::ptr::null();
        let mutnull: *mut c_char = null.clone() as *mut c_char;
        return mutnull;
    }
    let wallet_str = opt_wallet_str.unwrap();

    
    let raw_network_str = unsafe { CStr::from_ptr(c_network) };
    let opt_network_str = raw_network_str.to_str();
    if opt_network_str.is_err() {
        unsafe {
            *c_error = -1
        };
        let null: *const c_char = std::ptr::null();
        let mutnull: *mut c_char = null.clone() as *mut c_char;
        return mutnull;
    }
    let network_str = opt_network_str.unwrap();
    let network: bitcoin::network::constants::Network = network_str.parse::<bitcoin::network::constants::Network>().unwrap();

    let raw_psbt_str = unsafe { CStr::from_ptr(c_psbt_str) };
    let opt_psbt_str = raw_psbt_str.to_str();
    if opt_psbt_str.is_err() {
        unsafe {
            *c_error = -1
        };
        let null: *const c_char = std::ptr::null();
        let mutnull: *mut c_char = null.clone() as *mut c_char;
        return mutnull;
    }
    let psbt_str = opt_psbt_str.unwrap();

    let nc = sdk::network::NetworkClient::new(connstr);

    let psbt = bitcoin::util::psbt::PartiallySignedTransaction::from_hex_string(&psbt_str);
    let result = sdk::sign::sign_psbt(&nc, &String::from(wallet_str), network, &psbt, pcb, c_user_data);
    if result.is_err() {
        unsafe {
            *c_error = -2
        };
        let null: *const c_char = std::ptr::null();
        let mutnull: *mut c_char = null.clone() as *mut c_char;
        return mutnull;
    }

    let signed_psbt = result.unwrap();
    let tx = signed_psbt.clone().extract_tx();
    let tx_vec = bitcoin::consensus::serialize(&tx);
    let tx_hex = hex::encode(&tx_vec);

    println!("PSBT: {:?}", &signed_psbt);
    let signed_psbt_hex_str = match signed_psbt.to_hex_string() {
        None => {
            unsafe {
                *c_error = -3
            };
            let null: *const c_char = std::ptr::null();
            let mutnull: *mut c_char = null.clone() as *mut c_char;
            return mutnull;
        },
        Some(s) => s,
    };
    println!("PSBT HEX: {:?}", signed_psbt_hex_str);
    CString::new(tx_hex).unwrap().into_raw()
}


#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
struct PSBTValue {
    value: u64,
    address: String
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
struct PSBTSummary {
    inputs: Vec<PSBTValue>,
    outputs: Vec<PSBTValue>,
    fee: u64,
    memo: String,
}

#[no_mangle]
pub extern "C" fn psbt_to_json(c_network: *const c_char, c_psbt: *const c_char) -> *mut c_char {
    
    let mutnull: *mut c_char = std::ptr::null_mut();
    let raw_network = unsafe { CStr::from_ptr(c_network) };
    let network_str = match raw_network.to_str() {
        Ok(s) => s,
        Err(_e) => return mutnull,
    };
    let network = match network_str.parse::<bitcoin::network::constants::Network>() {
        Ok(s) => s,
        Err(_e) => return mutnull,
    };

    let raw_psbt = unsafe { CStr::from_ptr(c_psbt) };
    let psbt_hex = match raw_psbt.to_str() {
        Ok(s) => s,
        Err(_e) => return mutnull,
    };

    let psbt = bitcoin::util::psbt::PartiallySignedTransaction::from_hex_string(&psbt_hex);

    let tx = &psbt.global.unsigned_tx;
    let inputs = &psbt.inputs;
    let outputs = &psbt.outputs;


    let mut fee: u64 = 0;
    let mut iv: Vec<PSBTValue> = Vec::new();
    let mut ov: Vec<PSBTValue> = Vec::new();
    for i in 0..inputs.len() {
        // let tx_input: &bitcoin::TxIn = &tx.input.get(i).unwrap();
        let input: &bitcoin::util::psbt::Input = &inputs.get(i).unwrap();
        if input.hd_keypaths.len() > 0 {
            let (pubkey, (_fingerprint, _path)) = input.hd_keypaths.first_key_value().unwrap();
            let address = bitcoin::Address::p2wpkh(&pubkey, network);
            let value = input.witness_utxo.as_ref().unwrap().value;
            let v = PSBTValue{
                value: value,
                address: address.to_string(),
            };
            fee = fee + value;
            iv.push(v);
        }
    }
    for i in 0..outputs.len() {
        let tx_output: &bitcoin::TxOut = &tx.output.get(i).unwrap();
        let output: &bitcoin::util::psbt::Output = &outputs.get(i).unwrap();
        // tx_output.script_pubkey.is_v0_p2wpkh()
        
        let address: String = match output.hd_keypaths.first_key_value() {
            None => bitcoin::Address::from_script(&tx_output.script_pubkey, network).unwrap().to_string(),
            Some((pubkey, (_fingerprint, _path))) => bitcoin::Address::p2wpkh(&pubkey, network).to_string(),
        };
        
        let value = tx_output.value;
        fee = fee - value;
        let v = PSBTValue{
            value: value,
            address: address,
        };
        ov.push(v);
    }

    let summary = PSBTSummary {
        inputs: iv,
        outputs: ov,
        fee: fee,
        memo: String::new(),
    };

    let summary_json_str = serde_json::to_string(&summary).unwrap();
    println!("PSBT: {:}", summary_json_str);

    CString::new(summary_json_str.to_owned()).unwrap().into_raw()
}

#[cfg(test)]
mod tests {
    
    #[test]
    fn test_parse_address_path(){
        let path = "m/84'/0'/0'";
        let result = super::parse_address_path(path).unwrap();
        
        assert_eq!(result.len(), 3);
        assert_eq!(result[0], 84);
        assert_eq!(result[1], 0);
        assert_eq!(result[2], 0);
    }
}