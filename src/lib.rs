
// iOS bindings
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int, c_void};


#[macro_use] 
extern crate  failure;
#[macro_use]
extern crate serde_derive;
pub mod ecdsa;
pub mod wallet;
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
// use std::{time};


#[no_mangle]
pub extern "C" fn get_master_address(c_wallet_json: *const c_char, c_error: *mut c_int) -> *mut c_char {

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
    let addr = util::address::pubkey_to_address(&y_sum);

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


pub fn ecdsa_sign(server: &str, token: &str, threshold: i32, parties: i32) {
    
}


#[no_mangle]
pub extern "C" fn c_sign_psbt(c_psbt: *const c_char) -> *mut c_char {
    let raw_psbt = unsafe { CStr::from_ptr(c_psbt) };
    let psbt = match raw_psbt.to_str() {
        Ok(s) => s,
        Err(e) => return error_to_c_string(format_err!("decoding raw endpoint failed: {}", e)),
    };
    let signature_json = sign_psbt(psbt);
    CString::new(signature_json.to_owned()).unwrap().into_raw()
}

pub fn sign_psbt(hex: &str) -> String {
    let psbt = bitcoin::util::psbt::PartiallySignedTransaction::from_hex_string(hex);
    let tx = psbt.extract_tx();
    let signed_psbt = bitcoin::util::psbt::PartiallySignedTransaction::from_unsigned_tx(tx).unwrap();
    //let mut s = String::new();
    //let mut buf = Vec::new();
    //let r: Result<usize, _> = psbt.consensus_encode(buf);
    let str1 = signed_psbt.to_hex_string().unwrap();
    return  str1;
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