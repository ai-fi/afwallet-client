//use crypto::aead::AeadDecryptor;
//use crypto::aead::AeadEncryptor;
//use crypto::aes::KeySize::KeySize256;
//use crypto::aes_gcm::AesGcm;

//use curv::arithmetic::traits::Converter;
//use curv::cryptographic_primitives::proofs::sigma_dlog::DLogProof;
//use curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;
use curv::elliptic::curves::traits::*;
//use curv::BigInt;
// use curv::{FE, GE};
use curv::{GE};
// use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2018::party_i::*;
// use paillier::EncryptionKey;
// use std::iter::repeat;
use std::str::FromStr;
use bitcoin::network::constants::Network;

pub fn pubkey_to_address(ge: &GE, network: &Network) -> String {
    let pubkeystr = ge.bytes_compressed_to_big_int().to_str_radix(16);
    let pkstr: String;
    if pubkeystr.len() != 66 {
        let mut owned_string: String = "0".to_owned();
        owned_string.push_str(&pubkeystr);
        pkstr = owned_string.clone();
    } else {
        pkstr = pubkeystr.clone();
    }
    let pubkey = bitcoin::PublicKey::from_str(&pkstr).unwrap();
    let address = bitcoin::util::address::Address::p2wpkh(&pubkey, *network);
    address.to_string()
}

pub fn zpub_from(ge: &GE, chain_code: &String) -> String {
    let pubkeystr = ge.bytes_compressed_to_big_int().to_str_radix(16);
    let pkstr: String;
    if pubkeystr.len() != 66 {
        let mut owned_string: String = "0".to_owned();
        owned_string.push_str(&pubkeystr);
        pkstr = owned_string.clone();
    } else {
        pkstr = pubkeystr.clone();
    }

    let ccstr: String;
    if chain_code.len() != 64 {
        let mut owned_string: String = "0".to_owned();
        owned_string.push_str(chain_code);
        ccstr = owned_string.clone();
    } else {
        ccstr = chain_code.clone();
    }

    let mut hexstr: String = "04b247460000000000".to_owned();
    hexstr.push_str(&ccstr);
    hexstr.push_str(&pkstr);
    hexstr.push_str(&String::from("767a344a"));
    println!("pubkey: {}", pkstr);
    println!("chaincode: {}", ccstr);
    println!("hex: {}", hexstr);
    let data = hex::decode(hexstr).unwrap();
    let b58 = bitcoin::util::base58::encode_slice(&data);
    println!("base58: {}", b58);
    //bitcoin::hashes::sha256::from_slice()
    return b58;
    /*
    ['xpub', '0488b21e'],
    ['ypub', '049d7cb2'],
    ['Ypub', '0295b43f'],
    ['zpub', '04b24746'],
    ['Zpub', '02aa7ed3'],
    ['tpub', '043587cf'],
    ['upub', '044a5262'],
    ['Upub', '024289ef'],
    ['vpub', '045f1cf6'],
    ['Vpub', '02575483'],
    */
}