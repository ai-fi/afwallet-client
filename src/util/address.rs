
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
use std::str::FromStr;
use bitcoin::network::constants::Network;

pub fn pubkey_to_address(ge: &GE) -> String {
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
    let address = bitcoin::util::address::Address::p2wpkh(&pubkey, Network::Testnet);
    address.to_string()
}