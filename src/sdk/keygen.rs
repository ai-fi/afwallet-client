//#![allow(non_snake_case)]
extern crate crypto;
extern crate curv;
/// to run:
/// 1: go to rocket_server -> cargo run
/// 2: cargo run from PARTIES number of terminals
extern crate multi_party_ecdsa;
extern crate paillier;
extern crate reqwest;

extern crate serde_json;

use super::Result;

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
use super::network::*;

use std::os::raw::{c_int, c_void};

pub type KeyGenProgress = extern "C" fn(c_int, *mut c_void);

pub fn keygen(nc: &NetworkClient, network: &String, pcb: KeyGenProgress, c_user_data: *mut c_void) -> Result<(
    String,
    String,
    Keys,
    SharedKeys,
    u32,
    Vec<VerifiableSS>,
    Vec<EncryptionKey>,
    GE,
    String
)> {

    let threshold: u32 = 1;
    let parties: u32 = 2;
    let party_num_int: u32 = 2;

    let parames = Parameters {
        threshold: threshold as usize,
        share_count: parties as usize,
    };

    let msg1 = format!("init:{}", network);
    
    // round0: 
    let mut req = RequestMessage {
        uuid: String::from(""),
        message: msg1,
    };
    let (uuid, chaincode): (String, String) = nc.keygen(&req)?;
    pcb(0, c_user_data);
    
    req.uuid = uuid.clone();
    
    // round1:
    let party_keys = Keys::create(party_num_int.clone() as usize);
    let (bc_i, decom_i) = party_keys.phase1_broadcast_phase3_proof_of_correct_key();

    req.message = serde_json::to_string(&bc_i).unwrap();
    let (_uuid, resp) = nc.keygen(&req)?;
    pcb(1, c_user_data);


    // round2:
    let bc1_j: KeyGenBroadcastMessage1 =
                    serde_json::from_str(&resp).unwrap();

    let mut bc1_vec: Vec<KeyGenBroadcastMessage1> = Vec::new();
    bc1_vec.push(bc1_j);
    bc1_vec.push(bc_i.clone());
    
    
    req.message = serde_json::to_string(&decom_i).unwrap();
    let (_uuid, resp) = nc.keygen(&req)?;
    pcb(2, c_user_data);

    // round3:
    let mut y_vec: Vec<GE> = Vec::new();
    let mut decom_vec: Vec<KeyGenDecommitMessage1> = Vec::new();
    let mut enc_keys: Vec<BigInt> = Vec::new();

    let decom_j: KeyGenDecommitMessage1 = serde_json::from_str(&resp).unwrap();
    y_vec.push(decom_j.y_i.clone());
    decom_vec.push(decom_j.clone());
    enc_keys.push(
        (party_keys.y_i.clone() + decom_j.y_i.clone()).x_coor() .unwrap(),
    );
    
    y_vec.push(party_keys.y_i.clone());
    decom_vec.push(decom_i.clone());

    let mut y_vec_iter = y_vec.iter();
    let head = y_vec_iter.next().unwrap();
    let tail = y_vec_iter;
    let y_sum = tail.fold(head.clone(), |acc, x| acc + x);

    let (vss_scheme, secret_shares, _index) = party_keys
        .phase1_verify_com_phase3_verify_correct_key_phase2_distribute(
            &parames, &decom_vec, &bc1_vec,
        )
        .expect("invalid key");

    
    // prepare encrypted ss for party i:
    let key_i = BigInt::to_vec(&enc_keys[0]);
    let nonce: Vec<u8> = repeat(3).take(12).collect();
    let aad: [u8; 0] = [];
    let mut gcm = AesGcm::new(KeySize256, &key_i[..], &nonce[..], &aad);
    let plaintext = BigInt::to_vec(&secret_shares[0].to_big_int());
    let mut out: Vec<u8> = repeat(0).take(plaintext.len()).collect();
    let mut out_tag: Vec<u8> = repeat(0).take(16).collect();
    gcm.encrypt(&plaintext[..], &mut out[..], &mut out_tag[..]);
    let aead_pack_i = AEAD {
        ciphertext: out.to_vec(),
        tag: out_tag.to_vec(),
    };

    req.message = serde_json::to_string(&aead_pack_i).unwrap();
    let (_uuid, resp) = nc.keygen(&req)?;
    pcb(3, c_user_data);
    
    // round 4: send vss commitments
    let mut party_shares: Vec<FE> = Vec::new();

    let aead_pack: AEAD = serde_json::from_str(&resp).unwrap();
    let mut out: Vec<u8> = repeat(0).take(aead_pack.ciphertext.len()).collect();
    let key_i = BigInt::to_vec(&enc_keys[0]);
    let nonce: Vec<u8> = repeat(3).take(12).collect();
    let aad: [u8; 0] = [];
    let mut gcm = AesGcm::new(KeySize256, &key_i[..], &nonce[..], &aad);
    let result = gcm.decrypt(&aead_pack.ciphertext[..], &mut out, &aead_pack.tag[..]);
    assert!(result);
    let out_bn = BigInt::from(&out[..]);
    let out_fe = ECScalar::from(&out_bn);

    party_shares.push(out_fe);
    party_shares.push(secret_shares[1 as usize].clone());
    

    req.message = serde_json::to_string(&vss_scheme).unwrap();
    let (_uuid, resp) = nc.keygen(&req)?;
    pcb(4, c_user_data);

    let mut vss_scheme_vec: Vec<VerifiableSS> = Vec::new();
    let vss_scheme_j: VerifiableSS = serde_json::from_str(&resp).unwrap();
    vss_scheme_vec.push(vss_scheme_j);
    vss_scheme_vec.push(vss_scheme.clone());

    let (shared_keys, dlog_proof) = party_keys
        .phase2_verify_vss_construct_keypair_phase3_pok_dlog(
            &parames,
            &y_vec,
            &party_shares,
            &vss_scheme_vec,
            &(party_num_int as usize),
        )
        .expect("invalid vss");


    // round 5: send vss commitments
    req.message = serde_json::to_string(&dlog_proof).unwrap();
    let (_uuid, resp) = nc.keygen(&req)?;
    pcb(5, c_user_data);
    
    let mut dlog_proof_vec: Vec<DLogProof> = Vec::new();
    let dlog_proof_j: DLogProof = serde_json::from_str(&resp).unwrap();
    dlog_proof_vec.push(dlog_proof_j);
    dlog_proof_vec.push(dlog_proof.clone());
    
    let verify_result = Keys::verify_dlog_proofs(&parames, &dlog_proof_vec, &y_vec);
    if verify_result.is_err() {
        return Err(format_err!("Failed to verify dlog proofs: {:?}", verify_result.err()));
    }
    
    //////////////////////////////////////////////////////////////////////////////

    let paillier_key_vec = (0..parties)
        .map(|i| bc1_vec[i as usize].e.clone())
        .collect::<Vec<EncryptionKey>>();
        
    Ok((uuid, 
        network.clone(), 
        party_keys,
        shared_keys,
        party_num_int,
        vss_scheme_vec,
        paillier_key_vec,
        y_sum,
        chaincode))
}