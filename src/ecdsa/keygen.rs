#![allow(non_snake_case)]
extern crate crypto;
extern crate curv;
/// to run:
/// 1: go to rocket_server -> cargo run
/// 2: cargo run from PARTIES number of terminals
extern crate multi_party_ecdsa;
extern crate paillier;
extern crate reqwest;

extern crate serde_json;

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
use std::{time};
use super::network::*;
/*
#[derive(Hash, PartialEq, Eq, Clone, Debug, Serialize, Deserialize)]
pub struct TupleKey {
    pub first: String,
    pub second: String,
    pub third: String,
    pub fourth: String,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct AEAD {
    pub ciphertext: Vec<u8>,
    pub tag: Vec<u8>,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct PartySignup {
    pub number: u32,
    pub uuid: String,
    pub chaincode: String,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct Index {
    pub key: TupleKey,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct Entry {
    pub key: TupleKey,
    pub value: String,
}

#[derive(Serialize, Deserialize)]
pub struct Params {
    pub parties: String,
    pub threshold: String,
}
*/

pub fn keygen(nc: &NetworkClient, threshold: u32, parties: u32) -> Result<(
    Keys,
    SharedKeys,
    u32,
    Vec<VerifiableSS>,
    Vec<EncryptionKey>,
    GE,
    String
), String> {
    
    // delay:
    let delay = time::Duration::from_millis(100);
    let parames = Parameters {
        threshold: threshold as usize,
        share_count: parties as usize,
    };

    //signup:
    let party_i_signup_result = nc.signup_keygen();
    if party_i_signup_result.is_err() {
        return Err(String::from("Failed to signup keygen"));
    }
    // assert!(party_i_signup_result.is_ok());
    
    let party_i_signup = party_i_signup_result.unwrap();
    println!("{:?}", party_i_signup.clone());
    let party_num_int = party_i_signup.number.clone();
    let uuid = party_i_signup.uuid;
    let chaincode = party_i_signup.chaincode;

    let party_keys = Keys::create(party_num_int.clone() as usize);
    let (bc_i, decom_i) = party_keys.phase1_broadcast_phase3_proof_of_correct_key();

    //////////////////////////////////////////////////////////////////////////////

    // send commitment to ephemeral public keys, get round 1 commitments of other parties
    if nc.broadcast(
        party_num_int.clone(),
        "round1",
        serde_json::to_string(&bc_i).unwrap(),
        uuid.clone()
    ).is_err() {
        return Err(String::from("Failed to send commitment to ephemeral public keys, get round 1 commitments of other parties"));
    }

    let round1_ans_vec = nc.poll_for_broadcasts(
        party_num_int.clone(),
        parties,
        delay.clone(),
        "round1",
        uuid.clone(),
    );

    let mut j = 0;
    let bc1_vec = (1..parties + 1)
        .map(|i| {
            if i == party_num_int {
                bc_i.clone()
            } else {
                let bc1_j: KeyGenBroadcastMessage1 =
                    serde_json::from_str(&round1_ans_vec[j]).unwrap();
                j = j + 1;
                bc1_j
            }
        })
        .collect::<Vec<KeyGenBroadcastMessage1>>();

    // round 2: send ephemeral public keys and  check commitments correctness
    if nc.broadcast(
        party_num_int.clone(),
        "round2",
        serde_json::to_string(&decom_i).unwrap(),
        uuid.clone()
    )
    .is_err() {
        return Err(String::from("Failed to send ephemeral public keys and  check commitments correctness"));
    }
    let round2_ans_vec = nc.poll_for_broadcasts(
        party_num_int.clone(),
        parties,
        delay.clone(),
        "round2",
        uuid.clone(),
    );

    //////////////////////////////////////////////////////////////////////////////

    let mut j = 0;
    let mut y_vec: Vec<GE> = Vec::new();
    let mut decom_vec: Vec<KeyGenDecommitMessage1> = Vec::new();
    let mut enc_keys: Vec<BigInt> = Vec::new();
    for i in 1..parties + 1 {
        if i == party_num_int {
            y_vec.push(party_keys.y_i.clone());
            decom_vec.push(decom_i.clone());
        } else {
            let decom_j: KeyGenDecommitMessage1 = serde_json::from_str(&round2_ans_vec[j]).unwrap();
            y_vec.push(decom_j.y_i.clone());
            decom_vec.push(decom_j.clone());
            enc_keys.push(
                (party_keys.y_i.clone() + decom_j.y_i.clone())
                    .x_coor()
                    .unwrap(),
            );
            j = j + 1;
        }
    }

    let mut y_vec_iter = y_vec.iter();
    let head = y_vec_iter.next().unwrap();
    let tail = y_vec_iter;
    let y_sum = tail.fold(head.clone(), |acc, x| acc + x);

    let (vss_scheme, secret_shares, _index) = party_keys
        .phase1_verify_com_phase3_verify_correct_key_phase2_distribute(
            &parames, &decom_vec, &bc1_vec,
        )
        .expect("invalid key");

    //////////////////////////////////////////////////////////////////////////////

    let mut j = 0;
    let mut k = 0;
    let round = 3;
    for i in 1..parties + 1 {
        if i != party_num_int {
            // prepare encrypted ss for party i:
            let key_i = BigInt::to_vec(&enc_keys[j]);
            let nonce: Vec<u8> = repeat(round).take(12).collect();
            let aad: [u8; 0] = [];
            let mut gcm = AesGcm::new(KeySize256, &key_i[..], &nonce[..], &aad);
            let plaintext = BigInt::to_vec(&secret_shares[k].to_big_int());
            let mut out: Vec<u8> = repeat(0).take(plaintext.len()).collect();
            let mut out_tag: Vec<u8> = repeat(0).take(16).collect();
            gcm.encrypt(&plaintext[..], &mut out[..], &mut out_tag[..]);
            let aead_pack_i = AEAD {
                ciphertext: out.to_vec(),
                tag: out_tag.to_vec(),
            };
            if nc.sendp2p(
                party_num_int.clone(),
                i,
                "round3",
                serde_json::to_string(&aead_pack_i).unwrap(),
                uuid.clone()
            )
            .is_err() {
                return Err(String::from("Failed to dispatch share key"));
            }
            j = j + 1;
        }
        k = k + 1;
    }

    let round3_ans_vec = nc.poll_for_p2p(
        party_num_int.clone(),
        parties,
        delay.clone(),
        "round3",
        uuid.clone(),
    );

    let mut j = 0;
    let mut party_shares: Vec<FE> = Vec::new();
    for i in 1..parties + 1 {
        if i == party_num_int {
            party_shares.push(secret_shares[(i - 1) as usize].clone());
        } else {
            let aead_pack: AEAD = serde_json::from_str(&round3_ans_vec[j]).unwrap();
            let mut out: Vec<u8> = repeat(0).take(aead_pack.ciphertext.len()).collect();
            let key_i = BigInt::to_vec(&enc_keys[j]);
            let nonce: Vec<u8> = repeat(round).take(12).collect();
            let aad: [u8; 0] = [];
            let mut gcm = AesGcm::new(KeySize256, &key_i[..], &nonce[..], &aad);
            let result = gcm.decrypt(&aead_pack.ciphertext[..], &mut out, &aead_pack.tag[..]);
            assert!(result);
            let out_bn = BigInt::from(&out[..]);
            let out_fe = ECScalar::from(&out_bn);
            party_shares.push(out_fe);

            j = j + 1;
        }
    }
    //////////////////////////////////////////////////////////////////////////////

    // round 4: send vss commitments
    if nc.broadcast(
        party_num_int.clone(),
        "round4",
        serde_json::to_string(&vss_scheme).unwrap(),
        uuid.clone()
    )
    .is_err() {
        return Err(String::from("Failed to send vss commitments"));
    }
    let round4_ans_vec = nc.poll_for_broadcasts(
        party_num_int.clone(),
        parties,
        delay.clone(),
        "round4",
        uuid.clone(),
    );

    let mut j = 0;
    let mut vss_scheme_vec: Vec<VerifiableSS> = Vec::new();
    for i in 1..parties + 1 {
        if i == party_num_int {
            vss_scheme_vec.push(vss_scheme.clone());
        } else {
            let vss_scheme_j: VerifiableSS = serde_json::from_str(&round4_ans_vec[j]).unwrap();
            vss_scheme_vec.push(vss_scheme_j);
            j = j + 1;
        }
    }

    let (shared_keys, dlog_proof) = party_keys
        .phase2_verify_vss_construct_keypair_phase3_pok_dlog(
            &parames,
            &y_vec,
            &party_shares,
            &vss_scheme_vec,
            &(party_num_int as usize),
        )
        .expect("invalid vss");

    //////////////////////////////////////////////////////////////////////////////
    // round 5: send vss commitments
    if nc.broadcast(
        party_num_int.clone(),
        "round5",
        serde_json::to_string(&dlog_proof).unwrap(),
        uuid.clone()
    )
    .is_err() {
        return Err(String::from("Failed to send vss commitments (dlog_proof)"));
    }
    let round5_ans_vec = nc.poll_for_broadcasts(
        party_num_int.clone(),
        parties,
        delay.clone(),
        "round5",
        uuid.clone(),
    );

    let mut j = 0;
    let mut dlog_proof_vec: Vec<DLogProof> = Vec::new();
    for i in 1..parties + 1 {
        if i == party_num_int {
            dlog_proof_vec.push(dlog_proof.clone());
        } else {
            let dlog_proof_j: DLogProof = serde_json::from_str(&round5_ans_vec[j]).unwrap();
            dlog_proof_vec.push(dlog_proof_j);
            j = j + 1;
        }
    }
    Keys::verify_dlog_proofs(&parames, &dlog_proof_vec, &y_vec).expect("bad dlog proof");
    //////////////////////////////////////////////////////////////////////////////
    //save key to file:

    let paillier_key_vec = (0..parties)
        .map(|i| bc1_vec[i as usize].e.clone())
        .collect::<Vec<EncryptionKey>>();

    Ok((party_keys,
        shared_keys,
        party_num_int,
        vss_scheme_vec,
        paillier_key_vec,
        y_sum,
        chaincode))
    /*
    let keygen_json = serde_json::to_string(&(
        party_keys,
        shared_keys,
        party_num_int,
        vss_scheme_vec,
        paillier_key_vec,
        y_sum,
    ))
    .unwrap();

    fs::write(env::args().nth(2).unwrap(), keygen_json).expect("Unable to save !");
    */
}