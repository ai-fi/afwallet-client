
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

use curv::cryptographic_primitives::hashing::hmac_sha512;
use curv::cryptographic_primitives::proofs::sigma_correct_homomorphic_elgamal_enc::HomoELGamalProof;
use curv::cryptographic_primitives::hashing::traits::KeyedHash;

use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2018::mta::*;
use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2018::party_i::*;
use paillier::*;
use reqwest::Client;
use std::env;
use std::fs;
use std::time::Duration;
use std::{thread, time};



pub fn combine_pubkey_and_index(pubkey: &BigInt, index: &i32) -> BigInt {
    
    let mut pk_vec = BigInt::to_vec(&pubkey);
    let index_bz = index.to_be_bytes();
    let mut index_vec = index_bz.to_vec();
    pk_vec.append(&mut index_vec);

    let pk_and_idx_bz = &pk_vec[0..];
    let pk_and_idx_bi = BigInt::from(pk_and_idx_bz);
    println!("ParentPK_IDX: {:?}", BigInt::to_vec(&pk_and_idx_bi));
    return pk_and_idx_bi;
}


pub fn hd_key(
    mut location_in_hir: Vec<i32>,
    pubkey: &GE,
    chain_code_bi: &BigInt,
) -> (GE, FE, BigInt) {

    println!("Default Chain Code: {:?}", chain_code_bi);
    let mask = BigInt::from(2).pow(256) - BigInt::one();
    // let public_key = self.public.q.clone();

    // calc first element:
    let first = location_in_hir.remove(0);
    let pub_key_bi = pubkey.bytes_compressed_to_big_int();
    let pub_key_and_idx_bi = combine_pubkey_and_index(&pub_key_bi, &first);
    let f = hmac_sha512::HMacSha512::create_hmac(&chain_code_bi, &[&pub_key_and_idx_bi]);
    println!("{:?}", BigInt::to_vec(&f));
    let f_l = &f >> 256;
    let f_r = &f & &mask;
    let f_l_fe: FE = ECScalar::from(&f_l);
    let f_r_fe: FE = ECScalar::from(&f_r);

    let bn_to_slice = BigInt::to_vec(chain_code_bi);
    // let chain_code = GE::from_bytes(&bn_to_slice[1..33]).unwrap() * &f_r_fe;
    let g: GE = ECPoint::generator();
    let pub_key = *pubkey + g * &f_l_fe;


    let xxx = BigInt::to_vec(&pub_key.bytes_compressed_to_big_int());
    println!("Child PK {:?}", xxx);
    let (public_key_new_child, f_l_new, cc_new) =
        location_in_hir
            .iter()
            .fold((pub_key, f_l_fe, f_r), |acc, index| {
                let pub_key_bi = acc.0.bytes_compressed_to_big_int();
                let pub_key_and_idx_bi = combine_pubkey_and_index(&pub_key_bi, &index);
                let f = hmac_sha512::HMacSha512::create_hmac(
                    &acc.2,
                    &[&pub_key_and_idx_bi],
                );
                let f_l = &f >> 256;
                let f_r = &f & &mask;
                let f_l_fe: FE = ECScalar::from(&f_l);
                let f_r_fe: FE = ECScalar::from(&f_r);
                let cpk = acc.0 + g * &f_l_fe;

                let xxx = BigInt::to_vec(&cpk.bytes_compressed_to_big_int());
                println!("Child PK {:?}", xxx);
                (cpk, f_l_fe + &acc.1, f_r)
                //(acc.0 + g * &f_l_fe, f_l_fe + &acc.1, &acc.2 * &f_r_fe)
            });
    (public_key_new_child, f_l_new, cc_new)
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

fn format_vec_from_reads<'a, T: serde::Deserialize<'a> + Clone>(
    ans_vec: &'a [String],
    party_num: usize,
    value_i: T,
    new_vec: &'a mut Vec<T>,
) {
    let mut j = 0;
    for i in 1..ans_vec.len() + 2 {
        if i == party_num {
            new_vec.push(value_i.clone());
        } else {
            let value_j: T = serde_json::from_str(&ans_vec[j]).unwrap();
            new_vec.push(value_j);
            j += 1;
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct SignRound0 {
    pub path: String,
    pub msg: Vec<u8>,
    pub signers_vec: Vec<usize>,
}

impl SignRound0 {
    fn new() -> SignRound0 {
        SignRound0 {
            path: String::new(),
            msg: Vec::new(),
            signers_vec: Vec::new(),
        }
    }
}


#[derive(Clone, Serialize, Deserialize)]
pub struct SignRound1 {
    pub bc1_vec: Vec<SignBroadcastPhase1>,
    pub m_a_vec: Vec<MessageA>,
    pub child_y_sum: GE,
    pub decommit: SignDecommitPhase1,
    pub sign_keys: Option<SignKeys>,
    pub vss_scheme_vec: Vec<VerifiableSS>, 
}

impl SignRound1 {
    fn new() -> SignRound1 {
        SignRound1 {
            bc1_vec: Vec::new(),
            m_a_vec: Vec::new(),
            child_y_sum: GE::random_point(),
            decommit: SignDecommitPhase1{blind_factor: BigInt::from(0), g_gamma_i: GE::random_point()},
            sign_keys: None,
            vss_scheme_vec: Vec::new(),
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct SignRound2 {

    pub m_b_gamma_send_vec: Vec<MessageB>,
    pub m_b_gamma_rec_vec: Vec<MessageB>,
    pub beta_vec: Vec<FE>,
    pub m_b_w_send_vec: Vec<MessageB>,
    pub ni_vec: Vec<FE>,
    pub alpha_vec: Vec<FE>,
    pub miu_vec: Vec<FE>,
}

impl SignRound2 {
    fn new() -> SignRound2 {
        SignRound2 {
            m_b_gamma_rec_vec: Vec::new(),
            m_b_gamma_send_vec: Vec::new(),
            beta_vec: Vec::new(),
            m_b_w_send_vec: Vec::new(),
            ni_vec: Vec::new(),
            alpha_vec: Vec::new(),
            miu_vec: Vec::new(),
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct SignRound3 {

    pub sigma: FE,
    pub delta_inv: FE,
}

impl SignRound3 {
    fn new() -> SignRound3 {
        SignRound3 {
            sigma: FE::new_random(),
            delta_inv: FE::new_random(),
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct SignRound4 {
    decommit_vec: Vec<SignDecommitPhase1>,
}

impl SignRound4 {
    fn new() -> SignRound4 {
        SignRound4 {
            decommit_vec: Vec::new(),
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct SignRound5 {
    pub phase_5a_decom: Option<Phase5ADecom1>, 
    pub helgamal_proof: Option<HomoELGamalProof>,
    pub local_sig: Option<LocalSignature>,
    pub r: GE,
    pub commit5a_vec: Vec<Phase5Com1>,
}

impl SignRound5 {
    fn new() -> SignRound5 {
        SignRound5 {
            phase_5a_decom: None,
            helgamal_proof: None,
            local_sig: None,
            r: GE::random_point(),
            commit5a_vec: Vec::new(),
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct SignRound6 {
    pub decommit5a_and_elgamal_vec_includes_i: Vec<(Phase5ADecom1, HomoELGamalProof)>,
    pub phase5_com2: Option<Phase5Com2>, 
    pub phase_5d_decom2: Option<Phase5DDecom2>,
}

impl SignRound6 {
    fn new() -> SignRound6 {
        SignRound6 {
            decommit5a_and_elgamal_vec_includes_i: Vec::new(),
            phase5_com2: None,
            phase_5d_decom2: None,
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct SignRound7 {
    commit5c_vec: Vec<Phase5Com2>,
}

impl SignRound7 {
    fn new() -> SignRound7 {
        SignRound7 {
            commit5c_vec: Vec::new(),
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct SignRound8 {
    pub s_i: FE,
}

impl SignRound8 {
    fn new() -> SignRound8 {
        SignRound8 {
            s_i: FE::new_random(),
        }
    }
}
#[derive(Clone, Serialize, Deserialize)]
pub struct SignTask {
    pub round0: SignRound0,
    pub round1: SignRound1,
    pub round2: SignRound2,
    pub round3: SignRound3,
    pub round4: SignRound4,
    pub round5: SignRound5,
    pub round6: SignRound6,
    pub round7: SignRound7,
    pub round8: SignRound8,
    pub wallet_uuid: String,
    pub uuid: String,
    pub next_round: i32,

    pub threshold: u32,
    pub party_keys: Keys,
    pub shared_keys: SharedKeys,
    pub party_id: u32,
    pub vss_scheme_vec: Vec<VerifiableSS>, 
    pub paillier_key_vector: Vec<EncryptionKey>, 
    pub y_sum: GE, 
    pub chaincode: String,
}

impl SignTask {
    pub fn new(wallet_data: &str) -> Result<SignTask> {
        
        let (uuid, party_keys, shared_keys, party_id, vss_scheme_vec, paillier_key_vector, y_sum, chaincode): (
            String,
            Keys,
            SharedKeys,
            u32,
            Vec<VerifiableSS>,
            Vec<EncryptionKey>,
            GE,
            String
        ) = serde_json::from_str(wallet_data)?;
        
        Ok(SignTask {
            round0: SignRound0::new(),
            round1: SignRound1::new(),
            round2: SignRound2::new(),
            round3: SignRound3::new(),
            round4: SignRound4::new(),
            round5: SignRound5::new(),
            round6: SignRound6::new(),
            round7: SignRound7::new(),
            round8: SignRound8::new(),
            wallet_uuid: uuid,
            uuid: String::new(),
            next_round: 0,
            threshold: 1,
        
            party_keys: party_keys.clone(),
            shared_keys: shared_keys.clone(),
            party_id: party_id,
            vss_scheme_vec: vss_scheme_vec.clone(), 
            paillier_key_vector: paillier_key_vector.clone(), 
            y_sum: y_sum.clone(), 
            chaincode: chaincode.clone(),
        })
    }


    pub fn from_string(string: &String) -> Self {
        let mut task: SignTask = serde_json::from_str(string).unwrap();
        return task;
    }
    pub fn to_string(&self) -> String {
        let string: String = serde_json::to_string(self).unwrap();
        string.clone()
    }

    fn update_round0(&mut self, uuid: &String, msg: &String) -> Result<Json<(String, String)>> {

        let v: Vec<&str> = msg.split(':').collect();
        if v.len() != 4 {
            return Err(format_err!("Initial request is invalid ({:})", msg));
        }
        // init:path:msg:party_id
        self.uuid = uuid.clone();

        let path = String::from(v[1]);
        let hash_hex = String::from(v[2]);
        let s_peer_party_id = String::from(v[3]);

        let mut round0_ans_vec: Vec<String> = Vec::new();
        round0_ans_vec.push(String::from(s_peer_party_id));


        let party_num_int = self.party_id.clone();
        let party_id = self.party_id.clone();
        let threshold = self.threshold.clone();
    
        let mut j = 0;
        let mut signers_vec: Vec<usize> = Vec::new();
        for i in 1..threshold + 2 {
            if i == party_num_int {
                signers_vec.push((party_id - 1) as usize);
            } else {
                let signer_j: u32 = serde_json::from_str(&round0_ans_vec[j]).unwrap();
                signers_vec.push((signer_j - 1) as usize);
                j = j + 1;
            }
        }

        self.round0.path = path.clone();
        self.round0.msg = hex::decode(hash_hex)?;
        self.round0.signers_vec = signers_vec.clone();

        let reply: String = serde_json::to_string(&party_num_int)?;
        Ok(Json((self.uuid.clone(), reply)))

    }

    fn update_round1(&mut self, uuid: &String, msg: &String) -> Result<Json<(String, String)>> {
        // round1:
        let party_num_int = self.party_id.clone();
        let threshold = self.threshold.clone();

        let path = self.round0.path.clone();
        let chaincode = self.chaincode.clone();
        let y_sum = self.y_sum.clone();
        let mut vss_scheme_vec = self.vss_scheme_vec.clone();
        let party_keys = self.party_keys.clone();
        let shared_keys = self.shared_keys.clone();
        let signers_vec = self.round0.signers_vec.clone();

        let location_in_hir = match parse_address_path(&path) {
            None => return Err(format_err!("Invalid Path ({:})", path)),
            Some(loc) => loc
        };

        let chain_code_bi: BigInt = match BigInt::from_str_radix(&chaincode, 16) {
            Err(e) => return Err(format_err!("Cloud not convert chaincode to bigint ({:})", e)),
            Ok(cci) => cci
        };
        let (y_sum_child, f_l_new, _cc_new) = hd_key(location_in_hir.clone(), &y_sum, &chain_code_bi);




        // optimize!
        let g: GE = ECPoint::generator();
        // apply on first commitment for leader (leader is party with num=1)
        let com_zero_new = vss_scheme_vec[0].commitments[0] + g * f_l_new;
        // println!("old zero: {:?}, new zero: {:?}", vss_scheme_vec[0].commitments[0], com_zero_new);
        // get iterator of all commitments and skip first zero commitment 
        let mut com_iter_unchanged = vss_scheme_vec[0].commitments.iter();
        com_iter_unchanged.next().unwrap();
        // iterate commitments and inject changed commitments in the beginning then aggregate into vector
        let com_vec_new = (0..vss_scheme_vec[1].commitments.len())
            .map(|i| {
                if i == 0 {
                    com_zero_new
                } else {
                    com_iter_unchanged.next().unwrap().clone()
                }
            })
            .collect::<Vec<GE>>();
        let new_vss = VerifiableSS {
            parameters: vss_scheme_vec[0].parameters.clone(),
            commitments: com_vec_new,
        };
        // replace old vss_scheme for leader with new one at position 0
        // println!("comparing vectors: \n{:?} \nand \n{:?}", vss_scheme_vec[0], new_vss);

        let y_sum = y_sum_child.clone();
        vss_scheme_vec.remove(0);
        vss_scheme_vec.insert(0, new_vss);
        println!("NEW VSS VECTOR: {:?}", vss_scheme_vec);
        let mut private = PartyPrivate::set_private(party_keys.clone(), shared_keys);
        if party_num_int == 1 {
            // update u_i and x_i for leader
            private = private.update_private_key(&f_l_new, &f_l_new);
        } else {
            // only update x_i for non-leaders
            private = private.update_private_key(&FE::zero(), &f_l_new);
        }
        println!("New public key: {:?}", &y_sum);

        let sign_keys = SignKeys::create(
            &private,
            &vss_scheme_vec[signers_vec[(party_num_int - 1) as usize]],
            signers_vec[(party_num_int - 1) as usize],
            &signers_vec,
        );

        //////////////////////////////////////////////////////////////////////////////
        let (com, decommit) = sign_keys.phase1_broadcast();
        let m_a_k = MessageA::a(&sign_keys.k_i, &party_keys.ek);
        
        let reply = serde_json::to_string(&(com.clone(), m_a_k.clone()))?;
        let mut round1_ans_vec: Vec<String> = Vec::new();
        round1_ans_vec.push(msg.clone());

        let mut j = 0;
        let mut bc1_vec: Vec<SignBroadcastPhase1> = Vec::new();
        let mut m_a_vec: Vec<MessageA> = Vec::new();

        for i in 1..threshold + 2 {
            if i == party_num_int {
                bc1_vec.push(com.clone());
            //   m_a_vec.push(m_a_k.clone());
            } else {
                //     if signers_vec.contains(&(i as usize)) {
                let (bc1_j, m_a_party_j): (SignBroadcastPhase1, MessageA) =
                    serde_json::from_str(&round1_ans_vec[j]).unwrap();
                bc1_vec.push(bc1_j);
                m_a_vec.push(m_a_party_j);
    
                j = j + 1;
                //       }
            }
        }
        assert_eq!(signers_vec.len(), bc1_vec.len());

        self.round1.bc1_vec = bc1_vec.clone();
        self.round1.m_a_vec = m_a_vec.clone();
        self.round1.decommit = decommit.clone();
        self.round1.child_y_sum = y_sum.clone();
        self.round1.sign_keys = Some(sign_keys.clone());
        self.round1.vss_scheme_vec = vss_scheme_vec.clone();

        Ok(Json((self.uuid.clone(), reply)))
    }

    fn update_round2(&mut self, uuid: &String, msg: &String) -> Result<Json<(String, String)>> {

        let party_num_int = self.party_id.clone();
        let threshold = self.threshold;

        let sign_keys = self.round1.sign_keys.unwrap();
        let paillier_key_vector = self.paillier_key_vector.clone();
        let m_a_vec = self.round1.m_a_vec.clone();
        let signers_vec = self.round0.signers_vec.clone();
        let vss_scheme_vec = self.round1.vss_scheme_vec.clone();
        let party_keys = self.party_keys.clone();

        //////////////////////////////////////////////////////////////////////////////
        let mut m_b_gamma_send_vec: Vec<MessageB> = Vec::new();
        let mut beta_vec: Vec<FE> = Vec::new();
        let mut m_b_w_send_vec: Vec<MessageB> = Vec::new();
        let mut ni_vec: Vec<FE> = Vec::new();
        let mut j = 0;
        for i in 1..threshold + 2 {
            if i != party_num_int {
                let (m_b_gamma, beta_gamma) = MessageB::b(
                    &sign_keys.gamma_i,
                    &paillier_key_vector[signers_vec[(i - 1) as usize]],
                    m_a_vec[j].clone(),
                );
                let (m_b_w, beta_wi) = MessageB::b(
                    &sign_keys.w_i,
                    &paillier_key_vector[signers_vec[(i - 1) as usize]],
                    m_a_vec[j].clone(),
                );
                m_b_gamma_send_vec.push(m_b_gamma);
                m_b_w_send_vec.push(m_b_w);
                beta_vec.push(beta_gamma);
                ni_vec.push(beta_wi);
                j = j + 1;
            }
        }

        let reply = serde_json::to_string(&(m_b_gamma_send_vec[0].clone(), m_b_w_send_vec[0].clone()))?;
        let mut round2_ans_vec: Vec<String> = Vec::new(); 
        round2_ans_vec.push(msg.clone());
        
        let mut m_b_gamma_rec_vec: Vec<MessageB> = Vec::new();
        let mut m_b_w_rec_vec: Vec<MessageB> = Vec::new();

        for i in 0..threshold {
            //  if signers_vec.contains(&(i as usize)) {
            let (m_b_gamma_i, m_b_w_i): (MessageB, MessageB) =
                serde_json::from_str(&round2_ans_vec[i as usize]).unwrap();
            m_b_gamma_rec_vec.push(m_b_gamma_i);
            m_b_w_rec_vec.push(m_b_w_i);
            //     }
        }

        let mut alpha_vec: Vec<FE> = Vec::new();
        let mut miu_vec: Vec<FE> = Vec::new();

        let xi_com_vec = Keys::get_commitments_to_xi(&vss_scheme_vec);
        let mut j = 0;
        for i in 1..threshold + 2 {
            println!("mbproof p={}, i={}, j={}", party_num_int, i, j);
            if i != party_num_int {
                println!("verifying: p={}, i={}, j={}", party_num_int,
                        i, j);
                let m_b = m_b_gamma_rec_vec[j].clone();

                let alpha_ij_gamma = m_b
                    .verify_proofs_get_alpha(&party_keys.dk, &sign_keys.k_i)
                    .expect("wrong dlog or m_b");
                let m_b = m_b_w_rec_vec[j].clone();
                let alpha_ij_wi = m_b
                    .verify_proofs_get_alpha(&party_keys.dk, &sign_keys.k_i)
                    .expect("wrong dlog or m_b");
                alpha_vec.push(alpha_ij_gamma);
                miu_vec.push(alpha_ij_wi);
                let g_w_i = Keys::update_commitments_to_xi(
                    &xi_com_vec[signers_vec[(i - 1) as usize]],
                    &vss_scheme_vec[signers_vec[(i - 1) as usize]],
                    signers_vec[(i - 1) as usize],
                    &signers_vec,
                );
                //println!("Verifying client {}", party_num_int);
                assert_eq!(m_b.b_proof.pk.clone(), g_w_i);
                //println!("Verified client {}", party_num_int);
                j = j + 1;
            }
        }

        self.round2.m_b_gamma_rec_vec = m_b_gamma_rec_vec.clone();
        self.round2.m_b_gamma_send_vec = m_b_gamma_send_vec.clone();
        self.round2.beta_vec = beta_vec.clone();
        self.round2.m_b_w_send_vec = m_b_w_send_vec.clone();
        self.round2.ni_vec = ni_vec.clone();

        self.round2.alpha_vec = alpha_vec;
        self.round2.miu_vec = miu_vec;
        

        Ok(Json((self.uuid.clone(), reply)))
    }

    fn update_round3(&mut self, uuid: &String, msg: &String) -> Result<Json<(String, String)>> {
        let sign_keys = self.round1.sign_keys.unwrap();
        let alpha_vec = self.round2.alpha_vec.clone();
        let miu_vec = self.round2.miu_vec.clone();
        let ni_vec = self.round2.ni_vec.clone();
        let beta_vec = self.round2.beta_vec.clone();

        //////////////////////////////////////////////////////////////////////////////
        let delta_i = sign_keys.phase2_delta_i(&alpha_vec, &beta_vec);
        let sigma = sign_keys.phase2_sigma_i(&miu_vec, &ni_vec);

        let reply = serde_json::to_string(&delta_i)?;
        
        let mut delta_vec: Vec<FE> = Vec::new();
        
        let mut msgs: Vec<String> = Vec::new();
        msgs.push(msg.clone());

        format_vec_from_reads(
            &msgs,
            self.party_id.clone() as usize,
            delta_i,
            &mut delta_vec,
        );

        let delta_inv = SignKeys::phase3_reconstruct_delta(&delta_vec);
        self.round3.sigma = sigma.clone();
        self.round3.delta_inv = delta_inv.clone();

        Ok(Json((self.uuid.clone(), reply)))
    }

    fn update_round4(&mut self, uuid: &String, msg: &String) -> Result<Json<(String, String)>> {

        let decommit = self.round1.decommit.clone();


        let mut decommit_vec: Vec<SignDecommitPhase1> = Vec::new();
        let mut msgs: Vec<String> = Vec::new();
        msgs.push(msg.clone());

        format_vec_from_reads(
            &msgs,
            self.party_id as usize,
            decommit.clone(),
            &mut decommit_vec,
        );

        self.round4.decommit_vec = decommit_vec.clone();
        let reply = serde_json::to_string(&decommit).unwrap();

        Ok(Json((self.uuid.clone(), reply)))
    }

    fn update_round5(&mut self, uuid: &String, msg: &String) -> Result<Json<(String, String)>> {
        
        let party_num_int = self.party_id.clone();
        let threshold = self.threshold;

        let mut decommit_vec = self.round4.decommit_vec.clone();
        let mut bc1_vec = self.round1.bc1_vec.clone();
        let m_b_gamma_rec_vec = self.round2.m_b_gamma_rec_vec.clone();
        let delta_inv = self.round3.delta_inv.clone();
        let sign_keys = self.round1.sign_keys.unwrap().clone();
        let sigma = self.round3.sigma;
        let y_sum = self.round1.child_y_sum;

        
        let decomm_i = decommit_vec.remove((party_num_int - 1) as usize);
        bc1_vec.remove((party_num_int - 1) as usize);
        let b_proof_vec = (0..m_b_gamma_rec_vec.len())
            .map(|i| &m_b_gamma_rec_vec[i].b_proof)
            .collect::<Vec<&DLogProof>>();
        let R = SignKeys::phase4(&delta_inv, &b_proof_vec, decommit_vec, &bc1_vec)
            .expect("bad gamma_i decommit");


        // adding local g_gamma_i
        let R = R + decomm_i.g_gamma_i * &delta_inv;

        // we assume the message is already hashed (by the signer).
        let message = &self.round0.msg[..];
        let message_bn = BigInt::from(message);
        let two = BigInt::from(2);
        let message_bn = message_bn.modulus(&two.pow(256));
        let local_sig =
            LocalSignature::phase5_local_sig(&sign_keys.k_i, &message_bn, &R, &sigma, &y_sum);

        let (phase5_com, phase_5a_decom, helgamal_proof) = local_sig.phase5a_broadcast_5b_zkproof();


        let reply = serde_json::to_string(&phase5_com)?;
        
        let mut msgs: Vec<String> = Vec::new();
        msgs.push(msg.clone());

        let mut commit5a_vec: Vec<Phase5Com1> = Vec::new();
        format_vec_from_reads(
            &msgs,
            self.party_id.clone() as usize,
            phase5_com,
            &mut commit5a_vec,
        );

        
        self.round5.helgamal_proof = Some(helgamal_proof.clone());
        self.round5.phase_5a_decom = Some(phase_5a_decom.clone());
        self.round5.local_sig = Some(local_sig);
        self.round5.r = R.clone();
        self.round5.commit5a_vec = commit5a_vec.clone();
        Ok(Json((self.uuid.clone(), reply)))
        // Err(format_err!("invalid round({})", self.next_round))
    }

    fn update_round6(&mut self, uuid: &String, msg: &String) -> Result<Json<(String, String)>> {
        

        let R = self.round5.r.clone();
        let local_sig = self.round5.local_sig.clone().unwrap();
        let helgamal_proof = self.round5.helgamal_proof.clone().unwrap();
        let phase_5a_decom = self.round5.phase_5a_decom.clone().unwrap();
        let mut commit5a_vec = self.round5.commit5a_vec.clone();
        let party_num_int = self.party_id;
        let THRESHOLD = 1;

        let mut msgs: Vec<String> = Vec::new();
        msgs.push(msg.clone());

        let reply = serde_json::to_string(&(phase_5a_decom.clone(), helgamal_proof.clone()))?;
        let mut decommit5a_and_elgamal_vec: Vec<(Phase5ADecom1, HomoELGamalProof)> = Vec::new();
        format_vec_from_reads(
            &msgs,
            self.party_id.clone() as usize,
            (phase_5a_decom.clone(), helgamal_proof.clone()),
            &mut decommit5a_and_elgamal_vec,
        );


        let decommit5a_and_elgamal_vec_includes_i = decommit5a_and_elgamal_vec.clone();
        decommit5a_and_elgamal_vec.remove((party_num_int - 1) as usize);
        commit5a_vec.remove((party_num_int - 1) as usize);
        let phase_5a_decomm_vec = (0..THRESHOLD)
            .map(|i| decommit5a_and_elgamal_vec[i as usize].0.clone())
            .collect::<Vec<Phase5ADecom1>>();
        let phase_5a_elgamal_vec = (0..THRESHOLD)
            .map(|i| decommit5a_and_elgamal_vec[i as usize].1.clone())
            .collect::<Vec<HomoELGamalProof>>();
        let (phase5_com2, phase_5d_decom2) = local_sig
            .phase5c(
                &phase_5a_decomm_vec,
                &commit5a_vec,
                &phase_5a_elgamal_vec,
                &phase_5a_decom.V_i,
                &R.clone(),
            ).expect("error phase5");

        self.round6.decommit5a_and_elgamal_vec_includes_i = decommit5a_and_elgamal_vec_includes_i.clone();
        self.round6.phase5_com2 = Some(phase5_com2.clone());
        self.round6.phase_5d_decom2 = Some(phase_5d_decom2.clone());
        
        Ok(Json((self.uuid.clone(), reply)))
            // Err(format_err!("invalid round({})", self.next_round))
    }

    fn update_round7(&mut self, uuid: &String, msg: &String) -> Result<Json<(String, String)>> {
        let party_num_int = self.party_id;
        let phase5_com2 = self.round6.phase5_com2.clone().unwrap();
        // let phase_5d_decom2 = self.round6.phase_5d_decom2.clone().unwrap();


        let mut msgs: Vec<String> = Vec::new();
        msgs.push(msg.clone());

        let reply = serde_json::to_string(&phase5_com2).unwrap();


        let mut commit5c_vec: Vec<Phase5Com2> = Vec::new();
        format_vec_from_reads(
            &msgs,
            party_num_int.clone() as usize,
            phase5_com2,
            &mut commit5c_vec,
        );

        self.round7.commit5c_vec = commit5c_vec.clone();

        Ok(Json((self.uuid.clone(), reply)))
    }

    fn update_round8(&mut self, uuid: &String, msg: &String) -> Result<Json<(String, String)>> {
        let party_num_int = self.party_id;
        let phase_5d_decom2 = self.round6.phase_5d_decom2.clone().unwrap();
        let decommit5a_and_elgamal_vec_includes_i = self.round6.decommit5a_and_elgamal_vec_includes_i.clone();
        let THRESHOLD = 1;
        let local_sig = self.round5.local_sig.clone().unwrap();
        let commit5c_vec = self.round7.commit5c_vec.clone();

        let reply = serde_json::to_string(&phase_5d_decom2).unwrap();

        let mut msgs: Vec<String> = Vec::new();
        msgs.push(msg.clone());


        let mut decommit5d_vec: Vec<Phase5DDecom2> = Vec::new();
        format_vec_from_reads(
            &msgs,
            party_num_int.clone() as usize,
            phase_5d_decom2.clone(),
            &mut decommit5d_vec,
        );
    

        let phase_5a_decomm_vec_includes_i = (0..THRESHOLD + 1)
        .map(|i| decommit5a_and_elgamal_vec_includes_i[i as usize].0.clone())
        .collect::<Vec<Phase5ADecom1>>();
        let s_i = local_sig.phase5d(
            &decommit5d_vec,
            &commit5c_vec,
            &phase_5a_decomm_vec_includes_i,
        )
        .expect("bad com 5d");
        self.round8.s_i = s_i.clone();
        Ok(Json((self.uuid.clone(), reply)))
        // Err(format_err!("invalid round({})", self.next_round))
    }

    fn update_round9(&mut self, uuid: &String, msg: &String) -> Result<Json<(String, String)>> {
        let local_sig = self.round5.local_sig.clone().unwrap();
        let party_num_int = self.party_id;
        let s_i = self.round8.s_i.clone();

        let reply = serde_json::to_string(&s_i)?;

        let mut msgs: Vec<String> = Vec::new();
        msgs.push(msg.clone());
        
        let mut s_i_vec: Vec<FE> = Vec::new();
        format_vec_from_reads(
            &msgs,
            party_num_int.clone() as usize,
            s_i,
            &mut s_i_vec,
        );

        s_i_vec.remove((party_num_int - 1) as usize);
        let sig = local_sig
        .output_signature(&s_i_vec)
        .expect("verification failed");

        println!(" \n");
        println!("party {:?} Output Signature: \n", party_num_int);
        println!("R: {:?}", sig.r);
        println!("s: {:?} \n", sig.s);
        println!("child pubkey: {:?} \n", self.round1.child_y_sum.clone());
        println!("pubkey: {:?} \n", self.y_sum.clone());

        let sign_json = serde_json::to_string(&(
            "r",
            (BigInt::from(&(sig.r.get_element())[..])).to_str_radix(16),
            "s",
            (BigInt::from(&(sig.s.get_element())[..])).to_str_radix(16),
        )).unwrap();


        let y_sum = self.round1.child_y_sum.clone();
        let message = &self.round0.msg[..];
        let message_bn = BigInt::from(message);

        println!("verifying signature with public key");
        verify(&sig, &y_sum, &message_bn).expect("false");
        println!("verifying signature with child pub key");


        Ok(Json((self.uuid.clone(), reply)))
    }

    pub fn update(&mut self, uuid: &String, msg: &String) -> Result<Json<(String, String)>> {
        if self.next_round == 0 {
            let result = self.update_round0(uuid, msg);
            if result.is_ok() {
                self.next_round += 1;
            }
            return result;
        } else if self.next_round == 1 {
            let result = self.update_round1(uuid, msg);
            if result.is_ok() {
                self.next_round += 1;
            }
            return result;

        } else if self.next_round == 2 {
            let result = self.update_round2(uuid, msg);
            if result.is_ok() {
                self.next_round += 1;
            }
            return result;
            
        } else if self.next_round == 3 {
            let result = self.update_round3(uuid, msg);
            if result.is_ok() {
                self.next_round += 1;
            }
            return result;
            
        } else if self.next_round == 4 {
            let result = self.update_round4(uuid, msg);
            if result.is_ok() {
                self.next_round += 1;
            }
            return result;
        } else if self.next_round == 5 {
            
            let result = self.update_round5(uuid, msg);
            if result.is_ok() {
                self.next_round += 1;
            }
            return result;
        } else if self.next_round == 6 {
            
            let result = self.update_round6(uuid, msg);
            if result.is_ok() {
                self.next_round += 1;
            }
            return result;
        } else if self.next_round == 7 {
            
            let result = self.update_round7(uuid, msg);
            if result.is_ok() {
                self.next_round += 1;
            }
            return result;
        } else if self.next_round == 8{
            
            let result = self.update_round8(uuid, msg);
            if result.is_ok() {
                self.next_round += 1;
            }
            return result;
        } else if self.next_round == 9 {

            let result = self.update_round9(uuid, msg);
            if result.is_ok() {
                self.next_round += 1;
            }
            return result;
        }

        Err(format_err!("invalid round({})", self.next_round))
    }

    fn is_done(&mut self) -> bool {
        return self.next_round == 10
    }
}

#[post("/ecdsa/sign", format = "json", data = "<request>")]
pub fn sign(
    state: State<Config>,
    db_mtx: State<RwLock<HashMap<String, String>>>,
    claim: Claims,
    request: Json<RequestMessage>,
) -> Result<Json<(String, String)>> {

    if request.message.starts_with("init:") {// Round 0
        let uuid = request.uuid.clone();

        let wallet_data: String =db::get(&state.db, &claim.sub, &uuid.clone(), &VaultStruct::VaultData)?
        .ok_or(format_err!("No data for such identifier {}", uuid.clone()))?;

        println!("{}",wallet_data);
        let mut sign_task = SignTask::new(&wallet_data)?;

        let sign_uuid = Uuid::new_v4().to_string();
        println!("Round0: {:}", sign_uuid);
        let result = sign_task.update(&sign_uuid, &request.message);
        if result.is_err() {
            return result;
        }

        let key = format!("sign-{}-{}", claim.sub, sign_uuid.clone());
        let value = sign_task.to_string();
        println!("task : {:}", value);

        let mut hm = db_mtx.write().unwrap();
        hm.insert(key, value);

        return result;
    }

    let uuid = request.uuid.clone();
    println!("Round1: {:}", uuid);
    let key = format!("sign-{}-{}", claim.sub, request.uuid.clone());

    let mut hm = db_mtx.write().unwrap();
    let value = hm.get(&key);
    if value.is_none() {
        return Err(format_err!("Invalid uuid({}), Task not found", uuid));
    }

    let mut sign_task = SignTask::from_string(value.unwrap());
    let result = sign_task.update(&request.uuid, &request.message);
    if result.is_err() {
        return result;
    }

    if sign_task.is_done() {
        hm.remove(&key);
    } else {
        let value = sign_task.to_string();
        hm.insert(key, value);
    }

    return result;
}