#![allow(non_snake_case)]
//extern crate crypto;
extern crate curv;
/// to run:
/// 1: go to rocket_server -> cargo run
/// 2: cargo run from PARTIES number of terminals
extern crate multi_party_ecdsa;
extern crate paillier;
extern crate reqwest;

extern crate hex;
extern crate serde_json;

use curv::arithmetic::traits::Converter;
use curv::cryptographic_primitives::hashing::hmac_sha512;
use curv::cryptographic_primitives::proofs::sigma_correct_homomorphic_elgamal_enc::HomoELGamalProof;
use curv::cryptographic_primitives::hashing::traits::KeyedHash;
use curv::cryptographic_primitives::proofs::sigma_dlog::DLogProof;
use curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;
use curv::elliptic::curves::traits::*;

use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2018::mta::*;
use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2018::party_i::*;
use paillier::*;
use std::env;
use std::fs;
use std::{time};
use curv::{BigInt, FE, GE};
use super::network::*;

pub fn combine_pubkey_and_index(pubkey: &BigInt, index: &i32) -> BigInt {
    
    let mut pk_vec = BigInt::to_vec(&pubkey);
    let index_bz = index.to_be_bytes();
    //let index_bz1 = index.to_le_bytes();
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
    // let f_r_fe: FE = ECScalar::from(&f_r);

    // let bn_to_slice = BigInt::to_vec(chain_code_bi);
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
                //let f_r_fe: FE = ECScalar::from(&f_r);
                let cpk = acc.0 + g * &f_l_fe;

                let xxx = BigInt::to_vec(&cpk.bytes_compressed_to_big_int());
                println!("Child Pub Key {:?}", xxx);
                (cpk, f_l_fe + &acc.1, f_r)
                //(acc.0 + g * &f_l_fe, f_l_fe + &acc.1, &acc.2 * &f_r_fe)
            });
    (public_key_new_child, f_l_new, cc_new)
}

pub fn sign(nc: &NetworkClient, threshold: u32, message: &Vec<u8>) {
    let message = &message[..];
    // delay:
    let delay = time::Duration::from_millis(25);
    // read key file
    let data = fs::read_to_string(env::args().nth(2).unwrap())
        .expect("Unable to load keys, did you run keygen first? ");
    let (party_keys, shared_keys, party_id, mut vss_scheme_vec, paillier_key_vector, y_sum): (
        Keys,
        SharedKeys,
        u32,
        Vec<VerifiableSS>,
        Vec<EncryptionKey>,
        GE
    ) = serde_json::from_str(&data).unwrap();
    println!("y_sum: {:?}", y_sum);


    //////////////////////////////////////////////////////////////////////////////
    //signup:
    let party_i_signup_result = nc.signup_sign();
    assert!(party_i_signup_result.is_ok());
    let party_i_signup = party_i_signup_result.unwrap();
    println!("{:?}", party_i_signup.clone());
    let party_num_int = party_i_signup.number.clone();
    let uuid = party_i_signup.uuid;

    //////////////////////////////////////////////////////////////////////////////
    // round 0: collect signers IDs
    assert!(nc.broadcast(
        party_num_int.clone(),
        "round0",
        serde_json::to_string(&party_id).unwrap(),
        uuid.clone()
    )
    .is_ok());
    let round0_ans_vec = nc.poll_for_broadcasts(
        party_num_int.clone(),
        threshold + 1,
        delay.clone(),
        "round0",
        uuid.clone(),
    );

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
    // signers_vec.sort();

    // generate a random but shared chain code, this will do
    let chain_code = GE::generator();
    println!("chain code {:?}", chain_code);

    // derive a new pubkey and LR sequence, y_sum becomes a new child pub key
    let (y_sum_child, f_l_new, _cc_new) =
        hd_key(vec![84, 0, 0], &y_sum, &chain_code.x_coor().unwrap());

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
    assert!(nc.broadcast(
        party_num_int.clone(),
        "round1",
        serde_json::to_string(&(com.clone(), m_a_k.clone())).unwrap(),
        uuid.clone()
    )
    .is_ok());
    let round1_ans_vec = nc.poll_for_broadcasts(
        party_num_int.clone(),
        threshold + 1,
        delay.clone(),
        "round1",
        uuid.clone(),
    );

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

    let mut j = 0;
    for i in 1..threshold + 2 {
        if i != party_num_int {
            assert!(nc.sendp2p(
                party_num_int.clone(),
                i.clone(),
                "round2",
                serde_json::to_string(&(m_b_gamma_send_vec[j].clone(), m_b_w_send_vec[j].clone()))
                    .unwrap(),
                uuid.clone()
            )
            .is_ok());
            j = j + 1;
        }
    }

    let round2_ans_vec = nc.poll_for_p2p(
        party_num_int.clone(),
        threshold + 1,
        delay.clone(),
        "round2",
        uuid.clone(),
    );

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
    //////////////////////////////////////////////////////////////////////////////
    let delta_i = sign_keys.phase2_delta_i(&alpha_vec, &beta_vec);
    let sigma = sign_keys.phase2_sigma_i(&miu_vec, &ni_vec);

    assert!(nc.broadcast(
        party_num_int.clone(),
        "round3",
        serde_json::to_string(&delta_i).unwrap(),
        uuid.clone()
    )
    .is_ok());
    let round3_ans_vec = nc.poll_for_broadcasts(
        party_num_int.clone(),
        threshold + 1,
        delay.clone(),
        "round3",
        uuid.clone(),
    );
    let mut delta_vec: Vec<FE> = Vec::new();
    format_vec_from_reads(
        &round3_ans_vec,
        party_num_int.clone() as usize,
        delta_i,
        &mut delta_vec,
    );
    let delta_inv = SignKeys::phase3_reconstruct_delta(&delta_vec);

    //////////////////////////////////////////////////////////////////////////////
    // decommit to gamma_i
    assert!(nc.broadcast(
        party_num_int.clone(),
        "round4",
        serde_json::to_string(&decommit).unwrap(),
        uuid.clone()
    )
    .is_ok());
    let round4_ans_vec = nc.poll_for_broadcasts(
        party_num_int.clone(),
        threshold + 1,
        delay.clone(),
        "round4",
        uuid.clone(),
    );

    let mut decommit_vec: Vec<SignDecommitPhase1> = Vec::new();
    format_vec_from_reads(
        &round4_ans_vec,
        party_num_int.clone() as usize,
        decommit,
        &mut decommit_vec,
    );
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
    let message_bn = BigInt::from(message);
    let two = BigInt::from(2);
    let message_bn = message_bn.modulus(&two.pow(256));
    let local_sig =
        LocalSignature::phase5_local_sig(&sign_keys.k_i, &message_bn, &R, &sigma, &y_sum);

    let (phase5_com, phase_5a_decom, helgamal_proof) = local_sig.phase5a_broadcast_5b_zkproof();

    //phase (5A)  broadcast commit
    assert!(nc.broadcast(
        party_num_int.clone(),
        "round5",
        serde_json::to_string(&phase5_com).unwrap(),
        uuid.clone()
    )
    .is_ok());
    let round5_ans_vec = nc.poll_for_broadcasts(
        party_num_int.clone(),
        threshold + 1,
        delay.clone(),
        "round5",
        uuid.clone(),
    );

    let mut commit5a_vec: Vec<Phase5Com1> = Vec::new();
    format_vec_from_reads(
        &round5_ans_vec,
        party_num_int.clone() as usize,
        phase5_com,
        &mut commit5a_vec,
    );

    //phase (5B)  broadcast decommit and (5B) ZK proof
    assert!(nc.broadcast(
        party_num_int.clone(),
        "round6",
        serde_json::to_string(&(phase_5a_decom.clone(), helgamal_proof.clone())).unwrap(),
        uuid.clone()
    )
    .is_ok());
    let round6_ans_vec = nc.poll_for_broadcasts(
        party_num_int.clone(),
        threshold + 1,
        delay.clone(),
        "round6",
        uuid.clone(),
    );

    let mut decommit5a_and_elgamal_vec: Vec<(Phase5ADecom1, HomoELGamalProof)> = Vec::new();
    format_vec_from_reads(
        &round6_ans_vec,
        party_num_int.clone() as usize,
        (phase_5a_decom.clone(), helgamal_proof.clone()),
        &mut decommit5a_and_elgamal_vec,
    );
    let decommit5a_and_elgamal_vec_includes_i = decommit5a_and_elgamal_vec.clone();
    decommit5a_and_elgamal_vec.remove((party_num_int - 1) as usize);
    commit5a_vec.remove((party_num_int - 1) as usize);
    let phase_5a_decomm_vec = (0..threshold)
        .map(|i| decommit5a_and_elgamal_vec[i as usize].0.clone())
        .collect::<Vec<Phase5ADecom1>>();
    let phase_5a_elgamal_vec = (0..threshold)
        .map(|i| decommit5a_and_elgamal_vec[i as usize].1.clone())
        .collect::<Vec<HomoELGamalProof>>();
    let (phase5_com2, phase_5d_decom2) = local_sig
        .phase5c(
            &phase_5a_decomm_vec,
            &commit5a_vec,
            &phase_5a_elgamal_vec,
            &phase_5a_decom.V_i,
            &R.clone(),
        )
        .expect("error phase5");

    //////////////////////////////////////////////////////////////////////////////
    assert!(nc.broadcast(
        party_num_int.clone(),
        "round7",
        serde_json::to_string(&phase5_com2).unwrap(),
        uuid.clone()
    )
    .is_ok());
    let round7_ans_vec = nc.poll_for_broadcasts(
        party_num_int.clone(),
        threshold + 1,
        delay.clone(),
        "round7",
        uuid.clone(),
    );

    let mut commit5c_vec: Vec<Phase5Com2> = Vec::new();
    format_vec_from_reads(
        &round7_ans_vec,
        party_num_int.clone() as usize,
        phase5_com2,
        &mut commit5c_vec,
    );

    //phase (5B)  broadcast decommit and (5B) ZK proof
    assert!(nc.broadcast(
        party_num_int.clone(),
        "round8",
        serde_json::to_string(&phase_5d_decom2).unwrap(),
        uuid.clone()
    )
    .is_ok());
    let round8_ans_vec = nc.poll_for_broadcasts(
        party_num_int.clone(),
        threshold + 1,
        delay.clone(),
        "round8",
        uuid.clone(),
    );

    let mut decommit5d_vec: Vec<Phase5DDecom2> = Vec::new();
    format_vec_from_reads(
        &round8_ans_vec,
        party_num_int.clone() as usize,
        phase_5d_decom2.clone(),
        &mut decommit5d_vec,
    );

    let phase_5a_decomm_vec_includes_i = (0..threshold + 1)
        .map(|i| decommit5a_and_elgamal_vec_includes_i[i as usize].0.clone())
        .collect::<Vec<Phase5ADecom1>>();
    let s_i = local_sig
        .phase5d(
            &decommit5d_vec,
            &commit5c_vec,
            &phase_5a_decomm_vec_includes_i,
        )
        .expect("bad com 5d");

    //////////////////////////////////////////////////////////////////////////////
    assert!(nc.broadcast(
        party_num_int.clone(),
        "round9",
        serde_json::to_string(&s_i).unwrap(),
        uuid.clone()
    )
    .is_ok());
    let round9_ans_vec = nc.poll_for_broadcasts(
        party_num_int.clone(),
        threshold + 1,
        delay.clone(),
        "round9",
        uuid.clone(),
    );

    let mut s_i_vec: Vec<FE> = Vec::new();
    format_vec_from_reads(
        &round9_ans_vec,
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
    println!("child pubkey: {:?} \n", y_sum);

    println!("pubkey: {:?} \n", y_sum);
    let sign_json = serde_json::to_string(&(
        "r",
        (BigInt::from(&(sig.r.get_element())[..])).to_str_radix(16),
        "s",
        (BigInt::from(&(sig.s.get_element())[..])).to_str_radix(16),
    ))
        .unwrap();
    println!("verifying signature with public key");
    verify(&sig, &y_sum, &message_bn).expect("false");
    println!("verifying signature with child pub key");
    //verify(&sig, &new_key, &message_bn).expect("false");
    fs::write("signature".to_string(), sign_json).expect("Unable to save !");
}

fn format_vec_from_reads<'a, T: serde::Deserialize<'a> + Clone>(
    ans_vec: &'a Vec<String>,
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
            j = j + 1;
        }
    }
}
