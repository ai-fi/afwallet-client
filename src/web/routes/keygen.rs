

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

pub trait Round {
    fn new() -> Self;
    fn update(&mut self, context: &mut KeyGenContext, uuid: &String, msg: &String) -> Result<Json<(String, String)>>;
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct AEAD {
    pub ciphertext: Vec<u8>,
    pub tag: Vec<u8>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct KeyGenRound0 {
    pub uuid: Option<String>,
    pub chaincode: Option<String>
}

#[derive(Clone, Serialize, Deserialize)]
pub struct KeyGenRound1 {
    
    pub decom1: Option<KeyGenDecommitMessage1>,
    // 
    pub bc1_vec: Option<Vec<KeyGenBroadcastMessage1>>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct KeyGenRound2 {

    pub y_vec: Option<Vec<GE>>,
    pub enc_keys: Option<Vec<BigInt>>,
    pub y_sum: Option<GE>,

    pub vss_scheme: Option<VerifiableSS>, 
    pub secret_shares: Option<Vec<FE>>, 
    pub party_index: Option<usize>
}

#[derive(Clone, Serialize, Deserialize)]
pub struct KeyGenRound3 {
    pub party_shares: Option<Vec<FE>>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct KeyGenRound4 {

    pub vss_scheme_vec: Option<Vec<VerifiableSS>>,

    pub shared_keys: Option<SharedKeys>, 
    pub dlog_proof: Option<DLogProof>
}

#[derive(Clone, Serialize, Deserialize)]
pub struct KeyGenRound5 {
    pub paillier_key_vec: Option<Vec<EncryptionKey>>
}

#[derive(Clone, Serialize, Deserialize)]
pub struct KeyGenContext {
    pub round0: Option<KeyGenRound0>,
    pub round1: Option<KeyGenRound1>,
    pub round2: Option<KeyGenRound2>,
    pub round3: Option<KeyGenRound3>,
    pub round4: Option<KeyGenRound4>,
    pub round5: Option<KeyGenRound5>,
    pub next_round: i32, // 0
    pub party_num: i32, // 1
    pub parties: i32,
    pub uuid: Option<String>,
    pub party_keys: Keys,
}


impl Round for KeyGenRound0 {
    fn new() -> Self {
        KeyGenRound0{uuid: None, chaincode: None}
    }
    fn update(&mut self, context: &mut KeyGenContext, uuid: &String, msg: &String) -> Result<Json<(String, String)>> {
        self.uuid = Some(uuid.clone());
        context.uuid = Some(uuid.clone());
        self.chaincode = Some(msg.clone());
        Ok(Json((uuid.clone(), msg.clone())))
    }
}

impl Round for KeyGenRound1 {
    fn new() -> Self {
        KeyGenRound1{
            decom1: None,
            bc1_vec: None,
        }
    }
    fn update(&mut self, context: &mut KeyGenContext, uuid: &String, msg: &String)  -> Result<Json<(String, String)>> {
        
        let party_keys = context.party_keys.clone();
        let (bc1_i, decom1_i) = party_keys.phase1_broadcast_phase3_proof_of_correct_key();
        let bc1_j: KeyGenBroadcastMessage1 = serde_json::from_str(&msg).unwrap();

        self.decom1 = Some(decom1_i);

        let bc1_vec = (1..context.parties + 1)
        .map(|i| {
            if i == context.party_num {
                bc1_i.clone()
            } else {
                bc1_j.clone()
            }
        })
        .collect::<Vec<KeyGenBroadcastMessage1>>();

        self.bc1_vec = Some(bc1_vec);

        let out_msg = serde_json::to_string(&bc1_i)?;
        
        Ok(Json((uuid.clone(), out_msg)))
    }
}

impl Round for KeyGenRound2 {

    fn new() -> Self {
        KeyGenRound2 {
        
            y_vec: None,
            enc_keys: None,
            y_sum: None,
        
            vss_scheme: None, 
            secret_shares: None, 
            party_index: None,
        }
    }

    fn update(&mut self, context: &mut KeyGenContext, uuid: &String, msg: &String)  -> Result<Json<(String, String)>> {
        let parames = Parameters {
            threshold: 1 as usize,
            share_count: 2 as usize,
        };
        let party_keys = context.party_keys.clone();
        let decom_i = context.round1.clone().unwrap().decom1.unwrap();
        let bc1_vec = context.round1.clone().unwrap().bc1_vec.unwrap();

        let mut y_vec: Vec<GE> = Vec::new();
        let mut decom_vec: Vec<KeyGenDecommitMessage1> = Vec::new();
        let mut enc_keys: Vec<BigInt> = Vec::new();

        y_vec.push(party_keys.y_i.clone());
        decom_vec.push(decom_i.clone());

        let decom_j: KeyGenDecommitMessage1 = serde_json::from_str(msg)?;
        y_vec.push(decom_j.y_i.clone());
        decom_vec.push(decom_j.clone());
        enc_keys.push(
            (party_keys.y_i.clone() + decom_j.y_i.clone())
                .x_coor()
                .unwrap(),
        );

        let mut y_vec_iter = y_vec.iter();
        let head = y_vec_iter.next().unwrap();
        let tail = y_vec_iter;
        let y_sum = tail.fold(head.clone(), |acc, x| acc + x);
    
        let (vss_scheme, secret_shares, index) = party_keys
            .phase1_verify_com_phase3_verify_correct_key_phase2_distribute(
                &parames, &decom_vec, &bc1_vec,
            )
            .expect("invalid key");

        self.enc_keys = Some(enc_keys.clone());
        self.party_index = Some(index.clone());
        self.secret_shares = Some(secret_shares.clone());
        self.vss_scheme = Some(vss_scheme.clone());
        self.y_sum = Some(y_sum.clone());
        self.y_vec = Some(y_vec.clone());


        let out_msg = serde_json::to_string(&decom_i)?;
        Ok(Json((uuid.clone(), out_msg)))
    }
}


impl Round for KeyGenRound3 {

    fn new() -> Self {
        KeyGenRound3 {
            party_shares: None,
        }
    }

    fn update(&mut self, context: &mut KeyGenContext, uuid: &String, msg: &String)  -> Result<Json<(String, String)>> {

        let round = 3;
        let enc_keys = context.round2.clone().unwrap().enc_keys.unwrap();
        let secret_shares = context.round2.clone().unwrap().secret_shares.unwrap();

        let mut party_shares: Vec<FE> = Vec::new();
        party_shares.push(secret_shares[0 as usize].clone());

        let aead_pack: AEAD = serde_json::from_str(msg).unwrap();
        let mut out: Vec<u8> = repeat(0).take(aead_pack.ciphertext.len()).collect();
        let key_i = BigInt::to_vec(&enc_keys[0]);
        let nonce: Vec<u8> = repeat(round).take(12).collect();
        let aad: [u8; 0] = [];
        let mut gcm = AesGcm::new(KeySize256, &key_i[..], &nonce[..], &aad);
        let result = gcm.decrypt(&aead_pack.ciphertext[..], &mut out, &aead_pack.tag[..]);
        assert!(result);
        let out_bn = BigInt::from(&out[..]);
        let out_fe = ECScalar::from(&out_bn);
        party_shares.push(out_fe);
        
        
        self.party_shares = Some(party_shares.clone());

        let key_i = BigInt::to_vec(&enc_keys[0]);
        let nonce: Vec<u8> = repeat(round).take(12).collect();
        let aad: [u8; 0] = [];
        let mut gcm = AesGcm::new(KeySize256, &key_i[..], &nonce[..], &aad);
        let plaintext = BigInt::to_vec(&secret_shares[1].to_big_int());
        let mut out: Vec<u8> = repeat(0).take(plaintext.len()).collect();
        let mut out_tag: Vec<u8> = repeat(0).take(16).collect();
        gcm.encrypt(&plaintext[..], &mut out[..], &mut out_tag[..]);
        let aead_pack_i = AEAD {
            ciphertext: out.to_vec(),
            tag: out_tag.to_vec(),
        };

        let out_msg = serde_json::to_string(&aead_pack_i)?;
        // j = j + 1;
        return Ok(Json((uuid.clone(), out_msg)));
    }
}
        

impl Round for KeyGenRound4 {

    fn new() -> Self {
        KeyGenRound4 {
            vss_scheme_vec: None,
            shared_keys: None,
            dlog_proof: None,
        }
    }

    fn update(&mut self, context: &mut KeyGenContext, uuid: &String, msg: &String)  -> Result<Json<(String, String)>> {
        let parames = Parameters {
            threshold: 1 as usize,
            share_count: 2 as usize,
        };
        
        let party_keys = context.party_keys.clone();
        let vss_scheme = context.round2.clone().unwrap().vss_scheme.unwrap();
        let y_vec = context.round2.clone().unwrap().y_vec.unwrap();

        let party_shares = context.round3.clone().unwrap().party_shares.unwrap();

        let mut vss_scheme_vec: Vec<VerifiableSS> = Vec::new();
        vss_scheme_vec.push(vss_scheme.clone());

        let vss_scheme_j: VerifiableSS = serde_json::from_str(&msg).unwrap();
        vss_scheme_vec.push(vss_scheme_j);
        
        self.vss_scheme_vec = Some(vss_scheme_vec.clone());

        let (shared_keys, dlog_proof) = party_keys
        .phase2_verify_vss_construct_keypair_phase3_pok_dlog(
            &parames,
            &y_vec,
            &party_shares,
            &vss_scheme_vec,
            &(context.party_num as usize),
        )
        .expect("invalid vss");

        self.shared_keys = Some(shared_keys);
        self.dlog_proof = Some(dlog_proof);

        let out_msg = serde_json::to_string(&vss_scheme)?;
        Ok(Json((uuid.clone(), out_msg)))
    }
}


impl Round for KeyGenRound5 {

    fn new() -> Self {
        KeyGenRound5 {
            paillier_key_vec: None,
        }
    }

    fn update(&mut self, context: &mut KeyGenContext, uuid: &String, msg: &String)  -> Result<Json<(String, String)>> {
        let parames = Parameters {
            threshold: 1 as usize,
            share_count: 2 as usize,
        };
        let bc1_vec = context.round1.clone().unwrap().bc1_vec.unwrap();
        let y_vec = context.round2.clone().unwrap().y_vec.unwrap();
        let dlog_proof = context.round4.clone().unwrap().dlog_proof.unwrap();

        let mut j = 0;
        let mut dlog_proof_vec: Vec<DLogProof> = Vec::new();
        for i in 1..context.parties + 1 {
            if i == context.party_num {
                dlog_proof_vec.push(dlog_proof.clone());
            } else {
                let dlog_proof_j: DLogProof = serde_json::from_str(&msg).unwrap();
                dlog_proof_vec.push(dlog_proof_j);
                j = j + 1;
            }
        }
        Keys::verify_dlog_proofs(&parames, &dlog_proof_vec, &y_vec).expect("bad dlog proof");
        //////////////////////////////////////////////////////////////////////////////
        //save key to file:

        let paillier_key_vec = (0..context.parties)
            .map(|i| bc1_vec[i as usize].e.clone())
            .collect::<Vec<EncryptionKey>>();
        self.paillier_key_vec = Some(paillier_key_vec);
        let out_msg = serde_json::to_string(&dlog_proof)?;
        Ok(Json((uuid.clone(), out_msg)))
    }
}
impl KeyGenContext {
    pub fn new() -> Self {
        
        let party_keys = Keys::create(2i32 as usize);
        KeyGenContext{
            round0: None,
            round1: None,
            round2: None,
            round3: None,
            round4: None,
            round5: None,
            next_round: 0,
            party_num: 1,
            parties: 2,
            uuid: None,
            party_keys: party_keys,
        }
    }

    pub fn from_string(string: &String) -> Self {
        let context: KeyGenContext = serde_json::from_str(string).unwrap();
        return context;
    }
    pub fn to_string(&self) -> String {
        let string: String = serde_json::to_string(self).unwrap();
        string.clone()
    }

    pub fn update(&mut self, uuid: &String, msg: &String) -> Result<Json<(String, String)>> {
        if self.next_round == 0 { // round0: generate uuid & chain code
            let mut round0 = KeyGenRound0::new();
            let result = round0.update(self, uuid, msg);
            if result.is_err() {
                return result;
            }

            self.next_round += 1;
            self.round0 = Some(round0);
            return result;
        } else if self.next_round == 1 { // round1: handle (send, receive and process) KeyGenBroadcastMessage1
            let mut round1 = KeyGenRound1::new();
            let result = round1.update(self, uuid, msg);
            if result.is_err() {
                return result;
            }
            self.next_round += 1;
            self.round1 = Some(round1);
            return result;
        } else if self.next_round == 2 {
            let mut round2 = KeyGenRound2::new();
            let result = round2.update(self, uuid, msg);
            if result.is_err() {
                return result;
            }
            self.next_round += 1;
            self.round2 = Some(round2);
            return result;
        } else if self.next_round == 3 {
            let mut round3 = KeyGenRound3::new();
            let result = round3.update(self, uuid, msg);
            if result.is_err() {
                return result;
            }
            self.next_round += 1;
            self.round3 = Some(round3);
            return result;
        } else if self.next_round == 4 {
            let mut round4 = KeyGenRound4::new();
            let result = round4.update(self, uuid, msg);
            if result.is_err() {
                return result;
            }
            self.next_round += 1;
            self.round4 = Some(round4);
            return result;
        } else if self.next_round == 5 {
            let mut round5 = KeyGenRound5::new();
            let result = round5.update(self, uuid, msg);
            if result.is_err() {
                return result;
            }
            self.next_round += 1;
            self.round5 = Some(round5);
            return result;
        }

        Err(format_err!("invalid round({})", self.next_round))
    }

    pub fn save_result(&self, db: &db::DB, user: &String) -> Result<()> {

        let vault_wallet_ids_id = String::from("vault_wallet_ids_id");
        
        
        let option_wallet_ids: Option<Vec<String>> = db::get(db, user, &vault_wallet_ids_id, &VaultStruct::VaultWalletIDs)?;
        
        let mut wallet_ids: Vec<String>;
        if option_wallet_ids.is_none() {
            wallet_ids = Vec::new();
        } else {
            wallet_ids = option_wallet_ids.unwrap();
        }

        let party_keys = self.party_keys.clone();
        let party_num_int = self.party_num;
        let uuid = self.uuid.clone().unwrap();

        let chaincode = self.round0.clone().unwrap().chaincode.unwrap();
        
        let y_sum = self.round2.clone().unwrap().y_sum.unwrap();

        let shared_keys = self.round4.clone().unwrap().shared_keys.unwrap();
        let vss_scheme_vec = self.round4.clone().unwrap().vss_scheme_vec.unwrap();
        
        let paillier_key_vec = self.round5.clone().unwrap().paillier_key_vec.unwrap();
       

        let keygen_result = serde_json::to_string(&(uuid.clone(), party_keys,
            shared_keys,
            party_num_int,
            vss_scheme_vec,
            paillier_key_vec,
            y_sum,
            chaincode)).unwrap();

        wallet_ids.push(uuid.clone());

        db::insert(
            db,
            user,
            &vault_wallet_ids_id,
            &VaultStruct::VaultWalletIDs,
            &wallet_ids,
        )?;

        db::insert(
            db,
            user,
            &uuid.clone(),
            &VaultStruct::VaultData,
            &keygen_result,
        )
        // let dbname = format!("vault-{}.db", uuid.clone());
        // std::fs::write(dbname, keygen_result.unwrap()).is_ok()
    }

    pub fn is_done(&self) -> bool {
        return self.next_round == 6;
    }

}

fn generate_chaincode() -> String {
    let u: FE = ECScalar::new_random();
    let y = &ECPoint::generator() * &u;
    let px = y.x_coor().unwrap();
    let hex = px.to_hex();
    return hex;
}

#[post("/ecdsa/keygen", format = "json", data = "<request>")]
pub fn keygen(
    state: State<Config>,
    db_mtx: State<RwLock<HashMap<String, String>>>,
    claim: Claims,
    request: Json<RequestMessage>,
) -> Result<Json<(String, String)>> {
    
    if request.uuid == "" && request.message == "init" {// Round 0
        let uuid = Uuid::new_v4().to_string();
        let key = format!("keygen-{}-{}", claim.sub, uuid.clone());
        let chaincode = generate_chaincode();

        let mut context = KeyGenContext::new();

        let result = context.update(&uuid, &chaincode);
        if result.is_err() {
            return result;
        }

        let value = context.to_string();

        let mut hmw = db_mtx.write().unwrap();
        hmw.insert(key, value);
        return result;
    }
    
    
        
    let uuid = request.uuid.clone();
    let key = format!("keygen-{}-{}", claim.sub, uuid.clone());

    
    //let hm = db_mtx.write().unwrap();
    let mut hm = db_mtx.write().unwrap();
    let value = hm.get(&key);
    if value.is_none() {
        return Err(format_err!("Invalid uuid({}), context not found", uuid));
    }

    let mut context = KeyGenContext::from_string(value.unwrap());
    let result = context.update(&request.uuid, &request.message);
    
    //let mut hmw = db_mtx.write().unwrap();
    if result.is_err() || context.is_done() {
        context.save_result(&state.db, &claim.sub)?;
        hm.remove(&key);
    } else {
        hm.insert(key, context.to_string());
    }
    result
}
