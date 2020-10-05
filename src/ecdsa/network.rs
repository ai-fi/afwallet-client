#![allow(non_snake_case)]

/// to run:
/// 1: go to rocket_server -> cargo run
/// 2: cargo run from PARTIES number of terminals
extern crate multi_party_ecdsa;
extern crate paillier;
extern crate reqwest;

extern crate hex;
extern crate serde_json;

use reqwest::Client;
use std::time::Duration;
use std::{thread};
use serde_json::{Value, Map};

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

pub struct NetworkClient {
    pub connInfo: Map<String, Value>,
    client: Client,
}

impl NetworkClient {
    pub fn new(connstr: &String) -> NetworkClient {
        let parsed: Value = serde_json::from_str(connstr).expect("Invalid connstr");
        let connInfo: Map<String, Value> = parsed.as_object().expect("Invalid connjson").clone();
        connInfo.get("server").expect("Not have a server address");
        

        let client = Client::new();
        NetworkClient{
            connInfo: connInfo,
            client: client
        }
    }
        
    fn get_server(&self) -> String {
        let server = self.connInfo.get("server").unwrap().as_str().unwrap();
        String::from(server)
    }
    pub fn postb<T>(&self, path: &str, body: T) -> Option<String>
    where
        T: serde::ser::Serialize,
    {
        let res = self.client
            .post(&format!("{}/{}", self.get_server(), path))
            .json(&body)
            .send();
        Some(res.unwrap().text().unwrap())
    }

    pub fn signup_keygen(&self) -> Result<PartySignup, ()> {
        let key = TupleKey {
            first: "signup".to_string(),
            second: "keygen".to_string(),
            third: "".to_string(),
            fourth: "".to_string(),
        };

        let res_body = self.postb("signupkeygen", key).unwrap();
        println!("{}", res_body);
        let answer: Result<PartySignup, ()> = serde_json::from_str(&res_body).unwrap();
        return answer;
    }
    
    pub fn signup_sign(&self) -> Result<PartySignup, ()> {
        let key = TupleKey {
            first: "signup".to_string(),
            second: "keygen".to_string(),
            third: "".to_string(),
            fourth: "".to_string(),
        };

        let res_body = self.postb("signupsign", key).unwrap();
        let answer: Result<PartySignup, ()> = serde_json::from_str(&res_body).unwrap();
        return answer;
    }

    pub fn broadcast(&self, 
        party_num: u32,
        round: &str,
        data: String,
        uuid: String,
    ) -> Result<(), ()> {
        let key = TupleKey {
            first: party_num.to_string(),
            second: round.to_string(),
            third: uuid,
            fourth: "".to_string(),
        };
        let entry = Entry {
            key: key.clone(),
            value: data,
        };

        let res_body = self.postb("set", entry).unwrap();
        let answer: Result<(), ()> = serde_json::from_str(&res_body).unwrap();
        return answer;
    }

    pub fn sendp2p(&self, 
        party_from: u32,
        party_to: u32,
        round: &str,
        data: String,
        uuid: String,
    ) -> Result<(), ()> {
        let key = TupleKey {
            first: party_from.to_string(),
            second: round.to_string(),
            third: uuid,
            fourth: party_to.to_string(),
        };
        let entry = Entry {
            key: key.clone(),
            value: data,
        };

        let res_body = self.postb("set", entry).unwrap();
        let answer: Result<(), ()> = serde_json::from_str(&res_body).unwrap();
        return answer;
    }

    pub fn poll_for_broadcasts(&self,
        party_num: u32,
        n: u32,
        delay: Duration,
        round: &str,
        uuid: String,
    ) -> Vec<String> {
        let mut ans_vec = Vec::new();
        for i in 1..n + 1 {
            if i != party_num {
                let key = TupleKey {
                    first: i.to_string(),
                    second: round.to_string(),
                    third: uuid.clone(),
                    fourth: "".to_string(),
                };
                let index = Index { key };
                loop {
                    // add delay to allow the server to process request:
                    thread::sleep(delay);
                    let res_body = self.postb("get", index.clone()).unwrap();
                    let answer: Result<Entry, ()> = serde_json::from_str(&res_body).unwrap();
                    if answer.is_ok() {
                        ans_vec.push(answer.unwrap().value);
                        println!("party {:?} {:?} read success", i, round);
                        break;
                    }
                }
            }
        }
        ans_vec
    }

    pub fn poll_for_p2p(
        &self,
        party_num: u32,
        n: u32,
        delay: Duration,
        round: &str,
        uuid: String,
    ) -> Vec<String> {
        let mut ans_vec = Vec::new();
        for i in 1..n + 1 {
            if i != party_num {
                let key = TupleKey {
                    first: i.to_string(),
                    second: round.to_string(),
                    third: uuid.clone(),
                    fourth: party_num.to_string(),
                };
                let index = Index { key };
                loop {
                    // add delay to allow the server to process request:
                    thread::sleep(delay);
                    let res_body = self.postb("get", index.clone()).unwrap();
                    let answer: Result<Entry, ()> = serde_json::from_str(&res_body).unwrap();
                    if answer.is_ok() {
                        ans_vec.push(answer.unwrap().value);
                        println!("party {:?} {:?} read success", i, round);
                        break;
                    }
                }
            }
        }
        ans_vec
    }

}