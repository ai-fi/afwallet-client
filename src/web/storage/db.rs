// Gotham-city
//
// Copyright 2018 by Kzen Networks (kzencorp.com)
// Gotham city is free software: you can redistribute
// it and/or modify it under the terms of the GNU General Public
// License as published by the Free Software Foundation, either
// version 3 of the License, or (at your option) any later version.
//
use serde;
use super::super::Result;
use kv::*;



pub enum DB {
    Local(Store),
}

pub trait MPCStruct {
    fn to_string(&self) -> String;

    fn to_table_name(&self, env: &str) -> String {
        format!("{}_{}", env, self.to_string())
    }

    fn require_customer_id(&self) -> bool {
        true
    }
}

fn idify(user_id: &str, id: &str, name: &dyn MPCStruct) -> String {
    format!("{}_{}_{}", user_id, id, name.to_string())
}

pub fn insert<T>(db: &DB, user_id: &str, id: &str, name: &dyn MPCStruct, v: T) -> Result<()>
where
    T: serde::ser::Serialize,
{
    match db {
        DB::Local(store) => {
            let wallet_bucket = store.bucket::<String, String>(Some("wallet"))?;
            let identifier = idify(user_id, id, name);
            let v_string = serde_json::to_string(&v).unwrap();
            wallet_bucket.set(identifier, v_string)?;
            wallet_bucket.flush()?;
            // walletDB.set(identifier.as_ref(), v_string.as_ref())?;
            Ok(())
        }
    }
}

pub fn get<T>(db: &DB, user_id: &str, id: &str, name: &dyn MPCStruct) -> Result<Option<T>>
where
    T: serde::de::DeserializeOwned,
{
    match db {
        DB::Local(store) => {
            let wallet_bucket = store.bucket::<String, String>(Some("wallet"))?;
            let identifier = idify(user_id, id, name);
            debug!("Getting from db ({})", identifier);
            let db_option = wallet_bucket.get(identifier)?;
            
            match db_option {
                None => Ok(None),
                Some(vaule) => Ok(serde_json::from_str(&vaule).unwrap()),
            }

            // let db_option = rocksdb_client.get(identifier.as_ref())?;
            // let vec_option: Option<Vec<u8>> = db_option.map(|v| v.to_vec());
            /*match vec_option {
                Some(vec) => Ok(serde_json::from_slice(&vec).unwrap()),
                None => Ok(None),
            }*/
        }
    }
}
