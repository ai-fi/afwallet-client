// Gotham-city
//
// Copyright 2018 by Kzen Networks (kzencorp.com)
// Gotham city is free software: you can redistribute
// it and/or modify it under the terms of the GNU General Public
// License as published by the Free Software Foundation, either
// version 3 of the License, or (at your option) any later version.
//

use config;
use rocket;
use rocket::{Request, Rocket};
use rocket_contrib::serve::StaticFiles;

use super::routes::*;
use super::storage::db;
use super::Config;


use std::collections::HashMap;

use std::sync::RwLock;
// use uuid::Uuid;

#[derive(Deserialize)]
pub struct AuthConfig {
    pub issuer: String,
    pub audience: String,
    pub region: String,
    pub pool_id: String,
}

impl AuthConfig {
    pub fn load(settings: HashMap<String, String>) -> AuthConfig {
        let issuer = settings.get("issuer").unwrap_or(&"".to_string()).to_owned();
        let audience = settings
            .get("audience")
            .unwrap_or(&"".to_string())
            .to_owned();
        let region = settings.get("region").unwrap_or(&"".to_string()).to_owned();
        let pool_id = settings
            .get("pool_id")
            .unwrap_or(&"".to_string())
            .to_owned();

        AuthConfig {
            issuer,
            audience,
            region,
            pool_id,
        }
    }
}

#[catch(500)]
fn internal_error() -> &'static str {
    "Internal server error"
}

#[catch(400)]
fn bad_request() -> &'static str {
    "Bad request"
}

#[catch(404)]
fn not_found(req: &Request) -> String {
    format!("Unknown route '{}'.", req.uri())
}

pub fn get_server() -> Rocket {
    let settings = get_settings_as_map();
    
    let db_config = Config {
        db: get_db(settings.clone()),
    };

    let db: HashMap<String, String> = HashMap::new();
    let db_mtx = RwLock::new(db);

    let auth_config = AuthConfig::load(settings.clone());

    rocket::ignite()
        .register(catchers![internal_error, not_found, bad_request])
        .mount(
            "/", 
            StaticFiles::from("static")
        )
        .mount(
            "/api",
            routes![
                ping::ping,
                vault::pairing_info,
                vault::vault_status,
                vault::vault_data,
                vault::list_vaults,
                vault::restore,
                vault::erase_all_data,
                keygen::keygen,
                sign::sign,
                wallet::get_default,
                token::srp,
                token::save,
                token::retrieve,
                token::update,
            ]
        )
        //.manage(db_config)
        .manage(auth_config)
        .manage(db_mtx)
        .manage(db_config)
}

fn get_settings_as_map() -> HashMap<String, String> {
    let config_file = include_str!("Settings.toml");
    let mut settings = config::Config::default();
    settings
        .merge(config::File::from_str(
            config_file,
            config::FileFormat::Toml,
        ))
        .unwrap()
        .merge(config::Environment::new())
        .unwrap();

    settings.try_into::<HashMap<String, String>>().unwrap()
}

fn get_db(settings: HashMap<String, String>) -> db::DB {
    let db_type_string = settings
        .get("db")
        .unwrap_or(&"local".to_string())
        .to_uppercase();
    let db_type = db_type_string.as_str();
    /*
    let env = settings
        .get("env")
        .unwrap_or(&"dev".to_string())
        .to_string();
    */
    match db_type {
        _ => {
            let cfg = kv::Config::new("./db");
            let store = kv::Store::new(cfg).unwrap();
            db::DB::Local(store)
        },
    }
}
