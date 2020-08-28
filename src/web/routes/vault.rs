

use rocket::State;

use super::super::Result;
use rocket_contrib::json::Json;

use super::super::auth::jwt::Claims;
use super::super::storage::db;
use super::super::Config;
use super::*;

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct PairingInfo {
    //#[serde(rename(serialize = "server"))]
    pub server: String,
    //#[serde(rename(serialize = "authInfo"))]
    pub auth: String,
}
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct VaultStatus {
    //#[serde(rename(serialize = "server"))]
    pub is_ready: bool,
    //#[serde(rename(serialize = "authInfo"))]
}

#[get("/vault/pairing_info")]
pub fn pairing_info() -> Result<Json<PairingInfo>> {
    // TODO: Add logic for health check
    let ip = crate::util::local_ip::get().unwrap();
    let server = format!("http://{}:{}", ip, 8000);
    let info = PairingInfo{
        server: server,
        auth: String::from(""),
    };
    Ok(Json(info))
}


#[get("/vault/status")]
pub fn vault_status(
    state: State<Config>,
    claim: Claims
) -> Result<Json<VaultStatus>> {
    let mut is_ready = false;

    let vault_wallet_ids_id = String::from("vault_wallet_ids_id");
    let result: Result<Option<Vec<String>>> = db::get(&state.db, &claim.sub, &vault_wallet_ids_id, &VaultStruct::VaultWalletIDs);
    if result.is_ok() {
        let option_wallet_ids = result.unwrap();
        if option_wallet_ids.is_some() {
            let wallet_ids = option_wallet_ids.unwrap();
            is_ready =  wallet_ids.len() > 0;
        }
    } 

    let status = VaultStatus{
        is_ready: is_ready
    };
    Ok(Json(status))
}

#[get("/vault/list")]
pub fn list_vaults(
    state: State<Config>,
    claim: Claims
) -> Result<Json<Vec<String>>> {

    let vault_wallet_ids_id = String::from("vault_wallet_ids_id");
    let result: Vec<String> = db::get(&state.db, &claim.sub, &vault_wallet_ids_id, &VaultStruct::VaultWalletIDs)?
    .ok_or(format_err!("No data for such identifier {}", vault_wallet_ids_id))?;
    
    Ok(Json(result))
}

#[get("/vault/data/<uuid>")]
pub fn vault_data(
    state: State<Config>,
    claim: Claims,
    uuid: String,
) -> Result<Json<String>> {
    let data: String =db::get(&state.db, &claim.sub, &uuid, &VaultStruct::VaultData)?
    .ok_or(format_err!("No data for such identifier {}", uuid))?;
    Ok(Json(data))
}
