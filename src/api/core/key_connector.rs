use rocket::serde::json::Json;
use rocket::Route;

use crate::{
    CONFIG,
    api::{EmptyResult, JsonResult},
    auth::Headers,
    db::DbConn,
};

pub fn routes() -> Vec<Route> {
    routes![post_set_key_connector_key, get_confirmation_details]
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SetKeyConnectorKeyData {
    key: String,
    keys: KeysData,
    kdf: i32,
    kdf_iterations: i32,
    kdf_memory: Option<i32>,
    kdf_parallelism: Option<i32>,
    #[allow(dead_code)]
    org_identifier: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct KeysData {
    public_key: String,
    encrypted_private_key: String,
}

/// Completes Key Connector setup: the client generated the user key + keypair,
/// wrapped the user key with the connector-held key, and posts the results here.
#[post("/accounts/set-key-connector-key", data = "<data>")]
async fn post_set_key_connector_key(data: Json<SetKeyConnectorKeyData>, headers: Headers, conn: DbConn) -> EmptyResult {
    if CONFIG.sso_key_connector_url().is_empty() {
        err!("Key Connector is not enabled");
    }
    let data = data.into_inner();
    let user = headers.user;
    if !user.uses_key_connector && !CONFIG.is_sso_key_connector_user(&user.email) {
        err!("This account is not configured for Key Connector");
    }
    let mut user = user;

    // Enrollment is one-time: prevents overwriting akey/keys and destroying existing ciphers.
    if user.private_key.is_some() {
        err!("Account is already initialized; Key Connector enrollment cannot overwrite existing keys");
    }

    user.akey = data.key;
    user.public_key = Some(data.keys.public_key);
    user.private_key = Some(data.keys.encrypted_private_key);
    user.client_kdf_type = data.kdf;
    user.client_kdf_iter = data.kdf_iterations;
    user.client_kdf_memory = data.kdf_memory;
    user.client_kdf_parallelism = data.kdf_parallelism;
    // Key Connector user: no master password is ever stored.
    user.password_hash = Vec::new();
    user.uses_key_connector = true;

    user.save(&conn).await
}

/// The web client requests this before running Key Connector setup (the
/// "confirm Key Connector domain" screen). We only run one connector, so we
/// echo back its URL regardless of the supplied org identifier.
#[get("/accounts/key-connector/confirmation-details/<_org_identifier>")]
fn get_confirmation_details(_org_identifier: String, _headers: Headers) -> JsonResult {
    if CONFIG.sso_key_connector_url().is_empty() {
        err!("Key Connector is not enabled");
    }
    Ok(Json(json!({
        "keyConnectorUrl": CONFIG.sso_key_connector_url(),
        "object": "keyConnectorUserDecryptionOption"
    })))
}
