extern crate dotenv;
extern crate pretty_env_logger;
extern crate serde;
#[macro_use]
extern crate log;

use bluzelle;
use dotenv::dotenv;
use std::env;
// use std::error::Error;
use failure::Error;
use serde_derive::{Deserialize, Serialize};
use std::convert::Infallible;
use std::time::{SystemTime, UNIX_EPOCH};
use warp::http::StatusCode;
use warp::Filter;

#[derive(Default, Serialize, Deserialize, Debug)]
pub struct Request {
    method: String,
    args: Vec<serde_json::Value>,
}

#[tokio::main]
async fn main() {
    std::env::set_var("RUST_LOG", "bluzelle");
    dotenv().ok();
    pretty_env_logger::init();

    let port = read_env_number(String::from("PORT"), 4565);

    let handler = warp::post().and(warp::body::json()).and_then(handler);
    info!("listening on port {}", port);
    warp::serve(handler).run(([127, 0, 0, 1], port)).await
}

async fn handler(req: Request) -> Result<impl warp::Reply, Infallible> {
    let (reply, code) = match call_api(req).await {
        Ok(json) => (json, StatusCode::OK),
        Err(e) => (
            warp::reply::json(&String::from(format!("{}", e))),
            StatusCode::INTERNAL_SERVER_ERROR,
        ),
    };
    Ok(warp::reply::with_status(reply, code))
}

async fn call_api(req: Request) -> Result<warp::reply::Json, Error> {
    let mnemonic = read_env(String::from("MNEMONIC"));
    let endpoint = read_env(String::from("ENDPOINT"));
    let chain_id = read_env(String::from("CHAIN_ID"));
    let uuid = read_env(String::from("UUID"));

    let mut client = bluzelle::new_client(mnemonic, endpoint, chain_id, uuid).await?;

    match req.method.as_str() {
        "account" => {
            let account = client.account().await?;
            Ok(warp::reply::json(&account))
        }
        "version" => {
            let version = client.version().await?;
            Ok(warp::reply::json(&version))
        }
        // tx
        "create" => {
            let key: String = serde_json::from_value(req.args[0].clone())?;
            let val: String = serde_json::from_value(req.args[1].clone())?;
            let gas_info: bluzelle::GasInfo = serde_json::from_value(req.args[2].clone())?;
            let lease_info: Option<bluzelle::LeaseInfo> =
                match serde_json::from_value(req.args[3].clone()) {
                    Ok(l) => Some(l),
                    Err(_) => None,
                };
            client
                .create(&String::from(key), &String::from(val), gas_info, lease_info)
                .await?;
            Ok(warp::reply::json(&String::from("null")))
        }
        "update" => {
            let key: String = serde_json::from_value(req.args[0].clone())?;
            let val: String = serde_json::from_value(req.args[1].clone())?;
            let gas_info: bluzelle::GasInfo = serde_json::from_value(req.args[2].clone())?;
            let lease_info: Option<bluzelle::LeaseInfo> =
                match serde_json::from_value(req.args[3].clone()) {
                    Ok(l) => Some(l),
                    Err(_) => None,
                };
            client
                .update(&String::from(key), &String::from(val), gas_info, lease_info)
                .await?;
            Ok(warp::reply::json(&String::from("null")))
        }
        "delete" => {
            let key: String = serde_json::from_value(req.args[0].clone())?;
            let gas_info: bluzelle::GasInfo = serde_json::from_value(req.args[1].clone())?;
            client.delete(&String::from(key), gas_info).await?;
            Ok(warp::reply::json(&String::from("null")))
        }
        "rename" => {
            let key: String = serde_json::from_value(req.args[0].clone())?;
            let new_key: String = serde_json::from_value(req.args[1].clone())?;
            let gas_info: bluzelle::GasInfo = serde_json::from_value(req.args[2].clone())?;
            client
                .rename(&String::from(key), &String::from(new_key), gas_info)
                .await?;
            Ok(warp::reply::json(&String::from("null")))
        }
        "delete_all" => {
            let gas_info: bluzelle::GasInfo = serde_json::from_value(req.args[0].clone())?;
            client.delete_all(gas_info).await?;
            Ok(warp::reply::json(&String::from("null")))
        }
        "multi_update" => {
            let key_values: Vec<bluzelle::KeyValue> = serde_json::from_value(req.args[0].clone())?;
            let gas_info: bluzelle::GasInfo = serde_json::from_value(req.args[1].clone())?;
            client.multi_update(key_values, gas_info).await?;
            Ok(warp::reply::json(&String::from("null")))
        }
        "renew_lease" => {
            let key: String = serde_json::from_value(req.args[0].clone())?;
            let gas_info: bluzelle::GasInfo = serde_json::from_value(req.args[1].clone())?;
            let lease_info: Option<bluzelle::LeaseInfo> =
                match serde_json::from_value(req.args[2].clone()) {
                    Ok(l) => Some(l),
                    Err(_) => None,
                };
            client
                .renew_lease(&String::from(key), gas_info, lease_info)
                .await?;
            Ok(warp::reply::json(&String::from("null")))
        }
        "renew_lease_all" => {
            let gas_info: bluzelle::GasInfo = serde_json::from_value(req.args[0].clone())?;
            let lease_info: Option<bluzelle::LeaseInfo> =
                match serde_json::from_value(req.args[1].clone()) {
                    Ok(l) => Some(l),
                    Err(_) => None,
                };
            client.renew_lease_all(gas_info, lease_info).await?;
            Ok(warp::reply::json(&String::from("null")))
        }
        // query
        "read" => {
            let key: String = serde_json::from_value(req.args[0].clone())?;
            let val = client.read(&String::from(&key)).await?;
            Ok(warp::reply::json(&val))
        }
        "has" => {
            let key: String = serde_json::from_value(req.args[0].clone())?;
            let has = client.has(&String::from(&key)).await?;
            Ok(warp::reply::json(&has))
        }
        "count" => {
            let count = client.count().await?;
            Ok(warp::reply::json(&count))
        }
        "keys" => {
            let keys = client.keys().await?;
            Ok(warp::reply::json(&keys))
        }
        "keyvalues" => {
            let key_values = client.key_values().await?;
            Ok(warp::reply::json(&key_values))
        }
        "get_lease" => {
            let key: String = serde_json::from_value(req.args[0].clone())?;
            let lease = client.get_lease(&String::from(key)).await?;
            Ok(warp::reply::json(&lease))
        }
        "get_n_shortest_leases" => {
            let n: u64 = serde_json::from_value(req.args[0].clone())?;
            let kls = client.get_n_shortest_leases(n).await?;
            Ok(warp::reply::json(&kls))
        }
        // tx query
        "tx_read" => {
            let key: String = serde_json::from_value(req.args[0].clone())?;
            let gas_info: bluzelle::GasInfo = serde_json::from_value(req.args[1].clone())?;
            let val = client.tx_read(&String::from(&key), gas_info).await?;
            Ok(warp::reply::json(&val))
        }
        "tx_has" => {
            let key: String = serde_json::from_value(req.args[0].clone())?;
            let gas_info: bluzelle::GasInfo = serde_json::from_value(req.args[1].clone())?;
            let has = client.tx_has(&String::from(&key), gas_info).await?;
            Ok(warp::reply::json(&has))
        }
        "tx_count" => {
            let gas_info: bluzelle::GasInfo = serde_json::from_value(req.args[0].clone())?;
            let count = client.tx_count(gas_info).await?;
            Ok(warp::reply::json(&count))
        }
        "tx_keys" => {
            let gas_info: bluzelle::GasInfo = serde_json::from_value(req.args[0].clone())?;
            let keys = client.tx_keys(gas_info).await?;
            Ok(warp::reply::json(&keys))
        }
        "tx_key_values" => {
            let gas_info: bluzelle::GasInfo = serde_json::from_value(req.args[0].clone())?;
            let key_values = client.tx_key_values(gas_info).await?;
            Ok(warp::reply::json(&key_values))
        }
        "tx_get_lease" => {
            let key: String = serde_json::from_value(req.args[0].clone())?;
            let gas_info: bluzelle::GasInfo = serde_json::from_value(req.args[1].clone())?;
            let lease = client.tx_get_lease(&String::from(key), gas_info).await?;
            Ok(warp::reply::json(&lease))
        }
        "tx_get_n_shortest_leases" => {
            let n: u64 = serde_json::from_value(req.args[0].clone())?;
            let gas_info: bluzelle::GasInfo = serde_json::from_value(req.args[1].clone())?;
            let kls = client.tx_get_n_shortest_leases(n, gas_info).await?;
            Ok(warp::reply::json(&kls))
        }
        _ => Ok(warp::reply::json(&String::from("unknown method"))),
    }
}

fn read_env(key: String) -> String {
    match env::var(key) {
        Ok(val) => val,
        Err(_e) => String::from(""),
    }
}

fn read_env_number(key: String, default: u16) -> u16 {
    match env::var(key) {
        Ok(val) => match val.parse::<u16>() {
            Ok(port) => port,
            Err(_e) => default,
        },
        Err(_e) => default,
    }
}
