extern crate serde;
extern crate dotenv;
extern crate pretty_env_logger;
#[macro_use] extern crate log;

use bluzelle;
use dotenv::dotenv;
use std::env;
// use std::error::Error;
use std::convert::Infallible;
use failure::Error;
use std::time::{SystemTime, UNIX_EPOCH};
use warp::Filter;
use warp::http::StatusCode;
use serde_derive::{Serialize, Deserialize};

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

    let handler = warp::post()
        .and(warp::body::json())
        .and_then(handler);
   
    info!("listening on port {}", port);
    warp::serve(handler).run(([127, 0, 0, 1], port)).await
}

async fn handler(req: Request) -> Result<impl warp::Reply, Infallible> {
    let (reply, code) = match call_api(req).await {
        Ok(json) => (json, StatusCode::OK),
        Err(e) => (warp::reply::json(&String::from(format!("{}", e))), StatusCode::INTERNAL_SERVER_ERROR)
    };
    Ok(warp::reply::with_status(reply, code))
}

async fn call_api(req: Request) -> Result<warp::reply::Json, Error> {
    let mnemonic = read_env(String::from("MNEMONIC"));
    let endpoint = read_env(String::from("ENDPOINT"));
    let chain_id = read_env(String::from("CHAIN_ID"));
    let uuid = read_env(String::from("UUID"));

    let client = bluzelle::new_client(mnemonic, endpoint, chain_id, uuid).await?;

    match req.method.as_str() {
        "account" => {
            let account = client.account().await?;
            Ok(warp::reply::json(&account))
        },
        "version" => {
            let version = client.version().await?;
            Ok(warp::reply::json(&version))
        },
        "create" => { 
            let key: String = serde_json::from_value(req.args[0].clone())?;
            let val: String = serde_json::from_value(req.args[1].clone())?;

            let mut gas_info: bluzelle::GasInfo = serde_json::from_value(req.args[2].clone())?;
            let lease_info: bluzelle::LeaseInfo = match serde_json::from_value(req.args[3].clone()) {
                Ok(l) => l,
                Err(_) => bluzelle::LeaseInfo::default()
            };

            client.create(&String::from(key), &String::from(val), gas_info, Some(lease_info)).await?;
            Ok(warp::reply::json(&String::from("nil")))
        },
        "read" => {
            let key: String = serde_json::from_value(req.args[0].clone())?;
            let val = client.read(&String::from(&key)).await?;
            Ok(warp::reply::json(&val))
        },
        _ => {
            Ok(warp::reply::json(&String::from("unknown method")))
        }
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
        Ok(val) => {
            match val.parse::<u16>() {
                Ok(port) => port,
                Err(_e) => default,
            }
        },
        Err(_e) => default,
    }
}
