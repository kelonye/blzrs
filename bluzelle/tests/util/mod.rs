extern crate pretty_env_logger;
// #[macro_use] extern crate log;

use std::sync::Once;
use bluzelle;
use dotenv::dotenv;
use std::env;
use failure::Error;
use std::time::{SystemTime, UNIX_EPOCH};

static INIT: Once = Once::new();

pub async fn new_client() -> Result<bluzelle::Client, Error> {
    INIT.call_once(|| {
        std::env::set_var("RUST_LOG", "bluzelle");
        pretty_env_logger::init();
        dotenv().ok();
    });

    let mnemonic = read_env(String::from("MNEMONIC"));
    let endpoint = read_env(String::from("ENDPOINT"));
    let chain_id = read_env(String::from("CHAIN_ID"));
    let uuid = read_env(String::from("UUID"));

    bluzelle::new_client(mnemonic, endpoint, chain_id, uuid).await
}

fn read_env(key: String) -> String {
    match env::var(key) {
        Ok(val) => val,
        Err(_e) => String::from(""),
    }
}

pub fn random_string() -> Result<String, Error> {
    let now = SystemTime::now();
    let since_the_epoch = now.duration_since(UNIX_EPOCH)?;
    Ok(format!("rust-{}", since_the_epoch.as_secs()))
}

pub fn gas_info() -> bluzelle::GasInfo {
    let mut gas_info = bluzelle::GasInfo::default();
    gas_info.max_fee = 4000001;
    gas_info
}

pub fn lease_info() -> bluzelle::LeaseInfo {
    let lease_info = bluzelle::LeaseInfo::default();
    lease_info
}
