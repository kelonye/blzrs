extern crate pretty_env_logger;
// #[macro_use] extern crate log;

use bluzelle;
use dotenv::dotenv;
use failure::{err_msg, Error};
use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use std::env;
use std::sync::Once;

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
    let uuid = random_string();

    bluzelle::new_client(&mnemonic, &endpoint, &chain_id, &uuid).await
}

fn read_env(key: String) -> String {
    match env::var(key) {
        Ok(val) => val,
        Err(_e) => String::from(""),
    }
}

pub fn random_string() -> String {
    let s: String = thread_rng().sample_iter(&Alphanumeric).take(10).collect();
    format!("rust-{}", s)
}

pub fn gas_info() -> bluzelle::GasInfo {
    let mut gas_info = bluzelle::GasInfo::default();
    gas_info.max_fee = Some(4_000_000);
    gas_info.max_gas = Some(400_000);
    gas_info
}

pub fn lease_info() -> Option<bluzelle::LeaseInfo> {
    let mut lease_info = bluzelle::LeaseInfo::default();
    lease_info.seconds = Some(100);
    Some(lease_info)
}

pub fn assert_key_in_keys(keys: Vec<String>, key: &str) -> Result<(), Error> {
    if keys.contains(&String::from(key)) {
        return Ok(());
    }
    Err(err_msg("key_value not found in key_values"))
}

pub fn assert_kv_in_kvs(
    key_values: Vec<bluzelle::KeyValue>,
    key: &str,
    value: &str,
) -> Result<(), Error> {
    for key_value in key_values {
        if key_value.key == key && key_value.value == value {
            return Ok(());
        }
    }
    Err(err_msg("key_value not found in key_values"))
}
