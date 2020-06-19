extern crate bluzelle;
extern crate dotenv;
extern crate pretty_env_logger;
#[macro_use] extern crate log;

use dotenv::dotenv;
use std::env;
use std::error::Error;
use std::time::{SystemTime, UNIX_EPOCH};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    std::env::set_var("RUST_LOG", "bluzelle");

    dotenv().ok();
    pretty_env_logger::init();

    let mnemonic = read_env(String::from("MNEMONIC"));
    let endpoint = read_env(String::from("ENDPOINT"));
    let chain_id = read_env(String::from("CHAIN_ID"));
    let uuid = read_env(String::from("UUID"));

    let mut client = bluzelle::new_client(mnemonic, endpoint, chain_id, uuid).await?;

    let now = SystemTime::now();
    let since_the_epoch = now.duration_since(UNIX_EPOCH)?;
    let key = String::from(format!("rust-{}", since_the_epoch.as_secs()));
    let value = String::from("value");

    let mut gas_info = bluzelle::GasInfo::default();
    gas_info.max_fee = Some(4_000_001);

    let lease_info = bluzelle::LeaseInfo::default();

    info!("account");
    let account = client.account().await?;
    info!("account({:?})", account);

    info!("creating key({})", key);
    client.create(&key, &value, gas_info, Some(lease_info)).await?;
    info!("created key({})", key.clone());

    info!("reading key({})", key);
    let read_value = client.read(&key).await?;
    info!("read key({}) value({:?})", key, read_value);

    Ok(())
}

fn read_env(key: String) -> String {
    match env::var(key) {
        Ok(val) => val,
        Err(_e) => String::from(""),
    }
}
