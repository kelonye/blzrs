use failure::{Error, err_msg};

mod util;

// util

#[tokio::test]
async fn account() -> Result<(), Error> {
    let client = util::new_client().await?;
    let account = client.account().await?;
    println!("sequence: {}", account.sequence);
    assert!(account.sequence != 0);
    assert!(account.account_number != 0);
    Ok(())
}

#[tokio::test]
async fn version() -> Result<(), Error> {
    let client = util::new_client().await?;
    let version = client.version().await?;
    assert!(version != "");
    Ok(())
}

// tx

#[tokio::test]
async fn create_key_with_no_lease_info() -> Result<(), Error> {
    let client = util::new_client().await?;
    let key = util::random_string()?;
    let val = util::random_string()?;
    client.create(&key, &val, util::gas_info(), Some(bluzelle::LeaseInfo::default())).await?;
    let read_val = client.read(&key).await?;
    assert_eq!(val, read_val);
    Ok(())
}

#[tokio::test]
async fn creates_key_with_lease_info() -> Result<(), Error> {
    let client = util::new_client().await?;
    let key = util::random_string()?;
    let val = util::random_string()?;
    client.create(&key, &val, util::gas_info(), util::lease_info()).await?;
    let read_val = client.read(&key).await?;
    assert_eq!(val, read_val);
    Ok(())
}

#[tokio::test]
async fn creates_key_validates_gas_info() -> Result<(), Error> {
    let mut gas_info = bluzelle::GasInfo::default();
    gas_info.max_fee = Some(1);

    let client = util::new_client().await?;
    let key = util::random_string()?;
    let val = util::random_string()?;

    match client.create(&key, &val, gas_info, util::lease_info()).await {
        Ok(_) => Err(err_msg("did not raise error")),
        Err(_) => Ok(())
    }
}

#[tokio::test]
async fn creates_key_with_symbols() -> Result<(), Error> {
    let client = util::new_client().await?;
    let key = util::random_string()? + " !\"#$%&'()*+,-.0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~";
    let val = util::random_string()?;
    client.create(&key, &val, util::gas_info(), util::lease_info()).await?;
    match client.keys().await {
        Err(e) => Err(e),
        Ok(keys) => {
            for k in keys.iter() {
                if *k == key.to_string() {
                    return Ok(());
                }
            }
            Err(err_msg(format!("key({}) was not found in ({:?})", key, keys)))
        }
    }
}

#[tokio::test]
async fn create_fails_if_key_contains_hash() -> Result<(), Error> {
    let client = util::new_client().await?;
    let key = "123/";
    let val = util::random_string()?;

    match client.create(&key, &val, util::gas_info(), util::lease_info()).await {
        Ok(_) => Ok(()),
        Err(e) => {
            if e.to_string().contains("Key cannot contain a slash") {
                Ok(())
            } else {
                Err(err_msg("error was not raised"))
            }
        },
    }
}

#[tokio::test]
async fn update() -> Result<(), Error> {
    Ok(())
}

#[tokio::test]
async fn delete() -> Result<(), Error> {
    Ok(())
}

#[tokio::test]
async fn rename() -> Result<(), Error> {
    Ok(())
}

#[tokio::test]
async fn delete_all() -> Result<(), Error> {
    Ok(())
}

#[tokio::test]
async fn multi_update() -> Result<(), Error> {
    Ok(())
}

#[tokio::test]
async fn renew_lease() -> Result<(), Error> {
    Ok(())
}

#[tokio::test]
async fn renew_all_leases() -> Result<(), Error> {
    Ok(())
}


// query

#[tokio::test]
async fn read() -> Result<(), Error> {
    let client = util::new_client().await?;
    let key = util::random_string()?;
    let val = util::random_string()?;
    client.create(&key, &val, util::gas_info(), util::lease_info()).await?;
    let read_val = client.read(&key).await?;
    assert_eq!(val, read_val);
    Ok(())
}

#[tokio::test]
async fn has() -> Result<(), Error> {
    Ok(())
}

#[tokio::test]
async fn count() -> Result<(), Error> {
    Ok(())
}

#[tokio::test]
async fn keys() -> Result<(), Error> {
    Ok(())
}

#[tokio::test]
async fn key_values() -> Result<(), Error> {
    Ok(())
}

#[tokio::test]
async fn get_lease() -> Result<(), Error> {
    Ok(())
}

#[tokio::test]
async fn get_n_shortest_leases() -> Result<(), Error> {
    Ok(())
}

// tx query

#[tokio::test]
async fn tx_read() -> Result<(), Error> {
    Ok(())
}

#[tokio::test]
async fn tx_has() -> Result<(), Error> {
    Ok(())
}

#[tokio::test]
async fn tx_count() -> Result<(), Error> {
    Ok(())
}

#[tokio::test]
async fn tx_keys() -> Result<(), Error> {
    Ok(())
}

#[tokio::test]
async fn tx_key_values() -> Result<(), Error> {
    Ok(())
}

#[tokio::test]
async fn tx_get_lease() -> Result<(), Error> {
    Ok(())
}

#[tokio::test]
async fn tx_get_n_shortest_leases() -> Result<(), Error> {
    Ok(())
}
