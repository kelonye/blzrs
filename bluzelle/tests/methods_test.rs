use failure::{Error, err_msg};

mod util;

// util

#[tokio::test]
async fn test_account() -> Result<(), Error> {
    let client = util::new_client().await?;
    let account = client.account().await?;
    println!("sequence: {}", account.sequence);
    assert!(account.sequence != 0);
    assert!(account.account_number != 0);
    Ok(())
}

#[tokio::test]
async fn test_version() -> Result<(), Error> {
    let client = util::new_client().await?;
    let version = client.version().await?;
    assert!(version != "");
    Ok(())
}

// tx

#[tokio::test]
async fn test_create_key_with_no_lease_info() -> Result<(), Error> {
    let mut client = util::new_client().await?;
    let key = util::random_string()?;
    let val = util::random_string()?;
    client.create(&key, &val, util::gas_info(), Some(bluzelle::LeaseInfo::default())).await?;
    let read_val = client.read(&key).await?;
    assert_eq!(val, read_val);
    Ok(())
}

#[tokio::test]
async fn test_creates_key_with_lease_info() -> Result<(), Error> {
    let mut client = util::new_client().await?;
    let key = util::random_string()?;
    let val = util::random_string()?;
    client.create(&key, &val, util::gas_info(), util::lease_info()).await?;
    let read_val = client.read(&key).await?;
    assert_eq!(val, read_val);
    Ok(())
}

#[tokio::test]
async fn test_creates_key_validates_gas_info() -> Result<(), Error> {
    let mut gas_info = bluzelle::GasInfo::default();
    gas_info.max_fee = Some(1);

    let mut client = util::new_client().await?;
    let key = util::random_string()?;
    let val = util::random_string()?;

    match client.create(&key, &val, gas_info, util::lease_info()).await {
        Ok(_) => Err(err_msg("did not raise error")),
        Err(_) => Ok(())
    }
}

#[tokio::test]
async fn test_creates_key_with_symbols() -> Result<(), Error> {
    let mut client = util::new_client().await?;
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
async fn test_create_fails_if_key_contains_hash() -> Result<(), Error> {
    let mut client = util::new_client().await?;
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
async fn test_update() -> Result<(), Error> {
    let mut client = util::new_client().await?;
    let key = util::random_string()?;
    client.create(&key, "1", util::gas_info(), util::lease_info()).await?;
    client.update(&key, "2", util::gas_info(), None).await?;
    let read_val = client.read(&key).await?;
    assert_eq!(read_val, "2");
    Ok(())
}

#[tokio::test]
async fn test_delete() -> Result<(), Error> {
    let key = util::random_string()?;
    let mut client = util::new_client().await?;
    client.create(&key, "1", util::gas_info(), util::lease_info()).await?;
    client.delete(&key, util::gas_info()).await?;
    assert!(client.has(&key).await?);
    Ok(())
}

#[tokio::test]
async fn test_rename() -> Result<(), Error> {
    Ok(())
}

#[tokio::test]
async fn test_delete_all() -> Result<(), Error> {
    Ok(())
}

#[tokio::test]
async fn test_multi_update() -> Result<(), Error> {
    Ok(())
}

#[tokio::test]
async fn test_renew_lease() -> Result<(), Error> {
    Ok(())
}

#[tokio::test]
async fn test_renew_all_leases() -> Result<(), Error> {
    Ok(())
}


// query

#[tokio::test]
async fn test_read() -> Result<(), Error> {
    let mut client = util::new_client().await?;
    let key = util::random_string()?;
    let val = util::random_string()?;
    client.create(&key, &val, util::gas_info(), util::lease_info()).await?;
    let read_val = client.read(&key).await?;
    assert_eq!(val, read_val);
    Ok(())
}

#[tokio::test]
async fn test_has() -> Result<(), Error> {
    let mut client = util::new_client().await?;
    let key = util::random_string()?;
    let val = util::random_string()?;
    assert!(!client.has(&key).await?);
    client.create(&key, &val, util::gas_info(), util::lease_info()).await?;
    assert!(client.has(&key).await?);
    Ok(())
}

#[tokio::test]
async fn test_count() -> Result<(), Error> {
    Ok(())
}

#[tokio::test]
async fn test_keys() -> Result<(), Error> {
    Ok(())
}

#[tokio::test]
async fn test_key_values() -> Result<(), Error> {
    Ok(())
}

#[tokio::test]
async fn test_get_lease() -> Result<(), Error> {
    Ok(())
}

#[tokio::test]
async fn test_get_n_shortest_leases() -> Result<(), Error> {
    Ok(())
}

// tx query

#[tokio::test]
async fn test_tx_read() -> Result<(), Error> {
    Ok(())
}

#[tokio::test]
async fn test_tx_has() -> Result<(), Error> {
    Ok(())
}

#[tokio::test]
async fn test_tx_count() -> Result<(), Error> {
    Ok(())
}

#[tokio::test]
async fn test_tx_keys() -> Result<(), Error> {
    Ok(())
}

#[tokio::test]
async fn test_tx_key_values() -> Result<(), Error> {
    Ok(())
}

#[tokio::test]
async fn test_tx_get_lease() -> Result<(), Error> {
    Ok(())
}

#[tokio::test]
async fn test_tx_get_n_shortest_leases() -> Result<(), Error> {
    Ok(())
}
