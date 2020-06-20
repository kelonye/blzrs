![](https://raw.githubusercontent.com/bluzelle/api/master/source/images/Bluzelle%20-%20Logo%20-%20Big%20-%20Colour.png)

### Getting started

Ensure you have a recent version of [Rust](https://www.rust-lang.org/) installed.

1. Add package in the `[dependencies]` section of your `Cargo.toml` config.

```
[dependencies]
bluzelle = { git = "https://github.com/vbstreetz/blzrs" }
```

2. Use:

```rust
extern crate bluzelle;

use std::error::Error;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let mnemonic = "jelly practice...";
    let endpoint = "http://dev.testnet.public.bluzelle.com:1317";
    let chain_id = "bluzelle";
    let uuid = "my-app";

    let mut client = bluzelle::new_client(mnemonic, endpoint, chain_id, uuid).await?;

    let key = "key";
    let value = "value";

    let mut gas_info = bluzelle::GasInfo::default();
    gas_info.max_fee = 4_000_001;

    let mut lease_info = bluzelle::LeaseInfo::default();
    lease_info.days = 1;

    client.create(key, value, gas_info, lease_info).await?;
    let read_value = client.read(key).await?;
    println!("val: {}", read_value);

    Ok(())
}
```

### Examples

Copy `.env.sample` to `.env` and configure if needed.

```
cp .env.sample .env
```

Then run the example:

```
    make example
```

### Tests

Configure env as described in the examples section above, and run:

```
    make test
```

### User Acceptance Testing

Please checkout the [UAT.md](https://github.com/vbstreetz/blzrs/blob/master/UAT.md) document for more details.

### Licence

MIT
