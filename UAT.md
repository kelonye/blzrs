### User Acceptance Testing

The following guide describes setting up the project and running an example code and tests in an AWS Ubuntu 18.04 machine. Once ssh'ed into the machine:

1. Ensure the system package index is up to date:

```
sudo apt -y update
```

2. Install required system tools

```
sudo apt install -y build-essential make pkg-config libssl-dev
```

3. Ensure latest rustlang version is installed:

```
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

Select `1) Proceed with installation (default)` if prompted.

Add `cargo` bin directory (`$HOME/.cargo/bin`) in the PATH environment variable by running the below command. `cargo` is the Rust package manager.

```
source $HOME/.cargo/env
```

4. Clone the project:

```
git clone https://github.com/vbstreetz/blzrs.git
cd blzrs
```

5. Setup the sample environment variables:

```
cp .env.sample .env
```

The example code and tests will read the bluzelle settings to use from that file i.e. `.env`.

6. Run the example code located at `examples/src/main.rs`:

```
make example
```

This example code performs simple CRUD operations against the testnet.

7. The project also ships a complete suite of integration tests for all the methods. To run all the tests simply run:

```
make test
```

This will run all the tests in the `test` directory using the same environment settings defined in the `.env` file. A successful run should result in an output like this:

```
test result: ok. 28 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
```
