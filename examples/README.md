# Examples
This crate contains a set of examples for using AKD.

## Running Examples

There are currently three examples supported in this library:
- `whatsapp-kt-auditor`: An auditor for WhatsApp key transparency audit proofs
- `mysql-demo`: An interactive application that demonstrates the use of AKD with a MySQL storage layer
- `fixture-generator`: A utility for producing test fixtures which can be used to measure when the underlying byte
  format for the AKD operations change

### WhatsApp Key Transparency Auditor

To run this example:
```
cargo run -p examples --release -- whatsapp-kt-auditor
```
and this will bring up an interactive interface which allows you to load the current epochs, and choose which epochs to audit.

You can also automatically audit the latest epoch with the `-l` parameter (for "latest"), by running:
```
cargo run -p examples --release -- whatsapp-kt-auditor -l
```

### MySQL Demo

This example requires setting up [Docker](https://docs.docker.com/get-docker/) (which will host the MySQL instance). Once Docker
is up and running, you can simply run:
```
cargo run -p examples --release -- mysql-demo
```
to run the demo. You can also pass the `--help` argument to view various options for running benchmarks and auto-populating the instance.
For example, you can try:
```
cargo run -p examples --release -- mysql-demo bench-publish 1000 3
```
which will create a publish with 1000 users each with 3 updates (across 3 epochs).

Note that if you are encountering the error:
```
Failed 1 reconnection attempt(s) to MySQL database
```
then this means that establishing a connection with the Docker instance failed, and you will need to double-check your Docker setup.

### Fixture Generator

This is primarily used for testing and compatibility purposes when the AKD library updates. For example, say that you as a developer
make a change to an existing AKD configuration which affects the byte format (either by replacing the hash function,
adjusting how hashing is done, or modifying the VRF computation). Then, when re-running the tests, the fixture tests will fail, to
indicate that a non-backwards-compatible change has been made.

If making a non-backwards-compatible change is intended, then this can be addressed by re-running the fixture generation code with
the following command:
```
cargo run -p examples -- fixture-generator \
  --epochs 10 \
  --max_updates 5 \
  --capture_states 9 10 \
  --capture_deltas 10 \
  --out examples/src/fixture_generator/examples/
```
This will automatically write the new fixtures to the appropriate files under `examples/src/fixture_generator/examples/`, and
the tests should now pass.