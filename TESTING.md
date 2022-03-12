# Testing code changes within `akd`

We are running a few types of tests within the AKD crate. They can be broken into the following categories

1. Unit tests
2. Integration tests
3. Manual testing through the proof-of-concept application

## Unit tests

Unit tests are pretty simple Rust tests utilizing [built-in testing best practices](https://doc.rust-lang.org/book/ch11-01-writing-tests.html). A few caveats worth noting however:

1. If your test is going to require calling async code you'll need to use ```#[tokio::test]``` instead of ```#[test]``` as the function decorator. It'll look something like
```rust
#[test]
fn my_test() {
  panic!("boom");
}

#[tokio::test]
async fn my_async_test() {
  panic!("async boom!");
}
```
2. Test organization is generally done by decorating a ```test``` or ```tests``` sub-module to the module under test with the ```#[cfg(test)]``` attribute which only makes the code included in the binary in test compilation.
3. Test log output is managed centrally with a single global startup function in [test_utils.rs](akd/src/test_utils.rs). If you're adding a new crate, you may want to add this in your crate as well to make sure you benefit from log messages when tests fail
```rust
/// Global test startup constructor. Only runs in the TEST profile. Each
/// crate which wants logging enabled in tests being run should make this call
/// itself.
///
/// However we additionally call the init_logger(..) fn in the external storage
/// based test suite in case an external entity doesn't want to deal with the
/// ctor construction (or initializing the logger themselves)
#[cfg(test)]
#[ctor::ctor]
fn test_start() {
    init_logger(Level::Info);
}
```
You'll need to add a dev-dependency on the `ctor` crate for this as well.

### `Storage` trait consistency testing

If you write a new storage layer for the AKD crate, you can run our standard suite of storage tests by adding a dev-dependency on the `akd` crate with the following configuration

```toml
[dev-dependencies]
akd = { path = "../akd", version = "^0.5.0", features = ["public-tests", "serde"] }
```

which will expose a common-testing pattern with the `public-tests` feature. The [`akd_mysql`](akd_mysql/src/mysql_db_tests.rs) crate does exactly this. You can simply run ths same test-suite for your new storage implementation that we run against all of them (and you'll benefit from downstream storage testing changes as well). Once you've setup your storage layer in your test case you simply invoke the suite

```rust
#[tokio::test]
async fn my_new_storage_tests() {
    // setup
    let storage = ...;

    // Run the test cases (will panic if error occurs so you get a stack trace)
    akd::storage::tests::run_test_cases_for_storage_impl(&storage).await;

    // teardown / cleanup (if necessary)
}
```

## Integration tests

If you want to add integration tests, they are organized in their own crate (`akd_integration_tests` in the [`integration_tests`](integration_tests/src) folder). We are still using the `#[cfg(test)]` build target and the test cases are still decorated with `#[tokio::test]`, however they run more full end-to-end test cases against real storage implementations.

The test organization is pretty straightforward. We have a common test structure defined in [`test_util.rs`](integration_tests/src/test_util.rs) as `directory_test_suite` which takes a database, number of users for the test, and VRF signing function. You can add tests in this location, and it is assuming the storage layer has been initialized and is ready for use. This is a common test-flow for all storage implementations we provide to make sure we don't break compatability with new implementations.

You can additionally add a new data-layer to the integration tests by adding a dev-dependency in the `akd_integration_tests` crate and adding a new `<storage>_tests.rs` file along with referencing it in [`lib.rs`](integration_tests/src/lib.rs).

## Manual testing

We additionally have a "proof-of-concept" (POC) application in the [`poc`](poc/src) folder. This application is a small command-line REPL (read-eval-print-loop) application to interact directly with an AKD hosted in a variety of configurations. You can see all the command line options and experiment with the app with

```bash
> cargo run -- --help
...truncated...
akd_app 0.0.0
applicationModes

USAGE:
    akd_app [FLAGS] [OPTIONS] [SUBCOMMAND]

FLAGS:
    -d, --debug      Activate debuging mode
        --memory     The database implementation to utilize
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
    -l, --log_level <Adjust the console log-level (default = INFO)>
             [default: Info]  [possible values: Error, Warn, Info, Debug, Trace]

    -m, --multirow_size <MySQL multi-row insert size>                   [default: 100]

SUBCOMMANDS:
    bench-db-insert    Benchmark database insertion
    bench-lookup       Benchmark lookup API
    bench-publish      Benchmark publish API
    drop               Drop existing database tables (for schema migration etc.)
    flush              Flush data from database tables
    help               Prints this message or the help of the given subcommand(s)
```

Note: The actual output of the command may differ if its arguments have been updated since this document was written.

# Running tests

Tests are run a few ways for this repository.

## CI pipeline

We have a [CI workflow](.github/ci.yml) which will run on any pull request. If you're adding special compilation flags to crates, you may need to add test coverage here for PRs for future devs.

## Local testing

Local testing is pretty straightforward with the standard Rust practice of

```bash
cargo test
```

run at the root of the repository. This will run all of the tests from all of the crates utilizing the default features for all crates. If you're trying to test just a single crate you can run

```bash
cargo test --package akd
```

to isolate what runs (some of the integration tests take some time to run and require a live Docker instance for example). You can optionally `cd` into a specific crate's root folder and run the tests for that crate there specifically. Example

```bash
cd akd
cargo test
```

is equivalent. Otherwise the full Rust suite of testing options with [Cargo Test](https://doc.rust-lang.org/cargo/commands/cargo-test.html) are available as well in this repo. Feel free to run the suite as you see fit. Another common adjustment done in this repository worth nothing is the used of specific features. For example, to test the `akd` crate with no verifiable random function (VRF) implementation, you can use the arguments

```bash
cargo test --package akd --no-default-features --features public-tests
```

which will disable the feature `vrf`, effectively running code paths tagged with

```rust
#[cfg(not(feature = "vrf"))]
```

See [no_vrf.rs](akd/src/ecvrf/no_vrf.rs) for an example of this in practice.
