# Flamegraph analysis

## Installation

First is the need to install flamegraph tools with

```
cargo install flamegraph
```

Package [documentation](https://github.com/flamegraph-rs/flamegraph)

## Execution

Ideally before benchmarking you will want to flush the database (if pointing @ MySQL) which can be done with the stand-alone command

```
cargo run -- flush
```

run within the ```poc``` folder.

The following will execute the flamegraph doing a benchmark publish operation for 10 users with 10 updates / ea (i.e. 10 epochs with the same 10 users updating every epoch).

```
cargo flamegraph --dev --root -- bench-publish 10 10
```

Alternate the benchmark commands as you see fit, but the REPL is not supported with flamegraph. You can also add the ```-o``` flag to support specifying the flamegraph output location such as

```
cargo run -- flush && cargo flamegraph -o "doc/flamegraph-09-11-2021.svg" --dev --root -- bench-publish 10 10
```
