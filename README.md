## vkd ![Build Status](https://github.com/novifinancial/SEEMless/workflows/CI/badge.svg)

An implementation of a verifiable key directory (also known as a verifiable registry).

Verifiable key directories can be used to help provide key transparency for end-to-end encrypted
messaging.

This implementation is based off of the protocol described in
[SEEMless: Secure End-to-End Encrypted Messaging with less trust](https://eprint.iacr.org/2018/607).

This library provides a stateless API for a verifiable key directory, meaning that a consumer of this library must provide their own solution for the storage of the entries of the directory.

Documentation
-------------

The API can be found [here](https://docs.rs/vkd/) along with an example for usage.

Installation
------------

Add the following line to the dependencies of your `Cargo.toml`:

```
seemless = "0.1.0"
```

### Minimum Supported Rust Version

Rust **1.51** or higher.

Contributors
------------

The authors of this code are
Jasleen Malvai ([@jasleen1](https://github.com/jasleen1)),
Kevin Lewi ([@kevinlewi](https://github.com/kevinlewi)), and
Sean Lawlor ([@slawlor](https://github.com/slawlor)).
To learn more about contributing to this project, [see this document](./CONTRIBUTING.md).

License
-------

This project is [licensed](./LICENSE) under either Apache 2.0 or MIT, at your option.
