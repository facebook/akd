## akd ![Build Status](https://github.com/novifinancial/akd/workflows/CI/badge.svg)

An implementation of an auditable key directory (also known as a verifiable registry).

Auditable key directories can be used to help provide key transparency for end-to-end encrypted
messaging.

This implementation is based off of the protocol described in
[SEEMless: Secure End-to-End Encrypted Messaging with less trust](https://eprint.iacr.org/2018/607).

This library provides a stateless API for an auditable key directory, meaning that a consumer of this library must provide their own solution for the storage of the entries of the directory.

⚠️ **Warning**: This implementation has not been audited and is not ready for a production application. Use at your own risk!

Documentation
-------------

The API can be found [here](https://docs.rs/akd/) along with an example for usage.

Installation
------------

Add the following line to the dependencies of your `Cargo.toml`:

```
akd = "0.3"
```

### Minimum Supported Rust Version

Rust **1.51** or higher.

Contributors
------------

The authors of this code are
Jasleen Malvai ([@jasleen1](https://github.com/jasleen1)),
Kevin Lewi ([@kevinlewi](https://github.com/kevinlewi)), and
Sean Lawlor ([@slawlor](https://github.com/slawlor)).
To learn more about contributing to this project, [see this document](https://github.com/novifinancial/akd/blob/main/CONTRIBUTING.md).

License
-------

This project is licensed under either [Apache 2.0](https://github.com/novifinancial/akd/blob/main/LICENSE-APACHE) or [MIT](https://github.com/novifinancial/akd/blob/main/LICENSE-MIT), at your option.
