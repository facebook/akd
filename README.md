## akd ![Build Status](https://github.com/facebook/akd/workflows/CI/badge.svg)

An implementation of an auditable key directory (also known as a verifiable registry or authenticated dictionary).

Auditable key directories can be used to help provide key transparency for end-to-end encrypted
messaging.

This implementation is based off of the protocols described in
[SEEMless](https://eprint.iacr.org/2018/607), with ideas incorporated from [Parakeet](https://eprint.iacr.org/2023/081).

This library provides a stateless API for an auditable key directory, meaning that a consumer of this library must provide their own solution for the storage of the entries of the directory.

⚠️ **Warning**: This implementation has not been audited (yet). Use at your own risk!

Documentation
-------------

The API can be found [here](https://docs.rs/akd/) along with an example for usage. To learn more about the technical details
behind how the directory is constructed, see [here](https://docs.rs/akd_core/).

Installation
------------

Add the following line to the dependencies of your `Cargo.toml`:

```
akd = "0.9.0-pre.1"
```

### Minimum Supported Rust Version

Rust **1.51** or higher.

Contributors
------------

The original authors of this code are
Evan Au ([@afterdusk](https://github.com/afterdusk)),
Alex Chernyak ([@alexme22](https://github.com/alexme22)),
Dillon George ([@dillonrg](https://github.com/dillonrg)),
Sean Lawlor ([@slawlor](https://github.com/slawlor)),
Kevin Lewi ([@kevinlewi](https://github.com/kevinlewi)),
Jasleen Malvai ([@jasleen1](https://github.com/jasleen1)), and
Ercan Ozturk ([@eozturk1](https://github.com/eozturk1)).
To learn more about contributing to this project, [see this document](https://github.com/facebook/akd/blob/main/CONTRIBUTING.md).

License
-------

This project is licensed under either [Apache 2.0](https://github.com/facebook/akd/blob/main/LICENSE-APACHE) or [MIT](https://github.com/facebook/akd/blob/main/LICENSE-MIT), at your option.
