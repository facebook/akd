## akd ![Build Status](https://github.com/facebook/akd/workflows/CI/badge.svg)

An implementation of an auditable key directory (also known as a verifiable registry or authenticated dictionary).

Auditable key directories can be used to help provide key transparency for end-to-end encrypted
messaging.

This implementation is based off of the protocols described in
[SEEMless](https://eprint.iacr.org/2018/607), with ideas incorporated from [Parakeet](https://eprint.iacr.org/2023/081).

This library provides a stateless API for an auditable key directory, meaning that a consumer of this library must provide their own solution for the storage of the entries of the directory.

Documentation
-------------

The API can be found [here](https://docs.rs/akd/) along with an example for usage. To learn more about the technical details
behind how the directory is constructed, see [here](https://docs.rs/akd_core/).

Installation
------------

Add the following line to the dependencies of your `Cargo.toml`:

```
akd = "0.12.0-pre.3"
```

### Minimum Supported Rust Version

Rust **1.51** or higher.

Top-Level Directory Organization
--------------------------------

| Subfolder           | On crates.io? | Description |
| :---                |  :---:        | :---        |
| `akd`               |    ✓          | Main implementation of AKD which a service provider that manages the underlying directory would need to run. A good starting point for diving into this implementation. |
| `akd_core`          |    ✓          | Minimal library consisting of core operations in AKD. |
| `examples`          |               | Contains various examples for using AKD, along with utilities such as locally verifying audit proofs that are produced by WhatsApp's key transparency deployment. More details are contained [here](examples/README.md). |
| `xtask`             |               | Used for running the code coverage pipeline. |


Audit
-----

This library was audited by NCC Group in August of 2023. The audit was sponsored by Meta for its use in [WhatsApp's key transparency deployment](https://engineering.fb.com/2023/04/13/security/whatsapp-key-transparency/).

The audit found issues in release `v0.9.0`, and the fixes were subsequently incorporated into release `v0.11.0`. See the [full audit report here](https://research.nccgroup.com/2023/11/14/public-report-whatsapp-auditable-key-directory-akd-implementation-review/).

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

This project is dual-licensed under either the [MIT license](https://github.com/facebook/akd/blob/main/LICENSE-MIT)
or the [Apache License, Version 2.0](https://github.com/facebook/akd/blob/main/LICENSE-APACHE).
You may select, at your option, one of the above-listed licenses.
