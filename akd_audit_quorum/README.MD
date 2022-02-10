## akd ![Build Status](https://github.com/novifinancial/akd/workflows/CI/badge.svg)

An implementation of a distributed auditor for the auditable key directory (also known as a verifiable registry).

Auditable key directories can be used to help provide key transparency for end-to-end encrypted
messaging.

This implementation is based off of the protocol described in
[SEEMless: Secure End-to-End Encrypted Messaging with less trust](https://eprint.iacr.org/2018/607).

This library is the distributed, shard-based proof signature on the epoch and the changes which have been published in that
epoch.

### Purpose

To prevent a split-view attack the root hash of every epoch needs to have a signature signed by a private key which cannot be leaked
from the quorum (via shared-secret methodology). This quorum participates to independently validate the append-only proof of the
key directory and each one provides their partial shard of the quorum signing key and when enough participants agree, the changes
are signed off on and stored in stable storage. That way only a proof only needs to give the root hash, and the signature on it to acertain
the quorum has agreed on the changes, and the AKD (or any other 3rd party) cannot generate its own signatures.

⚠️ **Warning**: This implementation has not been audited and is not ready for a production application. Use at your own risk!

Documentation
-------------

The API can be found [here](https://docs.rs/akd_audit_quorum/) along with an example for usage.

Installation
------------

Add the following line to the dependencies of your `Cargo.toml`:

```
akd_audit_quorum = "0.4"
```

### Minimum Supported Rust Version

Rust **1.51** or higher.

Contributors
------------

The authors of this code are
Sean Lawlor ([@slawlor](https://github.com/slawlor)), and
Kevin Lewi ([@kevinlewi](https://github.com/kevinlewi)).

To learn more about contributing to this project, [see this document](https://github.com/novifinancial/akd/blob/main/CONTRIBUTING.md).

License
-------

This project is licensed under either [Apache 2.0](https://github.com/novifinancial/akd/blob/main/LICENSE-APACHE) or [MIT](https://github.com/novifinancial/akd/blob/main/LICENSE-MIT), at your option.
