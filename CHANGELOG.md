# Changelog

## 0.12.0-pre.3 (April 4, 2024)
* Eliminates a rare bug that can result in an aZKS being overwritten during Directory initialization

## 0.12.0-pre.2 (March 26, 2024)
* Updated storage tombstone API params to be more ergonomic
* Renamed HistoryParams enum variants to highlight caveats
* Added NCC audit report to README
* Improved documentation
* Updated deploy script to support pre-release version strings

## 0.11.0 (October 26, 2023)
* Added error-handling for various edge-cases when performing akd_core verification
* Updated dependencies

## 0.10.0 (September 21, 2023)
* Updated VRF checks and public key validation
* Added duplicate entries check in publish
* Added zeroize on drop for VRFExpandedPrivateKey
* Reduced visibility of membership verification functions
* Added error checks for NodeLabel::try_from and get_bit_at functions

## 0.9.0 (August 21, 2023)
* Clarified dual-licensing wording
* Updated documentation and dependencies
* Renamed public-tests feature to public_tests
* Added a Configuration trait for specifying different cryptographic configurations of the tree
* Reorganized local_auditor, poc, akd_client, and others into an examples/ directory
* Added lookup verify check for version number exceeding epoch

## 0.8.9 (March 15, 2023)
* Added an opt-out optimization on batch-retrieval of nodes for lookup proof generation

## 0.8.8 (January 29, 2023)
* Contains optimizations for audit proof generation
* Adds support for parallelization of the audit proof generation along with disabling cache cleaning in audit proof generation

## 0.8.7 (January 18, 2023)
* More naming cleanups + reorganization
* Cleanup of unwrap()s in the codebase
* Use AzksValue as node value instead of Digest
* Preloading optimizations in history proofs

## 0.8.6 (January 11, 2023)
* Big naming cleanups
* Ability to mock the Database trait
* Fix in history proof validations
* Moving in-memory testing/audit database to DashMap for better parallel performance
* A auditor user-interface based on iced in Rust
* Code-coverage CI

## 0.8.5 (January 3, 2023)
* Avoid looking up previous version of nodes that are new

## 0.8.4 (January 2, 2023)
* Fixed bug in longest common prefix calculation
* Added sha512/256 support
* Updated Direction from Option<usize> to u8 enum
* Updated VRF label derivation and commitment generation
* Updated serialization to use big endian
* Optimized protobuf encoding
* Optimized VRF computations
* Optimized node preloading
* Optimized node insertion
* Parallelized calculations of VRF labels
* Parallelized node insertion

## 0.8.2 (December 16, 2022)
A slew of bug fixes (transactions not cleaning up, cache management, etc)
Reductions in loggers
Tests on WASM generation + proof verification
Fixing some namespace clashes (on proto module name)
General cleanups

## 0.8.0 (December 6, 2022)
* Remove defunct get_root_hash_at_epoch functionality
* Minimize the dependencies on tokio such that it minimizes imported crates into the dependency tree
* Major rewrite to remove all winter_* crates such that all verification functions and types are shared in a common akd_core crate
* Adapt best-practices for generated code in akd_core [for protobuf]

## 0.7.7 (November 24, 2022)
* Cleaned up documentation
* Updated history checks for validity
* Hasher generic moved from method calls to Directory struct
* Update VRF to latest specification
* VRF's enabled always
* API cleanups
* Large rewrite of storage management. Cache + transaction logic abstracted to common logic so database implementations are much more basic

## 0.7.6 (November 9, 2022)
* Protobuf serialization support for all over-the-wire types for efficient, backwards compatible encoding
* Leaning down of akd_client to reduce dependencies when feature flags not set
* Serialized proof validation in akd_client for embedded usages
* Independent auditor REPL for easy validation of proofs from a public storage account
* Breadth-first-search preloading for audit proofs

## 0.7.1 (August 30, 2022)
* Fix the cache concurrency problem where new node construction caused a database write-through and cache miss
* Fix handling of transactions with batch_set in the memory-based implementations such that caches weren't getting populated properly
* Added initial solution for public auditing from an S3 bucket (including backwards compatible protobuf serialization of the append-only proofs)

## 0.7.0 (July 21, 2022)
* oZKS construction removing the need for history node states, greatly reducing overall storage requirements
* Concurrent access (reading while writing) is supported, assuming atomic row operations

## 0.6.2 (June 1, 2022)
* Create an akd_test_tools crate to house test utilities that clients can import

## 0.6.1 (May 26, 2022)
* Check for sequential history in client key history proof validation
* Check values against last published value and skips duplicates in publish
* Migrate POC app from structopt to clap3
* Add tree fixture generator tool for tests
* Note: This release contains backward-incompatible changes to the Storage trait

## 0.5.5 (April 22, 2022)
* AKD dependency tree adjustments. No logical changes in the code

## 0.5.4 (April 22, 2022)
* A re-publish of 0.5.2

## 0.5.2 (March 15, 2022)
* "Lean" client supports key history proof validation
* Support tombstone's for expired value-states (GDPR style compliance)
* Bulk lookup proofs
* Cleanup of error handling patterns & flow
* Fixing the MySQL testing infra
* Verifiable random functions (VRFs) for node labels
* Better support for distributed environment (many read-nodes, single writer node)

## 0.4.0 (February 7, 2022)
* "Lean" client which is only dependent on the core hashing functionality. This is a new crate akd_client
* Full serialization of public structs
* Cleaning up risky unwrap() calls within the lib to minimize panic! risks

## 0.3.8 (January 25, 2022)
* Error and error code cleanups in the library
* Proof structs prefer vec of structs rather than paired vectors
* Fix CI pipeline publish
* Standardize AKD label & value partners
* Refactor storage interface

## 0.3.6 (December 14, 2021)
* Remove unbounded storage of epochs in HistoryTreeNode
* Deprecate the location field in HistoryTreeNode in favor of using the label directly to identify node position in storage
* POC db drop and bench-lookup operations

## 0.3.5 (December 10, 2021)
* Version bump

## 0.3.4 (December 10, 2021)
* Changed visibility of structs that are publicly exposed
* Upgrade winter_* to 0.2
* Other minor cleanups

## 0.3.3 (December 7, 2021)
* Pinning to tokio 1.10 instead of specifically 1.10.2

## 0.3.2 (December 7, 2021)
* Specific version is not required for the akd_mysql crate since major versions didn't change
* Require absolute URLs to reference information within crate documentation see
* Move publish pipeline to run checks on both packages before starting publish

## 0.3.1 (December 7, 2021)
* Versioning information changes & proper links for public release on crates.io

## 0.3.0 (December 7, 2021)
* Cleanup of DB layer and more performance improvements for MySQL storage.
* Additional documentation and general cleanups
* Removed MySQL dependencies on the core library functionality so if a user uses a different data-layer they are not dependent on MySQL
* Proof-of-concept (REPL) application + integration tests in CI pipeline
* Migration from tokio 0.2 to 1.X and mysql_async from 0.23.1 to 0.28.1

## 0.2.0 (November 5, 2021)

* Added more crate-level documentation
* Added a proof-of-concpt application that interacts with
  the storage layer

## 0.1.0 (November 1, 2021)

* Initial release
