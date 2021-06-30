## SEEMless ![Build Status](https://github.com/novifinancial/SEEMless/workflows/CI/badge.svg)

The history tree consists of a vector of HistoryTreeNodes and is assumed to be a k-ary trie. The vector is stored in an append only zero-knowledge set, which calls the various recursive functions on the root node.


## Immediate TODOs

* **DONE** Add API for a SEEMless directory.
* **DONE** Add one or two more tests for the `insert_single_leaf` function in `tests.rs`.
    - In particular add three leaves all on the same side of the root.
    - Also add multiple leaves to each side.
* **IN PROGRESS** Clean up the functions in `history_tree_node.rs` and refactor to remove redundant/repeated code.
* Implement the algorithms for `append_only_zks.rs`.


## A few points to take care of later

* In `seemless_directory.rs`, the verification functions are not supplied with commitments or VRF proofs. Need to update this.
* `HistoryProof`s currently contain some redundancy. In particular, the non-existence of future logarithmic entries can just be done for the last update.
