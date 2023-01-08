This package is included here to support the automatic reporting of code coverage on 
Github.

## Current code coverage

[![codecov](https://codecov.io/gh/facebook/akd/branch/main/graph/badge.svg?token=VFE82QWLTK)](https://codecov.io/gh/facebook/akd)

<img src="https://codecov.io/gh/facebook/akd/branch/main/graphs/sunburst.svg?token=VFE82QWLTK">

## Viewing code coverage locally

Do this once to set it up:
```
rustup component add llvm-tools-preview
cargo install grcov
```

Subsequently, run:
```
cargo xtask coverage --dev
```