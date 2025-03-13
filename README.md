# TurTLS 🐢

## A work-in-progress TLS 1.3 dynamic library
Note: Although turtls is written in Rust, it only provides a C API.

WARNING: This code has not been audited. Use it at your own risk.
================================================================

## Documentation

#### Latest Release
- [TurTLS](https://docs.rs/turtls)
- [crylib](https://docs.rs/crylib)

#### Master Branch
TODO: generate documentation for the master branch.

## Features
See `./ROADMAP.md` for a roadmap and complete list of features

### Cryptography
TurTLS maintains a general-purpose crypto library called [crylib](https://docs.rs/crylib). Its code can be found at `./crylib/`.

## Building
Make sure you have a recent version of Rust installed. This project uses on new language features as they release,
so make sure your version is recent enough.

To build in debug mode:
```bash
cargo build
```

To build in release mode:
```bash
cargo build --release
```

Move `libturtls.so` from `./target/debug/` -- debug -- or `./target/release/` -- release to the desired directory.

## License
Copyright 2024 Lukas Renner

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

See LICENSE for details
