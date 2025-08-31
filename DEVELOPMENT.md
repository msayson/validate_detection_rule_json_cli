## Developer set-up

### First-time Rust/Cargo installation via Rustup

1. Run `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh` to install Rust, as per the official Rustup installation guide at https://doc.rust-lang.org/stable/book/ch01-01-installation.html.
2. Restart your current shell, or source the env file under `$HOME/.cargo`
   * Eg. If using sh/bash/zsh, run `. "$HOME/.cargo/env"` to update your current shell's PATH to include Cargo's bin directory
3. Run `rustc --version` to validate Rust has been successfully installed
4. Run `cargo --version` to validate Cargo has been successfully installed

### Building / testing the package locally

* `cargo build` builds the executable so that it can be run via `./target/debug/validate_json`
* `cargo test` runs all unit tests
* `./target/debug/validate_json [OPTIONS]` runs the locally built executable with the given options, if it has been set up via `cargo build`
  * Eg. `./target/debug/validate_json --help` displays the CLI's help text
  * Eg. `./target/debug/validate_json some_file.json` runs the validator against the provided input file
* `cargo run -- [OPTIONS]` builds the executable and runs it with the given options
  * Eg. `cargo run -- --help` builds the package and displays the CLI's help text
  * Eg. `cargo run -- some_file.json` builds the package and runs the validator against the provided input file
