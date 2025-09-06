## Developer set-up

### First-time Rust/Cargo installation via Rustup

1. Run `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh` to install Rust, as per the official Rustup installation guide at https://doc.rust-lang.org/stable/book/ch01-01-installation.html.
2. Restart your current shell, or source the env file under `$HOME/.cargo`
   * Eg. If using sh/bash/zsh, run `. "$HOME/.cargo/env"` to update your current shell's PATH to include Cargo's bin directory
3. Run `rustc --version` to validate Rust has been successfully installed
4. Run `cargo --version` to validate Cargo has been successfully installed
5. Run `cargo install --no-default-features --force cargo-make` to install cargo-make with minimal features, to enable defining and running custom tasks such as chained cargo commands to simplify validations during development
6. Run `cargo install cargo-llvm-cov` to enable evaluating test coverage
7. Run `cargo install cargo-audit --locked` to install cargo-audit, to enable auditing vulnerabilities in dependencies via `cargo audit`

### Building / testing the package locally

* `cargo make release-check` runs fmt check, build, test, and clippy - requires installing cargo-make, see first-time set-up steps above
* `cargo build` builds the executable so that it can be run via `./target/debug/validate_detection_rule_json`
* `cargo test` runs all unit tests
* `cargo llvm-cov --html` runs all unit tests and generates an HTML test coverage report
* `cargo clippy --all-targets -- -D warnings` evaluates code for common style issues, failing if there are any warnings/errors
* `./target/debug/validate_detection_rule_json [OPTIONS]` runs the locally built executable with the given options, if it has been set up via `cargo build`
  * Eg. `./target/debug/validate_detection_rule_json --help` displays the CLI's help text
  * Eg. `./target/debug/validate_detection_rule_json some_file.json` runs the validator against the provided input file
* `cargo run -- [OPTIONS]` builds the executable and runs it with the given options
  * Eg. `cargo run -- --help` builds the package and displays the CLI's help text
  * Eg. `cargo run -- some_file.json` builds the package and runs the validator against the provided input file
* `cargo fmt` reformats code to enforce the [Rust Style Guide](https://doc.rust-lang.org/stable/style-guide/), with support for project configurations
* `cargo fmt --all -- --check` evaluates whether there is any code violating the [Rust Style Guide](https://doc.rust-lang.org/stable/style-guide/), failing if there are style violations without automatically reformatting the code
* `cargo audit` evaluates whether dependencies imported via Cargo have reported vulnerabilities
