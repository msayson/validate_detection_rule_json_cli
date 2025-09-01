# validate_detection_rule_json_cli

[![Cargo Test](https://github.com/msayson/validate_detection_rule_json_cli/actions/workflows/cargo_test.yaml/badge.svg?branch=main)](https://github.com/msayson/validate_detection_rule_json_cli/actions/workflows/cargo_test.yaml)

Rust-based CLI to validate whether a file at a given filepath matches the [detection rule JSON Schema](resources/detection_rule_schema.json).

Usage:
* `validate_json FILEPATH` - validate provided file against the detection rule JSON Schema
* `validate_json --help` - display help message and exit
